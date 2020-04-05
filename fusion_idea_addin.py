# Copyright 2020, Ben Gruver
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""
This add-in serves as a bridge between IDEA/PyCharm and Fusion 360.

It provides an http server that the IDE connects to in order to launch a script and connect back to the IDE's debugger.

Since multiple copies of Fusion 360 may be running at the same time, the http server starts listening on a random port.
To allow the IDE to discover the correct port for a given pid, this add-in also listens for and responds to SSDP search
requests.

And finally, in order to run a script on Fusion's main thread, this add-in registers a custom event with Fusion 360.
The http server triggers the custom event, and then the event handler gets run on Fusion's main thread and launches the
script, similarly to how Fusion would normally run it.
"""

import adsk.core
import adsk.fusion
import http.client
from http.server import HTTPServer, BaseHTTPRequestHandler
import importlib
import io
import json
import logging
import os
import socketserver
import sys
import threading
import logging.handlers
import traceback
from typing import Optional

# name of asynchronous even which will be used to launch a script inside fusion 360
CUSTOM_EVENT_NAME = "fusion_idea_addin_run_script"


def app():
    return adsk.core.Application.get()


def ui():
    return app().userInterface


logger = logging.getLogger("fusion_idea_addin")
logger.propagate = False


class AddIn(object):
    def __init__(self):
        self._event_handler: Optional[DebugScriptEventHandler] = None
        self._custom_event: Optional[adsk.core.CustomEvent] = None
        self._http_server: Optional[HTTPServer] = None
        self._ssdp_server: Optional["SSDPServer"] = None
        self._logging_file_handler: Optional[logging.Handler] = None

    def start(self):
        try:
            try:
                app().unregisterCustomEvent(CUSTOM_EVENT_NAME)
            except Exception:
                pass

            self._logging_file_handler = logging.handlers.RotatingFileHandler(
                filename=os.path.join(os.path.dirname(os.path.realpath(__file__)), "fusion_idea_addin_log.txt"),
                maxBytes=2**20,
                backupCount=1)
            self._logging_file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
            logger.addHandler(self._logging_file_handler)
            logger.setLevel(logging.DEBUG)

            self._custom_event = app().registerCustomEvent(CUSTOM_EVENT_NAME)
            self._event_handler = DebugScriptEventHandler()
            self._custom_event.add(self._event_handler)

            # Run the http server on a random port, to avoid conflicts when multiple instances of Fusion 360 are
            # running.
            self._http_server = HTTPServer(("localhost", 0), RunScriptHTTPRequestHandler)

            http_server_thread = threading.Thread(target=self.run_http_server, daemon=True)
            http_server_thread.start()

            ssdp_server_thread = threading.Thread(target=self.run_ssdp_server, daemon=True)
            ssdp_server_thread.start()
        except Exception:
            ui().messageBox("Error while starting fusion_idea_addin.\n\n%s" % traceback.format_exc())

    def run_http_server(self):
        logger.debug("starting http server")
        try:
            with self._http_server:
                self._http_server.serve_forever()
        except Exception:
            logger.error("Error occurred while starting the http server.", exc_info=sys.exc_info())

    def run_ssdp_server(self):
        logger.debug("starting ssdp server")
        try:
            with SSDPServer(self._http_server.server_port) as server:
                self._ssdp_server = server
                server.serve_forever()
        except Exception:
            logger.error("Error occurred while starting the ssdp server.", exc_info=sys.exc_info())

    def stop(self):
        if self._http_server:
            try:
                self._http_server.shutdown()
                self._http_server.server_close()
            except Exception:
                logger.error("Error while stopping fusion_idea_addin's HTTP server.", exc_info=sys.exc_info())
        self._http_server = None

        if self._ssdp_server:
            try:
                self._ssdp_server.shutdown()
                self._ssdp_server.server_close()
            except Exception:
                logger.error("Error while stopping fusion_idea_addin's SSDP server.", exc_info=sys.exc_info())
        self._ssdp_server = None

        try:
            if self._event_handler and self._custom_event:
                self._custom_event.remove(self._event_handler)

            if self._custom_event:
                app().unregisterCustomEvent(CUSTOM_EVENT_NAME)
        except Exception:
            logger.error("Error while unregistering fusion_idea_addin's custom event handler.", exc_info=sys.exc_info())
        self._event_handler = None
        self._custom_event = None

        try:
            if self._logging_file_handler:
                self._logging_file_handler.close()
                logger.removeHandler(self._logging_file_handler)
        except Exception:
            ui().messageBox("Error while closing fusion_idea_addin's logger.\n\n%s"
                            % traceback.format_exc())
        self._logging_file_handler = None


# noinspection PyUnresolvedReferences
class DebugScriptEventHandler(adsk.core.CustomEventHandler):
    """
    An event handler that can run a python script in the main thread of fusion 360, and initiate debugging.
    """

    # noinspection PyMethodMayBeStatic
    def notify(self, args):
        try:
            args = json.loads(args.additionalInfo)
            script_path = os.path.abspath(args["script"])
            detach = args["detach"]
            pydevd_path = args["pydevd_path"]

            if os.path.isfile(script_path):
                script_name = os.path.splitext(os.path.basename(script_path))[0]
                script_dir = os.path.dirname(script_path)

                sys.path.append(pydevd_path)
                sys.path.append(os.path.join(pydevd_path, "pydevd_attach_to_process"))
                sys.path.append(script_dir)
                try:
                    try:
                        import attach_script
                        attach_script.attach(args["debug_port"], "localhost")
                    except Exception:
                        logger.error("An error occurred while while starting debugger.", exc_info=sys.exc_info())
                        ui().messageBox("An error occurred while while starting debugger.\n\n%s" %
                                        traceback.format_exc())

                    try:
                        module = importlib.import_module(script_name)
                        importlib.reload(module)
                        module.run({"isApplicationStartup": False})
                    except Exception:
                        logger.error("Unhandled exception while importing and running script.", exc_info=sys.exc_info())
                        ui().messageBox("Unhandled exception while importing and running script.\n\n%s" %
                                        traceback.format_exc())
                finally:
                    if detach:
                        try:
                            import pydevd
                            pydevd.stoptrace()
                        except Exception:
                            logger.error("Error while stopping tracing.", exc_info=sys.exc_info())
                    del sys.path[-1]
                    del sys.path[-1]
        except Exception:
            logger.error("An error occurred while attempting to start script.", exc_info=sys.exc_info())
            ui().messageBox("An error occurred while attempting to start script.\n\n%s" %
                            traceback.format_exc())


class RunScriptHTTPRequestHandler(BaseHTTPRequestHandler):
    """An HTTP request handler that queues an event in the main thread of fusion 360 to run a script."""

    # noinspection PyPep8Naming
    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        body = self.rfile.read(content_length)

        try:
            request_data = json.loads(body.decode())

            adsk.core.Application.get().fireCustomEvent(CUSTOM_EVENT_NAME, json.dumps(request_data))

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"done")
        except Exception:
            self.send_response(500)
            self.end_headers()
            self.wfile.write(traceback.format_exc().encode())
            logger.error("An error occurred while handling http request.", exc_info=sys.exc_info())


class SSDPRequestHandler(socketserver.BaseRequestHandler):

    def handle(self):
        data = self.request[0].strip()
        socket = self.request[1]

        logger.log(logging.DEBUG, "got ssdp request:\n%s" % data)

        try:
            request_line, headers_text = data.split(b"\r\n", 1)
            headers = http.client.parse_headers(io.BytesIO(headers_text))
        except Exception:
            logger.error("An error occurred while parsing ssdp request:\n%s" % data,
                         exc_info=sys.exc_info())
            return

        if (request_line == b"M-SEARCH * HTTP/1.1" and
                headers["MAN"] == '"ssdp:discover"' and
                headers["ST"] == "fusion_idea:debug"):
            response = ("HTTP/1.1 200 OK\r\n"
                        "ST: fusion_idea:debug\r\n"
                        "USN: pid:%(pid)d\r\n"
                        "Location: 127.0.0.1:%(debug_port)d\r\n\r\n") % {
                           "pid": os.getpid(),
                           "debug_port": self.server.debug_port}

            logger.debug("responding to ssdp request")
            socket.sendto(response.encode("utf-8"), self.client_address)
        else:
            logger.warning("Got an unexpected ssdp request:\n%s" % data)


class SSDPServer(socketserver.UDPServer):

    def __init__(self, debug_port):
        self.debug_port = debug_port
        self.allow_reuse_address = True
        super().__init__(("127.0.0.1", 1900), SSDPRequestHandler)

    def handle_error(self, request, client_address):
        logger.error("An error occurred while processing ssdp request.", exc_info=sys.exc_info())


addin = AddIn()


def run(_):
    addin.start()


def stop(_):
    logger.debug("stopping")
    addin.stop()
