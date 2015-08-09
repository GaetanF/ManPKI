__author__ = 'ferezgaetan'

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from SocketServer import ThreadingMixIn
from Tools import SSL
import json
import base64
import OpenSSL
import threading
import logging
import sys
import daemonocle
import urlparse


class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content = self.rfile.read()
        data = json.JSONDecoder().decode(content)
        parsed_path = urlparse.urlparse(self.path)
        path = parsed_path.path
        if hasattr(self, 'cmd_'+path[1:]):
            data = getattr(self, 'cmd_'+path[1:])(data)
            state = data[0]
            msg = data[1]
            message = json.JSONEncoder().encode({'state': state, 'response':msg})

        self.send_response(200)
        self.end_headers()
        self.wfile.write(message)
        return


    def do_GET(self):
        parsed_path = urlparse.urlparse(self.path)
        path = parsed_path.path
        if hasattr(self, 'cmd_'+path[1:]):
            data = getattr(self, 'cmd_'+path[1:])()
            state = data[0]
            msg = data[1]
            message = json.JSONEncoder().encode({'state': state, 'response':msg})

        self.send_response(200)
        self.end_headers()
        self.wfile.write(message)
        return

    def cmd_ca_sign(self, data):
        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(data['cert']))
        cert.add_extensions([
            OpenSSL.crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=SSL.get_ca())
        ])
        capriv = SSL.get_ca_privatekey()
        certsigned = SSL.sign(cert, capriv, str(data['digest']))
        return 'OK', OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, certsigned)

    def cmd_ca_subject(self):
        return 'OK', "C=FR/ST=Savoie/L=Chambery/O=Ferez.FR/OU=PKI/CN=Root CA Ferez.FR"

    def cmd_ca_email(self):
        return 'OK', "pki@ferez.fr"

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    allow_reuse_address = True

    def shutdown(self):
        self.socket.close()
        HTTPServer.shutdown(self)


class SimpleHttpServer():
    def __init__(self, ip, port):

        self.server = ThreadedHTTPServer(("0.0.0.0", 2572), HTTPRequestHandler)

    def start(self):

        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

    def waitForThread(self):

        self.server_thread.join()

    def stop(self):

        self.server.shutdown()
        self.waitForThread()

def cb_shutdown(message, code):
    logging.info('Daemon is stopping')
    logging.debug(message)

def main():
    """This is my awesome daemon. It pretends to do work in the background."""
    logging.basicConfig(
        filename='/tmp/webapi.log',
        level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s',
    )
    logging.info('Daemon is starting')
    server = SimpleHttpServer("localhost", 2572)
    print 'ManPKI Web API Server Running...........'
    server.start()
    server.waitForThread()

if __name__ == '__main__':
    daemon = daemonocle.Daemon(
        worker=main,
        detach=True,
        shutdown_callback=cb_shutdown,
        pidfile='/tmp/webapi_daemon.pid',
    )
    daemon.do_action(sys.argv[1])


