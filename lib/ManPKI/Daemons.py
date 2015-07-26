__author__ = 'ferezgaetan'

import BaseHTTPServer, SimpleHTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler
from Tools import SSL
import ssl
import urlparse
import json
import OpenSSL
import base64

class WebAPIServer:

    class GetHandler(BaseHTTPRequestHandler):

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

    def run(self):
        httpd = BaseHTTPServer.HTTPServer(('localhost', 2572), WebAPIServer.GetHandler)
        httpd.socket = ssl.wrap_socket (httpd.socket, certfile='./server.pem', server_side=True)
        print 'Starting server, use <Ctrl-C> to stop'
        httpd.serve_forever()


class SmtpPKIServer:

    pass


class Daemons:

    @staticmethod
    def check_status():
        print "OK"
