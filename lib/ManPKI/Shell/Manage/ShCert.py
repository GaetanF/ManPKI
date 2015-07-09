__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config, SSL, Render

class ShCert(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_disable(self, line):
        Config().config.set("ocsp", "enable", "false")

    def do_enable(self, line):
        Config().config.set("ocsp", "enable", "true")

    def do_uri(self, line):
        Config().config.set("ocsp", "uri", line)

    def show_cert(self, certid=None):
        list = []
        if certid:
            i=0
            for cert in SSL.get_all_certificates():
                if certid == cert['id']:
                    i=1
                    SSL.display_cert(cert['cert'])
            if i == 0:
                print "*** Certificate not found"
        else:
            for cert in SSL.get_all_certificates():
                list.append((cert['id'], SSL.get_x509_name(cert['cert'].get_subject())))
            Render.print_table(('ID', 'Subject'), list)


