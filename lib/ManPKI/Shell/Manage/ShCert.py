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

    def show_cert(self):
        list = []
        for cert in SSL.get_all_certificates():
            list.append((cert['id'], SSL.get_x509_name(cert['cert'].get_subject())))
        Render.print_table(('ID', 'Subject'), list)


