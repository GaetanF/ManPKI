__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config, SSL, Render
import re

class ShCert(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_disable(self, line):
        Config().config.set("ocsp", "enable", "false")

    def do_enable(self, line):
        Config().config.set("ocsp", "enable", "true")

    def do_uri(self, line):
        Config().config.set("ocsp", "uri", line)

    def do_create(self, line):
        pass

    def do_keysize(self, line):
        if re.match("^\d*$", line):
            Config().config.set("cert", "keysize", line)
        else:
            print "*** Keysize is not valid"

    def do_validity(self, line):
        if re.match("^\d*$", line):
            Config().config.set("cert", "validity", line)
        else:
            print "*** Day validity is not valid"

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


