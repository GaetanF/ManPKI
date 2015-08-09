__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config, SSL, Render
from Daemons import Daemons


class ShOcsp(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_disable(self, line):
        Config().config.set("ocsp", "enable", "false")

    def do_enable(self, line):
        Config().config.set("ocsp", "enable", "true")
        if Config().config.getboolean("ocsp", "enable") and len(Config().config.get("ocsp", "cert")) > 0:
            Daemons.start_daemon("ocsp")
        else:
            print "OCSP Responder won't be started without an OCSP Certificate"

    def do_cert(self, line):
        if SSL.check_cert_exist(line):
            cert = SSL.get_cert(line)
            keyusage = ['digitalSignature', 'nonRepudiation', 'keyEncipherment']
            extendedkeys = ['1.3.6.1.5.5.7.3.9']
            if SSL.cert_equal_to_key_and_extended_key(cert, keyusage, extendedkeys, strict=False):
                Config().config.set("ocsp", "cert", line)
            else:
                print "Certificate is not valid to use with OCSP Responder"
        else:
            profile = Render.select_profile()
            certid = Render.select_cert(profile=profile)
            Config().config.set("ocsp", "cert", certid)
        if Config().config.getboolean("ocsp", "enable") and len(Config().config.get("ocsp", "cert")) > 0:
            Daemons.start_daemon("ocsp")
        else:
            print "OCSP must be enable and valid certificate for responder must be present"

    def do_uri(self, line):
        Config().config.set("ocsp", "uri", line)

    def show_ocsp(self):
        for name in Config().config.options("ocsp"):
            value = Config().config.get("ocsp", name)
            print '  %-12s : %s' % (name.title(), value)
        print "Daemon Status : "
        Daemons.check_status("ocsp")