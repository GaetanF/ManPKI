__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config, SSL
import hashlib


class ShDane(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_disable(self, line):
        Config().config.set("dane", "enable", "false")

    def do_enable(self, line):
        Config().config.set("dane", "enable", "true")

    def do_generate(self, line):
        if " " in line and len(line.split(" ")) == 4:
            (proto, port, fqdn, certid) = line.split(" ")
            if proto in ("tcp", "udp"):
                if 1 < int(port) < 65535:
                    if SSL.check_cert_exist(certid):
                        hash = hashlib.sha256(SSL.get_asn_cert_raw(certid)).hexdigest()
                        print "_%s._%s.%s.\tIN\tTLSA\t3 0 1 ( %s )" % (port, proto, fqdn, hash)
                    else:
                        print "*** Certificate does not exist"
                else:
                    print "*** Invalid port number"
            else:
                print "*** Invalid protocol"
        else:
            print "generate <proto> <port> <fqdn> <certid>"

    def show_dane(self):
        for name in Config().config.options("dane"):
            value = Config().config.get("dane", name)
            print '  %-12s : %s' % (name.title(), value)
