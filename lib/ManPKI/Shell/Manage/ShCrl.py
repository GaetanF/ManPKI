__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config
import re


class ShCrl(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_disable(self, line):
        Config().config.set("crl", "enable", "false")

    def do_enable(self, line):
        Config().config.set("crl", "enable", "true")

    def do_validity(self, line):
        if re.match("^\d*$", line):
            Config().config.set("crl", "validity", line)
        else:
            print "*** CRL Validity is not valid"

    def do_digest(self, line):
        if line in ("md2", "md5", "mdc2", "rmd160", "sha", "sha1", "sha224", "sha256", "sha384", "sha512"):
            Config().config.set("crl", "digest", line)
        else:
            print "*** Digest is not valid"

    def do_publisher(self, line):
        if re.match('^(ssh|ftp|tftp)://.*$'):
            Config().config.set("crl", "publisher", line)
        else:
            print "*** CRL Remote publish is not valid"

    def do_uri(self, line):
        Config().config.set("crl", "uri", line)

    def show_crl(self):
        for name in Config().config.options("crl"):
            value = Config().config.get("crl", name)
            print '  %-12s : %s' % (name.title(), value)
