__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config, EventManager, Cron
import Secret
import re


class ShCrl(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)
        if not Cron().hasjob("crl"):
            Cron().add("crl", Secret.base_dir + "/lib/ManPKI/Cron/generate_crl.py", "5m", False)

    def do_disable(self, line):
        Config().config.set("crl", "enable", "false")
        Cron().disable("crl")

    def do_enable(self, line):
        Config().config.set("crl", "enable", "true")
        Cron().enable("crl")

    def do_validity(self, line):
        if re.match("^\d*$", line):
            Config().config.set("crl", "validity", line)
            Cron().set_schedule("crl", str(int(line)-1) + "d")
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
