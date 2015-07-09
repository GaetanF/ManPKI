__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config

class ShCrl(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_disable(self, line):
        Config().config.set("ocsp", "enable", "false")

    def do_enable(self, line):
        Config().config.set("ocsp", "enable", "true")

    def do_uri(self, line):
        Config().config.set("ocsp", "uri", line)

    def show_ocsp(self):
        for name in Config().config.options("ocsp"):
            value = Config().config.get("ocsp", name)
            print '  %-12s : %s' % (name.title(), value)