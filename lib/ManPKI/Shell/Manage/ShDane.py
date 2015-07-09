__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config

class ShDane(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_disable(self, line):
        Config().config.set("dane", "enable", "false")

    def do_enable(self, line):
        Config().config.set("dane", "enable", "true")

    def show_dane(self):
        for name in Config().config.options("dane"):
            value = Config().config.get("dane", name)
            print '  %-12s : %s' % (name.title(), value)