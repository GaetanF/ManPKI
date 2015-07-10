__author__ = 'ferezgaetan'
from ShShell import ShShell
from Tools import Config
import Daemons


class ShManage(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    @staticmethod
    def help_manage():
        print "Enter configuration mode"

    def show_status(self):
        Daemons.Daemons.check_status()

    def do_smtp(self, line):
        if " " in line:
            if line.split(" ")[0] == "server":
                Config().config.set("smtp", "server", line.split(" ")[1])
            elif line.split(" ")[0] == "from":
                Config().config.set("smtp", "from", line.split(" ")[1])
        else:
            print "server\tConfigure smtp server\nfrom\tConfigure source mail address"
