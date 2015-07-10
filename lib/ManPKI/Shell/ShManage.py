__author__ = 'ferezgaetan'
from ShShell import ShShell
import Daemons


class ShManage(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    @staticmethod
    def help_manage():
        print "Enter configuration mode"

    def show_status(self):
        Daemons.Daemons.check_status()




