__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config
import shlex


class ShOpenssl(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_set(self, line):
        if line and len(shlex.split(line)) == 3:
            (type, oid, name) = shlex.split(line)
            if type in ("keyusage", "extended"):
                Config().config.set(type, oid, name)
            else:
                print "set [keyusage|extended] <oid> <name>"
        else:
            print "set [keyusage|extended] <oid> <name>"

    def do_remove(self, line):
        if line and len(shlex.split(line)) == 2:
            (type, oid) = shlex.split(line)
            if type in ("keyusage", "extended"):
                Config().config.remove_option(type, oid)
            else:
                print "remove [keyusage|extended] <oid>"
        else:
            print "remove [keyusage|extended] <oid>"

    def show_openssl(self):
        print "Key Usage :"
        for it in Config().config.items("keyusage"):
            print "\t%s => %s" % it

        print "\nExtended Key Usage :"
        for it in Config().config.items("extended"):
            print "\t%s => %s" % it
