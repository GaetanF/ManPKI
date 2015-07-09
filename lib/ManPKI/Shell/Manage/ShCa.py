__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config, SSL
import re

class ShCa(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_name(self, line):
        Config().config.set("ca", "name", line)

    def do_basecn(self, line):
        Config().config.set("ca", "basecn", line)

    def do_extend(self, line):
        pass

    def do_create(self, line):
        if not SSL.check_ca_exist():
            self.create_ca()
        else:
            if raw_input("Do you want to erase current CA ? (y/n) :").lower() is "y":
                self.create_ca()
            else:
                print "*** CA already created !"

    def do_digest(self, line):
        if line in ("md2", "md5", "mdc2", "rmd160", "sha", "sha1", "sha224", "sha256", "sha384", "sha512"):
            Config().config.set("ca", "digest", line)
        else:
            print "*** Digest is not valid"

    def do_type(self, line):
        (type, perimeter) = line.split(" ")
        Config().config.set("ca", "isfinal", "false")
        if perimeter is "isfinal":
            Config().config.set("ca", "isfinal", "true")
        if type in ("rootca", "subca"):
            Config().config.set("ca", "type", type)
        else:
            print "*** CA Type is not valid"

    def do_keysize(self, line):
        if re.match("^\d*$", line):
            Config().config.set("ca", "keysize", line)
        else:
            print "*** Keysize is not valid"

    def do_validity(self, line):
        if re.match("^\d*$", line):
            Config().config.set("ca", "validity", line)
        else:
            print "*** Day validity is not valid"

    def do_parentca(self, line):
        if Config().config.get("ca", "type") is "subca":
            Config().config.set("ca", "parentca", line)
        else:
            print "*** Only SubCA can have a parent ca"

    def do_email(self, line):
        if re.match("([\w\-\.]+@(\w[\w\-]+\.)+[\w\-]+)", line):
            Config().config.set("ca", "email", line)
        else:
            print "*** Mail address is not valid"

    def show_ca(self):
        for name in Config().config.options("ca"):
            value = Config().config.get("ca", name)
            print '  %-12s : %s' % (name.title(), value)
        if SSL.check_ca_exist():
            print "Status : OK"
        else:
            print "Status : Not Created"

    def show_ca_detail(self):
        self.show_ca()
        if SSL.check_ca_exist():
            print "##################################################"
            print "### Detail"
            SSL.display_cert(SSL.get_ca())
        else:
            print "Cannot get details. CA not created yet"

    def create_ca(self):
        print "create ca"