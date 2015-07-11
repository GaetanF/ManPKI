__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config, SSL, Render
import re


class ShCert(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_create(self, line):
        pass

    def profile(self, line):
        if line:
            profile = line.split(' ')[0]
        else:
            profile = raw_input("Profile name : ")
        keys_usage = extended_keys = []
        if Config().config.has_section("profile_" + profile):
            keys_usage = str(Config().config.get("profile_" + profile, "keyusage")).split('|')
            extended_keys = str(Config().config.get("profile_" + profile, "extended")).split('|')
        else:
            Config().config.add_section("profile_"+profile)
        keys_usage = Render.print_selector(SSL.get_key_usage(), keys_usage)
        extended_keys = Render.print_selector(SSL.get_extended_key_usage(), extended_keys)
        Config().config.set("profile_" + profile, "keyusage", '|'.join(keys_usage.keys()))
        Config().config.set("profile_" + profile, "extended", '|'.join(extended_keys.keys()))

    def do_keysize(self, line):
        if re.match("^\d*$", line):
            Config().config.set("cert", "keysize", line)
        else:
            print "*** Keysize is not valid"

    def do_validity(self, line):
        if re.match("^\d*$", line):
            Config().config.set("cert", "validity", line)
        else:
            print "*** Day validity is not valid"

    def show_cert(self, certid=None):
        list = []
        if certid:
            i=0
            for cert in SSL.get_all_certificates():
                if certid == cert['id']:
                    i=1
                    SSL.display_cert(cert['cert'])
            if i == 0:
                print "*** Certificate not found"
        else:
            for cert in SSL.get_all_certificates():
                list.append((cert['id'], SSL.get_x509_name(cert['cert'].get_subject())))
            Render.print_table(('ID', 'Subject'), list)


