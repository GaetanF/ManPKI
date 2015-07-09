__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config
import ldap
import re

class ShLdap(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_disable(self, line):
        Config().config.set("ldap", "enable", "false")

    def do_enable(self, line):
        Config().config.set("ldap", "enable", "true")

    def do_dn(self, line):
        (dn, password) = line.split(" ")
        try:
            l = ldap.initialize(line)
            try:
                l.bind_s(dn, password)
            except ldap.INVALID_CREDENTIALS:
                print "Your username or password is incorrect."

            except ldap.LDAPError, e:
                if type(e.message) == dict and e.message.has_key('desc'):
                    print e.message['desc']
                else:
                    print e
        finally:
            l.unbind()

    def do_server(self, line):
        try:
            l = ldap.initialize(line)
            Config().config.set("ldap", "server", line)
        except ldap.LDAPError, e:
            print "LDAP Server is not valid : " + e
        finally:
            l.unbind()

    def do_email(self, line):
        Config().config.set("ldap", "email", line)

    def do_mode(self, line):
        if line in ("never", "ondemand", "schedule"):
            Config().config.set("ldap", "mode", line)
        else:
            print "Invalid LDAP publish mode (never,ondemand,schedule)"

    def do_schedule(self, line):
        if Config().config.get("ldap", "mode") == "schedule":
            if re.match("^\d+[mhd]$", line):
                Config().config.set("ldap", "schedule", line)
            else:
                print "Schedule are not valid"
        else:
            print "'schedule' can only be call in scheduled publish mode"

    def do_publish(self, line):
        print "Publish to LDAP"

    def show_ldap(self):
        for name in Config().config.options("ldap"):
            value = Config().config.get("ldap", name)
            print '  %-12s : %s' % (name.title(), value)

    def show_ldap_help(self):
        print "show ldap"

    def show_ldap_statistics(self):
        print "show ldap statistics"
    
    def show_ldap_statistics_help(self):
        print "show ldap statistics"
