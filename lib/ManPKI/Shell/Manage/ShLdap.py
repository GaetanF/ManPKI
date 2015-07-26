__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config, EventManager, LDAP, SSL, Cron
import Secret
import ldap
import re


class ShLdap(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)
        if not Cron().hasjob("ldap"):
            Cron().add("ldap", Secret.base_dir + "/lib/ManPKI/Cron/publish_ldap.py", "5m", False)

    def do_disable(self, line):
        Config().config.set("ldap", "enable", "false")
        Cron().disable("ldap")

    def do_enable(self, line):
        Config().config.set("ldap", "enable", "true")
        LDAP().queue_all()

    def do_dn(self, line):
        (dn, password) = line.split(" ")
        l = ldap.initialize(Config().config.get("ldap", "server"))
        try:
            l.bind_s(dn, password)
            Config().config.set("ldap", "dn", dn)
            LDAP().set_password(password)
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
            if line in "schedule":
                Cron().enable("ldap")
            else:
                Cron().disable("ldap")
        else:
            print "Invalid LDAP publish mode (never,ondemand,schedule)"

    def do_schedule(self, line):
        if Config().config.get("ldap", "mode") == "schedule":
            if re.match("^\d+[mhd]$", line):
                Config().config.set("ldap", "schedule", line)
                Cron().set_schedule("ldap", line)
            else:
                print "Schedule are not valid"
        else:
            print "'schedule' can only be call in scheduled publish mode"

    def do_publish(self, line):
        if Config().config.getboolean("ldap", "enable"):
            if "never" not in Config().config.get("ldap", "mode"):
                print "Publish to LDAP"
                if "all" in line:
                    LDAP().queue_all()
                if LDAP().publish():
                    print "done"
            else:
                print "LDAP configured in Never publish mode"
        else:
            print "LDAP service not enable"

    def do_test(self, line):
        print LDAP().get_password()
        try:
            if LDAP().check_dn_exist(SSL.get_ca()):
                print "BaseDN : " + LDAP().get_basedn()
                print "Connection and require object successful"
            elif LDAP().check_dn_exist(SSL.get_ca(), depth=1):
                print "Connection successful. Required object need to be created"
            else:
                print "Connection OK. Require Base DN not exist"
        except ldap.CONNECT_ERROR:
            print "Unable to connect"


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
