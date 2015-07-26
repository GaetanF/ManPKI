__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config, SSL, Render, EventManager, LDAP
from datetime import datetime, timedelta
from OpenSSL import crypto
from time import time
import re


class ShCert(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_create(self, line):
        print "Profile : "
        profiles = []
        i = 0
        for sec in Config().config.sections():
            if "profile_" in sec:
                profiles.append(sec[8:])
                print "\t%s: %s" % (i, sec[8:])
                i += 1
        pid = raw_input("Profile Number : ")
        if pid.isdigit():
            profile = profiles[int(pid)]
        else:
            print "*** Profile number isn't valid"
            return

        self.create_cert(profile)

    def do_revoke(self, line):
        if line:
            i=0
            for cert in SSL.get_all_certificates():
                if line == cert['id']:
                    i = 1
                    print "Reason : "
                    reasons = crypto.Revoked().all_reasons()
                    for (k, v) in enumerate(reasons):
                        print " %s: %s" % (k, v)
                    res = raw_input("Select reason : ")
                    if res.isdigit() and 0 <= int(res) < len(reasons):
                        revoked = crypto.Revoked()
                        revoked.set_reason(reasons[int(res)])
                        revoked.set_serial(hex(cert['cert'].get_serial_number())[2:-1])
                        revoked.set_rev_date(datetime.utcnow().strftime("%Y%m%d%H%M%S%Z")+"Z")
                        SSL.add_revoked(revoked)
                    else:
                        print "*** Reason is not valid"
            if i == 0:
                print "*** Certificate not found"
        else:
            print "revoke <certid>"

    def do_profile(self, line):
        if line:
            profile = line.split(' ')[0]
        else:
            profile = raw_input("Profile name : ")
        keys_usage = []
        extended_keys = []
        if Config().config.has_section("profile_" + profile):
            keys_usage = str(Config().config.get("profile_" + profile, "keyusage")).split('|')
            extended_keys = str(Config().config.get("profile_" + profile, "extended")).split('|')
        else:
            Config().config.add_section("profile_"+profile)
        keys_usage = Render.print_selector(SSL.get_key_usage(), keys_usage)
        extended_keys = Render.print_selector(SSL.get_extended_key_usage(), extended_keys)
        Config().config.set("profile_" + profile, "keyusage", '|'.join(keys_usage))
        Config().config.set("profile_" + profile, "extended", '|'.join(extended_keys))
        rep = raw_input("Use LDAP if enable to search subject (y/n) : ")
        if "y" in rep:
            filter = raw_input("LDAP Filter : ")
            Config().config.set("profile_" + profile, "ldap", filter)
        else:
            Config().config.set("profile_" + profile, "ldap", "false")

    def do_digest(self, line):
        if line in ("md2", "md5", "mdc2", "rmd160", "sha", "sha1", "sha224", "sha256", "sha384", "sha512"):
            Config().config.set("cert", "digest", line)
        else:
            print "*** Digest is not valid"

    def do_keysize(self, line):
        if re.match("^\d*$", line):
            if int(line) <= Config().config.getint("ca", "key_size"):
                Config().config.set("cert", "key_size", line)
            else:
                print "*** Cert Keysize cannot be granter than CA Keysize"
        else:
            print "*** Keysize is not valid"

    def do_validity(self, line):
        if re.match("^\d*$", line):
            if int(line) < Config().config.getint("ca", "validity"):
                Config().config.set("cert", "validity", line)
            else:
                print "*** Cert validity cannot be granter than CA validity"
        else:
            print "*** Day validity is not valid"

    def show_cert(self, certid=None):
        list = []
        if certid:
            rawmode = False
            if "_" in certid and certid.split("_")[1] == "raw":
                rawmode = True
                certid = certid.split("_")[0]
            i=0
            for cert in SSL.get_all_certificates():
                if certid == cert['id']:
                    i = 1
                    SSL.display_cert(cert['cert'])
                    if rawmode:
                        print crypto.dump_certificate(crypto.FILETYPE_PEM, cert['cert'])
            if i == 0:
                print "*** Certificate not found"
        else:

            for cert in SSL.get_all_certificates():
                state = SSL.get_state_cert(cert['cert'])
                list.append((cert['id'], SSL.get_x509_name(cert['cert'].get_subject()), state))
            Render.print_table(('ID', 'Subject', 'State'), list)

    def show_profile(self, profile=None):
        if profile:
            if Config().config.has_section("profile_" + profile):
                print "Profile %s" % profile
                self.display_profile(profile)
                print ""
            else:
                print "*** Profile does not exist"
        else:
            for sec in Config().config.sections():
                if "profile_" in sec:
                    print "Profile %s" % sec[8:]
                    self.display_profile(sec[8:])
                    print ""

    def display_profile(self, profile):
        keys = str(Config().config.get("profile_" + profile, "keyusage")).split("|")
        print "\tKey Usage"
        for (k, v) in SSL.get_key_usage().iteritems():
            if k in keys:
                print "\t\t%s" % v

        keys = str(Config().config.get("profile_" + profile, "extended")).split("|")
        print "\tExtended Key Usage"
        for (k, v) in SSL.get_extended_key_usage().iteritems():
            if k in keys:
                print "\t\t%s" % v

    def create_cert(self, profile):
        before = datetime.utcnow()
        after = before + timedelta(days=Config().config.getint("cert", "validity"))

        pkey = SSL.create_key(Config().config.getint("cert", "key_size"))

        ca = SSL.get_ca()
        cert = SSL.create_cert(pkey)
        if Config().config.get("ldap", "enable") and "false" not in Config().config.get("profile_" + profile, "ldap"):
            print "Search in LDAP"
            l = LDAP()
            filter = Config().config.get("profile_" + profile, "ldap")
            res = l.get_dn(l.get_basedn(), filter, ['cn', 'mail', 'uid'])
            listSearch = {}
            users = {}
            for elt in res:
                key = elt[0]
                val = elt[1]['cn'][0]
                mail = None
                if 'mail' in elt[1].keys():
                    mail = elt[1]['mail'][0]
                    val = val + " (mail : " + elt[1]['mail'][0] + ")"
                listSearch.update({key: val})
                users.update({key: {'mail': mail, 'cn': elt[1]['cn'][0]}})
            nbr_select = 0
            while nbr_select != 1:
                userList = Render.print_selector(listSearch)
                nbr_select = len(userList)
            email = users[userList[0]]['mail']
            cn = users[userList[0]]['cn']
            subject_array = userList[0].split(',')
            subject_array.reverse()
            subject_array.pop()
            subject = '/'.join(subject_array) + "/CN=" + cn
        else:
            cn = raw_input("Common Name : ")
            email = raw_input("Mail address : ")
            subject = Config().config.get("ca", "base_cn") + "/CN=" + cn
        subject_x509 = SSL.parse_str_to_x509Name(subject, cert.get_subject())

        issuer_x509 = ca.get_subject()
        if email:
            subject_x509.emailAddress = email

        cert.set_subject(subject_x509)
        cert.set_issuer(issuer_x509)
        cert.set_notBefore(before.strftime("%Y%m%d%H%M%S%Z")+"Z")
        cert.set_notAfter(after.strftime("%Y%m%d%H%M%S%Z")+"Z")
        cert.set_serial_number(int(time() * 1000000))
        cert.set_version(2)

        bsConst = "CA:FALSE"
        cert.add_extensions([
            crypto.X509Extension("basicConstraints", True, bsConst),
            crypto.X509Extension("keyUsage", True, SSL.get_key_usage_from_profile(profile)),
            crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=cert),
        ])
        cert.add_extensions([
            crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=ca)
        ])
        cert.add_extensions([
            crypto.X509Extension("extendedKeyUsage", False, SSL.get_extended_key_usage_from_profile(profile))
        ])

        if Config().config.getboolean("crl", "enable"):
            crlUri = "URI:" + Config().config.get("crl", "uri")
            cert.add_extensions([
                crypto.X509Extension("crlDistributionPoints", False, crlUri)
            ])

        if Config().config.getboolean("ocsp", "enable"):
            ocspUri = "OCSP;URI:" + Config().config.get("ocsp", "uri")
            cert.add_extensions([
                crypto.X509Extension("authorityInfoAccess", False, ocspUri)
            ])

        cert_signed = SSL.sign(cert, SSL.get_ca_privatekey(), Config().config.get("cert", "digest"))
        SSL.set_cert(cert_signed)
        SSL.set_cert_privatekey(cert_signed, pkey)

        if Config().config.getboolean("ldap", "enable"):
                LDAP.add_queue(cert_signed)
