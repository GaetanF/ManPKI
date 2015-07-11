__author__ = 'ferezgaetan'

from ShShell import ShShell
from Tools import Config, SSL
from OpenSSL import crypto
from time import time
from datetime import datetime, timedelta
import re


class ShCa(ShShell):

    def __init__(self, init_all=True):
        ShShell.__init__(self, init_all)

    def do_name(self, line):
        Config().config.set("ca", "name", line)

    def do_basecn(self, line):
        Config().config.set("ca", "base_cn", line)

    def do_extend(self, line):
        pass

    def do_create(self, line):
        if not SSL.check_ca_exist():
            self.create_ca()
        else:
            if raw_input("Do you want to erase current CA ? (y/n) :").lower() == "y":
                print "All sub certificates will be resigned"
                self.create_ca(force=True)
            else:
                print "*** CA already created !"

    def do_digest(self, line):
        if line in ("md2", "md5", "mdc2", "rmd160", "sha", "sha1", "sha224", "sha256", "sha384", "sha512"):
            Config().config.set("ca", "digest", line)
        else:
            print "*** Digest is not valid"

    def do_type(self, line):
        if " " in line:
            (type, perimeter) = line.split(" ")
        else:
            type = line
            perimeter = None
        Config().config.set("ca", "isfinal", "false")
        if perimeter == "isfinal":
            Config().config.set("ca", "isfinal", "true")
        if type in ("rootca", "subca"):
            Config().config.set("ca", "type", type)
        else:
            print "*** CA Type is not valid"

    def do_keysize(self, line):
        if re.match("^\d*$", line):
            Config().config.set("ca", "key_size", line)
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

    def create_ca(self, force=False):
        if Config().config.get("ca", "type") == "subca":
            if SSL.check_parentca_exist():
                pass
            else:
                print "*** Parent CA must be exist before"
        else:
            before = datetime.utcnow()
            after = before + timedelta(days=Config().config.getint("ca", "validity"))

            pkey = SSL.create_key(Config().config.getint("ca", "key_size"))

            ca = SSL.create_cert(pkey)
            subject = Config().config.get("ca", "base_cn") + "/CN=" + Config().config.get("ca", "name")
            subject_x509 = SSL.parse_str_to_x509Name(subject, ca.get_subject())
            issuer_x509 = SSL.parse_str_to_x509Name(subject, ca.get_issuer())

            if Config().config.get("ca", "email"):
                subject_x509.emailAddress = Config().config.get("ca", "email")
                issuer_x509.emailAddress = Config().config.get("ca", "email")

            ca.set_subject(subject_x509)
            ca.set_issuer(issuer_x509)
            ca.set_notBefore(before.strftime("%Y%m%d%H%M%S%Z")+"Z")
            ca.set_notAfter(after.strftime("%Y%m%d%H%M%S%Z")+"Z")
            ca.set_serial_number(int(time() * 1000000))
            ca.set_version(2)

            bsConst = "CA:TRUE"
            if Config().config.getboolean("ca", "isfinal"):
                bsConst += ", pathlen:0"
            ca.add_extensions([
                crypto.X509Extension("basicConstraints", True, bsConst),
                crypto.X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
                crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=ca),
            ])
            ca.add_extensions([
                crypto.X509Extension("authorityKeyIdentifier", False, "keyid:always", issuer=ca)
            ])

            if Config().config.getboolean("crl", "enable"):
                crlUri = "URI:" + Config().config.get("crl", "uri")
                ca.add_extensions([
                    crypto.X509Extension("crlDistributionPoints", False, crlUri)
                ])

            if Config().config.getboolean("ocsp", "enable"):
                ocspUri = "OCSP;URI:" + Config().config.get("ocsp", "uri")
                ca.add_extensions([
                    crypto.X509Extension("authorityInfoAccess", False, ocspUri)
                ])

            ca_signed = SSL.sign(ca, pkey, Config().config.get("ca", "digest"))
            SSL.set_ca(ca_signed)
            SSL.set_ca_privatekey(pkey)

            if force:
                self.resigned_all_cert()

    def resigned_all_cert(self):
        for certhash in SSL.get_all_certificates():
            cert_signed = SSL.sign(certhash['cert'], SSL.get_ca_privatekey(), Config().config.get("cert", "digest"))
            SSL.set_cert(cert_signed)
