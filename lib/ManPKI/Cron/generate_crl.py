__author__ = 'ferezgaetan'

import os.path
import OpenSSL
import ConfigParser
import Secret
from Tools import Mailer

config = ConfigParser.ConfigParser()
config.read(Secret.config_file)

crl_file = config.get("default", "certdir") + "/public/ca/crl.pem"
ca_file = config.get("default", "certdir") + "/public/ca/ca.crt"
ca_private = config.get("default", "certdir") + "/private/ca.privkey"

if os.path.exists(ca_file) and os.path.exists(ca_private) and config.getint("crl", "validity") and config.get("crl", "digest"):
    ca_str = open(ca_file, "r").read()
    ca_private_str = open(ca_private, "r").read()
    ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ca_str)
    private_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, ca_private_str)

    crl = OpenSSL.crypto.CRL()
    if os.path.exists(crl_file):
        crl_str = open(crl_file, "r").read()
        crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, crl_str)

    crl_str = crl.export(ca_cert, private_key, type=OpenSSL.crypto.FILETYPE_PEM, days=config.getint("crl", "validity"))
    f = open(crl_file, "w")
    f.write(crl_str)
    f.close()
    if ca_cert.get_subject().emailAddress:
        mail = Mailer()
        mail.to(ca_cert.get_subject().emailAddress)
        mail.subject("CRL Creation")
        mail.send("CRL file has been created")
