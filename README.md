# ManPKI
Python Shell to Manage X509 PKI

Prerequisites
==========================================
- python-configparser
- python-pyasn1
- python-scp
- python-ldap
- python-crontab
- python-daemonocle
- python-pycrypto
- python-OpenSSL

Setup
==========================================

- Create Secret.py file in lib/ManPKI with content :

appSecret = ### SHA1 Secret to encode password ###
base_dir = ### Base Dir of ManPKI ###
IV = ### AES IV ###
config_file = base_dir + "/etc/manpki.conf"
base_show = base_dir + "/lib/ManPKI/Shell"
spool_dir = base_dir + "/var/spool/manpki"
debug = False
api_token = ### SHA1 Secret for WebAPI ManPKI ###

Features
==========================================
- X509 PKI
- Root-CA and Intermediate CA
- Copy file using FTP, HTTP, SCP, TFTP
- WebAPI between ManPKI instance to get information/file
- OCSP Responder
- LDAP Publisher
- OpenSSL Profile for certificate
- CRL Certificate
- Revoke certificate
- DANE TLSA Generator
