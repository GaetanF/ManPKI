# ManPKI
Python Daemon for managing X.509 PKI

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

- Fill /etc/manpki/manpki.conf file in manpki with content :
    WEB_SECRET = randomstring
    TOKEN_SECRET = randomstring


Features
==========================================
- RESTFUL API
- X509 PKI
- Root-CA and Intermediate CA
- JOSE
- Internationalization
- PAM authentication