ManPKI
======

X.509 PKI API Manager

|build| |coverage| |codacy| |readthedocs|


Setup
==========================================

- Fill /etc/manpki/manpki.conf file in manpki with content :
    [default]
    websecret = randomstring
    tokensecret = randomstring


Features
==========================================
- RESTFUL API
- X509 PKI
- Root-CA and Intermediate CA
- JOSE
- Internationalization
- PAM authentication
- Module extension


.. |build| image:: https://travis-ci.org/GaetanF/manpki.svg?branch=develop
.. |coverage| image:: https://codecov.io/gh/GaetanF/manpki/branch/develop/graph/badge.svg
.. |codacy| image:: https://api.codacy.com/project/badge/Grade/9514a70aca864380a95be6dea3fe76b3
.. |readthedocs| image:: https://readthedocs.org/projects/pip/badge/?version=latest
