# ManPKI
X.509 PKI API Manager

|Build Status| |Coverage Status| |Codacy Status| |Readthedocs Status|


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

.. |Build Status| image:: https://travis-ci.org/GaetanF/manpki.svg?branch=develop
   :target: https://travis-ci.org/GaetanF/manpki
.. |Coverage Status| image:: https://codecov.io/gh/GaetanF/manpki/branch/develop/graph/badge.svg
   :target: https://codecov.io/gh/GaetanF/manpki
.. |Codacy Status| image:: https://api.codacy.com/project/badge/Grade/9514a70aca864380a95be6dea3fe76b3
   :target: https://www.codacy.com/app/GaetanF/manpki
.. |Readthedocs Status| image:: https://readthedocs.org/projects/pip/badge/?version=latest
   :target: http://manpki.readthedocs.io/en/latest/
