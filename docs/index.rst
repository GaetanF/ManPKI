ManPKI
======

X.509 PKI Manager Daemon

|Build Status| |Coverage Status| |Codacy Status|

ManPKI Daemon deliver an api to manage X.509 PKI.
ManPKI implement root authority, subauthority, extension and profiles from X.509 Standard.
Modules can be integrated in this daemon like ldap or ocsp to extend functionnalities (example : ldap integration, ocsp responder).

By default, manpkid run only on local using unix socket. Next, it can be configured to be network accessible.
The package manpki-cli provide a shell to connect to manpkid daemon using local socket or remote connection.

Functionnality
==============

.. toctree::
   :maxdepth: 2

   functionnality

API
===

.. toctree::
   :maxdepth: 2

   api/index

Principles
==========

This is a X.509 PKI implementation which requires the use of the OpenSSL python library.

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

.. |Build Status| image:: https://travis-ci.org/GaetanF/manpki.svg?branch=develop
   :target: https://travis-ci.org/GaetanF/manpki
.. |Coverage Status| image:: https://codecov.io/gh/GaetanF/manpki/branch/develop/graph/badge.svg
   :target: https://codecov.io/gh/GaetanF/manpki
.. |Codacy Status| image:: https://api.codacy.com/project/badge/Grade/9514a70aca864380a95be6dea3fe76b3
   :target: https://www.codacy.com/app/GaetanF/manpki
