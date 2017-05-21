Quickstart
==========

First, :doc:`Install manpki <install>`.

ManPKI Daemon deliver an api to manage X.509 PKI.
ManPKI implement root authority, subauthority, extension and profiles from X.509 Standard.
Modules can be integrated in this daemon like ldap or ocsp to extend functions (example : ldap integration, ocsp responder).

By default, manpkid run only on local using unix socket. Next, it can be configured to be network accessible.
The package manpki-cli provide a shell to connect to manpkid daemon using local socket or remote connection.