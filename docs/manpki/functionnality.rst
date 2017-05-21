Functionnality
==============

X.509 Implementation
--------------------

ManPKI API implement function to manage a X.509 PKI.
Root CA and Sub CA can be managed by deploying multiple daemon (one daemon by certificate authority).

Module extension
----------------

The API can be extended with the installation of new python module.
For example, a module can installed to map certificate to ldap directory or to implement OCSP responder

PAM Authentication
------------------

All users must be authenticated to the daemon before interaction with it.
The API authentication are based on PAM authentication.

TLS Web Server
--------------

The daemon implement directly his TLS Web Server. Another web server or proxy are not necessary.

JOSE Signature
--------------

All request are based on JSON and all json message are signed by JOSE. The key are unique for each session.

Access rights
-------------

The API access are based on some basic groups.

.. tabularcolumns:: |p{3cm}|p{12cm}|

+-------------+---------------------------------------------------------+
| Base Group  | Description                                             |
+=============+=========================================================+
| ``user``    | Can only request certificate and show information       |
+-------------+---------------------------------------------------------+
| ``ra``      | Can validate request certificate                        |
+-------------+---------------------------------------------------------+
| ``ca``      | Can manage all the Certificate Authority                |
+-------------+---------------------------------------------------------+
| ``admin``   | Can manage the CA and the API Web Server                |
+-------------+---------------------------------------------------------+

Events
------

Some event can be fire by the daemon for other module registered.
For example, the daemon fire an event when the ca are created.
This event can be listen by a manpki module to insert the certificate in ldap directory
