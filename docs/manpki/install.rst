Installation and Configuration
==============================

From git
--------

To install manpki from git, download master.zip from github/GaetanF/manpki.git or clone the repository :

::

 $ git clone https://github.com/GaetanF/manpki.git

You need to install all dependencies needed by the program present in requirements.txt :

::

 $ make deps

And install ManPKI :

::

 $ make install


Configuration
-------------

ManPKI need some folder before running. If you have make tool can directly use it to correctly configure the structure.

::

 $ manpkid --init

File structure is define below :

.. tabularcolumns:: |p{6cm}|p{12cm}|

+---------------------+---------------------------------------------------------------------+
| Directory           | Description                                                         |
+=====================+=====================================================================+
| VARDIR/cert         | Contain all files related to the PKI (cert, ca, crl, privatekey)    |
+---------------------+---------------------------------------------------------------------+
| VARDIR/cert/public  | Contain all certificates (cert and ca)                              |
+---------------------+---------------------------------------------------------------------+
| VARDIR/cert/private | Contain all private key (cert and ca)                               |
+---------------------+---------------------------------------------------------------------+
| VARDIR/db           | Contain the manpki database formated in JSON                        |
+---------------------+---------------------------------------------------------------------+
| CFGDIR              | Contain manpki.conf                                                 |
+---------------------+---------------------------------------------------------------------+
| LOGDIR              | All logs created by ManPKI                                          |
+---------------------+---------------------------------------------------------------------+


You need to configure your personal account to have admin role in the application.

::

 $ tools/manageUser.py -a -u $USER -g admin

ManPKI daemon can be started directly using manpkid executable or by init scripts

::

 $ manpkid -d

The main executable have some arguments :

::

 $ manpkid -h
 usage: manpkid [-h] [-v] [-D] [-l LOGFILE] [-d] [-i]

 ManPKI daemon.

 optional arguments:
   -h, --help            show this help message and exit
   -v, --version         show version
   -D, --debug           debug mode
   -l LOGFILE, --logfile LOGFILE
                         log file
   -d, --daemon          daemon
   -i, --init            initialize manpki