CLI
===

ManPKI API have his own client named manpki-cli

Installation
^^^^^^^^^^^^

From git
--------

To install manpki from git, download master.zip from github/GaetanF/manpki.git or clone the repository :

::

 $ git clone https://github.com/GaetanF/manpki-cli.git

You need to install all dependencies needed by the program present in requirements.txt :

::

 $ make deps

And install ManPKI :

::

 $ make install


Usage
^^^^^

To launch the shell :

::

 $ manpki shell



The main executable have some arguments :

::

 $ manpki -h
 usage: manpki [COMMAND]

 available commands:
   service (not available)
   check   (not available)
   queue   (not available)
   shell

 Try manpki help [COMMAND]

When you launch the shell utility, it's start in disconnected mode.
You need to connect to your ManPKI daemon locally or remotely if daemon is configured to allow the remote access.

::

 $ manpki shell
 Welcome to the ManPKI shell !
 [disconnected manpki-cli]$ connect
 [ferezgaetan@local manpki-cli]$ help
