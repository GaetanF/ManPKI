API
===

Definition
^^^^^^^^^^

ManPKI Daemon are only accessible by the API.
The daemon directly implement a secured and authenticated web API.

Only user who have a local account on the server running the daemon can authenticated on the daemon.

API method accessible are describre bellow.

.. tabularcolumns:: |p{3cm}|p{12cm}|

+---------------------+-------------------------------------------------+
| URL                 | Description                                     |
+=====================+=================================================+
| ``/v1.0/ca``        | CA management                                   |
+---------------------+-------------------------------------------------+
| ``/v1.0/cert``      | Certificate management                          |
+---------------------+-------------------------------------------------+
| ``/v1.0/extension`` | SSL Extension management                        |
+---------------------+-------------------------------------------------+
| ``/v1.0/profile``   | Profile based on SSL Extension management       |
+---------------------+-------------------------------------------------+
| ``/v1.0/server``    | API Server management                           |
+---------------------+-------------------------------------------------+
| ``/ping``           | Ping/Pong daemon                                |
+---------------------+-------------------------------------------------+
| ``/discovery``      | Discover all available method for current user  |
+---------------------+-------------------------------------------------+
| ``/info``           | Get some information of current session         |
+---------------------+-------------------------------------------------+
| ``/login``          | Log in the application                          |
+---------------------+-------------------------------------------------+
| ``/logout``         | Disconnect the user                             |
+---------------------+-------------------------------------------------+
| ``/locale/<lang>``  | Get all locale for the specified language       |
+---------------------+-------------------------------------------------+
| ``/render``         | Get render system for the CLI                   |
+---------------------+-------------------------------------------------+

Global
^^^^^^

.. qrefflask:: manpki.server:app
   :undoc-static:


CA
^^

.. autoflask:: manpki.server:app
   :modules: manpki.api.ca

Cert
^^^^

.. autoflask:: manpki.server:app
   :modules: manpki.api.cert

Profile
^^^^^^^

.. autoflask:: manpki.server:app
   :modules: manpki.api.profile

Extension
^^^^^^^^^

.. autoflask:: manpki.server:app
   :modules: manpki.api.extension

Server
^^^^^^

.. autoflask:: manpki.server:app
   :modules: manpki.api.server