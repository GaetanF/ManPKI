#! /usr/bin/env python

# This file is part of ManPKI.
# Copyright 2016 Gaetan FEREZ <gaetan@ferez.fr>
#
# ManPKI is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ManPKI is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with ManPKI. If not, see <http://www.gnu.org/licenses/>.

"""This sub-module handles configuration values.

It contains the (hard-coded) default values, which can be overwritten
by /usr/local/etc/manpki/manpki.conf,
/usr/local/etc/manpki.conf, /etc/manpki/manpki.conf and/or
/etc/manpki.conf.

"""

import configparser
import os
import stat

__author__ = 'ferezgaetan'
__version__ = '0.2'


# Default values:
DB = "mongodb:///manpki"
DEFAULT_CONFIG = "/etc/manpki/manpki.conf"

if 'DEBUG' not in __builtins__:
    DEBUG = False
else:
    import builtins
    DEBUG = builtins.DEBUG

if 'LOGFILE' not in __builtins__:
    LOGFILE = '/var/log/manpki/manpkid.log'
else:
    import builtins
    LOGFILE = builtins.LOGFILE

if 'DAEMON' not in __builtins__:
    DAEMON = False
else:
    import builtins
    DAEMON = builtins.DAEMON

GZ_CMD = "zcat"
BZ2_CMD = "bzcat"

# Feed with a random value, like `openssl rand -base64 42`.
# *Mandatory* when WEB_PUBLIC_SRV == True
WEB_SECRET = '^\x02\xde\xbb\xb7\xd2\x9f\xf1\xbe\xc1$Rp\xc9\xc5\x11\xbf\x8f}\x0e\xe8^\x1aZ'
TOKEN_SECRET = 'MiQKYnxnmhI97KgqJe02XAg+ZAuz3N7B9x+/VPluk/Yr3BJPGxezC7kh'

API_VERSION = 'v1.0'

ConfigObject = None
ManPKIObject = None


def get_config_file(paths=None):
    """Generates (yields) the available config files, in the correct order."""
    if DEBUG:
        from manpki.logger import log
        log.debug("Get config file")
    if paths is None:
        paths = [os.path.join(path, 'manpki.conf')
                 for path in ['/etc/manpki', '/usr/local/etc/manpki',
                              '/usr/local/etc/manpki', './etc/manpki/', '../etc/manpki/']]
    for path in paths:
        if os.path.isfile(path):
            yield path


def get_config_directory(paths=None):
    """Generates (yields) the available config directory in the correct order."""
    if DEBUG:
        from manpki.logger import log
        log.debug("Get CONFIG directory")
    if paths is None:
        paths = ['/etc/manpki', '/usr/local/etc/manpki', './manpki', './etc/manpki', '../etc/manpki']
    for path in paths:
        if os.path.isdir(path) and os.access(path, os.W_OK):
            return path
    return None


def get_run_directory(paths=None):
    """Generates (yields) the available run directory in the correct order."""
    if DEBUG:
        from manpki.logger import log
        log.debug("Get RUN directory")
    if paths is None:
        paths = ['/var/run/manpki', '/run/manpki', './run/manpki/']
    for path in paths:
        if os.path.isdir(path) and os.access(path, os.W_OK):
            return path
    return None


def get_var_directory(paths=None):
    """Generates (yields) the available config files, in the correct order."""
    if DEBUG:
        from manpki.logger import log
        log.debug("Get VAR directory")
    if paths is None:
        paths = ['/var/lib/manpki', '/opt/manpki',
                 '/usr/local/var/manpki', '/usr/local/var/lib/manpki', './var/manpki', '../var/manpki']
    for path in paths:
        if os.path.isdir(path):
            return path
    return None


def init_directory():
    if not get_config_directory() and not os.path.exists("/etc/manpki"):
        os.makedirs("/etc/manpki")
    if not get_var_directory() and not os.path.exists("/var/lib/manpki"):
        os.makedirs("/var/lib/manpki")
        os.makedirs("/var/lib/manpki/cert")
        os.makedirs("/var/lib/manpki/db")
    elif get_var_directory():
        path = get_var_directory()
        if not os.path.exists(path+"/cert"):
            os.makedirs("/var/lib/manpki/cert")
        if not os.path.exists(path + "/db"):
            os.makedirs("/var/lib/manpki/db")
    if not get_run_directory(['/var/run/manpki', '/run/manpki']):
        os.makedirs("/var/run/manpki")
    if not os.path.exists("/var/log/manpki"):
        os.makedirs("/var/log/manpki")


def init_acl():
    import pwd
    import grp
    import sys
    try:
        pwd.getpwnam('manpki')
    except KeyError:
        print('User manpki does not exist. Create it before')
        sys.exit()
    try:
        grp.getgrnam('manpki')
    except KeyError:
        print('Group manpki does not exist. Create it before')
        sys.exit()

    if get_run_directory():
        path = get_run_directory()
        os.chown(path, pwd.getpwnam("manpki").pw_uid, grp.getgrnam('manpki').gr_gid)
    os.chown('/var/log/manpki', pwd.getpwnam("manpki").pw_uid, grp.getgrnam('manpki').gr_gid)
    if os.path.isfile('/var/log/manpki/manpkid.log'):
        os.chown('/var/log/manpki/manpkid.log', pwd.getpwnam("manpki").pw_uid, grp.getgrnam('manpki').gr_gid)
    if get_var_directory():
        path = get_var_directory()
        os.chown(path, pwd.getpwnam("manpki").pw_uid, grp.getgrnam('manpki').gr_gid)
        os.chown(path+'/cert', pwd.getpwnam("manpki").pw_uid, grp.getgrnam('manpki').gr_gid)
        os.chown(path+'/db', pwd.getpwnam("manpki").pw_uid, grp.getgrnam('manpki').gr_gid)
        os.chown(path + '/db/manpki.json', pwd.getpwnam("manpki").pw_uid, grp.getgrnam('manpki').gr_gid)
    if get_config_directory():
        path = get_config_directory()
        os.chown(path, pwd.getpwnam("manpki").pw_uid, grp.getgrnam('manpki').gr_gid)


def init_db():
    from tinydb import TinyDB
    path = get_var_directory() + "/db"
    db = TinyDB(path + '/manpki.json')
    db.purge_tables()

    ## Extension
    exten = db.table('extension')
    #### KeyUsage
    exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.0', 'name': 'digitalSignature', '_default': True})
    exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.1', 'name': 'nonRepudiation', '_default': True})
    exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.2', 'name': 'keyEncipherment', '_default': True})
    exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.3', 'name': 'dataEncipherment', '_default': True})
    exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.4', 'name': 'keyAgreement', '_default': True})
    exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.5', 'name': 'keyCertSign', '_default': True})
    exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.6', 'name': 'cRLSign', '_default': True})
    exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.7', 'name': 'encipherOnly', '_default': True})
    exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.8', 'name': 'decipherOnly', '_default': True})

    ### Extended Key Usage
    exten.insert(
        {'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.1', 'name': 'TLS Web Server Authentication', '_default': True})
    exten.insert(
        {'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.2', 'name': 'TLS Web Client Authentication', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.3', 'name': 'Code Signing', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.4', 'name': 'Email Protection', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.8', 'name': 'Time Stamping', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.9', 'name': 'OCSP Signer', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.13', 'name': 'EAP over PPP', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.14', 'name': 'EAP over LAN', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.15', 'name': 'SCVP Server', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.16', 'name': 'SCVP Client', '_default': True})
    exten.insert(
        {'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.17', 'name': 'Internal Key Exchange for IPSEC', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.20', 'name': 'SIP Domain', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.21', 'name': 'SSH Server', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.22', 'name': 'SSH Client', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.4.1.311.20.2.2', 'name': 'MS Smart Card Logon', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.4.1.311.10.3.12', 'name': 'MS Document Signing', '_default': True})
    exten.insert(
        {'type': 'extended', 'oid': '1.3.6.1.4.1.311.2.1.21', 'name': 'MS Individual Code Signing', '_default': True})
    exten.insert(
        {'type': 'extended', 'oid': '1.3.6.1.4.1.311.2.1.22', 'name': 'MS Commercial Code Signing', '_default': True})
    exten.insert(
        {'type': 'extended', 'oid': '1.3.6.1.4.1.311.10.3.4', 'name': 'MS Encrypted File System (EFS)', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.4.1.311.10.3.4.1', 'name': 'MS EFS Recovery', '_default': True})
    exten.insert({'type': 'extended', 'oid': '2.16.840.1.113741.1.2.3', 'name': 'Intel AMT Management', '_default': True})
    exten.insert({'type': 'extended', 'oid': '0.4.0.2231.3.0', 'name': 'ETSI TSL Signing', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.2.840.113583.1.1.5', 'name': 'Adobe PDF Signing', '_default': True})
    exten.insert(
        {'type': 'extended', 'oid': '1.2.203.7064.1.1.369791.1', 'name': 'CSN 369791 TLS Client', '_default': True})
    exten.insert(
        {'type': 'extended', 'oid': '1.2.203.7064.1.1.369791.2', 'name': 'CSN 368781 TLS Server', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.2.3.4', 'name': 'Kerberos Key Authentication', '_default': True})
    exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.2.3.5', 'name': 'Kerberos KDC', '_default': True})
    exten.insert({'type': 'extended', 'oid': '2.23.136.1.1.3', 'name': 'ICAO Master List Signing', '_default': True})
    exten.insert({'type': 'extended', 'oid': '2.16.840.1.101.3.6.8', 'name': 'PIV Card Authentication', '_default': True})

    ## Profile
    profile = db.table('profile')
    ### SSL Profile
    profile.insert({'name': 'SSLServer', 'keyusage': '2.5.29.15.3|2.5.29.15.2|2.5.29.15.1', 'extended': '1.3.6.1.5.5.7.3.1',
                    'ldap': '', '_default': True})
    profile.insert({'name': 'SSLUser', 'keyusage': '2.5.29.15.1|2.5.29.15.2|2.5.29.15.3',
                    'extended': '1.3.6.1.5.5.7.3.22|1.3.6.1.5.5.7.3.2|1.3.6.1.5.5.7.3.3', 'ldap': '(objectClass=person)',
                    '_default': True})
    profile.insert(
        {'name': 'OCSPResponder', 'keyusage': '2.5.29.15.0|2.5.29.15.1|2.5.29.15.2', 'extended': '1.3.6.1.5.5.7.3.9',
         'ldap': '', '_default': True})

    ## Parameters
    param = db.table('parameter')
    ### CA
    param.insert(
        {'object': 'ca', 'email': '', 'validity': 3560, 'keysize': 1024, 'basecn': 'C=FR', 'name': 'CA', 'digest': 'sha256',
         'typeca': 'rootca', 'isfinal': True})

    ### CERT
    param.insert({'object': 'cert', 'validity': 365, 'keysize': 1024, 'digest': 'sha256'})

    ## CRL
    param.insert({'object': 'crl', 'enable': False, 'digest': 'md5', 'validity': 30})

    ## OCSP
    param.insert({'object': 'ocsp', 'enable': False, 'uri': 'http://ocsp/'})

    ## LDAP
    param.insert({'object': 'ldap', 'enable': False, 'host': 'ldap://ldap:389/', 'dn': 'cn=admin', 'password': 'password',
                  'mode': 'ondemand', 'schedule': '5m'})

    ## Mail
    param.insert({'object': 'mail', 'enable': False, 'host': 'smtp', 'sender': 'manpki@example.com'})

    ## Server
    param.insert({'object': 'server', 'sslcert': 'cert.pem', 'sslkey': 'key.pem', 'host': 'socket', 'port': 8080})

    ## Users
    db.table('user')
    db.close()


def init_files():
    path = None
    if os.path.isdir('/usr/share/manpki'):
        path = '/usr/share/manpki'
    if os.path.isdir('/usr/local/share/manpki'):
        path = '/usr/local/share/manpki'
    if path:
        from shutil import copyfile
        import platform

        copyfile(path+'/config/manpki.conf', get_config_directory()+'/manpki.conf')
        distro = platform.dist()[0]
        distro_major_version = platform.dist()[1].split('.')[0]

        if distro == 'Ubuntu':
            copyfile(path + '/startup/upstart/manpkid.conf', '/etc/init/manpkid.conf')
        if distro in ['centos', 'redhat', 'debian', 'fedora']:
            copyfile(path + '/startup/initd/manpkid', '/etc/init.d/manpkid')
            if distro_major_version >= '7' and not distro == 'debian':
                copyfile(path + '/startup/systemd/manpkid.service', '/usr/lib/systemd/system/manpkid.service')
            elif distro_major_version >= '6' and not distro == 'debian':
                copyfile(path + '/startup/upstart/manpkid.conf', '/etc/init/manpkid.conf')
    else:
        config_file = get_config_directory()+'/manpki.conf'
        with open(config_file, 'w') as f:
            f.write("[default]")
            f.write("")
            f.write("[server]")
            f.write("host = socket")
            f.write("cert = ")
            f.write("port = 0")
            f.write("key = ")
            f.write()
            f.close()


def setup():
    init_directory()
    init_db()
    init_acl()
    init_files()


def check_candidate(path, directory=None):
    """Auxilliary function that checks whether a particular
    path is a good candidate.

    """
    path_candidate = os.path.join(path, 'share', 'manpki')
    if directory is not None:
        path_candidate = os.path.join(path_candidate, directory)
    try:
        if stat.S_ISDIR(os.stat(path_candidate).st_mode):
            return path_candidate
    except OSError:
        pass


def guess_prefix(directory=None):
    """Attempts to find the base directory where ManPKI components are
    installed.

    """

    if __file__.startswith('/'):
        path = '/'
        # absolute path
        for elt in __file__.split('/')[1:]:
            if elt in ['lib', 'lib32', 'lib64']:
                candidate = check_candidate(path, directory=directory)
                if candidate is not None:
                    return candidate
            path = os.path.join(path, elt)
    for path in ['/usr', '/usr/local', '/opt', '/opt/manpki']:
        candidate = check_candidate(path, directory=directory)
        if candidate is not None:
            return candidate


def write():
    from manpki.logger import log
    log.debug("Building configuration...")
    for f_name in get_config_file():
        if DEBUG:
            log.debug("Write configuration file : " + f_name)
        with open(f_name, 'w') as configfile:
            ConfigObject.write(configfile)
    log.debug("[OK]")


def envready():
    import pwd
    import grp
    if DAEMON:
        try:
            pwd.getpwnam('manpki')
        except KeyError:
            return False
        try:
            grp.getgrnam('manpki')
        except KeyError:
            return False
    if not get_var_directory():
        return False
    if not get_run_directory():
        return False
    if not get_config_directory():
        return False
    if not get_config_file():
        return False

    if DAEMON and not os.path.isdir('/var/log/manpki'):
        return False
    return True

if envready():
    class ManPKIConfig(object):
        vardir = get_var_directory()
        certdir = vardir + "/cert"
        dbdir = vardir + "/db"


    if not ConfigObject:
        ConfigObject = configparser.ConfigParser()
        configRead = False
        for f_name in get_config_file():
            if DEBUG:
                from manpki.logger import log
                log.debug("Read configuration file : " + f_name)
            ConfigObject.read(f_name)
            configRead = True
        if not configRead:
            ConfigObject = None

    if not ManPKIObject:
        ManPKIObject = ManPKIConfig()
        if not ManPKIObject.certdir:
            ManPKIObject = None
