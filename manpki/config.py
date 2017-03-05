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
                 for path in ['/etc', '/etc/manpki', '/usr/local/etc',
                              '/usr/local/etc/manpki', './etc']]
    for path in paths:
        if os.path.isfile(path):
            yield path


def get_run_directory(paths=None):
    """Generates (yields) the available run directory in the correct order."""
    if DEBUG:
        from manpki.logger import log
        log.debug("Get RUN directory")
    if paths is None:
        paths = ['/var/run/manpki', '/var/tmp/manpki', './run']
    for path in paths:
        if os.path.isdir(path):
            return path
    return None


def get_var_directory(paths=None):
    """Generates (yields) the available config files, in the correct order."""
    if DEBUG:
        from manpki.logger import log
        log.debug("Get VAR directory")
    if paths is None:
        paths = ['/var/lib/manpki', '/opt/manpki',
                 '/usr/local/var/manpki', '/usr/local/var/lib/manpki', './var']
    for path in paths:
        if os.path.isdir(path):
            return path
    return None


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
    if ConfigObject and ManPKIObject:
        return True
    return False


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
