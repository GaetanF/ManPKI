#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
from glob import glob
import platform

from setuptools import find_packages

VERSION = __import__('manpki').VERSION

with open(os.path.join(os.path.dirname(__file__), 'README.rst')) as readme:
    long_description = readme.read()


def running_under_virtualenv():
    if hasattr(sys, 'real_prefix'):
        return True
    elif sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        return True
    if os.getenv('VIRTUAL_ENV', False):
        return True
    return False


if os.environ.get('USE_SETUPTOOLS'):
    from setuptools import setup
    setup_kwargs = dict(zip_safe=0)
else:
    from distutils.core import setup
    setup_kwargs = dict()

if os.name == 'nt':
    pgm_files = os.environ["ProgramFiles"]
    base_files = os.path.join(pgm_files, 'manpki')
    data_files = [
        (base_files, ['README.rst']),
        (os.path.join(base_files, 'utils'), []),
        (os.path.join(base_files, 'etc'), glob('etc/*.conf')),
    ]

else:
    data_files = [
        ('share/manpki/tools', ['tools/manageUser.py', 'tools/initDatabase.py']),
        ('share/manpki/config', ['etc/manpki/manpki.conf']),
        ('share/manpki/startup', []),
        ('share/manpki/startup/upstart', ['tools/upstart/manpkid.conf']),
        ('share/manpki/startup/initd', ['tools/initd/manpkid']),
        ('share/manpki/startup/systemd', ['tools/systemd/manpkid.service']),
    ]

    #distro = platform.dist()[0]
    #distro_major_version = platform.dist()[1].split('.')[0]

    #if running_under_virtualenv():
    #    data_files.append(('/etc/manpki',
    #                       glob('etc/*.conf')))
    #else:
    #    data_files.append(('/etc/manpki',
    #                       glob('etc/*.conf')))

    #    if distro == 'Ubuntu':
    #        data_files.append(('/etc/init',
    #                           ['tools/upstart/manpkid.conf']))
    #    if distro in ['centos', 'redhat', 'debian', 'fedora']:
    #        data_files.append(('/etc/init.d',
    #                           ['tools/initd/manpkid']))
    #        if distro_major_version >= '7' and not distro == 'debian':
    #            data_files.append(('/usr/lib/systemd/system',
    #                               ['tools/systemd/manpkid.service']))
    #        elif distro_major_version >= '6' and not distro == 'debian':
    #            data_files.append(('/etc/init',
    #                               ['tools/upstart/manpkid.conf']))

setup(

    name='manpki',

    version=VERSION,

    packages=find_packages(),

    author="Gaetan FEREZ",

    author_email="manpki@ferez.fr",

    description="X509 PKI Manager",
    long_description=long_description,

    # Dependency Manager
    #
    # Ex: ["gunicorn", "docutils >= 0.3", "lxml==0.5a7"]
    install_requires=[
        "pyOpenSSL",
        "colorlog",
        "Flask",
        "flask_httpauth",
        "gevent",
        "python-jose",
        "jsonmodels",
        "python-pam",
        "polib",
        "pyasn1",
        "pytz",
        "tinydb",
        "tinydb-jsonorm"
    ],

    # Default Web Page
    url='http://github.com/GaetanF/manpki',

    # https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 1 - Planning",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Natural Language :: French",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],

    scripts=['bin/manpkid'],

    include_package_data=True,
    data_files=data_files,

)
