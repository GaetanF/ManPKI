import os

__version__ = "1.0.dev3"

AUTHOR = "Gaetan FEREZ <manpki@ferez.fr>"

_DIR = os.path.dirname(__file__)
_VERSION_FILE = os.path.join(_DIR, 'VERSION')


def _get_version_from_init():
    return __version__


def _version():
    try:
        with open(_VERSION_FILE) as f_desc:
            return f_desc.read()
    except IOError:
        pass
    version = _get_version_from_init()
    try:
        with open(_VERSION_FILE, 'w') as fdesc:
            fdesc.write(version)
    except IOError:
        pass
    return version


VERSION = _version()


def show_version():
    print("ManPKI by {}\nVersion : {}".format(AUTHOR, VERSION))
