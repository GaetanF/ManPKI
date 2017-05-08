import os
import subprocess

__version__ = "1.0.dev3"

AUTHOR = "Gaetan FEREZ <manpki@ferez.fr>"

_DIR = os.path.dirname(__file__)
_VERSION_FILE = os.path.join(_DIR, 'VERSION')


def _get_version_from_init():
    return __version__


def _get_version_from_git():
    import re
    subproc = subprocess.Popen(['/usr/bin/git', 'describe', '--always'],
                               stdout=subprocess.PIPE, stderr=open(os.devnull),
                               cwd=os.path.join(_DIR, os.path.pardir))
    out, err = subproc.communicate()
    if subproc.returncode != 0:
        raise subprocess.CalledProcessError(subproc.returncode, err)
    tag = out.strip()
    subproc = subprocess.Popen(['/usr/bin/git', 'branch', '--contains', 'HEAD'],
                               stdout=subprocess.PIPE, stderr=open(os.devnull),
                               cwd=os.path.join(_DIR, os.path.pardir))
    out, err = subproc.communicate()
    if subproc.returncode != 0:
        raise subprocess.CalledProcessError(subproc.returncode, err)
    try:
        branch = (branch[1:].strip() for branch in out.splitlines()
                  if branch.startswith(b'*')).__next__()
    except StopIteration:
        branch = "master"
    # branch = develop
    match = re.match(br'^v?(.+?)-(\d+)-g[a-f0-9]+$', tag)
    if match:
        value = '%s.dev%s' % match.groups()
    elif tag.startswith(b'v'):
        value = tag[1:]
    else:
        raise Exception("No tag available")
    if branch == 'master':
        return value
    return '%s.%s' % (value, branch)


def _version():
    try:
        with open(_VERSION_FILE) as f_desc:
            return f_desc.read()

    except IOError:
        pass
    try:
        version = _get_version_from_git()
    except subprocess.CalledProcessError as exc:
        pass
    except Exception as exc:
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
