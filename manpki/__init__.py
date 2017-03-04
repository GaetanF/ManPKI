import os

AUTHOR = "Gaetan FEREZ <manpki@ferez.fr>"

_DIR = os.path.dirname(__file__)
_VERSION_FILE = os.path.join(_DIR, 'VERSION')


def _get_version_from_git():
    import subprocess
    import re
    subproc = subprocess.Popen(['git', 'describe', '--always'],
                               stdout=subprocess.PIPE, stderr=open(os.devnull),
                               cwd=os.path.join(_DIR, os.path.pardir))
    out, err = subproc.communicate()
    if subproc.returncode != 0:
        raise subprocess.CalledProcessError(subproc.returncode, err)
    tag = out.strip()
    subproc = subprocess.Popen(['git', 'branch', '--contains', 'HEAD'],
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
    match = re.match(br'^v?(.+?)-(\d+)-g[a-f0-9]+$', tag)
    if match:
        value = '%s.dev%s' % match.groups()
    else:
        value = tag[1:] if tag.startswith(b'v') else tag
    if branch == 'master':
        return value
    return '%s-%s' % (value, branch)


def _version():
    try:
        with open(_VERSION_FILE) as f_desc:
            return f_desc.read()
    except IOError:
        pass
    hash_val, ref_names = '$Format:%h %D$'.split(' ', 1)
    try:
        return next(ref[6:] for ref in ref_names.split(', ') if ref.startswith('tag: v'))
    except StopIteration:
        pass
    return hash_val if hash_val else 'unknown.version'


VERSION = _version()


def show_version():
    print("ManPKI by {}\nVersion : {}".format(AUTHOR, VERSION))
