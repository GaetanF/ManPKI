import os

AUTHOR = "Gaetan FEREZ <manpki@ferez.fr>"

_DIR = os.path.dirname(__file__)
_VERSION_FILE = os.path.join(_DIR, 'VERSION')


def _get_version_from_git():
    import subprocess
    import re
    proc = subprocess.Popen(['git', 'describe', '--always'],
                            stdout=subprocess.PIPE, stderr=open(os.devnull),
                            cwd=os.path.join(_DIR, os.path.pardir))
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, err)
    tag = out.strip()
    proc = subprocess.Popen(['git', 'branch', '--contains', 'HEAD'],
                            stdout=subprocess.PIPE, stderr=open(os.devnull),
                            cwd=os.path.join(_DIR, os.path.pardir))
    out, err = proc.communicate()
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, err)
    try:
        branch = (branch[1:].strip() for branch in out.splitlines()
                  if branch.startswith(b'*')).__next__()
    except StopIteration:
        branch = "master"
    match = re.match(br'^v?(.+?)-(\d+)-g[a-f0-9]+$', tag)
    if match:
        # remove the 'v' prefix and add a '.devN' suffix
        value = '%s.dev%s' % match.groups()
    else:
        # just remove the 'v' prefix
        value = tag[1:] if tag.startswith(b'v') else tag
    if branch == 'master':
        return value
    return '%s-%s' % (value, branch)


def _version():
    import subprocess
    # try:
    #     tag = _get_version_from_git()
    # except subprocess.CalledProcessError as exc:
    #     pass
    # else:
    #     try:
    #         with open(_VERSION_FILE, 'w') as fdesc:
    #             fdesc.write(tag)
    #     except IOError:
    #         pass
    #     return tag
    try:
        with open(_VERSION_FILE) as fdesc:
            return fdesc.read()
    except IOError:
        pass
    hashval, refnames = '$Format:%h %D$'.split(' ', 1)
    try:
        return next(ref[6:] for ref in refnames.split(', ') if ref.startswith('tag: v'))
    except StopIteration:
        pass
    return hashval if hashval else 'unknown.version'

VERSION = _version()


def show_version():
    print("ManPKI by {}\nVersion : {}".format(AUTHOR, VERSION))
