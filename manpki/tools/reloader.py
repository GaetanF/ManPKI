import sys
import os
import time
import threading
import subprocess
import signal
from itertools import chain
from manpki.logger import log

PY2 = sys.version_info[0] == 2
WIN = sys.platform.startswith('win')

iteritems = lambda d, *args, **kwargs: iter(d.items(*args, **kwargs))


def _get_args_for_reloading():
    """Returns the executable. This contains a workaround for windows
    if the executable is incorrectly reported to not have the .exe
    extension which can cause bugs on reloading.
    """
    rv = [sys.executable]
    py_script = sys.argv[0]
    if os.name == 'nt' and not os.path.exists(py_script) and \
       os.path.exists(py_script + '.exe'):
        py_script += '.exe'
    rv.append(py_script)
    rv.extend(sys.argv[1:])
    return rv


def _iter_module_files():
    """This iterates over all relevant Python files.  It goes through all
    loaded files from modules, all files in folders of already loaded modules
    as well as all files reachable through a package.
    """
    # The list call is necessary on Python 3 in case the module
    # dictionary modifies during iteration.
    for module in list(sys.modules.values()):
        if module is None:
            continue
        filename = getattr(module, '__file__', None)
        if filename:
            old = None
            while not os.path.isfile(filename):
                old = filename
                filename = os.path.dirname(filename)
                if filename == old:
                    break
            else:
                if filename[-4:] in ('.pyc', '.pyo'):
                    filename = filename[:-1]
                yield filename


class ReloaderLoop(object):
    name = None

    # monkeypatched by testsuite. wrapping with `staticmethod` is required in
    # case time.sleep has been replaced by a non-c function (e.g. by
    # `eventlet.monkey_patch`) before we get here
    _sleep = staticmethod(time.sleep)

    def __init__(self, extra_files=None, interval=1):
        self.extra_files = set(os.path.abspath(x)
                               for x in extra_files or ())
        self.interval = interval

    def run(self):
        pass

    def restart_with_reloader(self):
        """Spawn a new Python interpreter with the same arguments as this one,
        but running the reloader thread.
        """
        while 1:
            log.info(' * Restarting with %s' % self.name)
            args = _get_args_for_reloading()
            new_environ = os.environ.copy()
            new_environ['MANPKI_RUN_MAIN'] = 'true'

            # a weird bug on windows. sometimes unicode strings end up in the
            # environment and subprocess.call does not like this, encode them
            # to latin1 and continue.
            if os.name == 'nt' and PY2:
                for key, value in iteritems(new_environ):
                    if isinstance(value, str):
                        new_environ[key] = value.encode('iso-8859-1')

            exit_code = subprocess.call(args, env=new_environ,
                                        close_fds=False)
            if exit_code != 3:
                return exit_code

    def trigger_reload(self, filename):
        self.log_reload(filename)
        sys.exit(3)

    def trigger_reload_with_sleep(self):
        sys.exit(3)

    def log_reload(self, filename):
        filename = os.path.abspath(filename)
        log.info(' * Detected change in %r, reloading' % filename)


class StatReloaderLoop(ReloaderLoop):
    name = 'stat'

    def run(self):
        mtimes = {}
        while 1:
            for filename in chain(_iter_module_files(),
                                  self.extra_files):
                try:
                    mtime = os.stat(filename).st_mtime
                except OSError:
                    continue

                old_time = mtimes.get(filename)
                if old_time is None:
                    mtimes[filename] = mtime
                    continue
                elif mtime > old_time:
                    self.trigger_reload(filename)
            self._sleep(self.interval)


def reload(time):
    log.info("Reload server in %s second" % str(time))
    signal.alarm(time)


def _reload(*args):
    reloader.trigger_reload_with_sleep()


def run_with_reloader(args, **kwargs):
    """Run the given function in an independent python interpreter."""
    signal.signal(signal.SIGTERM, lambda *args: sys.exit(0))
    signal.signal(signal.SIGHUP, lambda *args: sys.exit(3))
    signal.signal(signal.SIGALRM, _reload)
    try:
        if os.environ.get('MANPKI_RUN_MAIN') == 'true':
            t = threading.Thread(target=args, args=())
            t.setDaemon(True)
            t.start()
            reloader.run()
        else:
            sys.exit(reloader.restart_with_reloader())
    except KeyboardInterrupt:
        pass

reloader = StatReloaderLoop()
