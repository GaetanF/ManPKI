import logging
import os

try:
    import colorlog
    have_colorlog = True
except ImportError:
    have_colorlog = False


def mk_logger():
    log = logging.getLogger()  # root logger
    from manpki.config import DEBUG, LOGFILE, DAEMON
    if DEBUG:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)
    line_format = '%(asctime)s - %(levelname)-8s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    if have_colorlog and os.isatty(2):
        c_format = '%(log_color)s' + line_format
        f = colorlog.ColoredFormatter(c_format, date_format,
                                      log_colors={'DEBUG': 'reset', 'INFO': 'reset',
                                                  'WARNING': 'bold_yellow', 'ERROR': 'bold_red',
                                                  'CRITICAL': 'bold_red'})
    else:
        f = logging.Formatter(line_format, date_format)
    if not DAEMON:
        ch = logging.StreamHandler()
        ch.setFormatter(f)
        log.addHandler(ch)
    if not os.path.isdir(os.path.dirname(LOGFILE)) or os.geteuid() != 0:
        LOGFILE=os.path.expanduser('~/.manpki/log/manpkid.log')
    fh = logging.FileHandler(LOGFILE)
    fh.setFormatter(f)
    log.addHandler(fh)
    return logging.getLogger(__name__)


log = mk_logger()
