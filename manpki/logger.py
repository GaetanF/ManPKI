import logging
import os

try:
    import colorlog

    have_colorlog = True
except ImportError:
    have_colorlog = False


def mk_logger():
    log = logging.getLogger()  # root logger
    log.setLevel(logging.DEBUG)
    format = '%(asctime)s - %(levelname)-8s - %(message)s'
    date_format = '%Y-%m-%d %H:%M:%S'
    if have_colorlog and os.isatty(2):
        cformat = '%(log_color)s' + format
        f = colorlog.ColoredFormatter(cformat, date_format,
                                      log_colors={'DEBUG': 'reset', 'INFO': 'reset',
                                                  'WARNING': 'bold_yellow', 'ERROR': 'bold_red',
                                                  'CRITICAL': 'bold_red'})
    else:
        f = logging.Formatter(format, date_format)
    ch = logging.StreamHandler()
    ch.setFormatter(f)
    log.addHandler(ch)
    return logging.getLogger(__name__)


log = mk_logger()
