__author__ = 'ferezgaetan'


class Daemons:

    ocsp_daemon = '/Users/ferezgaetan/PycharmProjects/manpki/lib/ManPKI/Daemon/ocspd.py'
    smtp_daemon = '/Users/ferezgaetan/PycharmProjects/manpki/lib/ManPKI/Daemon/smtpd.py'
    webapi_daemon = '/Users/ferezgaetan/PycharmProjects/manpki/lib/ManPKI/Daemon/webapid.py'

    @staticmethod
    def start_daemon(daemon):
        pass

    @staticmethod
    def check_status(daemon):
        import os
        ret = None
        exec("ret = Daemons." + daemon + "_daemon")
        os.system("python " + ret + " status")
