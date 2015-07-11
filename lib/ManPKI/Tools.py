__author__ = 'ferezgaetan'

import sys
import Secret
import ConfigParser
import urlparse
import tempfile
import tftpy
import shutil
import urllib
import ftplib
import os
import string
import hashlib
import smtplib
from pytz import UTC
import datetime as dt
import OpenSSL.crypto
import shlex, subprocess, re

from scp import SCPClient
from paramiko import SSHClient
from os.path import splitext
from cStringIO import StringIO

import Exceptions.ProtocolException
import Exceptions.CopyException

IDENTCHARS = string.ascii_letters + string.digits + '_'


class Capturing(list):
    def __enter__(self):
        self._stdout = sys.stdout
        sys.stdout = self._stringio = StringIO()
        return self

    def __exit__(self, *args):
        self.extend(self._stringio.getvalue().splitlines())
        sys.stdout = self._stdout


class Config:
    config = None
    config_path = "/Users/ferezgaetan/PycharmProjects/manpki/etc/manpki.conf"

    sections = ("default", "ca", "crl", "ocsp", "keyusage", "extended", "ldap", "smtp")

    def __init__(self):
        if not Config.config:
            if Secret.debug:
                print "Read configuration file : " + Config.config_path
            Config.config = ConfigParser.ConfigParser()
            Config.config.read(Config.config_path)
            if Secret.debug:
                print "Verify all needed sections"
            for sec in self.sections:
                if not Config().config.has_section(sec):
                    Config().config.add_section(sec)

    def write(self):
        # Writing our configuration file to 'example.cfg'
        print "Building configuration..."
        with open(Config.config_path, 'wb') as configfile:
            Config.config.write(configfile)
        print "[OK]"


class Copy:

    def report_http_progress(self, blocknr, blocksize, size):
        current = blocknr*blocksize
        sys.stdout.write("\rDownloading : {0:.2f}%".format(100.0*current/size))
        if current/size == 1:
            sys.stdout.write("\rDownloading : done\n")

    def copy_tftp_to_tmp(self, uri):
        client = tftpy.TftpClient(uri.hostname, uri.port if uri.port != None else 69)
        client.download(uri.path, self.tmp_file.name)

    def copy_ftp_to_tmp(self, uri):
        urllib.urlretrieve(uri.geturl(), self.tmp_file.name, self.report_http_progress)

    def copy_ssh_to_tmp(self, uri):
        ssh = SSHClient()
        ssh.load_system_host_keys()
        print uri.username
        if not uri.username:
            ssh.connect(uri.hostname, allow_agent=True)
        elif uri.username  and not uri.password:
            ssh.connect(uri.hostname, username=uri.username, allow_agent=True)
        elif uri.username and uri.password:
            ssh.connect(uri.hostname, username=uri.username, password=uri.password, allow_agent=True)

        # SCPCLient takes a paramiko transport as its only argument
        scp = SCPClient(ssh.get_transport())
        scp.get(uri.path, self.tmp_file.name)
        scp.close()

    def copy_http_to_tmp(self, uri):
        urllib.urlretrieve(uri.geturl(), self.tmp_file.name, self.report_http_progress)

    def copy_file_to_tmp(self, uri):
        shutil.copy2(uri.path, self.tmp_file.name)

    def copy_tmp_to_tftp(self, uri):
        client = tftpy.TftpClient(uri.hostname, uri.port if uri.port != None else 69)
        client.upload(uri.path, self.tmp_file.name)

    def copy_tmp_to_ftp(self, uri):
        session = ftplib.FTP(uri.hostname)

        if uri.username  and not uri.password:
            session.login(uri.username)
        elif uri.username and uri.password:
            session.login(uri.username, uri.password)

        if os.path.dirname(uri.path):
            session.cwd(os.path.dirname(uri.path))

        session.storbinary('STOR ' + os.path.basename(uri.path), self.tmp_file)

    def copy_tmp_to_ssh(self, uri):
        ssh = SSHClient()
        ssh.load_system_host_keys()
        print uri.username
        if not uri.username:
            ssh.connect(uri.hostname, allow_agent=True)
        elif uri.username  and not uri.password:
            ssh.connect(uri.hostname, username=uri.username, allow_agent=True)
        elif uri.username and uri.password:
            ssh.connect(uri.hostname, username=uri.username, password=uri.password, allow_agent=True)

        # SCPCLient takes a paramiko transport as its only argument
        scp = SCPClient(ssh.get_transport())
        scp.put(self.tmp_file.name, uri.path)
        scp.close()

    def copy_tmp_to_file(self, uri):
        shutil.copy2(self.tmp_file.name, uri.path)

    def __init__(self, source, dest):
        self.methods_in = {
            'tftp': self.copy_tftp_to_tmp,
            'ftp' : self.copy_ftp_to_tmp,
            'ssh' : self.copy_ssh_to_tmp,
            'http': self.copy_http_to_tmp,
            'file': self.copy_file_to_tmp
        }

        self.methods_out = {
            'tftp': self.copy_tmp_to_tftp,
            'ftp' : self.copy_tmp_to_ftp,
            'ssh' : self.copy_tmp_to_ssh,
            'file': self.copy_tmp_to_file
        }
        self.tmp_file = tempfile.NamedTemporaryFile()

        source_uri = urlparse.urlparse(source)
        try:
            self.methods_in[source_uri.scheme](source_uri)
        except KeyError:
            print Exceptions.ProtocolException("Unknown protocol")
        except Exception, e:
            print e

        dest_uri = urlparse.urlparse(dest)
        try:
            tmp_func = self.methods_out[dest_uri.scheme]
            tmp_func(dest_uri)
        except KeyError:
            print Exceptions.ProtocolException("Unknown protocol")

        self.tmp_file.close()


class Mailer:
    def __init__(self):
        self.sender = Config().config.get("smtp", "from")

    def sender(self, address):
        self.sender = address

    def to(self, address):
        self.to = address

    def subject(self, subject):
        self.subject = subject

    def send(self, content, attachments=None):
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        msg = MIMEMultipart('alternative')
        msg.attach(MIMEText(content, 'plain'))
        msg['Subject'] = self.subject
        msg['From'] = self.sender
        msg['To'] = self.to

        # Send the message via our own SMTP server, but don't include the
        # envelope header.
        s = smtplib.SMTP(Config().config.get("smtp", "server"))
        s.sendmail(self.sender, [self.to], msg.as_string())
        s.quit()


class Render:

    @staticmethod
    def print_table(header, list):
        size_cols = []
        line = '+'
        for i in range(0,len(header)):
            size_cols.append(len(header[i])+2)
        for element in list:
            for i in range (0,len(header)):
                if len(element[i])+2 > size_cols[i]:
                    size_cols[i] = len(element[i])+2
        for col in size_cols:
            line += '-'*col + '+'
        table = line + '\n|'
        for i in range(0,len(header)):
            table += " " + header[i] + (" "*(size_cols[i]-len(header[i])-1)) + "|"
        table += "\n" + line + "\n"
        for element in list:
            table += "|"
            for i in range(0,len(header)):
                table += " " + element[i] + (" "*(size_cols[i]-len(element[i])-1)) + "|"
            table += "\n"
        print table + line + "\n"

    @staticmethod
    def render_menu(list, selected=[]):
        (row, cols) = Render.get_term_size()
        max_len = 0
        for i in list.values():
            if len(i)+7 > max_len:
                max_len = len(i)+7
        displayed_list = list.values()
        displayed_list.append("All")
        table = ''
        nbr_element = 0
        element_by_line = cols / max_len
        for (key, val) in enumerate(displayed_list):
            nbr_element += 1
            value_select = ' '
            if key in selected:
                value_select = '*'
            to_add = "%s:[%s]%s" % (str(key).rjust(2), value_select, val)
            table += to_add
            table += ' '*(max_len-len(to_add))
            if nbr_element % element_by_line == 0:
                table += '\n'
        return table[:-1], len(table[:-1].split('\n')), nbr_element

    @staticmethod
    def print_selector(list, selected=[], displayed=False):
        (menu, nbr_line, nbr_element) = Render.render_menu(list, selected)
        if displayed:
            print "\033[1A\033[2K\033[%sA" % (nbr_line+1)
        print menu
        select = raw_input("Please select element from 0 to " + str(nbr_element-1) + " (q to escape menu): ")
        if select.isdigit() and 0 < int(select) < nbr_element:
            selected.append(int(select))
        if "q" in select:
            print len(list.values())
            if len(list) in selected:
                return list
            else:
                d = {}
                for k, v in list.iteritems():
                    for i in selected:
                        if v in list.values()[i]:
                            d.update({k: v})
                return d

                #return selected
        else:
            return Render.print_selector(list, selected, True)

    @staticmethod
    def get_term_size():
        termsize = subprocess.check_output(['stty', 'size']).split()
        return int(termsize[0]), int(termsize[1])


class Show:

    base_dir = "/Users/ferezgaetan/PycharmProjects/manpki/lib/ManPKI/Shell"
    identchars = IDENTCHARS
    list_functions = []

    def __init__(self, line):
        self.load_functions()
        if "?" in line:
            self.show_help(line)
        else:
            self.call_command(self.parse_line(line))

    def parse_line(self, line):
        arg_path = line.lower().split(" ")
        if arg_path and len(arg_path)>0:
            command = 'show_' + '_'.join(arg_path)
            orig_command = command
            while not hasattr(self, command) and command != "show":
                command = "_".join(command.split("_")[:-1])
            if command == "show":
                print "% Undefine command"
                return "show_help"
            if not orig_command == command:
                command += "~" + orig_command.replace(command, "")[1:]
        else:
            command = None
        return command

    def call_command(self, command):
        try:
            args = None
            if '~' in command:
                (command, args) = command.split('~')

            if args:
                if Secret.debug:
                    print "SHOW Call : " + command
                    print "SHOW Args : " + args
                getattr(self, command)(args)
            else:
                if Secret.debug:
                    print "SHOW Call : " + command
                getattr(self, command)()
        except AttributeError:
            print "% Invalid input detected"
        except TypeError, e:
            print '% Type "show ?" for a list of subcommands'

    def show_help(self, line=None):
        list_cmd = []
        list_help = []
        search_func = "show_"
        if line and not "?" in line[0] and line.endswith("?"):
            search_func += '_'.join(line.replace("?","").strip().lower().split(" ")) + "_"
        for func in self.__class__.__dict__.keys():
            if func.startswith(search_func) and not func.endswith("_help") and not "_" in func[len(search_func):]:
                list_cmd.append(func[len(search_func):])
                if hasattr(self, func + "_help"):
                    with Capturing() as output:
                        getattr(self, func + "_help")()
                    list_help.append(output[0])
                else:
                    list_help.append("")
        if len(list_cmd)>0:
            print "\n".join("{0}\t{1}".format(a, b) for a, b in zip(list_cmd, list_help))
        if not search_func == "show_":
            if hasattr(self, search_func[:-1]):
                print "<cr>"
            else:
                print "% Invalid input detected"

    def show_config(self):
        for section in Config().config.sections():
            print section
            for option in Config().config.options(section):
                print " ", option, "=", Config().config.get(section, option)

    def load_functions(self):
        if os.path.isdir(self.base_dir) and len(Show.list_functions) == 0:
            for dirpath,dirnames,filenames in os.walk(self.base_dir):
                for name in filenames:
                    if name.startswith("Sh") and name.endswith(".py"):
                        module_name = splitext(name)[0]
                        path = dirpath.replace(self.base_dir, "")[1:]
                        module_path = "Shell."
                        if len(path)>0:
                            module_path += '.'.join(path.split("/")).title() + "." + module_name
                        else:
                            module_path += module_name
                        import_str = "from " + module_path + " import " + module_name
                        if Secret.debug:
                            print "Import all sub show from file " + name + " : " + import_str
                        exec import_str
                        modul = sys.modules[module_path]
                        for func_name in getattr(modul, module_name).__dict__.keys():
                            if func_name.startswith("show_"):
                                Show.list_functions.append([modul, module_name, func_name])
                                setattr(self.__class__, func_name, self._make_show_cmd(modul, module_name, func_name))

    @staticmethod
    def _make_show_cmd(modul, module_name, func_name):
        def handler_show(self, args=None):
            try:
                class_inst = getattr(modul, module_name)(False)
                attr = getattr(class_inst, func_name)
                if args:
                    attr(args)
                else:
                    attr()
            except Exception, e:
                print '*** error:', e
        return handler_show


class SSL:

    @staticmethod
    def get_ca_path():
        return Config().config.get("default", "certdir") + "/public/ca/ca.crt"

    @staticmethod
    def get_parentca_path():
        return Config().config.get("default", "certdir") + "/public/ca/parentca.crt"

    @staticmethod
    def get_ca_privatekey_path():
        return Config().config.get("default", "certdir") + "/private/ca.privkey"

    @staticmethod
    def get_crl_path():
        return Config().config.get("default", "certdir") + "/public/ca/crl.pem"

    @staticmethod
    def get_cert_path(certid):
        return Config().config.get("default", "certdir") + "/public/certificates/" + certid + ".crt"

    @staticmethod
    def check_ca_exist():
        return os.path.exists(SSL.get_ca_path()) and os.path.exists(SSL.get_ca_privatekey_path())

    @staticmethod
    def check_parentca_exist():
        return os.path.exists(SSL.get_parentca_path())

    @staticmethod
    def check_crl_exist():
        return os.path.exists(SSL.get_crl_path())

    @staticmethod
    def check_cert_exist(certid):
        return os.path.exists(SSL.get_cert_path(certid))

    @staticmethod
    def get_cert_id(cert):
        cert_content = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        return hashlib.md5(cert_content).hexdigest()[:10].upper()

    @staticmethod
    def get_ca():
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(SSL.get_ca_path(), "rt").read())

    @staticmethod
    def get_ca_privatekey():
        content_privatekey = open(SSL.get_ca_privatekey_path(), "rt").read()
        return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, content_privatekey)

    @staticmethod
    def get_crl():
        return OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, open(SSL.get_crl_path(), "rt").read())

    @staticmethod
    def read_cert(filename):
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open(filename, "rt").read())

    @staticmethod
    def get_asn_cert_raw(certid):
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, SSL.read_cert(SSL.get_cert_path(certid)))

    @staticmethod
    def set_ca_privatekey(pkey):
        priv_key_str = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
        f = open(SSL.get_ca_privatekey_path(), 'w')
        f.write(priv_key_str)

    @staticmethod
    def set_ca(cert):
        ca_str = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        f = open(SSL.get_ca_path(), 'w')
        f.write(ca_str)
        f.close()

    @staticmethod
    def set_crl(crl):
        days = Config().config.getint("crl", "validity")
        crl_str = crl.export(SSL.get_ca(), SSL.get_ca_privatekey(), type=OpenSSL.crypto.FILETYPE_PEM, days=days)
        f = open(SSL.get_crl_path(), "w")
        f.write(crl_str)
        f.close()

    @staticmethod
    def revoke_cert(certid, reason):
        pass

    @staticmethod
    def get_all_certificates():
        list = []
        certdir = Config().config.get("default", "certdir") + "/public/certificates/"
        for name in os.listdir(certdir):
            if name.endswith(".crt"):
                list.append({'id': name[:-4], 'cert': SSL.read_cert(certdir + name)})
        return list

    @staticmethod
    def get_cert(certid):
        if SSL.check_cert_exist(certid):
            return SSL.read_cert(SSL.get_cert_path(certid))
        else:
            return None

    @staticmethod
    def get_x509_name(x509name):
        str = ""
        for (name,value) in x509name.get_components():
            str += name + "=%s, " % value
        return str[:-2]

    @staticmethod
    def decode_time(time):
        return dt.datetime.strptime(time, "%Y%m%d%H%M%SZ").replace(tzinfo=UTC)

    @staticmethod
    def create_key(size):
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, size)
        return key

    @staticmethod
    def create_cert(key):
        cert = OpenSSL.crypto.X509()
        cert.set_pubkey(key)
        return cert

    @staticmethod
    def create_extension(name, value, critical):
        ext = OpenSSL.crypto.X509Extension(name, critical, value)
        return ext

    @staticmethod
    def sign(cert, key, digest):
        cert.sign(key, digest)
        return cert

    @staticmethod
    def parse_str_to_x509Name(string, x509obj):
        cpts = string.split("/")
        x509Name = x509obj
        for elt in cpts:
            exec "x509Name.%s='%s'" % (elt.split("=")[0], elt.split("=")[1])
        return x509Name

    @staticmethod
    def generate_crl():
        if SSL.check_ca_exist():
            crl = OpenSSL.crypto.CRL()
            if SSL.check_crl_exist():
                crl = SSL.get_crl()

            SSL.set_crl(crl)
            return True
        else:
            return False

    @staticmethod
    def get_key_usage():
        return Config().config.items("keyusage")

    @staticmethod
    def get_extended_key_usage():
        return Config().config.items("extended")

    @staticmethod
    def display_cert_by_id(certid):
        SSL.display_cert(SSL.get_cert(certid))

    @staticmethod
    def display_cert(cert):
        print "ID : %s " % SSL.get_cert_id(cert)
        print "Subject : %s " % SSL.get_x509_name(cert.get_subject())
        print "Issuer : %s " % SSL.get_x509_name(cert.get_issuer())
        print "Serial : %s" % cert.get_serial_number()
        print "Key size : %s" % cert.get_pubkey().bits()
        print "Version : %s" % cert.get_version()
        print "State : Expired" if cert.has_expired() else "State : OK"
        print "Validity"
        after_datetime = SSL.decode_time(cert.get_notAfter())
        delta =  after_datetime.replace(tzinfo=None) - after_datetime.utcoffset() - dt.datetime.now()
        print "\tNot before : %s" % SSL.decode_time(cert.get_notBefore()).strftime("%c %Z")
        print "\tNot after : %s (%s)" % ( SSL.decode_time(cert.get_notAfter()).strftime("%c %Z"), delta)
        print "Algorithm"
        if cert.get_pubkey().type() == OpenSSL.crypto.TYPE_RSA:
            print "\tPublic key : %s" % "rsaEncryption"
        elif cert.get_pubkey().type() == OpenSSL.crypto.TYPE_DSA:
            print "\tPublic key : %s" % "dsaEncryption"
        print "\tSignature : %s" % cert.get_signature_algorithm()
        print "Fingerprint"
        print "\tSHA1 : %s" % cert.digest(b"sha1")
        print "\tMD5 : %s" % cert.digest(b"md5")
