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
import json
import string
import hashlib
import smtplib
import StringIO
import datetime as dt
import OpenSSL.crypto
import subprocess
import ldap
import ldap.modlist
import base64
import re
import httplib
import cPickle

from collections import OrderedDict
from pytz import UTC
from scp import SCPClient
from paramiko import SSHClient
from os.path import splitext
from cStringIO import StringIO
from queuelib import FifoDiskQueue
from Crypto.Cipher import Blowfish
from crontab import CronTab

import Exceptions.ProtocolException
import Exceptions.CopyException

from cryptography.hazmat.bindings.openssl.binding import Binding
binding = Binding()
ffi = binding.ffi
lib = binding.lib


IDENTCHARS = string.ascii_letters + string.digits + '_'


class API:

    def __init__(self, host, port=2372):
        if ':' in host:
            port = host.split(':')[1]
            host = host.split(':')[0]
        self.host = host
        self.port = port

    def connect(self):
        self.conn = httplib.HTTPSConnection(self.host, self.port, timeout=10)
        self.conn.connect()

    def has_valid(self):
        try:
            self.connect()
            return True
        except Exception:
            return False

    def request(self, method, command, data=''):
        self.connect()
        self.conn.putrequest(method, "/%s?token=%s" % (command, Secret.api_token), '', )
        self.conn.putheader('User-Agent', 'ManPKI/1.0')
        self.conn.endheaders()
        self.conn.send(data)
        r1 = self.conn.getresponse()
        if r1.status == 200:
            response = r1.read()
            print response
            data = json.JSONDecoder().decode(response)
            if 'state' in data.keys() and 'response' in data.keys():
                return data
            else:
                return {'state': 'NOK', 'response': None}
        else:
            return {'state': 'NOK', 'response': None}

    def get(self, command):
        return self.request('GET', command)

    def push(self, command, data):
        return self.request('POST', command, json.JSONEncoder().encode(data))

    def encode_object(self, obj):
        output = StringIO()
        cPickle.dump(obj, output)
        return base64.encode(output.getvalue())

    def decode_object(self, str):
        return cPickle.load(str)

    def encode_cert(self, obj):
        return base64.b64encode(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, obj))

    def decode_cert(self, str):
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, base64.b64decode(str))


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
    config_path = Secret.config_file

    sections = ("default", "ca", "crl", "ocsp", "keyusage", "extended", "ldap", "smtp", "cert")

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


class Cron:

    def __init__(self):
        Cron.crontab = CronTab(user=True)

    def add(self, id, command, schedule, enable=True):
        job = Cron.crontab.new(command=command, comment=id)
        job.schedule(self.parse_str_to_crontime(schedule))
        job.enable(enable)
        Cron.crontab.write()

    def enable(self, id):
        job = Cron.crontab.find_comment(id).next()
        job.enable(True)
        Cron.crontab.write()

    def disable(self, id):
        job = Cron.crontab.find_comment(id).next()
        job.enable(False)
        Cron.crontab.write()

    def parse_str_to_crontime(self, str):
        m = re.match("([0-9]*)m", str)
        if m:
            minute = '*/' + m.group(1)
        else:
            minute = '*'
        m = re.match("([0-9]*)h", str)
        if m:
            hour = '*/' + m.group(1)
        else:
            hour = '*'
        m = re.match("([0-9]*)d", str)
        if m:
            day = '*/' + m.group(1)
        else:
            day = '*'
        m = re.match("([0-9]*)M", str)
        if m:
            month = '*/' + m.group(1)
        else:
            month = '*'
        return "%s %s %s %s *" % (minute, hour, day, month)

    def set_schedule(self, id, schedule):
        job = Cron.crontab.find_comment(id).next()
        job.setall(self.parse_str_to_crontime(schedule))
        Cron.crontab.write()

    def hasjob(self, id):
        try:
            Cron.crontab.find_comment(id).next()
            return True
        except StopIteration:
            return False


class EventManager:

    class Event:
        def __init__(self, functions):
            if type(functions) is not list:
                raise ValueError("functions parameter has to be a list")
            self.functions = functions

        def __iadd__(self, func):
            self.functions.append(func)
            return self

        def __isub__(self, func):
            self.functions.remove(func)
            return self

        def __call__(self, *args, **kvargs):
            for func in self.functions:
                func(*args, **kvargs)

    @classmethod
    def addEvent(cls, **kvargs):
        """
        addEvent( event1 = [f1,f2,...], event2 = [g1,g2,...], ... )
        creates events using **kvargs to create any number of events. Each event recieves a list of functions,
        where every function in the list recieves the same parameters.

        Example:

        def hello(): print "Hello ",
        def world(): print "World"

        EventManager.addEvent( salute = [hello] )
        EventManager.salute += world

        EventManager.salute()

        Output:
        Hello World
        """
        for key in kvargs.keys():
            if type(kvargs[key]) is not list:
                raise ValueError("value has to be a list")
            else:
                kvargs[key] = cls.Event(kvargs[key])

        cls.__dict__.update(kvargs)

    @staticmethod
    def hasEvent(name):
        return hasattr(EventManager, name)


class LDAP:
    def __init__(self):
        """ Initialisation """
        if not hasattr(LDAP, 'queue'):
            LDAP.queue = FifoDiskQueue(Secret.spool_dir + "/ldap.queue")

    def add_queue(self, cert):
        LDAP.queue.push(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))

    def pop_queue(self):
        return LDAP.queue.pop()

    def queue_all(self):
        if SSL.check_ca_exist():
            LDAP.queue.push(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, SSL.get_ca()))
            certs = SSL.get_all_certificates()
            for cert in certs:
                LDAP.queue.push(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert['cert']))

    def _convert_cert_to_dn(self, cert, depth=None):
        subj = cert.get_subject().get_components()
        list_sub = []
        dn_allows = ('C', 'ST', 'L', 'OU', 'O', 'CN')
        for tup in subj:
            if tup[0] in dn_allows:
                list_sub.append("=".join(tup))
        list_sub.reverse()
        return ",".join(list_sub[depth:])

    def get_password(self):
        crypted_pass = Config().config.get("ldap", "password")
        bl = Blowfish.new(Secret.appSecret, Blowfish.MODE_CFB, base64.b64decode(Secret.IV))
        return bl.decrypt(base64.b64decode(crypted_pass))

    def set_password(self, password):
        bl = Blowfish.new(Secret.appSecret, Blowfish.MODE_CFB, base64.b64decode(Secret.IV))
        crypted_pass = base64.b64encode(bl.encrypt(password))
        Config().config.set("ldap", "password", crypted_pass)

    def get_conn(self):
        l = ldap.initialize(Config().config.get("ldap", "server"))
        l.simple_bind(Config().config.get("ldap", "dn"), self.get_password())
        return l

    def get_basedn(self):
        l = self.get_conn()
        res = l.search_s('', ldap.SCOPE_BASE, '(namingContexts=*)', ['*','+'])
        for nc in res[0][1]['namingContexts']:
            if nc.lower() in Config().config.get("ldap", "dn").lower():
                return nc

    def check_dn_exist(self, cert, depth=None):
        l = self.get_conn()
        try:
            dn = self._convert_cert_to_dn(cert, depth)
            l.search_s(dn, ldap.SCOPE_SUBTREE, '(cn=*)')
            exist_object = True
        except ldap.NO_SUCH_OBJECT:
            exist_object = False
        return exist_object

    def get_dn(self, dn, filter='(objectclass=*)', attributes=None):
        l = self.get_conn()
        try:
            res = l.search_s(dn, ldap.SCOPE_SUBTREE, filter, attributes)
        except ldap.NO_SUCH_OBJECT:
            res = None
        return res

    def get_count_result(self):
        pass

    def check_requirements(self):
        if not SSL.check_ca_exist():
            print "CA doesn't exist"
            return False
        if self.check_dn_exist(SSL.get_ca(), depth=2):
            if not self.check_dn_exist(SSL.get_ca(), depth=1):
                dn = self._convert_cert_to_dn(SSL.get_ca(), depth=1)
                ou_name = dn.split(",")[0].split("=")[1]
                self.create_ou(dn, ou_name)
            return True
        else:
            return False

    def create_ou(self, dn, name):
        l = self.get_conn()
        attrs = {}
        attrs['objectclass'] = ['top', 'organizationalUnit']
        attrs['ou'] = name
        ldif = ldap.modlist.addModlist(attrs)
        l.add_s(dn, ldif)

    def add_cert(self, cert):
        l = self.get_conn()
        dn = self._convert_cert_to_dn(cert)
        objectclass = ['top']
        if "people" in dn.lower() or "user" in dn.lower():
            objectclass.append('person')
        else:
            objectclass.append('device')
        certpem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
        add_record = []
        if cert.get_subject() == SSL.get_ca().get_subject():
            objectclass.append('pkiCA')
            key = "cACertificate"
            crl = SSL.get_crl_binary()
            add_record.append(('certificateRevocationList;binary', [crl]))
        else:
            objectclass.append('pkiUser')
            key = "userCertificate"
        add_record.append(('objectclass', objectclass))
        add_record.append(('cn', [str(cert.get_subject().CN)]))
        add_record.append((key + ';binary', [certpem]))
        l.add_s(dn, add_record)

    def update_cert(self, cert):
        l = self.get_conn()
        dn = self._convert_cert_to_dn(cert)
        res = self.get_dn(dn)
        if len(res) != 1:
            print "One cert must be found"
            return False
        oc = res[0][1]['objectClass']
        mod_attrs = []
        certpem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert)
        if cert.get_subject() == SSL.get_ca().get_subject():
            key = "cACertificate"
            crl = SSL.get_crl_binary()
            if 'pkiCA' not in oc:
                oc.append('pkiCA')
                mod_attrs.append((ldap.MOD_REPLACE, 'objectClass', oc))
                mod_attrs.append((ldap.MOD_ADD, 'certificateRevocationList;binary', [crl]))
                mod_attrs.append((ldap.MOD_ADD, key + ';binary', certpem))
            else:
                if 'certificateRevocationList;binary' in res[0][1].keys():
                    mod_attrs.append((ldap.MOD_REPLACE, 'certificateRevocationList;binary', [crl]))
                else:
                    mod_attrs.append((ldap.MOD_ADD, 'certificateRevocationList;binary', [crl]))
                if key + ';binary' in res[0][1].keys():
                    mod_attrs.append(( ldap.MOD_REPLACE, key + ';binary', certpem))
                else:
                    mod_attrs.append(( ldap.MOD_ADD, key + ';binary', certpem))
        else:
            key = "userCertificate"
            if 'pkiUser' not in oc:
                oc.append('pkiUser')
                mod_attrs.append((ldap.MOD_REPLACE, 'objectClass', oc))
                mod_attrs.append((ldap.MOD_ADD, key + ';binary', certpem))
            else:
                if key + ';binary' in res[0][1].keys():
                    mod_attrs.append(( ldap.MOD_REPLACE, key + ';binary', certpem))
                else:
                    mod_attrs.append(( ldap.MOD_ADD, key + ';binary', certpem))
        l.modify_s(dn, mod_attrs)

    def delete_cert(self, cert):
        if self.check_dn_exist(cert):
            l = self.get_conn()
            dn = self._convert_cert_to_dn(cert)
            res = self.get_dn(dn)
            oc = res[0][1]['objectClass']
            mod_attrs = []
            if 'pkiUser' in oc:
                oc.remove(oc.index('pkiUser'))
                mod_attrs.append((ldap.MOD_REPLACE, 'objectClass', oc))
                mod_attrs.append((ldap.MOD_DELETE, 'userCertificate;binary'))
            elif 'pkiCA' in oc:
                oc.remove(oc.index('pkiCA'))
                mod_attrs.append((ldap.MOD_DELETE, 'certificateRevocationList;binary'))
                mod_attrs.append((ldap.MOD_DELETE, 'cACertificate;binary'))
            l.modify_s(dn, mod_attrs)

    def publish(self):
        if self.check_requirements():
            deleted_cert = 0
            added_cert = 0
            updated_cert = 0
            while LDAP.queue:
                cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.pop_queue())
                state = SSL.get_state_cert(cert)
                if 'Revoked' in state:
                    print "Delete revoke cert in ldap " + self._convert_cert_to_dn(cert)
                    self.delete_cert(cert)
                    deleted_cert += 1
                else:
                    if self.check_dn_exist(cert):
                        print "Update cert in ldap " + self._convert_cert_to_dn(cert)
                        self.update_cert(cert)
                        updated_cert += 1
                    else:
                        print "Add cert in ldap " + self._convert_cert_to_dn(cert)
                        self.add_cert(cert)
                        added_cert += 1
            return added_cert, updated_cert, deleted_cert
        else:
            return False


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
        displayed_list = OrderedDict(sorted(list.items()))
        displayed_list.update({"all": "All"})
        table = ''
        nbr_element = 0
        element_by_line = cols / max_len
        for (key, val) in displayed_list.iteritems():
            value_select = ' '
            if key in selected:
                value_select = '*'
            to_add = "%s:[%s]%s" % (str(nbr_element).rjust(2), value_select, val)
            nbr_element += 1
            table += to_add
            table += ' '*(max_len-len(to_add))
            if nbr_element % element_by_line == 0:
                table += '\n'
        return table[:-1], len(table[:-1].split('\n')), nbr_element

    @staticmethod
    def print_selector(list, selected=[], displayed=False):
        ordered_keys = OrderedDict(sorted(list.items()))
        #print ordered_keys
        (menu, nbr_line, nbr_element) = Render.render_menu(list, selected)
        if displayed:
            print "\033[1A\033[2K\033[%sA" % (nbr_line+1)
        print menu
        select = raw_input("Please select element from 0 to " + str(nbr_element-1) + " (q to escape menu): ")
        if select.isdigit() and 0 <= int(select) < nbr_element-1 and ordered_keys.keys()[int(select)] not in selected:
            selected.append(ordered_keys.keys()[int(select)])
        elif select.isdigit() and int(select) == nbr_element and len(selected) < nbr_element:
            selected = ordered_keys
        elif select.isdigit() and 0 <= int(select) < nbr_element-1 and ordered_keys.keys()[int(select)] in selected:
            selected.remove(ordered_keys.keys()[int(select)])
        elif select.isdigit() and int(select) == nbr_element and len(selected) == nbr_element:
            selected = []
        if "q" in select:
            if len(list) in selected:
                return list
            else:
                return selected
        else:
            return Render.print_selector(list, selected, True)

    @staticmethod
    def get_term_size():
        termsize = subprocess.check_output(['stty', 'size']).split()
        return int(termsize[0]), int(termsize[1])


class Show:

    base_dir = Secret.base_show
    identchars = IDENTCHARS
    list_functions = []

    def __init__(self, line):
        self.load_functions()
        if "?" in line:
            self.show_help(line)
        else:
            self.call_command(self.parse_line(line))

    def parse_line(self, line):
        arg_path = line.split(" ")
        if arg_path and len(arg_path)>0:
            command = 'show_' + '_'.join(arg_path)
            orig_command = command
            while not hasattr(self, command.lower()) and command != "show":
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
                getattr(self, command.lower())(args)
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
    def get_cert_privatekey_path(certid):
        return Config().config.get("default", "certdir") + "/private/" + certid + ".privkey"

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
    def get_crl_binary():
        crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, open(SSL.get_crl_path(), "rt").read())
        days = Config().config.getint("crl", "validity")
        crl_binary = crl.export(SSL.get_ca(), SSL.get_ca_privatekey(), type=OpenSSL.crypto.FILETYPE_ASN1, days=days)
        return crl_binary

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
    def set_cert_privatekey(cert, pkey):
        priv_key_str = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
        f = open(SSL.get_cert_privatekey_path(SSL.get_cert_id(cert)), 'w')
        f.write(priv_key_str)

    @staticmethod
    def set_ca(cert):
        ca_str = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        f = open(SSL.get_ca_path(), 'w')
        f.write(ca_str)
        f.close()

    @staticmethod
    def set_cert(cert):
        cert_str = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        f = open(SSL.get_cert_path(SSL.get_cert_id(cert)), 'w')
        f.write(cert_str)
        f.close()

    @staticmethod
    def delete_cert(certid):
        path_cert = SSL.get_cert_path(certid)
        path_key = SSL.get_cert_privatekey_path(certid)
        os.unlink(path_key)
        os.unlink(path_cert)

    @staticmethod
    def set_crl(crl):
        days = Config().config.getint("crl", "validity")
        crl_str = crl.export(SSL.get_ca(), SSL.get_ca_privatekey(), type=OpenSSL.crypto.FILETYPE_PEM, days=days)
        f = open(SSL.get_crl_path(), "w")
        f.write(crl_str)
        f.close()

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
    def create_request(key):
        cert = OpenSSL.crypto.X509Req()
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
            exec "x509Name.%s='%s'" % (elt.split("=")[0].upper(), elt.split("=")[1])
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
    def add_revoked(revoked):
        if not SSL.check_crl_exist():
             SSL.generate_crl()

        crl = SSL.get_crl()
        crl.add_revoked(revoked)
        SSL.set_crl(crl)

    @staticmethod
    def get_key_usage():
        d = {}
        for e in Config().config.items("keyusage"):
            d.update({e[0]: e[1]})
        return d

    @staticmethod
    def get_extended_key_usage():
        d = {}
        for e in Config().config.items("extended"):
            d.update({e[0]: e[1]})
        return d

    @staticmethod
    def get_key_usage_from_profile(profile):
        if Config().config.has_section("profile_" + profile):
            keysusage = SSL.get_key_usage()
            keys = str(Config().config.get("profile_" + profile, "keyusage")).split('|')
            a_keys = []
            for (k,v) in keysusage.iteritems():
                if k in keys:
                    a_keys.append(v)
            return ', '.join(a_keys)
        else:
            return None

    @staticmethod
    def get_extended_key_usage_from_profile(profile):
        if Config().config.has_section("profile_" + profile):
            keysusage = SSL.get_extended_key_usage()
            keys = str(Config().config.get("profile_" + profile, "extended")).split('|')
            print keys
            a_keys = []
            for (k, v) in keysusage.iteritems():
                if k in keys:
                    a_keys.append(k)
            print a_keys
            return ', '.join(a_keys)
        else:
            return None

    @staticmethod
    def get_state_cert(cert):
        state = "OK"
        if SSL.check_crl_exist():
            crl = SSL.get_crl()
            for rev in crl.get_revoked():
                serial = "{:x}".format(cert.get_serial_number()).upper()
                if len(serial) % 2 != 0:
                    serial = "0" + serial
                if rev.get_serial() == serial:
                    state = "Revoked"
        if cert.has_expired():
            state = "Expired"
        return state

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
        delta =  after_datetime.replace(tzinfo=None) - after_datetime.utcoffset() - dt.datetime.utcnow()
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
