import os
import OpenSSL
import hashlib
from time import time
from datetime import datetime, timedelta
from pyasn1.codec.der import decoder
from pyasn1.type import univ
from pytz import UTC

from manpki.tools.event import event
from manpki.config import ConfigObject
from manpki.asn1 import rfc2459
from manpki.db import *


class SSL:
    @staticmethod
    def get_ca_path():
        return ManPKIObject.certdir + "/public/ca/ca.crt"

    @staticmethod
    def get_parentca_path():
        return ManPKIObject.certdir + "/public/ca/parentca.crt"

    @staticmethod
    def get_ca_privatekey_path():
        return ManPKIObject.certdir + "/private/ca.privkey"

    @staticmethod
    def get_crl_path():
        return ManPKIObject.certdir + "/public/ca/crl.pem"

    @staticmethod
    def get_cert_path(certid):
        return ManPKIObject.certdir + "/public/certificates/" + certid + ".crt"

    @staticmethod
    def get_cert_privatekey_path(certid):
        return ManPKIObject.certdir + "/private/" + certid + ".privkey"

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
        return isinstance(certid, str) and os.path.exists(SSL.get_cert_path(certid))

    @staticmethod
    def get_cert_id(cert):
        cert_content = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        return hashlib.sha256(cert_content).hexdigest()[:20].upper()

    @staticmethod
    def get_cert_raw(cert):
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

    @staticmethod
    def get_ca():
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, SSL.get_ca_content())

    @staticmethod
    def get_ca_content():
        with open(SSL.get_ca_path(), "rb") as cafile:
            return cafile.read()

    @staticmethod
    def get_ca_privatekey():
        log.info("Load private key : " + SSL.get_ca_privatekey_path())
        with open(SSL.get_ca_privatekey_path(), "rt") as pkey:
            return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey.read())

    @staticmethod
    def get_crl():
        with open(SSL.get_crl_path(), "rt") as crl:
            return OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, crl.read())

    @staticmethod
    def get_crl_binary():
        crlparam = CrlParameter.get()
        crl = OpenSSL.crypto.load_crl(OpenSSL.crypto.FILETYPE_PEM, open(SSL.get_crl_path(), "rt").read())
        days = crlparam.validity
        crl_binary = crl.export(SSL.get_ca(), SSL.get_ca_privatekey(), type=OpenSSL.crypto.FILETYPE_ASN1, days=days)
        return crl_binary

    @staticmethod
    def read_cert(filename):
        return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, SSL.get_cert_content(filename))

    @staticmethod
    def get_cert_content(filename):
        with open(filename, "rb") as certfile:
            return certfile.read()

    @staticmethod
    def get_asn_cert_raw(certid):
        return OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_ASN1, SSL.read_cert(SSL.get_cert_path(certid)))

    @staticmethod
    def set_ca_privatekey(pkey):
        priv_key_str = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
        log.info("Create new ca privatekey : " + SSL.get_ca_privatekey_path())
        f = open(SSL.get_ca_privatekey_path(), 'wt')
        f.write(priv_key_str.decode('utf-8'))
        f.close()

    @staticmethod
    def set_cert_privatekey(cert, pkey):
        priv_key_str = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
        log.info("Create new cert privatekey : " + SSL.get_cert_privatekey_path(SSL.get_cert_id(cert)))
        f = open(SSL.get_cert_privatekey_path(SSL.get_cert_id(cert)), 'w')
        f.write(priv_key_str.decode('utf-8'))
        f.close()

    @staticmethod
    def set_ca(cert):
        ca_str = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        f = open(SSL.get_ca_path(), 'w')
        f.write(ca_str.decode('utf-8'))
        f.close()

    @staticmethod
    def set_cert(cert):
        cert_str = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        f = open(SSL.get_cert_path(SSL.get_cert_id(cert)), 'w')
        f.write(cert_str.decode('utf-8'))
        f.close()

    @staticmethod
    def delete_cert(certid):
        path_cert = SSL.get_cert_path(certid)
        path_key = SSL.get_cert_privatekey_path(certid)
        if os.path.isfile(path_key):
            os.unlink(path_key)
        if os.path.isfile(path_cert):
            os.unlink(path_cert)

    @staticmethod
    def set_crl(crl):
        crlparam = CrlParameter.get()
        days = crlparam.validity
        digest = crlparam.digest.encode()
        crl_str = crl.export(SSL.get_ca(), SSL.get_ca_privatekey(), type=OpenSSL.crypto.FILETYPE_PEM, days=days, digest=digest)
        f = open(SSL.get_crl_path(), "w")
        f.write(crl_str.decode('utf-8'))
        f.close()

    @staticmethod
    def get_all_certificates():
        list_cert = []
        certdir = ManPKIObject.certdir + "/public/certificates/"
        if os.path.isdir(certdir):
            for name in os.listdir(certdir):
                if name.endswith(".crt"):
                    list_cert.append({'id': name[:-4], 'cert': SSL.read_cert(certdir + name)})
        return list_cert

    @staticmethod
    def delete_all_certs():
        for cert in SSL.get_all_certificates():
            SSL.delete_cert(cert['id'])

    @staticmethod
    def get_json_all_certificates():
        list_cert = []
        certdir = ManPKIObject.certdir + "/public/certificates/"
        for name in os.listdir(certdir):
            if name.endswith(".crt"):
                certid = name[:-4]
                list_cert.append(SSL.display_cert(SSL.get_cert(certid)))
        return list_cert

    @staticmethod
    def delete_ca():
        for cert in SSL.get_all_certificates():
            SSL.delete_cert(cert['id'])
        if os.path.isfile(SSL.get_ca_privatekey_path()):
            os.unlink(SSL.get_ca_privatekey_path())
        if os.path.isfile(SSL.get_ca_path()):
            os.unlink(SSL.get_ca_path())

    @staticmethod
    def get_cert(certid):
        if SSL.check_cert_exist(certid):
            return SSL.read_cert(SSL.get_cert_path(certid))
        else:
            return None

    @staticmethod
    def get_x509_name(x509name):
        str_name = ""
        for (name, value) in x509name.get_components():
            str_name += name.decode('utf-8') + "=%s, " % value.decode('utf-8')
        return str_name[:-2]

    @staticmethod
    def decode_time(time):
        return datetime.strptime(time.decode('utf-8'), "%Y%m%d%H%M%SZ").replace(tzinfo=UTC)

    @staticmethod
    def create_key(size):
        key = OpenSSL.crypto.PKey()
        key.generate_key(OpenSSL.crypto.TYPE_RSA, size)
        return key

    @staticmethod
    def create_x509cert(key):
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
    def parse_str_to_x509name(string, x509obj):
        cpts = string.split("/")
        x509name = x509obj
        for elt in cpts:
            exec("x509name.%s='%s'" % (elt.split("=")[0].upper(), elt.split("=")[1]))
        return x509name

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
    def _parse_bitstring_to_keyusage(bitstring):
        keyusage = SSL.get_key_usage()
        list_keyusage = []
        for n, v in enumerate(bitstring):
            if v:
                list_keyusage.append(keyusage["2.5.29.15." + str(n)])
        return list_keyusage

    @staticmethod
    def get_key_usage():
        d = {}
        for e in KeyUsage.search():
            d.update({e['oid']: e['name']})
        return d

    @staticmethod
    def get_extended_key_usage():
        d = {}
        for e in ExtendedKeyUsage.search():
            d.update({e['oid']: e['name']})
        return d

    @staticmethod
    def get_array_key_usage_from_profile(profile):
        keysusage = SSL.get_key_usage()
        keys = str(profile.keyusage).split('|')
        a_keys = []
        for (k, v) in keysusage.items():
            if k in keys:
                a_keys.append(v)
        return a_keys

    @staticmethod
    def get_key_usage_from_profile(profile):
        return bytes(', '.join(SSL.get_array_key_usage_from_profile(profile)), 'utf-8')

    @staticmethod
    def get_array_extended_key_usage_from_profile(profile):
        keysusage = SSL.get_extended_key_usage()
        keys = str(profile.extended).split('|')
        a_keys = []
        for elt in keysusage.items():
            k = elt[0]
            if k in keys:
                a_keys.append(k)
        return a_keys

    @staticmethod
    def get_extended_key_usage_from_profile(profile):
        return bytes(', '.join(SSL.get_array_extended_key_usage_from_profile(profile)), 'utf-8')

    @staticmethod
    def cert_equal_to_profile(cert, profile):
        keyprofile = SSL.get_array_key_usage_from_profile(profile)
        extendedkeyprofile = SSL.get_array_extended_key_usage_from_profile(profile)
        return SSL.cert_equal_to_key_and_extended_key(cert, keyprofile, extendedkeyprofile)

    @staticmethod
    def cert_equal_to_key_and_extended_key(cert, keysusage, extendedkeys, strict=True):
        extendkey_match = True
        keyusage_match = True
        for i in range(0, cert.get_extension_count()):
            if cert.get_extension(i).get_short_name() in "extendedKeyUsage":
                val, _ = decoder.decode(cert.get_extension(i).get_data(), asn1Spec=univ.Sequence())
                size_extendedkey = 0
                for elt in enumerate(val):
                    v = elt[1]
                    size_extendedkey += 1
                    if v.__str__() not in extendedkeys:
                        extendkey_match = False
                if len(extendedkeys) != size_extendedkey and strict:
                    extendkey_match = False
            elif cert.get_extension(i).get_short_name() in "keyUsage":
                val, _ = decoder.decode(cert.get_extension(i).get_data(), asn1Spec=rfc2459.KeyUsage())
                key_from_cert = SSL._parse_bitstring_to_keyusage(tuple(val))
                if strict:
                    if sorted(key_from_cert) != sorted(keysusage):
                        keyusage_match = False
                else:
                    for v in keysusage:
                        if v not in key_from_cert:
                            keyusage_match = False
        return extendkey_match & keyusage_match

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
    def create_ca(force=False):
        caparam = CAParameter.get()

        before = datetime.utcnow()
        after = before + timedelta(days=caparam.validity)

        pkey = SSL.create_key(caparam.keysize)

        ca = SSL.create_x509cert(pkey)
        subject = caparam.basecn + "/CN=" + caparam.name
        subject_x509 = SSL.parse_str_to_x509name(subject, ca.get_subject())
        if caparam.typeca == "rootca":
            issuer_x509 = SSL.parse_str_to_x509name(subject, ca.get_issuer())

        if caparam.email:
            subject_x509.emailAddress = caparam.email

        if caparam.typeca == "rootca":
            issuer_x509.emailAddress = caparam.email

        ca.set_subject(subject_x509)

        if caparam.typeca == "rootca":
            ca.set_issuer(issuer_x509)

        ca.set_notBefore(bytes(before.strftime("%Y%m%d%H%M%S%Z") + "Z", 'utf-8'))
        ca.set_notAfter(bytes(after.strftime("%Y%m%d%H%M%S%Z") + "Z", 'utf-8'))
        ca.set_serial_number(int(time() * 1000000))
        ca.set_version(2)

        bsConst = b"CA:TRUE"
        if caparam.isfinal:
            bsConst += b", pathlen:0"

        ca.add_extensions([
            OpenSSL.crypto.X509Extension(b"basicConstraints", True, bsConst),
            OpenSSL.crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
            OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca),
        ])

        if caparam.typeca == "rootca":
            ca.add_extensions([
                OpenSSL.crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca)
            ])

        # if EventManager.hasEvent("new_cert"):
        #     ca = EventManager.new_cert(ca)

        crlparam = CrlParameter.get()
        if crlparam.enable:
            crlUri = b"URI:" + crlparam.uri
            ca.add_extensions([
                OpenSSL.crypto.X509Extension(b"crlDistributionPoints", False, crlUri)
            ])

        ocspparam = OcspParameter.get()
        if ocspparam.enable:
            ocspUri = b"OCSP;URI:" + ocspparam.uri
            ca.add_extensions([
                OpenSSL.crypto.X509Extension(b"authorityInfoAccess", False, ocspUri)
            ])

        # @TODO if type = subca, sign this subca with the parent ca
        ca_signed = SSL.sign(ca, pkey, caparam.digest)

        SSL.set_ca(ca_signed)
        SSL.set_ca_privatekey(pkey)

        event.emit("manpki.ca.new", ca_signed)

        if force:
            SSL.resigned_all_cert()

    @staticmethod
    def create_cert(profile, data):
        certparam = CertParameter.get()
        before = datetime.utcnow()
        after = before + timedelta(days=certparam.validity)

        pkey = SSL.create_key(certparam.keysize)

        ca = SSL.get_ca()
        cert = SSL.create_x509cert(pkey)

        ldapparam = LdapParameter.get()
        if ldapparam.enable and "false" not in profile.ldap:
            log.info("Search in LDAP")
            # @TODO ldap search based on ManPKI Profile
        else:
            cn = data['cn']
            email = data['mail']
            caparam = CAParameter.get()
            subject = caparam.basecn + "/CN=" + cn

        subject_x509 = SSL.parse_str_to_x509name(subject, cert.get_subject())

        issuer_x509 = ca.get_subject()
        if email:
            subject_x509.emailAddress = email

        cert.set_subject(subject_x509)
        cert.set_issuer(issuer_x509)
        cert.set_notBefore(bytes(before.strftime("%Y%m%d%H%M%S%Z") + "Z", 'utf-8'))
        cert.set_notAfter(bytes(after.strftime("%Y%m%d%H%M%S%Z") + "Z", 'utf-8'))
        cert.set_serial_number(int(time() * 1000000))
        cert.set_version(2)

        bsConst = b"CA:FALSE"
        cert.add_extensions([
            OpenSSL.crypto.X509Extension(b"basicConstraints", True, bsConst),
            OpenSSL.crypto.X509Extension(b"keyUsage", True, SSL.get_key_usage_from_profile(profile)),
            OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
        ])
        cert.add_extensions([
            OpenSSL.crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca)
        ])
        cert.add_extensions([
            OpenSSL.crypto.X509Extension(b"extendedKeyUsage", False, SSL.get_extended_key_usage_from_profile(profile))
        ])

        crlparam = CrlParameter.get()
        if crlparam.enable:
            crlUri = b"URI:" + crlparam.uri
            cert.add_extensions([
                OpenSSL.crypto.X509Extension(b"crlDistributionPoints", False, crlUri)
            ])

        ocspparam = OcspParameter.get()
        if ocspparam.enable:
            ocspUri = b"OCSP;URI:" + ocspparam.uri
            cert.add_extensions([
                OpenSSL.crypto.X509Extension(b"authorityInfoAccess", False, ocspUri)
            ])

        cert_signed = SSL.sign(cert, SSL.get_ca_privatekey(), certparam.digest)
        SSL.set_cert(cert_signed)
        SSL.set_cert_privatekey(cert_signed, pkey)

        event.emit("manpki.cert.new", cert_signed)

        return SSL.get_cert_id(cert_signed)

    @staticmethod
    def display_cert(cert):
        jsoncert = {
            'id': SSL.get_cert_id(cert),
            'subject': SSL.get_x509_name(cert.get_subject()),
            'issuer': SSL.get_x509_name(cert.get_issuer()),
            'serial': cert.get_serial_number(),
            'keysize': cert.get_pubkey().bits(),
            'version': cert.get_version(),
            'state': 'expired' if cert.has_expired() else 'ok',
            'notbefore': SSL.decode_time(cert.get_notBefore()).strftime("%c %Z"),
            'notafter': SSL.decode_time(cert.get_notAfter()).strftime("%c %Z"),
            'signature': cert.get_signature_algorithm().decode('utf-8'),
            'finger_md5': cert.digest("md5").decode('utf-8'),
            'finger_sha1': cert.digest("sha1").decode('utf-8')
        }
        if cert.get_pubkey().type() == OpenSSL.crypto.TYPE_RSA:
            jsoncert['algorithm'] = "rsaEncryption"
        elif cert.get_pubkey().type() == OpenSSL.crypto.TYPE_DSA:
            jsoncert['algorithm'] = "dsaEncryption"
        else:
            jsoncert['algorithm'] = 'unknown'
        jsoncert['raw'] = SSL.get_cert_raw(cert).decode('utf-8')
        return jsoncert

    @staticmethod
    def resigned_all_cert():
        certparam = CertParameter.get()
        for certhash in SSL.get_all_certificates():
            cert_signed = SSL.sign(certhash['cert'], SSL.get_ca_privatekey(), certparam.digest)
            SSL.delete_cert(certhash['id'])
            SSL.set_cert(cert_signed)


class WebSSL:
    @staticmethod
    def _get_openssl_crypto_module():
        try:
            from OpenSSL import crypto
        except ImportError:
            raise TypeError('Using ad-hoc certificates requires the pyOpenSSL '
                            'library.')
        else:
            return crypto

    def generate_adhoc_ssl_pair(self, cn=None):
        import sys
        crypto = self._get_openssl_crypto_module()

        # pretty damn sure that this is not actually accepted by anyone
        if cn is None:
            cn = '*'

        cert = crypto.X509()
        cert.set_serial_number(int(time() * sys.maxsize))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(60 * 60 * 24 * 365)

        subject = cert.get_subject()
        subject.CN = cn
        subject.O = 'Dummy Certificate'

        issuer = cert.get_issuer()
        issuer.CN = 'Untrusted Authority'
        issuer.O = 'Self-Signed'

        pkey = crypto.PKey()
        pkey.generate_key(crypto.TYPE_RSA, 2048)
        cert.set_pubkey(pkey)
        cert.sign(pkey, 'sha256')

        return cert, pkey

    def generate_adhoc_ssl_context(self):
        """Generates an adhoc SSL context for the development server."""
        crypto = self._get_openssl_crypto_module()
        import tempfile
        import atexit

        cert, pkey = self.generate_adhoc_ssl_pair()
        cert_handle, cert_file = tempfile.mkstemp()
        pkey_handle, pkey_file = tempfile.mkstemp()
        atexit.register(os.remove, pkey_file)
        atexit.register(os.remove, cert_file)

        os.write(cert_handle, crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        os.write(pkey_handle, crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey))
        os.close(cert_handle)
        os.close(pkey_handle)

        return cert_file, pkey_file
