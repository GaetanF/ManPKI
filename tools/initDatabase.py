from tinydb import TinyDB
from manpki.config import ManPKIObject

db = TinyDB(ManPKIObject.dbdir + '/manpki.json')
db.purge_tables()

## Extension
exten = db.table('extension')
#### KeyUsage
exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.0', 'name': 'digitalSignature', '_default': True})
exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.1', 'name': 'nonRepudiation', '_default': True})
exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.2', 'name': 'keyEncipherment', '_default': True})
exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.3', 'name': 'dataEncipherment', '_default': True})
exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.4', 'name': 'keyAgreement', '_default': True})
exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.5', 'name': 'keyCertSign', '_default': True})
exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.6', 'name': 'cRLSign', '_default': True})
exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.7', 'name': 'encipherOnly', '_default': True})
exten.insert({'type': 'keyusage', 'oid': '2.5.29.15.8', 'name': 'decipherOnly', '_default': True})

### Extended Key Usage
exten.insert(
    {'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.1', 'name': 'TLS Web Server Authentication', '_default': True})
exten.insert(
    {'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.2', 'name': 'TLS Web Client Authentication', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.3', 'name': 'Code Signing', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.4', 'name': 'Email Protection', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.8', 'name': 'Time Stamping', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.9', 'name': 'OCSP Signer', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.13', 'name': 'EAP over PPP', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.14', 'name': 'EAP over LAN', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.15', 'name': 'SCVP Server', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.16', 'name': 'SCVP Client', '_default': True})
exten.insert(
    {'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.17', 'name': 'Internal Key Exchange for IPSEC', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.20', 'name': 'SIP Domain', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.21', 'name': 'SSH Server', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.5.7.3.22', 'name': 'SSH Client', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.4.1.311.20.2.2', 'name': 'MS Smart Card Logon', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.4.1.311.10.3.12', 'name': 'MS Document Signing', '_default': True})
exten.insert(
    {'type': 'extended', 'oid': '1.3.6.1.4.1.311.2.1.21', 'name': 'MS Individual Code Signing', '_default': True})
exten.insert(
    {'type': 'extended', 'oid': '1.3.6.1.4.1.311.2.1.22', 'name': 'MS Commercial Code Signing', '_default': True})
exten.insert(
    {'type': 'extended', 'oid': '1.3.6.1.4.1.311.10.3.4', 'name': 'MS Encrypted File System (EFS)', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.4.1.311.10.3.4.1', 'name': 'MS EFS Recovery', '_default': True})
exten.insert({'type': 'extended', 'oid': '2.16.840.1.113741.1.2.3', 'name': 'Intel AMT Management', '_default': True})
exten.insert({'type': 'extended', 'oid': '0.4.0.2231.3.0', 'name': 'ETSI TSL Signing', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.2.840.113583.1.1.5', 'name': 'Adobe PDF Signing', '_default': True})
exten.insert(
    {'type': 'extended', 'oid': '1.2.203.7064.1.1.369791.1', 'name': 'CSN 369791 TLS Client', '_default': True})
exten.insert(
    {'type': 'extended', 'oid': '1.2.203.7064.1.1.369791.2', 'name': 'CSN 368781 TLS Server', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.2.3.4', 'name': 'Kerberos Key Authentication', '_default': True})
exten.insert({'type': 'extended', 'oid': '1.3.6.1.5.2.3.5', 'name': 'Kerberos KDC', '_default': True})
exten.insert({'type': 'extended', 'oid': '2.23.136.1.1.3', 'name': 'ICAO Master List Signing', '_default': True})
exten.insert({'type': 'extended', 'oid': '2.16.840.1.101.3.6.8', 'name': 'PIV Card Authentication', '_default': True})

## Profile
profile = db.table('profile')
### SSL Profile
profile.insert({'name': 'SSLServer', 'keyusage': '2.5.29.15.3|2.5.29.15.2|2.5.29.15.1', 'extended': '1.3.6.1.5.5.7.3.1',
                'ldap': '', '_default': True})
profile.insert({'name': 'SSLUser', 'keyusage': '2.5.29.15.1|2.5.29.15.2|2.5.29.15.3',
                'extended': '1.3.6.1.5.5.7.3.22|1.3.6.1.5.5.7.3.2|1.3.6.1.5.5.7.3.3', 'ldap': '(objectClass=person)',
                '_default': True})
profile.insert(
    {'name': 'OCSPResponder', 'keyusage': '2.5.29.15.0|2.5.29.15.1|2.5.29.15.2', 'extended': '1.3.6.1.5.5.7.3.9',
     'ldap': '', '_default': True})

## Parameters
param = db.table('parameter')
### CA
param.insert(
    {'object': 'ca', 'email': '', 'validity': 3560, 'keysize': 1024, 'basecn': 'C=FR', 'name': 'CA', 'digest': 'sha256',
     'typeca': 'rootca', 'isfinal': True})

### CERT
param.insert({'object': 'cert', 'validity': 365, 'keysize': 1024, 'digest': 'sha256'})

## CRL
param.insert({'object': 'crl', 'enable': False, 'digest': 'md5', 'validity': 30})

## OCSP
param.insert({'object': 'ocsp', 'enable': False, 'uri': 'http://ocsp/'})

## LDAP
param.insert({'object': 'ldap', 'enable': False, 'host': 'ldap://ldap:389/', 'dn': 'cn=admin', 'password': 'password',
              'mode': 'ondemand', 'schedule': '5m'})

## Mail
param.insert({'object': 'mail', 'enable': False, 'host': 'smtp', 'sender': 'manpki@example.com'})

## Server
param.insert({'object': 'server', 'sslcert': 'cert.pem', 'sslkey': 'key.pem', 'host': 'socket', 'port': 8080})

## Users
userdb = db.table('user')
