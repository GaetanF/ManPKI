__author__ = 'ferezgaetan'

from command import Mailer, SSL

if SSL.generate_crl():
    ca = SSL.get_ca()
    if ca.get_subject().emailAddress:
        mail = Mailer()
        mail.to(ca.get_subject().emailAddress)
        mail.subject("CRL Creation")
        mail.send("CRL file has been created")
