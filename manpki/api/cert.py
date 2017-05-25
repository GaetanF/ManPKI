"""
    manpki.api.cert
    ~~~~~~~~~~~~~~~

    Certificate part API.
    Accessible by /v1.0/api/cert url

    :copyright: (c) 2017 by Gaëtan FEREZ.
    :license: BSD, see LICENSE for more details.
"""
from flask import json, request
from tinydb import where
from manpki.tools import SSL, API, multi_auth
from manpki.logger import log
from manpki.db import CertParameter, Profile


@API.route("/cert/", "show cert", method='GET', defaults={'certid': None}, args=[
    {"name": "certid", "type": "str", "mandatory": False}], level=API.USER)
@API.route("/cert/<certid>", "show cert [param]", method='GET', args=[
    {"name": "certid", "type": "str", "mandatory": False}], render="manpki.api.cert.show_cert_withid", level=API.USER)
@multi_auth.login_required
def show_cert(certid):
    """Show all cert or specific cert information

    :param: certid Certificate Identifier

    :shell: show cert
    :context: none
    :return: ca information
    """
    if certid:
        if SSL.check_cert_exist(certid):
            cert = SSL.display_cert(SSL.get_cert(certid))
            return {'cert': cert}, 200
        else:
            cert = {'cert': 'notexist'}
            return cert, 404
    else:
        certs = SSL.get_json_all_certificates()
        return {'cert': certs}, 200


@API.route("/cert/set", "set cert [param]", method='POST', args=[
    {"name": "validity", "type": "str", "mandatory": False},
    {"name": "keysize", "type": "email", "mandatory": False},
    {"name": "digest", "type": "email", "mandatory": False}
], level=API.USER, context="cert")
@multi_auth.login_required
def set_cert():
    """Set cert element

    :param: basecn Base CN of the next certificate
    :param: email Email for the next certificate

    :shell: set cert
    :context: cert
    :return: information if element are correctly set
    """
    data = request.get_json(silent=True)
    log.info('Parameter : ' + json.dumps(data))
    keys = list(data.keys())
    keys.sort()
    if set(keys) <= {"validity", "digest", "keysize"}:
        cert_param = CertParameter.get()
        for elt in cert_param:
            name = elt[0]
            if not name.startswith("_") and name in data:
                setattr(cert_param, name, data[name])
        try:
            cert_param.validate()
            cert_param.save()
            return {'state': 'OK'}, 200
        except BaseException as error:
            return {'state': 'NOK', 'exception': error.__repr__()}, 404
    else:
        return {'error': 'Certificate parameter not valid'}, 404


@API.route("/cert", "create [param=value]", method='PUT', args=[
    {"name": "cn", "type": "str", "mandatory": True},
    {"name": "mail", "type": "str", "mandatory": True},
    {"name": "profile", "type": "str", "mandatory": True}
], level=API.USER, context="cert")
@multi_auth.login_required
def add_cert():
    """Create new certificate

    :param: cn CN of the certificate
    :param: mail Email for the certificate
    :param: profile SSL Profile

    :shell: create
    :context: cert
    :return: information of the new certificate
    """
    data = request.get_json(silent=True)
    log.info('Parameter : ' + json.dumps(data))
    try:
        if not SSL.check_ca_exist():
            message = {'error': 'ca must be created before create new certificate'}
            code = 500
        else:
            if data.__class__.__name__ == "list" or not data.keys() >= {'cn', 'mail', 'profile'}:
                message = {'error': 'missing parameter'}
                code = 505
            else:
                try:
                    profile = Profile.get(where('name') == data['profile'])
                    cert_id = SSL.create_cert(profile, data)
                    cert = SSL.display_cert(SSL.get_cert(cert_id))
                    message = {'message': 'certificate created', 'certid': cert_id, 'cert': cert}
                    code = 200
                except Exception as e:
                    message = {'error': 'error during certificate creation', 'message': e.__repr__(),
                               'profile': data['profile']}
                    code = 404
    except Exception as e:
        message = {'error': 'certificate not created', 'message': e.__repr__()}
        code = 500

    return message, code


@API.route("/cert/param/", "show cert param", method='GET', defaults={'param': None}, args=[
    {"name": "param", "type": "str", "mandatory": False}], level=API.USER)
@API.route("/cert/param/<param>", "show cert param [param]", method='GET', args=[
    {"name": "param", "type": "str", "mandatory": False}], level=API.USER)
@multi_auth.login_required
def get_cert_param(param):
    """Get certificate parameter

    :param: param Specific parameter

    :shell: show cert param
    :context: None
    :return: information of the certificate parameter
    """
    cert_param = CertParameter.get()
    if param:
        the_return = {param: getattr(cert_param, param)}
    else:
        the_return = cert_param.to_struct()

    return the_return, 200
