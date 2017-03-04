from flask import json, request
from tinydb import where
from manpki.tools import SSL, API, multi_auth
from manpki.logger import log
from manpki.db import CertParameter, Profile


@API.route("/cert/", "show cert", method='GET', defaults={'certid': None}, args=[
    {"name": "certid", "type": "str", "mandatory": False}], level=API.USER)
@API.route("/cert/<certid>", "show cert [param]", method='GET', args=[
    {"name": "certid", "type": "str", "mandatory": False}], level=API.USER)
@multi_auth.login_required
def show_cert(certid):
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
    {"name": "basecn", "type": "str", "mandatory": False},
    {"name": "email", "type": "email", "mandatory": False}
], level=API.USER, context="cert")
@multi_auth.login_required
def set_cert():
    data = request.get_json(silent=True)
    log.info('Parameter : ' + json.dumps(data))
    cert_param = CertParameter.get()
    for name, field in cert_param:
        if not name.startswith("_") and name in data:
            setattr(cert_param, name, data[name])
    try:
        cert_param.validate()
        cert_param.save()
        return {'state': 'OK'}, 200
    except:
        return {'state': 'NOK'}, 404


@API.route("/cert", "create [param=value]", method='PUT', args=[
    {"name": "cn", "type": "str", "mandatory": True},
    {"name": "mail", "type": "str", "mandatory": True},
    {"name": "profile", "type": "str", "mandatory": True}
], level=API.USER, context="cert")
@multi_auth.login_required
def add_cert():
    data = request.get_json(silent=True)
    log.info('Parameter : ' + json.dumps(data))
    try:
        if data.__class__.__name__ == "list" or not data.keys() >= {'cn', 'mail', 'profile'}:
            message = {'error': 'missing parameter'}
            code = 505
        else:
            try:
                profile = Profile.get(where('name') == data['profile'])
                cert_id = SSL.create_cert(profile, data)
                message = {'message': 'certificate created', 'certid': cert_id}
                code = 200
            except Exception as e:
                message = {'error': 'error during certificate creation', 'message': e.__repr__(),
                           'profile': data['profile']}
                code = 404
    except Exception as e:
        message = {'error': 'certificate not created', 'message': e.__repr__()}
        code = 500

    return message, code


@API.route("/ca/param/", "show ca param", method='GET', defaults={'param': None}, args=[
    {"name": "param", "type": "str", "mandatory": False}], level=API.USER)
@API.route("/ca/param/<param>", "show ca param [param]", method='GET', args=[
    {"name": "param", "type": "str", "mandatory": False}], level=API.USER)
def get_cert_param(param):
    cert_param = CertParameter.get()
    if param:
        the_return = {param: getattr(cert_param, param)}
    else:
        the_return = cert_param.to_struct()

    return the_return, 200
