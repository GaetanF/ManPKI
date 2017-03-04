from flask import json, request

from manpki.tools import SSL, API, multi_auth
from manpki.logger import log
from manpki.db import CAParameter


@API.route("/ca", "show ca", method='GET', level=API.USER)
@multi_auth.login_required
def show_ca():
    if SSL.check_ca_exist():
        ca = SSL.display_cert(SSL.get_ca())
        return ca, 200
    else:
        ca = {'error': 'CA not ready'}
        return ca, 404


@API.route("/ca", "create", method='PUT', level=API.ADMIN, context="ca")
@API.route("/ca", "create [param]", method='PUT', level=API.ADMIN, context="ca", args=[
    {"name": "force", "type": "bool", "mandatory": False}
])
@multi_auth.login_required
def create_ca():
    if not SSL.check_ca_exist():
        SSL.create_ca()
        code = 200
        message = {'ca': 'created'}
    else:
        log.info("CA already exist")
        data = request.get_json(silent=True)
        if data and 'force' in data and data['force']:
            SSL.create_ca(force=data['force'])
            message = {'ca': 'created force'}
            code = 200
        else:
            code = 404
            message = {'error': 'CA already exist'}
    return message, code


@API.route("/ca/param", "set", method='POST', level=API.ADMIN, context="ca", args=[
    {"name": "basecn", "type": "str", "mandatory": False},
    {"name": "email", "type": "email", "mandatory": False},
    {"name": "keysize", "type": "int", "mandatory": False}
])
@multi_auth.login_required
def set_ca():
    print(request)
    data = request.get_json(silent=True)
    log.info('Parameter : ' + json.dumps(data))
    ca_param = CAParameter.get()
    for name, field in ca_param:
        if not name.startswith("_") and name in data:
            setattr(ca_param, name, data[name])
    try:
        ca_param.validate()
        ca_param.save()
        return {'state': 'OK'}, 200
    except BaseException as error:
        return {'error': 'CA param not valid', 'exception': error.__repr__()}, 404


@API.route("/ca/param/", "show ca param", method='GET', defaults={'param': None}, args=[
    {"name": "param", "type": "str", "mandatory": False}], level=API.USER)
@API.route("/ca/param/<param>", "show ca param [param]", method='GET', args=[
    {"name": "param", "type": "str", "mandatory": False}], level=API.USER)
@multi_auth.login_required
def get_caparam(param):
    print(param)
    ca_param = CAParameter.get()
    if param and hasattr(ca_param, param):
        the_return = {param: getattr(ca_param, param)}
    else:
        the_return = ca_param.to_struct()
    return the_return, 200
