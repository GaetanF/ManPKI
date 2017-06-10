"""
    manpki.api.ca
    ~~~~~~~~~~~~~

    CA part API.
    Accessible by /v1.0/api/ca url

    :copyright: (c) 2017 by Gaëtan FEREZ.
    :license: BSD, see LICENSE for more details.
"""
from flask import json, request

from manpki.tools import SSL, API, multi_auth
from manpki.logger import log
from manpki.db import CAParameter


@API.route("/ca", "show ca", method='GET', level=API.USER)
@multi_auth.login_required
def show_ca():
    """Show CA Information

    :shell: show ca
    :context: None
    :return: ca information
    """
    if SSL.check_ca_exist():
        ca = {'ca': SSL.display_cert(SSL.get_ca())}
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
    """Create a CA

    :param: force if present force the creation of the ca even if already exist

    :shell: create
    :context: ca

    :return: json info about the new ca
    """
    if not SSL.check_ca_exist():
        SSL.create_ca()
        if SSL.check_ca_exist():
            code = 200
            ca = SSL.display_cert(SSL.get_ca())
            message = {'message': 'ca created', 'ca': ca}
        else:
            code = 404
            message = {'error': 'unable to create the ca'}
    else:
        log.info("CA already exist")
        data = request.get_json(silent=True)
        if data and 'force' in data and data['force']:
            if SSL.delete_ca():
                toto = SSL.create_ca(force=data['force'])
                if SSL.check_ca_exist():
                    ca = SSL.display_cert(SSL.get_ca())
                    message = {'message': 'ca created with force', 'ca': ca}
                    code = 200
                else:
                    code = 404
                    message = {'error': 'unable to create the ca'}
            else:
                code = 404
                message = {'error': 'unable to create the ca'}
        else:
            code = 404
            message = {'error': 'CA already exist'}
    return message, code


@API.route("/ca/param", "set", method='POST', level=API.ADMIN, context="ca", args=[
    {"name": "basecn", "type": "str", "mandatory": False},
    {"name": "email", "type": "Mail", "mandatory": False},
    {"name": "keysize", "type": "int", "mandatory": False},
    {"name": "digest", "type": "str", "mandatory": False},
    {"name": "isfinal", "type": "bool", "mandatory": False},
    {"name": "name", "type": "str", "mandatory": False},
    {"name": "typeca", "type": "str", "mandatory": False},
    {"name": "validity", "type": "int", "mandatory": False},

])
@multi_auth.login_required
def set_ca():
    """Set parameter to the CA

    :return: boolean if parameter are correctly set
    """
    data = request.get_json(silent=True)
    log.info('Parameter : ' + json.dumps(data))
    keys = list(data.keys())
    keys.sort()
    if set(keys) <= {"basecn", "digest", "email", "isfinal", "keysize", "name", "typeca", "validity"}:
        ca_param = CAParameter.get()
        for elt in ca_param:
            name = elt[0]
            if not name.startswith("_") and name in data:
                setattr(ca_param, name, data[name])
        try:
            ca_param.validate()
            ca_param.save()
            return {'state': 'OK'}, 200
        except BaseException as error:
            return {'error': 'CA param not valid', 'exception': error.__repr__()}, 404
    else:
        return {'error': 'CA param not valid'}, 404


@API.route("/ca/param/", "show ca param", method='GET', defaults={'param': None}, args=[
    {"name": "param", "type": "str", "mandatory": False}], level=API.USER)
@API.route("/ca/param/<param>", "show ca param [param]", method='GET', args=[
    {"name": "param", "type": "str", "mandatory": False}], level=API.USER)
@multi_auth.login_required
def get_caparam(param):
    """Get specifed or all parameter of the CA

    :return: json info about parameters of the ca
    """
    ca_param = CAParameter.get()
    if param and hasattr(ca_param, param):
        the_return = {param: getattr(ca_param, param)}
    else:
        the_return = ca_param.to_struct()
    return the_return, 200


@API.route("/ca/register", None, method='POST', args=[
    {"name": "digest", "type": "str", "mandatory": True},
    {"name": "cert", "type": "str", "mandatory": True},
], level=API.ADMIN)
@multi_auth.login_required
def register_subca(digest, cert):
    log.info(digest)
    log.info(cert)
    # @TODO create register subca to parentca function
    pass


@API.route("/ca", "delete ca", method='DELETE', level=API.ADMIN)
@multi_auth.login_required
def delete_ca():
    if SSL.delete_ca():
        return {'ca': 'deleted'}, 200
    else:
        return {'ca': 'error with deletion'}, 404