import flask.json
from flask import json, request
from tinydb import where
from manpki.tools import SSL, API, multi_auth
from manpki.logger import log
from manpki.db import KeyUsage, ExtendedKeyUsage, ExtensionModel


@API.route("/extension/", "show extension", defaults={'oid': None}, method='GET', args=[
    {"name": "oid", "type": "str", "mandatory": False}], level=API.USER)
@API.route("/extension/<oid>", "show extension [param]", method='GET', args=[
    {"name": "oid", "type": "str", "mandatory": False}], level=API.USER)
def show_extension(oid):
    if oid:
        log.info('Search oid : ' + oid)
        extension = ExtensionModel.get(where('oid') == oid)
        if extension:
            message = {'extension': extension.__repr__()}
            code = 200
        else:
            message = {'error': 'notexist', 'oid': oid}
            code = 404
    else:
        list = ExtensionModel.all()
        finalList = []
        for l in list:
            finalList.append(l.__repr__())
        message = {'extension': finalList}
        code = 200

    return message, code


@API.route("/extension/<oid>", "set extension [param] [param=value]", method='POST', args=[
    {"name": "oid", "type": "str", "mandatory": False}
], level=API.USER, context="extension")
@multi_auth.login_required
def set_extension(oid):
    extension = ExtensionModel.get(where('oid') == oid)
    if extension:
        log.info('Update extension : ' + oid)
        data = request.json
        for name, field in extension:
            if not name.startswith("_") and name in data:
                setattr(extension, name, data[name])
        try:
            extension.validate()
            extension.save()
            message = {'oid': oid, 'message': 'updated'}
            code = 200
        except:
            message = {'error': 'cannotupdate', 'oid': oid}
            code = 404
    else:
        message = {'error': 'notexist', 'oid': oid}
        code = 404

    return message, code


@API.route("/extension/<oid>", "add extension [param] [param=value]", method='PUT', args=[
    {"name": "oid", "type": "str", "mandatory": False}
], level=API.USER, context="extension")
@multi_auth.login_required
def add_extension(oid):
    log.info('Add new extension : ' + oid)
    try:
        ExtensionModel.get(where('oid') == oid)
        message = {'error': 'alreadyexist', 'oid': oid}
        code = 404
    except:
        data = request.get_json(silent=True)
        log.info('Parameter : ' + json.dumps(data))
        if 'type' in data and data['type'] in ('extended', 'keyusage'):
            extension = ExtensionModel()
            for name, field in extension:
                if not name.startswith("_") and name in data:
                    setattr(extension, name, data[name])
            extension.oid = oid
            extension.type = data['type']
            try:
                extension.validate()
                id = extension.insert()
                log.info('New extension add id : ' + id.__str__() + ' oid : ' + oid)
                message = {'message': 'ok', 'oid': oid}
                code = 200
            except Exception as e:
                message = {'error': 'unable to add new extension', 'message': e.__repr__(), 'oid': oid}
                code = 404
        else:
            message = {'error': 'invalidtype', 'oid': oid}
            code = 500

    return message, code


@API.route("/extension/<oid>", "delete extension [param]", method='DELETE', args=[
    {"name": "oid", "type": "str", "mandatory": False}], level=API.USER, context="extension")
@multi_auth.login_required
def delete_extension(oid):
    log.info('Delete extension : ' + oid)
    try:
        extension = ExtensionModel.get(where('oid') == oid)
        if not extension.default:
            extension.delete()
            message = {'message': 'ok', 'oid': oid}
            code = 200
        else:
            message = {'error': 'defaultextension', 'oid': oid}
            code = 404
    except Exception as e:
        message = {'error': 'notexist', 'message': e.__repr__(), 'oid': oid}
        code = 404

    return message, code
