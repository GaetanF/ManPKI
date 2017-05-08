from flask import json, request
from tinydb import where
from manpki.tools import API, multi_auth
from manpki.logger import log
from manpki.db import ExtensionModel


@API.route("/extension/", "show extension", defaults={'oid': None}, method='GET', args=[
    {"name": "oid", "type": "str", "mandatory": False}], level=API.USER)
@API.route("/extension/<oid>", "show extension [param]", method='GET', args=[
    {"name": "oid", "type": "str", "mandatory": False}], level=API.USER)
def show_extension(oid):
    """Show all or specific SSL Extension

    :param: oid OID of the extension

    :shell: show extension
    :context: None
    :return: information of the extension
    """
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
        all_extension = ExtensionModel.all()
        final_list = []
        for l in all_extension:
            final_list.append(l.__repr__())
        message = {'extension': final_list}
        code = 200

    return message, code


@API.route("/extension/<oid>", "set extension [param] [param=value]", method='POST', args=[
    {"name": "oid", "type": "str", "mandatory": False}
], level=API.USER, context="extension")
@multi_auth.login_required
def set_extension(oid):
    """Set an extension

    :param: oid OID of the extension

    :shell: set extension
    :context: extension
    :return: information of the extension
    """
    extension = ExtensionModel.get(where('oid') == oid)
    if extension:
        log.info('Update extension : ' + oid)
        data = request.json
        for elt in extension:
            name = elt[0]
            if not name.startswith("_") and name in data:
                setattr(extension, name, data[name])
        try:
            extension.validate()
            extension.save()
            message = {'oid': oid, 'message': 'updated'}
            code = 200
        except BaseException as error:
            message = {'error': 'cannotupdate', 'oid': oid, 'exception': error.__repr__()}
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
    """Add a new extension

    :param: oid OID of the extension

    :shell: add extension
    :context: extension
    :return: information of the extension
    """
    log.info('Add new extension : ' + oid)
    try:
        ExtensionModel.get(where('oid') == oid)
        message = {'error': 'alreadyexist', 'oid': oid}
        code = 404
    except BaseException as error:
        data = request.get_json(silent=True)
        log.info('Parameter : ' + json.dumps(data))
        if 'type' in data and data['type'] in ('extended', 'keyusage'):
            extension = ExtensionModel()
            for elt in extension:
                name = elt[0]
                if not name.startswith("_") and name in data:
                    setattr(extension, name, data[name])
            extension.oid = oid
            extension.type = data['type']
            try:
                extension.validate()
                eid = extension.insert()
                log.info('New extension add id : ' + eid.__str__() + ' oid : ' + oid)
                message = {'message': 'ok', 'oid': oid}
                code = 200
            except Exception as e:
                message = {'error': 'unable to add new extension', 'message': e.__repr__(), 'oid': oid}
                code = 404
        else:
            message = {'error': 'invalidtype', 'oid': oid, 'exception': error.__repr__()}
            code = 500

    return message, code


@API.route("/extension/<oid>", "delete extension [param]", method='DELETE', args=[
    {"name": "oid", "type": "str", "mandatory": False}], level=API.USER, context="extension")
@multi_auth.login_required
def delete_extension(oid):
    """Delete an extension

    :param: oid OID of the extension

    :shell: delete extension
    :context: extension
    :return: message about the deletion
    """
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
