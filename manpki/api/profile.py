from tinydb import where
from flask import json, request
from manpki.tools import API, multi_auth
from manpki.logger import log
from manpki.db import Profile


@API.route("/profile/", "show profile", defaults={'profileid': None}, method='GET', args=[
    {"name": "profileid", "type": "str", "mandatory": False}], level=API.USER)
@API.route("/profile/<profileid>", "show profile [param]", method='GET', args=[
    {"name": "profileid", "type": "str", "mandatory": False}], level=API.USER)
def show_profile(profileid):
    if profileid:
        profile = Profile.get(where('name') == profileid)
        if profile:
            log.info('Show profile : ' + profileid)
            message = {'profile': profile.__repr__()}
            code = 200
        else:
            message = {'error': 'notexist', 'oid': profileid}
            code = 404
    else:
        log.info("Show all profiles")
        all_profile = Profile.all()
        final_list = []
        for l in all_profile:
            final_list.append(l.__repr__())
        message = {'profile': final_list}
        code = 200

    return message, code


@API.route("/profile/<profileid>", "set profile [param] [param=value]", method='POST', args=[
    {"name": "profileid", "type": "str", "mandatory": False}
], level=API.USER, context="profile")
@multi_auth.login_required
def set_profile(profileid):
    profile = Profile.get(where('name') == profileid)
    if profile:
        log.info('Update profile : ' + profileid)
        data = request.json
        for name, field in profile:
            if not name.startswith("_") and name in data:
                setattr(profile, name, data[name])
        try:
            profile.validate()
            profile.save()
            message = {'profile': profileid, 'message': 'created'}
            code = 200
        except BaseException as error:
            message = {'error': 'cannotcreate', 'profile': profileid, 'exception': error.__repr__()}
            code = 404
    else:
        message = {'error': 'notexist', 'profile': profileid}
        code = 404

    return message, code


@API.route("/profile/<profileid>", "add profile [param] [param=value]", method='PUT', args=[
    {"name": "profileid", "type": "str", "mandatory": False}
], level=API.USER, context="profile")
@multi_auth.login_required
def add_profile(profileid):
    log.info('Add new profile : ' + profileid)
    try:
        Profile.get(where('name') == profileid)
        message = {'error': 'alreadyexist', 'profile': profileid}
        code = 404
    except BaseException:
        profile = Profile()
        log.info('Parameter : ' + json.dumps(request.json))
        data = request.json
        for name, field in profile:
            if not name.startswith("_") and name in data:
                setattr(profile, name, data[name])
        profile.name = profileid
        try:
            profile.validate()
            id = profile.insert()
            log.info('New profile add id : ' + id.__str__() + ' name : ' + profileid)
            message = {'message': 'ok', 'profile': profileid}
            code = 200
        except Exception as e:
            message = {'error': 'unable to add new profile', 'message': e.__repr__(), 'profile': profileid}
            code = 404

    return message, code


@API.route("/profile/<oid>", "delete profile [param]", method='DELETE', context="profile", args=[
    {"name": "profileid", "type": "str", "mandatory": False}], level=API.USER)
@multi_auth.login_required
def delete_profile(profileid):
    log.info('Delete profile : ' + profileid)
    try:
        profile = Profile.get(where('name') == profileid)
        if not profile.default:
            profile.delete()
            message = {'message': 'ok', 'profile': profileid}
            code = 200
        else:
            message = {'error': 'defaultprofile', 'profile': profileid}
            code = 404
    except Exception as e:
        message = {'error': 'notexist', 'message': e.__repr__(), 'profile': profileid}
        code = 404

    return message, code
