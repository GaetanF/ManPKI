import os
import traceback
import flask_restful
import werkzeug.serving

from gevent.pywsgi import WSGIServer
from flask import Flask, url_for, request, session, g

from gevent import socket
from jose import jwt

from manpki.tools import API, WebSSL, ManPKIFlaskResponse, User, multi_auth, token_auth, basic_auth, load_api_modules
from manpki.config import WEB_SECRET, TOKEN_SECRET
from manpki.db import ServerParameter
from manpki.logger import log
from manpki.i18n import *
from manpki.templates import *

import manpki.api

__author__ = 'ferezgaetan'

load_api_modules()

app = Flask(__name__)
app.response_class = ManPKIFlaskResponse
app.debug = False
app.secret_key = WEB_SECRET
# api = flask_restful.Api(app)

API.build_routes(app)

for rule in app.url_map.iter_rules():
    log.info(rule)


@app.errorhandler(500)
def page_internal_server_error(error):
    log.error("Internal Server Error : %s" % error)
    return {'error': 'Internal Server Error'}, 500


@app.errorhandler(404)
def page_not_found(error):
    log.error("Page not found : %s" % error)
    return {'error': 'Page not found'}, 404


@app.errorhandler(Exception)
def unhandled_exception(e):
    traceback.print_exc()
    log.error('Unhandled Exception: %s' % e)
    return {'error': 'Unhandled Exception'}, 500


@token_auth.verify_token
def verify_token(token):
    try:
        data = jwt.decode(token, TOKEN_SECRET, algorithms='HS256')
    except Exception as e:
        log.info('error decode jwt')
        log.info(e)
        return False
    if 'username' in data:
        session['username'] = data['username']
        g.user = User(username=session['username'])
        return True
    return False


@basic_auth.verify_password
def verify_password(username, password):
    user = User(username=username)
    serverparam = ServerParameter.get()
    if user.authenticate(password) or serverparam.host == 'socket':
        g.user = user
        session['username'] = username
        return True
    return False


# @app.route('/router')
# @multi_auth.login_required
# def list_routes():
#     import urllib
#     routes = []
#     for rule in app.url_map.iter_rules():
#
#         options = {}
#         for arg in rule.arguments:
#             options[arg] = "[{0}]".format(arg)
#
#         methods = (','.join(rule.methods)).split(',')
#         if 'OPTIONS' in methods:
#             methods.remove('OPTIONS')
#         if 'HEAD' in methods:
#             methods.remove('HEAD')
#         methods = ','.join(methods)
#         url = url_for(rule.endpoint, **options)
#         routes.append({'endpoint': rule.endpoint, 'methods': methods, 'url': urllib.parse.unquote(url)})
#
#     return {'routes': tuple(routes)}, 200
#
#
# @app.route('/commands')
# @multi_auth.login_required
# def list_commands():
#     routes, statuscode = list_routes()
#     cmds = []
#     for rule in API.rulescli:
#         if API().is_authorized(rule):
#             findroute = None
#             for route in routes['routes']:
#                 if route['endpoint'] == rule.get_endpoint():
#                     findroute = {'methods': route['methods'], 'url': route['url']}
#
#             if findroute:
#                 cmds.append({
#                     "cmd": rule.path,
#                     "context": rule.context,
#                     "methods": findroute['methods'],
#                     "url": findroute['url']
#                 })
#
#     return {'commands': tuple(cmds)}, 200


@app.route('/discovery')
@multi_auth.login_required
def get_api_discovery():
    discoapi = []
    for rule in API.routes:
        if rule.is_authorized():
            discoapi.append(rule.json())
    return {'api': discoapi}, 200


@app.route("/locale/<lang>")
def get_locales(lang):
    locales = None
    if lang_is_defined(lang):
        locales = get_json_lang(lang)
    return {'lang': lang, 'locales': locales}, 200


@app.route("/render")
def get_render():
    render = ""
    if render_is_defined():
        render = get_content_render()
    return {'render': render}, 200


@app.route('/ping')
def ping():
    if 'secretjose' not in session:
        session['secretjose'] = tools.generate_sha256_string()
    return {'message': 'pong', 'hostname': os.uname()[1], 'secret': session['secretjose']}, 200


@app.route('/info')
@multi_auth.login_required
def info():
    return {
               'message': 'info',
               'hostname': os.uname()[1],
               'secret': session['secretjose'],
               'username': g.user.get_username(),
               'roles': g.user.get_roles()
           }, 200


@app.route('/login')
@multi_auth.login_required
def login():
    token = g.user.generate_auth_token()
    return {'message': 'login', 'hostname': os.uname()[1], 'token': token}, 200


@app.route('/logout')
@multi_auth.login_required
def logout():
    session.pop('secretjose', None)
    return {'message': 'logout', 'hostname': os.uname()[1]}, 200


@werkzeug.serving.run_with_reloader
def start():
    log.info("Prepare Web Server")
    serverparam = ServerParameter.get()
    host = serverparam.host
    port = int(serverparam.port)
    try:
        if host == 'socket':
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sockname = '/tmp/manpki.sock'
            if os.path.exists(sockname):
                os.remove(sockname)
            listener.bind(sockname)
            listener.listen(1)
            ssl = {}
        else:
            listener = (host, port)
            if os.path.exists(serverparam.sslcert) and os.path.exists(serverparam.sslkey):
                cert_file = serverparam.sslcert
                pkey_file = serverparam.sslkey
            else:
                cert_file, pkey_file = WebSSL().generate_adhoc_ssl_context()
            ssl = {
                'certfile': cert_file,
                'keyfile': pkey_file,
                'ciphers': 'RC4',
            }
        log.info("Start server")
        WSGIServer(listener, app, **ssl).serve_forever()
    except Exception as err:
        log.critical(err)
