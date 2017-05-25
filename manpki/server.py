import traceback

from gevent.pywsgi import WSGIServer
from flask import Flask, g

from gevent import socket
from ssl import PROTOCOL_SSLv23
import pwd

from manpki.config import WEB_SECRET, envready, get_run_directory
from manpki.tools import *
from manpki.db import ServerParameter
from manpki.i18n import *
from manpki.templates import *

import manpki.api

load_api_modules()

app = Flask(__name__)
app.response_class = ManPKIFlaskResponse
app.debug = manpki.config.DEBUG
app.secret_key = WEB_SECRET
# api = flask_restful.Api(app)

API.build_routes(app)

# for rule in app.url_map.iter_rules():
#    log.info(rule)


@app.errorhandler(500)
def page_internal_server_error(error):
    log.error("Internal Server Error : %s" % error)
    return {'error': 'Internal Server Error'}, 500


@app.errorhandler(404)
def page_not_found(error):
    log.error("Page not found : %s" % error)
    return {'error': 'Page not found'}, 404


@app.errorhandler(405)
def method_not_allowed(error):
    log.error("Method not allowed : %s" % error)
    return {'error': 'Method not allowed'}, 405


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
    server_param = ServerParameter.get()
    if server_param.host != 'socket' and user.authenticate(password) \
            or (server_param.host == 'socket' and username in [x[0] for x in pwd.getpwall()]):
        g.user = user
        session['username'] = username
        return True
    return False


@app.route('/')
def default_page():
    msg = "Welcome to the ManPKI API. Please read API documentation."
    return msg, 200


@app.route('/discovery')
@multi_auth.login_required
def get_api_discovery():
    disco_api = []
    for rule in API.routes:
        if rule.is_authorized():
            disco_api.append(rule.json())
    return {'api': disco_api}, 200


@app.route("/locale/<lang>")
def get_locales(lang):
    locales = None
    if lang_is_defined(lang):
        locales = json.loads(get_json_lang(lang))
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
        session['secretjose'] = generate_sha256_string()
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
    if 'secretjose' not in session:
        session['secretjose'] = generate_sha256_string()
    token = g.user.generate_auth_token()
    return {'message': 'login', 'hostname': os.uname()[1], 'secret': session['secretjose'], 'token': token}, 200


@app.route('/logout')
@multi_auth.login_required
def logout():
    session.pop('secretjose', None)
    return {'message': 'logout', 'hostname': os.uname()[1]}, 200


def start():
    log.debug("Prepare Web Server")
    host = ConfigObject.get("server", "host")
    port = int(ConfigObject.get("server", "port"))
    try:
        if host == 'socket':
            log.debug("Use Socket")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock_name = get_run_directory() + '/manpki.sock'
            if os.path.exists(sock_name):
                os.remove(sock_name)
            listener.bind(sock_name)
            listener.listen(1)
            ssl_ctxt = {}
        else:
            log.debug("Use Host and Port")
            listener = (host, port)
            if os.path.exists(ConfigObject.get("server", "cert")) and os.path.exists(ConfigObject.get("server", "key")):
                cert_file = ConfigObject.get("server", "cert")
                pkey_file = ConfigObject.get("server", "key")
            else:
                log.warn("Use auto-generated SSL Certificate")
                cert_file, pkey_file = WebSSL().generate_adhoc_ssl_context()
            ssl_ctxt = {
                'certfile': cert_file,
                'keyfile': pkey_file,
                'ssl_version': PROTOCOL_SSLv23
            }
        log.info("Start server on {}:{}".format(host, port))
        wsgi_server = WSGIServer(listener, app, **ssl_ctxt)
        wsgi_server.serve_forever()
    except Exception as err:
        log.critical(err)


def daemon_starter():
    if envready():
        log.debug("Envready")
        from manpki.tools.reloader import run_with_reloader
        run_with_reloader(start)
    else:
        log.critical("Cannot start ManPKID, the environnement isn't ready. Run 'manpkid -s' to setup env.")
