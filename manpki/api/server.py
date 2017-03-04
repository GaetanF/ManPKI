import os
from flask import json, request
from manpki.tools import SSL, API, multi_auth, ConfigObject
from manpki.config import write
from manpki.logger import log
from manpki.tools.reloader import reload


@API.route("/server/restart", "reload server", method='GET', context="server", level=API.ADMIN)
def restart_server():
    time = 5
    reload(time)
    return {'message': 'reload in ' + str(time) + ' second'}, 200


@API.route("/server/set", "set [param=value]", method='POST', args=[
    {"name": "host", "type": "str", "mandatory": False},
    {"name": "port", "type": "int", "mandatory": False},
    {"name": "cert", "type": "str", "mandatory": False},
    {"name": "key", "type": "str", "mandatory": False},
], context="server", level=API.ADMIN)
def set_param_server():
    data = request.get_json(silent=True)
    if "host" in data and data["host"] == "socket":
        ConfigObject.set("server", "host", "socket")
        ConfigObject.set("server", "port", "0")
        ConfigObject.set("server", "cert", "")
        ConfigObject.set("server", "key", "")
    else:
        for param in data.keys():
            if param in ("host", "port", "cert", "key"):
                if param in ("cert", "key"):
                    obj = ""
                    if SSL.check_cert_exist(data[param]):
                        obj = SSL.get_cert_path(data[param])
                        ConfigObject.set("server", "key", SSL.get_cert_privatekey_path(data[param]))
                    elif os.path.exists(data[param]):
                        obj = data[param]
                    ConfigObject.set("server", param, obj)
                else:
                    ConfigObject.set("server", param, data[param])
    write()
    log.info('Parameter : ' + json.dumps(data))
    log.info('here')
    return {'message': 'ok'}, 200


@API.route("/server", "show server", method='GET', level=API.USER)
@multi_auth.login_required
def show_server():
    info = ConfigObject.items("server")
    log.info(info)
    final_list = {}
    for l in info:
        final_list[l[0]] = l[1]
    message = {'server': final_list}
    return message, 200
