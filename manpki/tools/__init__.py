from flask import Response, jsonify
from jose import jws
from functools import wraps
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth

from manpki.tools.api import *
from manpki.tools.ssl import *
from manpki.tools.user import *

allowed_paths = ["/ping", "/login", "/logout"]
basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth('ManPKI')
multi_auth = MultiAuth(basic_auth, token_auth)


def isint(s):
    return all(map(str.isdigit, s))


def isfloat(s):
    return "." in s and isint(s.replace(".", ""))


def generate_sha256_string():
    return hashlib.sha256(os.urandom(24)).hexdigest()


def error_response():
    return {"error": "Access denied"}, 403


def get_current_user_role():
    if 'username' in session:
        return session['username'].get_roles()
    else:
        return 'anonymous'


def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if get_current_user_role() not in roles:
                return error_response()
            return f(*args, **kwargs)

        return wrapped

    return wrapper


class ManPKIFlaskResponse(Response):
    @classmethod
    def force_type(cls, rv, environ=None):
        if environ['PATH_INFO'] in allowed_paths:
            signed = rv
        else:
            signed = jws.sign(rv, session['secretjose'], algorithm='HS256')
        return super(ManPKIFlaskResponse, cls).force_type(jsonify(signed), environ)
