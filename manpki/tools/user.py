import pam
from datetime import datetime, timedelta
from tinydb import where
from jose import jwt, exceptions

from manpki.logger import log
from manpki.db import UserDB, Roles
from manpki.config import TOKEN_SECRET


class User:
    _username = None
    _roles = []

    def __init__(self, username):
        self._username = username
        if self.exist():
            self._roles = UserDB.get(where('username') == username).roles
        else:
            self._roles = [Roles(role='anonymous')]

    def authenticate(self, password):
        p = pam.pam()
        return p.authenticate(self._username, password)

    def get_roles(self):
        return [x.role for x in self._roles]

    def get_username(self):
        return self._username

    def exist(self):
        try:
            user = UserDB.get(where('username') == self._username)
            return bool(user)
        except BaseException:
            return False

    def generate_auth_token(self, expiration=600):
        expire = datetime.utcnow() + timedelta(seconds=expiration)
        return jwt.encode({'username': self._username, 'exp': expire}, TOKEN_SECRET, algorithm='HS256')

    def __repr__(self):
        return "<User username: {}, roles: {}>".format(
            self._username,
            self.get_roles()
        )

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, TOKEN_SECRET, algorithms='HS256')
        except exceptions.ExpiredSignatureError:
            log.info('Token expired')
            return None  # valid token, but expired
        except exceptions.JWTError:
            return None  # invalid token
        user = User(username=data['username'])
        return user
