from tinydb_jsonorm import Database
from tinydb_jsonorm import TinyJsonModel
from tinydb_jsonorm import fields
from tinydb import where
from jsonmodels import models
from manpki.logger import log
from manpki.config import ManPKIObject

dbj = Database(ManPKIObject.dbdir + '/manpki.json')


class ParamModel(TinyJsonModel):
    __tablename__ = "parameter"
    object = None

    def __init__(self, *args, **kwargs):
        super(ParamModel, self).__init__(*args, **kwargs)

    @classmethod
    def get(cls, cond=None, eid=None, cuid=None):
        cls.__tablename__ = ParamModel.__tablename__
        return super(ParamModel, cls).get(where('object') == cls.object)

    class Meta:
        database = dbj


class ServerParameter(ParamModel):
    __tablename__ = "parameter"
    object = 'server'

    sslcert = fields.StringField(required=True)
    sslkey = fields.StringField(required=True)
    host = fields.StringField(required=True)
    port = fields.IntField(required=True)

    def __init__(self, *args, **kwargs):
        super(ServerParameter, self).__init__(*args, **kwargs)


class CAParameter(ParamModel):
    __tablename__ = "parameter"
    object = 'ca'

    email = fields.StringField(required=True)
    validity = fields.IntField(required=True)
    keysize = fields.IntField(required=True)
    basecn = fields.StringField(required=True)
    name = fields.StringField(required=True)
    digest = fields.StringField(required=True)
    typeca = fields.StringField(required=True)
    isfinal = fields.BoolField(required=True)

    def __init__(self, *args, **kwargs):
        super(CAParameter, self).__init__(*args, **kwargs)


class CertParameter(ParamModel):
    __tablename__ = "parameter"
    object = 'cert'

    validity = fields.IntField(required=True)
    keysize = fields.IntField(required=True)
    digest = fields.StringField(required=True)

    def __init__(self, *args, **kwargs):
        super(CertParameter, self).__init__(*args, **kwargs)


class CrlParameter(ParamModel):
    __tablename__ = "parameter"
    object = 'crl'

    digest = fields.StringField(required=True)
    validity = fields.IntField(required=True)
    enable = fields.BoolField(required=True)

    def __init__(self, *args, **kwargs):
        super(CrlParameter, self).__init__(*args, **kwargs)


class OcspParameter(ParamModel):
    __tablename__ = "parameter"
    object = 'ocsp'

    enable = fields.BoolField(required=True)
    uri = fields.StringField(required=True)

    def __init__(self, *args, **kwargs):
        super(OcspParameter, self).__init__(*args, **kwargs)


class LdapParameter(ParamModel):
    __tablename__ = "parameter"
    object = 'ldap'

    enable = fields.BoolField(required=True)
    host = fields.StringField(required=True)
    dn = fields.StringField(required=True)
    password = fields.StringField(required=True)
    mode = fields.StringField(required=True)
    schedule = fields.StringField(required=True)

    def __init__(self, *args, **kwargs):
        super(LdapParameter, self).__init__(*args, **kwargs)


class MailParameter(ParamModel):
    __tablename__ = "parameter"
    object = 'mail'

    enable = fields.BoolField(required=True)
    host = fields.StringField(required=True)
    sender = fields.StringField(required=True)

    def __init__(self, *args, **kwargs):
        super(MailParameter, self).__init__(*args, **kwargs)


class ExtensionModel(TinyJsonModel):
    __tablename__ = "extension"
    type = fields.StringField(required=True)
    name = fields.StringField(required=True)
    oid = fields.StringField(required=True)
    _default = fields.BoolField(required=False)

    def __init__(self, *args, **kwargs):
        self._default = False
        super(ExtensionModel, self).__init__(*args, **kwargs)

    @classmethod
    def get(cls, cond=None, eid=None, cuid=None):
        cls.__tablename__ = ExtensionModel.__tablename__
        if isinstance(cls.type, str):
            return super(ExtensionModel, cls).get(where('type') == cls.type)
        else:
            return super(ExtensionModel, cls).get(cond=cond)

    @classmethod
    def search(cls, cond=None, eid=None, cuid=None):
        cls.__tablename__ = ExtensionModel.__tablename__
        table = cls.Meta.database.table(cls.__tablename__)
        if isinstance(cls.type, str):
            return table.search(where('type') == cls.type)
        else:
            return table.search(cond=cond)

    @classmethod
    def all(cls):
        cls.__tablename__ = ExtensionModel.__tablename__
        return super(ExtensionModel, cls).all()

    def save(self):
        if self._default:
            log.info("Can't edit or erase default extension")
            raise ValueError("Can't edit or erase default extension")
        else:
            return super(ExtensionModel, self).save()

    def __repr__(self):
        return {'type': self.type, 'name': self.name, 'oid': self.oid, 'default': self._default}

    @property
    def default(self):
        return self._default

    class Meta:
        database = dbj


class KeyUsage(ExtensionModel):
    __tablename__ = "extension"
    type = 'keyusage'


class ExtendedKeyUsage(ExtensionModel):
    __tablename__ = "extension"
    type = 'extended'


class Profile(TinyJsonModel):
    __tablename__ = "profile"

    name = fields.StringField(required=True)
    keyusage = fields.StringField(required=False)
    extended = fields.StringField(required=False)
    ldap = fields.StringField(required=False)
    _default = fields.BoolField(required=False)

    def __init__(self, *args, **kwargs):
        self._default = False
        super(Profile, self).__init__(*args, **kwargs)

    def save(self):
        if self._default:
            log.info("Can't edit or erase default profile")
            raise ValueError("Can't edit or erase default value")
        else:
            return super(Profile, self).save()

    def __repr__(self):
        return {'name': self.name, 'keyusage': self.keyusage,
                'extended': self.keyusage, 'ldap': self.ldap, 'default': self._default}

    @property
    def default(self):
        return self._default

    class Meta:
        database = dbj


class Roles(models.Base):
    role = fields.StringField(required=True)

    def __repr__(self):
        return self.role


class UserDB(TinyJsonModel):
    __tablename__ = "user"

    username = fields.StringField(required=True)
    roles = fields.ListField([Roles])

    def __init__(self, *args, **kwargs):
        super(UserDB, self).__init__(*args, **kwargs)

    def __repr__(self):
        return {'name': self.username, 'roles': self.roles}

    class Meta:
        database = dbj
