import pkgutil
import sys

from flask import session

from manpki.tools.user import User
from manpki.logger import log
from manpki.config import API_VERSION


def load_api_modules():
    for p in pkgutil.iter_modules():
        if "manpki" in p[1] and "manpkicli" not in p[1] and p[1] not in sys.modules.keys():
            log.info(p)
            if hasattr(__import__(p[1]), "api"):
                __import__("%s.%s" % (p[1], "api"))
    log.info([x for x in sys.modules.keys() if x.startswith('manpki')])


class APIMethodArg:
    validargs = {
        "name": "str",
        "type": "str",
        "mandatory": "bool"
    }

    validtype = ["int", "str", "bool", "email"]

    def __init__(self, name, type, mandatory):
        self.name = name
        self.type = type
        self.mandatory = mandatory

    def __repr__(self):
        return "<APIMethodArg name: {}, type: {}, mandatory: {}>".format(
            self.name,
            self.type,
            self.mandatory
        )

    def json(self):
        return {"name": self.name, "type": self.type, "mandatory": self.mandatory}

    @staticmethod
    def build_valid_arg(dictarg):
        tmparg = {}
        for karg, kval in dictarg.items():
            if karg in APIMethodArg.validargs.keys() and kval.__class__.__name__ == APIMethodArg.validargs[karg]:
                if karg != 'type' or kval in APIMethodArg.validtype:
                    tmparg.update({karg: kval})
        thearg = None
        if len(tmparg.keys()) == 3:
            thearg = APIMethodArg(name=tmparg['name'], type=tmparg['type'], mandatory=tmparg['mandatory'])
        return thearg

    @staticmethod
    def is_valid_arg(dictarg):
        thearg = APIMethodArg.build_valid_arg(dictarg)
        if thearg:
            return True
        else:
            return False


class APIRoute:
    validcmd = {
        "command": "str",
        "url": "str",
        "method": "str",
        "level": "int",
        "endpoint": "function",
        "context": "str",
        "args": "list",
        "defaults": "dict"
    }

    def __init__(self, url='', command='', endpoint=None, **options):
        self.endpoint = endpoint
        self.package = None
        if endpoint:
            self.package = endpoint.__module__
        self.command = command
        self.url = url
        self.method = options.pop('method', None)
        self.level = options.pop("level", None)
        self.context = options.pop("context", None)
        self.args = options.pop("args", None)
        self.defaults = options.pop("defaults", None)

    def build_from_api(self, apiDict):
        self.endpoint = apiDict['endpoint']
        self.package = self.endpoint.__module__
        self.method = apiDict['method']
        self.command = apiDict['command']
        self.url = apiDict['url']
        self.level = apiDict['level']
        self.context = apiDict['context']
        self.args = apiDict['args']
        self.defaults = apiDict['defaults']

    def get_endpoint(self):
        return "%s.%s" % (self.package, self.method.__name__)

    @staticmethod
    def build_valid_route(routedict):
        tmpdict = {}
        for key, value in routedict.items():
            if key in APIRoute.validcmd.keys() and (
                            value.__class__.__name__ == APIRoute.validcmd[
                            key] or value.__class__.__name__ == 'NoneType'):
                tmpvalue = value
                if value.__class__.__name__ == "list" and key == "args":
                    tmpvalue = []
                    for arg in value:
                        if APIMethodArg.is_valid_arg(arg):
                            tmpvalue.append(APIMethodArg.build_valid_arg(arg))
                tmpdict.update({key: tmpvalue})
        defaults = {}
        if "defaults" in tmpdict.keys():
            if tmpdict['args'] and tmpdict['defaults']:
                for args in tmpdict['args']:
                    if args.name in tmpdict['defaults'].keys():
                        defaults.update({args.name: routedict['defaults'][args.name]})
            del tmpdict['defaults']
        theroute = None
        if len(tmpdict.keys()) == 7:
            theroute = APIRoute(url=tmpdict['url'],
                                method=tmpdict['method'],
                                command=tmpdict['command'],
                                endpoint=tmpdict['endpoint'],
                                level=tmpdict['level'],
                                context=tmpdict['context'],
                                args=tmpdict['args'],
                                defaults=defaults)
        return theroute

    @staticmethod
    def is_valid_route(routedict):
        theroute = APIRoute.build_valid_route(routedict)
        if theroute:
            return True
        else:
            return False

    def __repr__(self):
        leveler = "ANONYMOUS"
        if self.level == 1:
            leveler = "USER"
        elif self.level == 100:
            leveler = "CA"
        elif self.level == 255:
            leveler = "ADMIN"

        mask = "<APIRoute endpoint: {}, package: {}, command: {}, context: {}, level: {}, defaults: {}, args: {}>"
        return mask.format(
            self.endpoint.__name__,
            self.package,
            self.command,
            self.context,
            leveler,
            self.defaults,
            self.args
        )

    def json(self):
        args = []
        if self.args:
            for arg in self.args:
                args.append(arg.json())
        return {
            "command": self.command,
            "url": self.url,
            "method": self.method,
            # "level": self.level,
            "endpoint": self.package + "." + self.endpoint.__name__,
            "context": self.context,
            "args": args
        }

    def is_authorized(self):
        if session['username']:
            user = User(username=session['username'])
            roles = user.get_roles()
        else:
            roles = ['anonymous']

        userlevel = max([API.groups[x] for x in roles])
        if self.level <= userlevel:
            return True
        return False


class API:
    routes = []

    ADMIN = 255
    USER = 1
    CA = 150
    RA = 100

    groups = {'admin': ADMIN, 'ca': CA, 'ra': RA, 'user': USER, 'anonymous': 0}

    @staticmethod
    def route(url, command, method='GET', level=USER, defaults=None, context=None, args=None):
        def decorator(f):
            if url and command:
                api_dict = {
                    "command": command,
                    "url": "/" + API_VERSION + url,
                    "defaults": defaults,
                    "method": method,
                    "level": level,
                    "endpoint": f,
                    "context": context,
                    "args": args
                }
                if APIRoute.is_valid_route(api_dict):
                    route = APIRoute.build_valid_route(api_dict)
                    API.add_route(route)
            return f

        return decorator

    @staticmethod
    def build_routes(app):
        for route in API.routes:
            log.info(route)
            app.add_url_rule(
                rule=route.url,
                endpoint=route.endpoint.__name__,
                view_func=route.endpoint,
                methods=[route.method],
                defaults=route.defaults
            )

    @staticmethod
    def add_route(route):
        if isinstance(route, APIRoute):
            API.routes.append(route)
