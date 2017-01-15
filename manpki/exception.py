class ManPKIException(Exception):
    """ A base class for exceptions used by ManPKI. """
    code = None
    message = None

    def __init__(self, message=None, response=None):
        Exception.__init__(self)
        if message is not None:
            self.description = message
        self.response = response

    def __str__(self):
        code = self.code if self.code is not None else '???'
        return '%s %s: %s' % (code, self.name, self.message)

    def __repr__(self):
        code = self.code if self.code is not None else '???'
        return "<%s '%s: %s'>" % (self.__class__.__name__, code, self.name)


class ShellException(Exception):
    pass


class ProtocolException(ShellException):
    code = 201
    message = (
        "Protocol exception"
    )


class CopyException(ShellException):
    code = 202
    message = (
        "Error during copy"
    )
