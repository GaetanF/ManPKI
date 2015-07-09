__author__ = 'ferezgaetan'

from ShellException import ShellException

class CopyException(ShellException):

    def __init__(self, reason):
        ShellException.__init__(self, reason)

    def __str__(self):
        return self.reason
