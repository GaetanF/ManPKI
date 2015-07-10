__author__ = 'ferezgaetan'
import cmd
import os
import sys
import shlex
from Tools import Config, Copy, Show
from os.path import isfile, join, splitext
import ManPKI


class ShShell(cmd.Cmd):

    headPrompt = "\033[92m" + os.uname()[1] + "\033[0m"
    footPrompt = " # "
    path = []
    dirModule = "/Users/ferezgaetan/PycharmProjects/manpki/lib/ManPKI/"
    base_dir = dirModule + "Shell"
    show_defined = False

    prompt = headPrompt + footPrompt
    manageMode = False

    def __init__(self, init_all=True):
        cmd.Cmd.__init__(self)
        if init_all:
            self.init_env_cmd()
            self.get_sub_shell()

    def init_env_cmd(self):
        if self.__class__.__bases__[0].__name__ is "Cmd" :
            self.intro  = "Welcome to the ManPKI console!"
        else:
            ShShell.path.append(self.__class__.__name__.lower()[2:])
            self.changePrompt()

    def preloop(self):
        """Initialization before prompting user for commands.
           Despite the claims in the Cmd documentaion, Cmd.preloop() is not a stub.
        """
        cmd.Cmd.preloop(self)
        self._hist    = []

    def precmd(self, line):
        self._hist += [ line.split() ]
        return line

    def changePrompt(self):
        if len(self.path)>0:
            self.prompt = self.headPrompt + " (" + ' '.join(self.path) + ")" + self.footPrompt
        else:
            self.prompt = self.headPrompt + self.footPrompt

    def get_sub_shell(self):
        dir_search = self.dirModule + self.__class__.__name__[2:]
        ShShell.dirModule = dir_search+"/"
        if os.path.isdir(dir_search):
            for name in os.listdir(dir_search):
                if name.startswith("Sh") and name.endswith(".py") and isfile(join(dir_search, name)):
                    module_name = splitext(name)[0]
                    path = ShShell.path
                    module_path = "Shell."
                    if len(path)>0:
                        module_path += '.'.join(path).title() + "." + module_name
                    else:
                        module_path += module_name
                    import_str = "from " + module_path + " import " + module_name
                    if ManPKI.ManPKI.debug:
                        print "Import sub shell from file " + name + ": " + import_str
                    exec import_str
                    modul = sys.modules[module_path]
                    if ManPKI.ManPKI.debug:
                        print "Generate do_" + module_name.lower()[2:] + " method"
                    setattr(self.__class__, 'do_' + module_name.lower()[2:], self._make_cmd(modul, module_name));
                    if ManPKI.ManPKI.debug:
                        print "Generate help_" + module_name.lower()[2:] + " method"
                    setattr(self.__class__, 'help_' + module_name.lower()[2:], self._make_help(modul, module_name));

    @staticmethod
    def _make_cmd(modul, module_name):
        def handler_cmd(self, line):
            try:
                class_inst = getattr(modul, module_name)
                instance = class_inst()
                attr = getattr(class_inst, "cmdloop")
                if callable(attr) :
                    instance.cmdloop()
            except Exception, e:
                print '*** error:', e
        return handler_cmd

    @staticmethod
    def _make_help(modul, module_name):
        def handler_help(self):
            try:
                class_inst = getattr(modul, module_name)
                attr = getattr(class_inst, "help_"+module_name.lower()[2:])
                if callable(attr):
                    attr()
            except Exception, e:
                print '*** error:', e
        return handler_help

    ## Help definitions ##
    def help_show(self):
        print "Display some information about sub modules"

    def help_exit(self):
        print "Quit the main program"

    def help_copy(self):
        print "Copy file between source and destination"
        print "tftp|ftp|ssh|http|local://[<user>[:<password>]@]<addr>:<source> tftp|ftp|ssh|local://[<user>[:<password>]@]<addr>:<destination>"

    ## Command definitions ##
    def do_exit(self, line):
        if len(ShShell.path)>0:
            ShShell.path.pop()
        return True

    def do_hist(self, line):
        """Print a list of commands that have been entered"""
        print self._hist

    def do_show(self, line):
        Show(line)

    def do_copy(self, line):
        line = shlex.split(line)
        Copy(line[0], line[1])

    def do_write(self, line):
        Config().write()


    # def completedefault(self, text, line, begidx, endidx):
    #     """
    #    Only gets here onced args have been typed in...
    #    completion of the 'command' by itself does not call this
    #    """
    #
    #     # parse out command (could be a partial command)
    #     command = line.split(' ', 1)[0]
    #
    #     # generates a list of commands...
    #     # from all methods in this class that start with 'do_'
    #     commands = [ i[3:] for i in dir(self) if i.startswith('do_') ]
    #
    #     # auto-complete the command
    #     command = [ i for i in commands if i.startswith(command) ]
    #
    #     # can not complete a partial arg if...
    #     # the command can not be found/completed
    #     if len(command) != 1:
    #         return [text]
    #
    #     # calls do_{command} method to load self.params
    #     getattr(self, 'do_' + command[0])(None)
    #     return self.params.parse(line, do=False)