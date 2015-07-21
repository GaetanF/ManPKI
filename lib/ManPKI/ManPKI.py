from ShShell import ShShell
from Tools import EventManager


class ManPKI:

    debug = False

    def __init__(self):
        """ Initialisation """
        EventManager.addEvent(new_cert=[])
        EventManager.addEvent(update_cert=[])
        EventManager.addEvent(delete_cert=[])
        EventManager.addEvent(new_ca=[])
        EventManager.addEvent(update_ca=[])

    def shell(self):
        ShShell().cmdloop()
