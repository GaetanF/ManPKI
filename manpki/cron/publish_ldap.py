__author__ = 'ferezgaetan'

from command import Mailer, LDAP, Config

if "schedule" in Config().config.get("ldap", "mode"):
    state = LDAP().publish()
    if len(Config().config.get("ldap", "email")) > 0:
        mail = Mailer()
        mail.to(Config().config.get("ldap", "email"))
        mail.subject("LDAP Publishing")
        if state:
            text = "LDAP Publish OK"
            text += "\n%d certificate(s) added" % state[0]
            text += "\n%d certificate(s) updated" % state[1]
            text += "\n%d certificate(s) removed" % state[2]
            mail.send(text)
        else:
            mail.send("LDAP Publishing requirements not respected")
