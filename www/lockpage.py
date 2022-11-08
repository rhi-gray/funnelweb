#!/funnelweb/python-env/bin/python

import web
import locks
import devices
import configuration

class SoftLock(object):
    def __init__(self):
        self.render = web.template.render("templates/",
                                          base="base")
        self.user = None

        self.msg_title = ""
        self.msg_content = ""

    def GET(self, *args):
        self.user = self.get_user()
        if self.user is None:
            return self.render.message(
                title="Unknown user",
                content="Couldn't find the user with device IP <span style=\"font-family: mono\">{}</span>".format(web.ctx.ip),
                redir_time="15",
                redir_dest="/usage")

        else:
            # Varies based on the path this was called from.
            self.perform_action()
            return self.render.message(
                title=self.msg_title,
                content=self.msg_content,
                redir_time="15",
                redir_dest="/usage")

    def get_user(self):
        IP = web.ctx.ip
        real_name = devices.canonical_name(IP)
        return configuration.get_device_owner(real_name) or None

    def perform_action(self):
        mode = web.ctx.path
        if mode == "/soft_lock":
            # Perform a soft lock.
            try:
                locks.do_soft_lock(self.user)
                self.msg_title = "Soft-locked"
                self.msg_content = "<h3>You have been soft-locked.</h3>"
            except:
                self.msg_title = "Error soft-locking"
                self.msg_content = "<h3>Failed to soft-lock {}</h3>".format(self.user)

        elif mode == "/soft_unlock":
            # Unlock us.
            try:
                locks.do_soft_unlock(self.user)
                self.msg_title = "Unlocked"
                self.msg_content = "<h3>You have been unlocked.</h3>"
            except:
                self.msg_title = "Error soft-unlocking"
                self.msg_content = "<h3>Failed to soft-unlock {}</h3>".format(self.user)
