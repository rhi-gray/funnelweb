#!/funnelweb/python-env/bin/python
# -*- mode: python; -*-

# We're using web.py now.
# It's got a nicer API and whatnot, and it's also simpler.
import web
from wsgilog import WsgiLog

url_map = (
    "/", "Root",
    "/usage", "usage.Usage",
    "/admin", "admin_mod.Admin",
    "/soft_(un)?lock", "lockpage.SoftLock",

    "/adduser", "admin_mod.AddUser",
    "/adddevice", "admin_mod.AddDevice",

    "/tradequota", "admin_mod.TradeQuota",
    )

# Password verification.
import auth
def authenticate(domain, user, passwd):
  return auth.authenticate(user, passwd)

class logger(WsgiLog):
  def __init__(self, application):
    WsgiLog.__init__(self,
                     application,
                     logformat = "funnelwebsite: %(message)s",
                     tofile = True,
                     toprint = True,
                     file = "/var/log/fwebsite.log")

class Root(object):
    def GET(self):
        site = web.template.render("templates/", base="base")
        return site.index()

if __name__ == "__main__":
    app = web.application(url_map, globals())
    app.run(logger)

