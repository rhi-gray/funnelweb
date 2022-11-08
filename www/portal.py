#!/funnelweb/python-env/bin/python

import cherrypy
from jinja2 import Environment, FileSystemLoader

env = Environment(loader=FileSystemLoader("templates"))

import captive

class Portal(object):
    def __init__(self):
        self.template = env.get_template("login.html")
        self.message = env.get_template("message.html")
        self.manage = env.get_template("user.html")
        
    @cherrypy.expose
    def index(self, *path):
        """ Show the login page, but store the original URL. """
        original_url = cherrypy.url()
        return self.template.render(page_title = "Login to FunnelWeb",
                                    ip = cherrypy.request.remote.ip,
                                    origin = original_url)

    @cherrypy.expose
    def funnelweb_login(self,
                        uname=None,
                        passwd=None,
                        remember_time=None, origin = ""):
        success = captive.authenticate(uname, passwd)

        # Do the right thing if we authenticated correctly.
        if success:
            captive.register_device(cherrypy.request.remote.ip)
        
        url = origin if success else "/"
        msg = ["Successful login. You will be redirected in 5 seconds...",
               "Bad username or password. Try again."][not success]

        return """ <html>
  <head>
    <meta http-equiv="refresh" content="5; URL={url}" />
  </head>
  <body>
    {msg}
  </body>
</html>""".format(url=url, msg=msg)

    @cherrypy.expose
    def funnelweb_manage(self,
               username = "", password = "",
               newpassword = "",
               device_action = ""):
        if username == "" and password == "":
            # Show the default page.
            return self.manage.render(page_title = "Update settings")
            
        if not captive.authenticate(username, password):
            return self.message.render(
                do_redir = True,
                redir_time = 5, redir_dest = "/funnelweb_manage",
                page_title = "Failed to authenticate!",
                msg_content = "Incorrect username / password!",
                )

        # Do we want to update the password?
        try:
            if newpassword != "":
                # Do the update.
                pass
            if device_action == "remove":
                # Unregister a device.
                captive.unregister_device(cherrypy.request.remote.ip)
                
            return self.message.render(
                page_title = "Success",
                msg_content = "Action performed successfully.",
                )
        except Exception as er:
            return self.message.render(
                page_title = "Error!",
                msg_content = "An error occurred while processing your request: <br /> <pre>" + str(er) + "</pre>",
                )

root = Portal()
cherrypy.tree.mount(root, "/")
cherrypy.engine.start()
cherrypy.engine.block()
