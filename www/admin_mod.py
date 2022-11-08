#!/funnelweb/python-env/bin/python
# -*- mode: python; -*-

import web
import base64, socket

from net_tools import get_bytes, get_usage, human_readable
import save_quota, locks, configuration, auth
import iptables, devices
from errors import *

import arrow

import logging as log
log.basicConfig(format="(www-admin)\t%(asctime)s %(message)s",
                filename="/var/log/funnelweb.log")

users = configuration.query_users()
devs = configuration.query_devices()
groups = configuration.query_groups()
users.sort(); devs.sort(); groups.sort()
names = users + groups + devs

site = web.template.render("templates/", base="base")

class StrRegexp(web.form.regexp):
    def __init__(self, regexp, mesg, noneFails = False):
        web.form.regexp.__init__(self, regexp, mesg)
        self.fails = noneFails
    def valid(self, value):
        if not isinstance(value, str): return not self.fails
        return bool(self.rexp.match(value))

valid_bytes = StrRegexp("^(\\d+\\.?\\d*[bBkKmMgGpP]?)?$", "Specify in bytes (B/K/M/G)")

# Hostnames are *hard*.
correct_ip = """^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"""
correct_host = """^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"""
valid_hostname = StrRegexp("({})|({})".format(correct_ip, correct_host), "Invalid hostname")

managementForm = web.form.Form(
    web.form.Dropdown("Action",
                      [("add", "Add quota, reset on a daily basis"),
                       ("bonus", "Add monthly quota"),
                       ("lock", "Lock a user or device"),
                       ("unlock", "Unlock a user or device"),
                       ("softlock", "Soft-lock a user"),
                       ("softunlock", "Soft-unlock a user")]),
    web.form.Textbox("amount", valid_bytes,
                     description="Amount (for adding quota; suffixes are K/M/G)"),
    web.form.Dropdown("users", names,
                      web.form.notnull,
                      multiple="true",
                      description="Target"),
    )

add_user_form = web.form.Form(
    web.form.Textbox("username", web.form.notnull, description="Username"),
    web.form.Password("passwd", web.form.notnull, description="Password"),
    web.form.Checkbox("use_quota", value="#t", description="Use a quota"),
    web.form.Checkbox("use_dyn_quota", value="#t", description="Dynamic quota"),
    web.form.Textbox("shares",
                     StrRegexp("^\\d*\\.?\\d*$", "Decimal number"),
                     description="Shares"),
    web.form.Textbox("static_quota",
                     valid_bytes,
                     description="Static quota (daily)"),
    web.form.Textbox("monthly_quota",
                     valid_bytes,
                     description="Static quota (monthly)"),
    )

change_passwd_form = web.form.Form(
    web.form.Dropdown("username", users, description="Username"),
    web.form.Password("old_passwd", description="Old password"),
    web.form.Password("passwd", description="New password"),
    web.form.Password("check", description="New password (check)"),

    validators=[web.form.Validator("Passwords must match!",
                                   lambda i: i.passwd == i.check)]
    )

add_device_form = web.form.Form(
    web.form.Textbox("username", web.form.notnull, description="Username"),
    web.form.Password("password", web.form.notnull, description="Password"),
    web.form.Textbox("hostname", web.form.notnull,
                     valid_hostname, description="Hostname"),
    web.form.Radio("mode", [("add", "Add"), ("remove", "Forget")],
                   web.form.notnull, description="Add/forget device"),
    )

transfer_quota_form = web.form.Form(
    web.form.Dropdown("target", users, web.form.notnull, description="Recipient"),
    web.form.Textbox("amount", web.form.notnull, valid_bytes, description="Amount"),
    web.form.Dropdown("type", [("dyn", "Daily dynamic quota"),
                               ("d-static", "Daily static quota"),
                               ("m-static", "Monthly static quota"),
                               ("m-bonus", "Bonus quota")],
                      web.form.notnull,
                      description="Type of quota"),
    )

def unauthorized():
    web.header("WWW-Authenticate", "Basic realm='funnelweb'")
    web.ctx.status = "401 Unauthorized"
    return "Unauthorized!"

def is_logged_in():
    au = web.ctx.env.get("HTTP_AUTHORIZATION")
    if au is not None:
      try:
        au = au.strip("Basic ")
        username, passwd = base64.decodestring(au).split(":", 1)
        return auth.authenticate(username, passwd)
      except base64.binascii.Error as er:
        return False
      except configuration.OptionNotFoundException as er:
        return False
      except configuration.UserNotFoundException as er:
        return False
    return False

def get_logged_in_username():
    au = web.ctx.env.get("HTTP_AUTHORIZATION")
    try:
        au = au.strip("Basic ")
        username, passwd = base64.decodestring(au).split(":", 1)
        return username
    except:
        return ""

def sanitise_user_list(userlist):
  """ Sanitise a list of users, making sure they exist.

  Returns a list of strings.
  """
  tokens = [x.strip() for x in userlist.split(",")]
  return [x for x in tokens if x in names]

class Admin(object):
  def __init__(self):
    self.user = "admin" # Need to keep track of who does what when we (eventually) get logging done.

  def GET(self):
    """ Display the admin page. Don't run anything; we perform actions on the POST method."""
    # If we're not logged in, prompt the user for their credentials.
    if is_logged_in():
      users, max_devs = self.construct_table()
      return site.administration(users, max_devs, managementForm())
    return unauthorized()
    
  def POST(self):
    # If we're not logged in, prompt the user for their credentials.
    if is_logged_in():
        return self.show_admin_page()
    return unauthorized()

  def error(self, msg):
    return site.message(title="Error!",
                        content=msg,
                        redir_time = "30",
                        redir_dest = web.ctx.homepath + web.ctx.path)

  def construct_table(self):
      USERS = []
      most_devices = 0
      iptables.refresh()
      for user in configuration.query_users():
        try:
          pk, bt, tot = get_usage(user)
        except ChainNotFoundException:
          bt, tot = 0, 0
        devlist = [(dev, locks.is_locked(dev)) for dev in configuration.query_devices(user)]
        if len(devlist) > most_devices:
          most_devices = len(devlist)
        USERS.append([user, locks.is_soft_locked(user),
                      human_readable(bt),
                      human_readable(tot)] + devlist)
      return USERS, most_devices
  
  def show_admin_page(self):
    pageform = managementForm()
    data = pageform.d
    pageform.validates()

    usrs = sanitise_user_list(data.get("users", "") or "")
    success_msg = ""

    if ("action" not in data) or not pageform.validates():
      USERS, most_devices = self.construct_table()
      return site.administration(USERS, most_devices,
                                 pageform)
    
    if data.action == "add":
      if not auth.check_privilege(get_logged_in_username(), "quota"):
        return self.error("You are not permitted to modify quotas.")
      quant = get_bytes(data.get("amount", "") or "0")
      # Add some quota.
      for usr in usrs:
        try:
          save_quota.add_quota(usr, "fw:quota-dynamic", quant)
        except:
          return error("Failed to add quota to " + usr)

      success_msg = "Added {} to {}.".format(data.amount,
                                             ", ".join(usrs))
      
    elif data.action == "bonus":
      if not auth.check_privilege(get_logged_in_username(), "quota"):
        return self.error("You are not permitted to modify quotas.")
      quant = get_bytes(data.get("amount", "") or "0")
      for usr in usrs:
        try:
          save_quota.add_quota(usr, "fw:quota-bonus", quant)
        except:
          return error("Error adding bonus quota to " + usr)

      success_msg = "Added {} bonus quota to {}.".format(
        data.amount, ", ".join(usrs)
        )
    
    elif data.action == "lock":
      # Authenticate.
      if not auth.check_privilege(get_logged_in_username(), "lock"):
        log.warning("{} attempted to lock {}.".format(get_logged_in_username(),
                                                      ", ".join(usrs)))
        return self.error("You are not permitted to lock users.")
      for usr in usrs:
        try:
          locks.do_lock(usr)
        except:
          return error("Error locking " + usr)
      success_msg = "Locked {}.".format(", ".join(usrs))

    elif data.action == "softlock":
      if not auth.check_privilege(get_logged_in_username(), "lock"):
        log.warning("{} attempted to soft-lock {}.".format(get_logged_in_username(),
                                                           ", ".join(usrs)))
        return self.error("You are not permitted to soft-lock users.")
      for usr in usrs:
        try:
          locks.do_soft_lock(usr)
        except:
          return self.error("Error soft-locking " + usr)
      success_msg = "Soft-locked {ulist}."

    elif data.action == "unlock":
      if not auth.check_privilege(get_logged_in_username(), "lock"):
        log.warning("{} attempted to unlock {}.".format(get_logged_in_username(),
                                                        ", ".join(usrs)))
        return self.error("You are not permitted to unlock users.")
      for usr in usrs:
        try:
          locks.do_unlock(usr)
        except:
          return self.error("Error unlocking " + usr)
      success_msg = "Unlocked {ulist}."

    elif data.action == "softunlock":
      if not auth.check_privilege(get_logged_in_username(), "lock"):
        log.warning("{} attempted to soft-unlock {}.".format(get_logged_in_username(),
                                                             ", ".join(usrs)))
        return self.error("You are not permitted to unlock users.")
      for usr in usrs:
        try:
          locks.do_soft_unlock(usr)
        except:
          return self.error("Error soft-unlocking " + usr)
      success_msg = "Soft-unlocked {ulist}."

    else:
      return self.error("Unknown action " + data.action + " requested")

    # Format the list of users.
    if not usrs:
      user_list = "no-one"
    elif len(usrs) == 1:
      user_list = usrs[0]
    else:
      user_list = ", ".join(usrs[:-1]) + " and " + usrs[-1]
    
    # Display the confirmation
    return site.message(title="Success",
                        content=success_msg.format(ulist=user_list),
                        redir_time="10",
                        redir_dest=web.ctx.homepath + web.ctx.path)

class AddUser(object):
    """ /adduser"""
    def GET(self):
        form = add_user_form()
        if not is_logged_in():
            # We aren't.
            unauthorized()
        elif not auth.check_privilege(get_logged_in_username(), "adduser"):
            log.warning("{} attempted to add a user.".format(get_logged_in_username()))
            return site.message("Unauthorised access",
                                "You are not permitted to add users.")
        else:
            # Do the thing
            return site.adduser(form)
            
    def POST(self):
        """ Add a user to the configuration file. """
        form = add_user_form()
        if form.validates() and is_logged_in():
            if not auth.check_privilege(get_logged_in_username(), "adduser"):
                log.warning("{} attempted to add a user.".format(get_logged_in_username()))
                return site.message("Unauthorised access",
                                    "You are not permitted to add users.")
            options = [
                ["password", auth.gen_passwd(form.d.username,
                                             form.d.passwd)],
                ["quota", form.d.use_quota],
                ["dynamic-quota", form.d.use_dyn_quota],
                ["shares", form.d.shares or 0.0],
                ["daily-static", form.d.static_quota or "0B"],
                # No monthly config flag yet.
                ]
            
            with configuration.read_config() as cfg:
                configuration.add_user(cfg,
                                       form.d.username,
                                       options,
                                       [])

        else:
            if not form.validates():
                # We didn't pass validation.
                # Add some sort of notice.
                return site.adduser(form, True)
        
        raise web.seeother("/adduser")

class AddDevice(object):
    """ /adddevice

    This will add devices to a user's list of devices. Note that to do so, the user *must* already be registered. Furthermore, at the moment, this *doesn't* add the device's MAC address or whatever to the dnsmasq configs. We'll need to hook this part up with devices.py at some point.

    Unlike many of the other modules in admin_mod, we don't need to be logged in for this, as we permit anyone to add devices to their own chain.
    """
    def GET(self):
        form = add_device_form()
        # If this device is already recognised, let the user know, with the option to forget about it.
        ip = web.ctx.ip
        # Look up the hostname of the user's device.
        try:
            host = socket.gethostbyaddr(ip)[0].split(",")[0]
        except socket.herror as er:
            # Unknown host
            host = ip

        form.fill(hostname=host)
        # Owned devices mustn't be added again.
        owner = configuration.get_device_owner(host)        
        if owner:
            # We want to disable the "add" option.
            form.inputs[-1].args.remove(("add", "Add"))
            # And prefill the owner field, since we know that.
            form.inputs[0].set_value(owner)
            # Note that this hard-coding is probably not robust, and we'll want to be careful if we change the order of the form in th future (obviously).
            
            return site.adddevice(form, host, owner)

        return site.adddevice(form)

    def POST(self):
        """ Responding to input. """
        form = add_device_form()

        if form.validates():
            # Check the password.
            if auth.authenticate(form.d.username, form.d.password):
                # Do the thing
                try:
                    if form.d.mode == "add":
                        # Ensure we're actually allowed to add devices.
                        if not auth.check_privilege(form.d.username, "adddevice"):
                            log.warning("{} attempted to add a device called {}."
                                        .format(form.d.username, form.d.hostname))
                            return site.message("Unauthorised access",
                                                "You are not permitted to add devices.")
                            
                        # Double check that this device doesn't already have an owner.
                        owner = configuration.get_device_owner(form.d.hostname)
                        if owner:
                            return site.message(title="Error!",
                                                content="{} already owns '{}'. "
                                                "They must deregister it before {} can use it."
                                                "".format(owner, form.d.hostname, form.d.username),
                                                redir_dest="/adddevice")
                        devices.add_device_to_user(form.d.hostname, form.d.username,
                                                   configuration.get_user_option(form.d.username, "quota"))
                        return site.message(title="Success!",
                                            content="Successfully added {} to {}'s list.".format(form.d.hostname, form.d.username))

                    elif form.d.mode == "remove":
                        if not auth.check_privilege(form.d.username, "deldevice"):
                            log.warning("{} attempted to remove {}.".format(get_logged_in_username(), form.d.hostname))
                            return site.message("Unauthorised access",
                                                    "You are not permitted to remove devices.")
                        devices.remove_device_from_user(form.d.hostname, form.d.username)
                        return site.message(title="Success!",
                                            content="Successfully removed {} from {}'s list.".format(form.d.hostname, form.d.username))
                except DeviceNotFoundException as er:
                    return site.message(title="Error!",
                                        content="Failed to perform the requested operation: '{}' could not be found.".format(form.d.hostname))
                except UserNotFoundException as er:
                    return site.message(title="Error!",
                                        content="Failed to perform the requested operation: '{}' could not be found.".format(form.d.username))

                else:
                    return site.message(title="Wrong username or password",
                                        content="We couldn't authenticate your username and password. Are you registered?")
        # Didn't pass validation.
        return site.adddevice(form)

class TradeQuota(object):
    """ /tradequota

    Trade quota from one user to another.
    The donor must be authenticated with a password.
    """
    typemap = {"dyn": "fw:quota-dynamic",
               "d-static": "fw:quota-static",
               "m-static": "fw:quota-monthly",
               "m-bonus": "fw:quota-bonus"}
    def GET(self, prefilled_form = None):
        if prefilled_form: form = prefilled_form
        else: form = transfer_quota_form()
        if not is_logged_in():
            unauthorized()
        elif not auth.check_privilege(get_logged_in_username(), "trade"):
            return site.message("Unauthorised access",
                                "You are not permitted to trade quota to other users.")
        else:
            balance = {}
            iptables.refresh()
            for var in self.typemap.values():
                try:
                    p, b, t = save_quota.read_quota(get_logged_in_username(), var)
                except ChainNotFoundException as er:
                    p = b = t = 0
                balance[var] = human_readable(t - b)
                
            return site.trade(form, balance)

    def POST(self):
        form = transfer_quota_form()
        if form.validates():
            # Do some stuff.
            if not is_logged_in():
                unauthorized()
                return

            target = form.d.target
            source = get_logged_in_username()
            amount = form.d.amount
            type_ = form.d.type

            if not auth.check_privilege(source, "trade"):
                log.warning("{} attempted to trade quota"
                            .format(source, target))
                return site.message("Unauthorised access",
                                    "You are not permitted to trade quota to other users.")

            # Make sure the amount is positive.
            if amount != amount.lstrip('-'):
                return site.message(title="Error!",
                                    content="You can't trade negative amounts.",
                                    redir_dest="/tradequota")
            
            # Sanity checks.
            var = self.typemap[type_]
            try:
                p, b, t = save_quota.read_quota(source, var)
            except ChainNotFoundException:
                return site.message(title="Error!",
                                    content="An error occurred: we could not find {}'s information.".format(source))
            
            if (t - b) < get_bytes(amount):
                # You don't have enough.
                return site.message(title="You don't have enough",
                                    content="You don't have enough quota; current balance: {} remaining.".format(human_readable(t-b)))
            if target not in configuration.query_users():
                return site.message(title="{} does not seem to exist".format(target),
                                    content="Did you spell their name correctly?")

            if target not in configuration.query_quota_users():
                return site.message(title="{} does not use a quota".format(target),
                                    content="They do not require quota.")

            # Everything seems to be in order.
            save_quota.add_quota(source, var, -get_bytes(amount))
            save_quota.add_quota(target, var, get_bytes(amount))

            log.info("{} sent {} to {}".format(source, amount, target))
            with open("/var/log/net-control/transfers", "a") as f:
                now = arrow.utcnow()
                f.write("{} sent {} to {} ({} UTC)\n".format(source, amount, target,
                                                             now.format("YYYY-MM-DD HH:mm:ss")))

            return site.message(title="Success!",
                                content="You gave {} to {}. Your new balance is {}.".format(amount, target, human_readable(t - b - get_bytes(amount))))

        # Failed validation.
        return self.GET() 
