# -*- mode: python; -*-
import bcrypt
import configuration

from errors import UserNotFoundException

import logging as log
log.basicConfig(format="(auth)\t%(asctime)s %(message)s",
                filename="/var/log/funnelweb.log")

def authenticate(username, passwrd):
    """ Authenticate a user.

    Returns True/False. True means that the user/pass combination was accepted, and the user should be allowed to log in.
    """
    compare_passwd = configuration.get_user_option(username, "password")

    # This way of storing passwords was decided based on https://medium.com/@martyweiner/store-your-users-passwords-correctly-c155ac90f0c2
    hashed = unicode(bcrypt.hashpw(passwrd.encode('utf-8'), compare_passwd.encode('utf-8')), "utf-8")
    if hashed == compare_passwd:
        return True
    return False

def gen_passwd(username, passwrd):
    if not username or not passwrd:
        return "NO PASSWORD"
    return unicode(bcrypt.hashpw(passwrd.encode("utf-8"), bcrypt.gensalt()), "utf-8")

def check_privilege(username, privilege):
    """ Check to see if a user should be permitted some action.

    Currently recognised privileges:
    lock : Allowed to lock/unlock any device/user.
    quota : Allowed to add/remove quota of any type from anyone.
    trade : Allowed to give quota to another user.
    adduser : Allowed to add new users.
    deluser : Allowed to delete users.
    adddevice : Allowed to add devices.
    deldevice : Allowed to remove devices.
    admin : Free access to everything.

    e.g. (user Someone ... (privileges (quota lock
    """
    try:
        privs = configuration.get_user_option(username,
                                              "privileges",
                                              default = [])
        # If we get something like (privileges (admin)) it won't work right.
        # So, wrap such things up in a list.
        if not isinstance(privs, list): privs = [privs]
    except UserNotFoundException as er:
        return False

    # Admins can do anything.
    return privilege in privs or "admin" in privs
