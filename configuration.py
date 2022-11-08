# -*- mode: python; -*-
__doc__ = """ Handle the configuration of Funnelweb.

This module contains information about loading and writing Funnelweb's configuration files.
It provides means of querying the config file for a list of users, devices, groups, settings, etc.

In the future, a complete specification of a "valid" configuration file will be attached to this document. For now, be happy there are comments ;)
"""

import sexpy
import re

import logging as log
log.basicConfig(format="(configuration)\t%(asctime)s %(message)s",
                filename="/var/log/funnelweb.log")

CONFIG_PATH = "/etc/net-control/conf.scm"
DEVICE_DB_PATH = "/etc/net-control/devices.scm"

# Use inotifyx to track changes to the config file.
import inotifyx
import atexit # So we can close watches.

from errors import *

def unique(iter_):
    seen = set()
    see = seen.add
    for i in iter_:
        if i not in seen:
            see(i)
            yield i

# Wrap up the configuration file so we only reload it when necessary.
class _config_container(object):
    """ Wrap the configuration in a list-like object.

    This uses inotifyx to track changes to the config file, and update when necessary. It should reduce unnecessary disk access.
    """
    def __init__(self, path = CONFIG_PATH):
        self.fd = inotifyx.init()
        self.conf_watch = inotifyx.add_watch(self.fd, path, inotifyx.IN_MODIFY)
        atexit.register(inotifyx.rm_watch, self.fd, self.conf_watch)
        self.path = path
        
        # Give us some contents.
        self.refresh()

    def refresh(self):
        log.info("Refreshing the contents of the config file at {}."
                 .format(self.path))
        with open(self.path) as f:
            self.contents = f.read()
            self.sexp = sexpy.sread(self.contents)

    def __getitem__(self, k):
        # Check for updates.
        if inotifyx.get_events(self.fd, 0) != []:
            self.refresh()
        return self.sexp[k]

    def __len__(self): return len(self.sexp)

    def __iter__(self):
        # Check for updates.
        if inotifyx.get_events(self.fd, 0) != []:
            self.refresh()
        return iter(self.sexp)

    def __contains__(self, k):
        # Check for updates.
        if inotifyx.get_events(self.fd, 0) != []:
            self.refresh()
        return k in self.sexp

    def raw(self):
        # Check for updates.
        if inotifyx.get_events(self.fd, 0) != []:
            self.refresh()
        return self.contents

# The instantiation.
CACHED_CONFIG = _config_container()
CACHED_DEVICE_DB = _config_container(DEVICE_DB_PATH)

def unwrap(lst):
  if len(lst) == 1:
    return lst[0]
  return lst

def _query_by_tag(tag=None, second=None, path=CONFIG_PATH):
  """ Internal method. Get a list of top-level things with the initial tag provided.
  """
  cfg = CACHED_CONFIG
  if second is None:
    return [k for k in cfg if k[0] == tag]
  else:
    return [k for k in cfg
            if k[0] == tag and k[1] == second]

def is_user(name, path=CONFIG_PATH):
  return [] != _query_by_tag("user", name, path)

def is_group(name, path=CONFIG_PATH):
  return [] != _query_by_tag("group", name, path)

def query_users(full_spec=False, path=CONFIG_PATH):
  """ Query the list of users defined in the config file, returning a list.

  If full_spec is True, the complete s-expression representing the user will be returned. By default, a list of strings will be returned, all of which must be valid user names found in the top-level of the configuration file.
  """
  things = _query_by_tag("user")
  if full_spec:
    return things
  else:
    return [u[1] for u in things]

def get_user_description(name, path=CONFIG_PATH):
  """ Get the description for a user, or raise a UserNotFoundException.
  """
  matches = _query_by_tag("user", name, path)
  if not matches:
    raise UserNotFoundException(name)
  return matches[-1]

def get_group_description(name, path=CONFIG_PATH):
  matches = _query_by_tag("group", name, path)
  if not matches:
    raise GroupNotFoundException(name)
  return matches[-1]

def query_groups(full_spec=False, path=CONFIG_PATH):
  """ See query_users.
  """
  things = _query_by_tag("group")
  if full_spec:
    return things
  else:
    return [g[1] for g in things]

def query_devices(name=None, path=CONFIG_PATH):
  """ Query the devices attached to a user, or find a list of all devices.

  Returns a list of strings in either case representing devices, which are probably hostnames but might also be IP addresses.
  If we are given a group, recurse, and find all the devices within it.
  """
  g = _query_by_tag("group", name)
  u = _query_by_tag("user", name)

  # We want everything
  if name is None:
    return list(unique(re.findall("""\(device ([-a-zA-Z0-9@!\.?/]+)\)""",
                                  CACHED_CONFIG.raw())))
    
  # First of all, if it's a device, leave soon.
  elif "(device {})".format(name) in CACHED_CONFIG.raw():
    return [name]

  elif g != []:
    group = group_dict(g[0])
    subdevs = []
    for u in group["users"]:
      subdevs += query_devices(u, path, CACHED_CONFIG.raw())
    return list(unique(group["devices"] + subdevs))

  elif u != []:
    user = user_dict(u[0])
    return list(unique(user["devices"]))

  return []

def query_quota_users(full_spec=False, path=CONFIG_PATH):
    all_ = query_users(full_spec=True, path=path)
    if full_spec:
        return [k for k in all_ if ["option", "quota"] in k]
    else:
        return [k[1] for k in all_ if ["option", "quota"] in k]

def get_user_option(user_name, option_name, default=None, path=CONFIG_PATH):
  """ Get the value of an option specific to a particular user.

  Fails if the user is not found.
  """
  users = query_users(True, path)
  match = [k for k in users if k[1] == user_name]
  if not match:
    raise UserNotFoundException(user_name)
  option_matches = [unwrap(k[2:]) for k in match[0]
                    if k[0] == "option" and k[1] == option_name]
  if not option_matches: # Empty list.
    if default is None:
      raise OptionNotFoundException(option_name, user_name)
    else:
      return default

  # Return the last value set. This means you can override earlier settings by appending, not that that's a good idea...
  return option_matches[-1]

def get_global_option(option_name, default=None, path=CONFIG_PATH):
  return option_dict(path).get(option_name, default)

def get_device_owner(device, path=CONFIG_PATH):
    """ Find the owner of a device.

    This returns the user who owns the device given, if one exists. If no user owns the device, return None.
    To find groups containing a device, use query_groups/group_dict/["devices"].

    Note that this isn't particularly smart about IP addresses vs hostnames, so it isn't guaranteed to find things if they've got weird names.
    """

    users = query_users(True, path)
    for u in users:
        if len(u) < 2: continue # Too short.
        if ["device", device] in u[2:]:
            return u[1] # The name.
    return None

def option_dict(path=CONFIG_PATH):
  """ Get a Python dictionary representing the top-level options found in the config file.
  """
  opts = _query_by_tag("option", path=path)
  return {thing[1] : unwrap(thing[2:])
          for thing in opts}

def user_dict(spec):
    """ Turn a user specification into a dictionary.

    This is read-only, but should simplify some logic.
    Devices are stored in user["devices"], options are top-level.
    The special entry "username" is the user's name.
    """
    if spec[0] != "user":
        # This isn't a user!
        raise NotAUserException("invalid format '{}'".format(spec))

    # The dictionary we'll be returning.
    user = {"username": spec[1], "devices": []}

    # If the list is empty, just leave.
    if len(spec) == 2: return user

    # Add devices.
    rest = spec[2:]
    user["devices"] = [dev[1]
                       for dev in rest
                       if dev[0] == "device"]

    # Parse options.
    for dat in [opt[1:] for opt in rest if opt[0] == "option"]:
        if len(dat) == 1: dat += [True]
        key, val = dat
        if key in ["devices", "username"]:
            raise KeyError("Illegal option {} in {}'s specification".format(key, user["username"]))
        user[key] = val

    return user

def group_dict(spec):
    """ Turn a group specification into a dictionary.

    Return a dict {"name": "", "users": [...], "devices": [...]}
    """
    if spec[0] != "group" or len(spec) <= 2:
        raise NotAGroupException(spec)
    group = {"name": spec[1], "devices": [], "users": []}
    for i in spec[2:]:
        if isinstance(i, list) and i[0] == "device":
            group["devices"].append(i[1])
        elif isinstance(i, str):
            # If this is a user, add it to the list of users. Otherwise, it must be a group. We want to flatten it out, so unpack it into a list of users (and devices).
            if is_user(i):
                group["users"].append(i)
            elif is_group(i):
                # Make sure we're not adding ourself.
                if i == group["name"]:
                    log.error("Group {} contains itself!".format(i))
                    continue
                # Add children
                child_group = group_dict(get_group_description(i))
                group["devices"].extend(child_group["devices"])
                group["users"].extend(child_group["users"])
            else:
                log.warning("Unknown item {} found in group {}. Ignoring.".format(i, group["name"]))

    # Ensure we don't have duplicates.
    for i in ("devices", "users"):
        group[i] = list(unique(group[i]))

    return group


## Configuration file (re)writing
## This needs to be done *carefully*, so that it doesn't totally clobber CACHED_CONFIG.

class _controlled_sexp(list):
    def __init__(self, path, *args):
        list.__init__(self, *args)
        self.path = path

    def __enter__(self):
        """ Return a sexp representation of the config file.
    
    Note: this is for internal use, so that we can rewrite the config file by inserting nodes into the sexp structure.
    This will return a Python list type thing. Hopefully, sexpy.swrite is the exact inverse operation of _read_config.
        """
        with open(self.path, "r") as f:
            sexp = sexpy.sread(f.read())
            list.__init__(self, sexp)
        return self

    def __exit__(self, type = None, value = None, traceback = None):
        """ Write a sexp representation of the config file back to disk.
    
    This will save changes that were performed programmatically. Later, we will be able to add consistency/error checking here.
        """
        self.close()
        return False

    def close(self):
        with open(self.path, "w") as f:
            sexpy.write(self, f)

def read_config(path=CONFIG_PATH):
    """ Return a sexp representation of the config file.
    """
    return _controlled_sexp(path)

def add_option(cfg, key, value):
    """ Insert a global option into the config structure.

    Operates in-place, on the cfg parameter.
    """
    for i, elem in enumerate(cfg):
        if elem[0] == "option" and elem[1] == key:
            cfg[i] = ["option", key, value]
            return cfg
    cfg.append(["option", key, value])
    return cfg

def add_user(cfg, name, optlist, devlist):
    """ Insert a user into the config structure.

    Note that if this user already exists, we will instead set the options, and add devices to the device list.
    A warning will be logged.
    """
    for i, elem in enumerate(cfg):
        if elem[0] == "user" and elem[1] == name:
            # We've already got this user somewhere in the tree.
            cfg[i] = merge_user(elem, optlist, devlist)
            return cfg

    # We've not found it yet, so add it to the end.
    cfg.append(["user", str(name)]
               + [["option", k[0], unwrap(k[1:])] for k in optlist]
               + [["device", k] for k in devlist])
    return cfg

def add_device(cfg, user, device):
    """ Add a device to a user's list of devices.

    This also updates iptables.
    """
    for i, elem in enumerate(cfg):
        if elem[0] == "user" and elem[1] == user:
            # Make sure it's not already there.
            if ["device", device] in elem[2:]: return

            cfg[i] = elem + [["device", device]]
            return
        
    raise UserNotFoundException(user)

def remove_device(cfg, name, device):
    """ Remove a device from a user or group's list. """
    for i, elem in enumerate(cfg):
        if elem[0] in ("user", "group") and elem[1] == name:
            # Found the right user/group
            try:
                elem.remove(["device", device])
                cfg[i] = elem
                return
            except ValueError as er:
                # The device wasn't where it's supposed to be.
                raise DeviceNotFoundException(device)
    raise DeviceNotFoundException("no user/group called '{}' containing '{}'."
                                  .format(name, device))

def merge_user(line, options, devices):
    name = line[1]

    oldopts = [el[1:] for el in line[2:]
               if el[0] == "option"]
    olddevs = [el[1] for el in line[2:]
               if el[0] == "device"]

    print(oldopts)
    optdict = dict(oldopts)
    optdict.update(dict(options))

    devset = set(olddevs + devices)

    opts = [["option", k, v] for k, v in optdict.items()]
    devs = [["device", d] for d in devset]

    return ["user", name] + opts + devs

def add_group(cfg, name, users=[], devices=[]):
    for i, elem in enumerate(cfg):
        if elem[0] == "group" and elem[1] == name:
            cfg[i] = merge_group(elem, users, devices)
            return cfg

    cfg.append(["group", str(name)]
               + users + [["device", dev] for dev in devices])
    return cfg

def merge_group(line, users, devices):
    name = line[1]
    users = set(users)
    devices = set(devices)
    
    for i in line[2:]:
        if isinstance(i, str):
            users += i
        elif i[0] == "device":
            devices += i[1]
    return ["group", name] + list(users) + list(devices)


################################
# Central device configuration #
################################
def known_device(name):
    pass

def recognise_device(mac, hostname, ip = None):
    """ Add a new device to the device database.
    
    This will return quickly if a device with the given MAC address or hostname is present. If there is an IP address conflict, it is ignored.
    """
    if known_device(mac) or known_device(hostname):
        return

    with read_config(DEVICE_DB_PATH) as db:
        db.append([mac, hostname, ip or ""])

def forget_device(name):
    with read_config(DEVICE_DB_PATH) as db:
        for i, elem in enumerate(db):
            if name in elem:
                # Found it.
                try:
                    db.remove(elem)
                except ValueError as er:
                    raise DeviceNotFoundException(device)

def get_known_hostnames():
    """ Return a list of recognised hostnames """
    return [expr[1] for expr in CACHED_DEVICE_DB]

def make_dnsmasq_conf(
