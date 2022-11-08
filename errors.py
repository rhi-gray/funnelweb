# -*- mode: python; -*-
## iptables errors ##
class ChainNotFoundException(Exception):
  def __str__(self):
    return "The chain {} was not found." \
      .format(self.args[0])

class InvalidChain (Exception):
    def __init__(self, name):
        self.chain = name

    def __str__(self):
        return "Couldn't find a chain called {}. This chain doesn't exist.".format(self.chain)

class InvalidRule (Exception):
    def __init__(self, name, chain = "unspecified"):
        self.rule = name
        self.chain = chain

    def __str__(self):
        return "Couldn't find the rule called {}. (Using chain {})".format(self.rule, self.chain)

## device errors ##
class DeviceNotFoundException(Exception):
    def __init__(self, name = "<not specified>", mesg = ""):
        self.name = name
        self.msg = mesg
    def __str__(self):
        return "Could not find a device called '{}'. {}".format(self.name, self.msg)

## config file errors ##
class UserNotFoundException(Exception):
  def __init__(self, username):
    self.msg = username
  def __str__(self):
    return "The user '{}' was not found in the configuration file.".format(self.msg)

class OptionNotFoundException(Exception):
  def __init__(self, option_name, user_name=None):
    self.opt = option_name
    self.ctx = user_name
  def __str__(self):
    if self.ctx:
      return 'The option "{}" in context "{}" could not be found, and no default value was provided.'.format(self.opt, self.ctx)
    else:
      return 'The option "{}" could not be found, and no default value was provided.'.format(self.opt)

class GroupNotFoundException(Exception):
  def __str__(self): return "The group '{}' could not be found in the configuration file".format(self.args[0])
  

class WrongThingException(Exception):
  thingType = "thing"
  def __str__(self):
    return "{} is not a {}!".format(self.args[0],
                                    self.thingType)

class NotADeviceException(WrongThingException):
  thingType = "device"

class NotAUserException(WrongThingException):
  thingType = "user"

class NotAGroupException(WrongThingException):
  thingType = "group"
