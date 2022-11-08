# -*- mode: python; -*-

__doc__ = """ Manage locks on devices and users.

  These functions are used to query and set the state of the two different lock mechanisms in FunnelWeb.
The soft/hard variants function in roughly the same way, although there are slight differences.
Locks are not persistent across reboots! (This is a bug; we need to implement that.)

  "Soft" locks are intended as self-imposed restrictions that a user can set and remove without the need for admin intervention.
They are useful for things like ensuring that only unmetered content (assuming such IPs have been correctly added to the whitelist) is downloaded.
Soft locks affect all devices belonging to a particular user. They are not reset by a "unlock all", and do not persist after reboots.
An interesting quirk of soft locks: they can (currently) only affect users with quota chains.

  "Hard" locks on the other hand are a (hopefully) unavoidable mechanism for the admin to control when particular devices are allowed to access the internet.
They may be used for a scheduled lock, or an ad-hoc system to e.g. punish a user for noncompliance.

"""

import re       # To search through the iptable.
import socket   # For resolving hostnames and such.
import iptables # Wrap the iptables library.
import logging as log

log.basicConfig(format="(locks)\t%(asctime)s %(message)s",
                filename="/var/log/funnelweb.log")

def is_locked(hostname, chain = "control_metered",
              do_ip_lookup = True):
    """ Determine if a hostname is locked.

    This will perform a lookup using socket.gethostbyname, unless you tell it not to.
    """
    if do_ip_lookup:
        try:
            my_ip = socket.gethostbyname(hostname)
        except socket.gaierror as er:
            # Commented out, since we are now moving to DHCP based ip addresses
            # and the hostname is unknown until a lease is issued
            #print("Unknown hostname '{}'.".format(hostname))
            return False
    else:
        # Assume that we've been given a preprocessed IP address.
        my_ip = hostname

    for i in [x for x in iptables.WHOLE_IPTABLE
              if "-A {} -s {}".format(chain, my_ip) in x]:
        if "-j REJECT" in i:
            return True
    return False

def get_locked(chain = "control_metered"):
    """ Get a list of all locked devices.

    Note; this may not be perfectly accurate, as we might resolve hostnames differently to the way they're specified in the config files or by iptables.
    """
    # Get a list of devices.
    # Then, we need to get their IPs, and search for them in the iptable-table.
    # (This is a bit hacky; we have to search the config file for things that look like '(device blah)' and keep track of them. These are real hostnames which we're supposed to know about.
    with open("/etc/net-control/conf.scm", "r") as ff:
        dat = ff.read()
        # Note that this doesn't strictly follow the rules regarding legal hostnames; it's much more lenient.
        matches = set(re.findall("""\(\s*device\s+([a-zA-Z0-9-]+)\s*\)""",
                                 dat))

        # So now we just need to filter that by whether or not they're locked in the main table.
        return filter(is_locked, matches)

def do_lock(device, chain = "control_metered"):
    """ Lock a device.

    This is a hard lock, and can't be undone by the user.
    """
    log.debug("locking {}".format(device))
    if not is_locked(device, chain):
        iptables.add_link(chain, "REJECT", source=device)
        iptables.add_link(chain, "REJECT", dest=device)

def do_unlock(device, chain = "control_metered"):
    """ Unlock a device.

    Performs a hard-unlock on a device. This does not affect a user's self-imposed soft-locks.
    """
    log.debug("unlocking {}".format(device))
    if is_locked(device, chain):
        try:
            iptables.del_link(chain, "REJECT", source=device)
            iptables.del_link(chain, "REJECT", dest=device)
        except InvalidRule as er:
            pass
    else:
        print("{} is already unlocked".format(device))

# Tag used to identify a soft lock in the user chains.
# This is added as a comment to the REJECT rule; it's mostly for the benefit of someone running iptables to inspect the running system.
SOFT_LOCK_TAG = "fw:soft-lock"

def is_soft_locked(username, variant=SOFT_LOCK_TAG):
    """ Determine if a user has locked themself.

    Note: importantly, this resolves by username, not host/device name. It's not always appropriate to use it in the same way as is_device_locked.
    """
    return bool([x for x in iptables.WHOLE_IPTABLE
                 if '-A {} -m comment --comment "{}" -j REJECT'.format(username, variant) in x])

def do_soft_lock(user, tag=SOFT_LOCK_TAG):
    """ Perform a soft lock on a user. """
    if not is_soft_locked(user):
        log.debug("soft-locking {}".format(user))
        iptables.iptables("-I", user,
                          "-m", "comment", "--comment", tag,
                          "-j", "REJECT")
    else:
        print("{} is already soft-locked.".format(user))

def do_soft_unlock(user, tag=SOFT_LOCK_TAG):
    """ Remove a user's self-imposed lock. """
    log.debug("soft-locking {}".format(user))
    if is_soft_locked(user):
        iptables.iptables("-D", user,
                          "-m", "comment", "--comment", tag,
                          "-j", "REJECT")
    else:
        print("{} is not soft-locked.".format(user))
