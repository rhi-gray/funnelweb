#!/funnelweb/python-env/bin/python
# -*- mode: python; -*-

from iptables import *

import re
import os, os.path
import subprocess
import logging as log

import configuration
from errors import *

# We need this so we can limit how often the table is updated.
import time, arrow

# Bonus quota is quota which this person has bought from the ISP.
# It should *not* be reset on a day-by-day basis.
# It should, however, be reset at the end of the month.
KNOWN_QUOTA_TYPES = [
    # Note that some things rely on "fw:quota-" prefixes to match correctly.
    "fw:quota-dynamic", # The day-to-day dynamically allocated quota.
    "fw:quota-static", # Daily static quota.
    "fw:quota-bonus", # Bonus quota, e.g. if you bought extra from the ISP.
    ]

# A sentinel value used to signal that a user has exceeded their quota.
# The watchdog sets this when someone's gone over their limit, so that the user can be informed appropriately.
QUOTA_EXCEEDED_SENTINEL = 86 # bytes.

# We store the user's current tally in these places.
LOG_DIR = "/var/log/net-control/"
LOG_FILENAME = "{username}.{date}.log"
LOG_FORMAT = "{date} {time} {variant} : {packets} {bytes} {total}\n"


quota_match = re.compile("[\[:\] ]")
def read_quota(user, variant = "fw:quota-dynamic",
               force_refresh = False):
    """ Read the amount of quota a user has used in a particular chain.

    The `variant` argument describes the comment associated with the quota rule. When quotas are added, it's always with a --comment fw:quota-*.
    Passing True as `force_refresh` causes a call to iptables-save; don't do it carelessly.
    If you want to read a total of all quota amounts, pass "*" as the variant.

    Returns:
     A tuple of (packets, bytes, total)
    """

    # **** Refresh Configuration file data for user

    if not chain_exists(user):
        raise ChainNotFoundException(user)

    # Refresh if need be.
    if force_refresh:
        WHOLE_IPTABLE.refresh(time.time())

    # Get the quota rule.
    # ** this needs to be replaced with a better/safer/something rewrite **
    rules = [x for x in WHOLE_IPTABLE
             if user in x and (variant in x) or ("fw:quota-" in x and variant == "*")]

    if not rules:
        return (0, 0, 0)
    if len(rules) > 1 and variant != "*":
        print("Found more than one matching quota rule in {}'s '{}' quota!"
              .format(user, variant))
        print("This may cause unexpected behaviour.")

    # Example rule line:
    # [1631:871831] -A Ryan -m quota --quota 416712000 -m comment --comment "fw:quota-dynamic" -j ACCEPT

    packets, btes, total = 0, 0, 0
    for r in rules:
        parts = quota_match.split(r)
        packets += int(parts[1])
        btes += int(parts[2])
        total += int(parts[9])

    return (int(packets), int(btes), int(total))

def save_quota(user, variant = "fw:quota-dynamic",
               logdir = LOG_DIR, now = None):
    """ Write this user's quota to disk.

    The destination is logdir/LOG_FILENAME
    LOG_FORMAT = "{date} {time} {variant} : {packets} {bytes} {total}\n"


    Load from this file using load_quota().
    """
    if variant not in KNOWN_QUOTA_TYPES:
        raise Exception("Unknown quota type {}".format(variant))
    
    packets, b_tes, total = read_quota(user, variant)

    if not now: now = arrow.utcnow()
    date = now.format("YYYY-MM-DD")
    time = now.format("HH:mm")
    
    # The user folder might need to be created.
    try:
        os.mkdir(logdir)
    except OSError as er:
        # Dir already exists.
        pass

    dest = os.path.join(logdir,
                         LOG_FILENAME.format(username=user,
                                             date=date))

    with open(dest, "a") as log:
        log.write(LOG_FORMAT.format(date=date, time=time,
                                    variant=variant,
                                    packets=packets,
                                    bytes=b_tes, total=total))

    return dest

def load_quota(user, variant = "fw:quota-dynamic",
               logdir = LOG_DIR):
    """ Load the user's quota from disk, returning the same format as read_quota()
    """
    now = arrow.utcnow()
    today = now.format("YYYY-MM-DD")
    
    src = logdir + LOG_FILENAME.format(username=user, date=today)

    try:
        with open(src, "r") as log:
            lines = log.readlines()
            select = [k for k in lines if variant in k]
            last = select[-1]
            d, t, v, _, packets, b_tes, total = last.split()

    except IOError as er:
        packets = 0
        b_tes = 0
        total = 0
    except IndexError:
        packets = 0
        b_tes = 0
        total = 0

    return (int(packets), int(b_tes), int(total))

def get_pool(unlimit_if_exceeded=True):
    """ Calculate the remaining total pool of quota available.

    This will rely on other scripts to keep an up-to-date tally (or a query from the ISP) in the log file.
    Note that as the ISP may rate-limit requests, it *must* be left up to other tools to keep track of such things.

    unlimit_if_exceeded controls the behaviour when we go over the monthly cap. If set to True, everyone gets a large amount of quota. Otherwise, the remainder is assumed to be very small (e.g. bytes). For example, if your ISP shapes you, you want this to be True; if there are fees for going over the limit, you want it set to False.
    """
    with open("/var/log/net-control/remainder", "r") as f:
        used, remainder = f.read().split()
        if remainder < 0:
            if unlimit_if_exceeded: remainder = 100 * 1000 * 1000 * 1000
            else: remainder = QUOTA_EXCEEDED_SENTINEL
        
        return int(used), max(int(remainder), 0)

def add_missing_quota(user, variant):
    """ Add an empty quota rule to a user if there is no rule already there.

    This is used so we can ensure that the order is *always* correct.
    """
    me = get_rule_number(user, variant)
    if me <= 0:
        return # As we already have a rule.

    # The rule doesn't already exist.
    # Therefore, we need to create it in the correct place.
    # What we'll do is read *all* existing quota rules, then delete them.
    # Then, we restore the state by inserting quota rules in the correct order, with the correct counts.
    previous_state = {variant: (0, 0, 0)}

    for var in KNOWN_QUOTA_TYPES:
        previous_state[var] = read_quota(user, var)
        # And delete it from the chain.
        if get_rule_number(user, var) > 0:
            iptables("-D", user,
                     "-m", "quota", "--quota", previous_state[var][2],
                     "-m", "comment", "--comment", variant,
                     "-j", "ACCEPT")

    # Now, the chain is clean of quota rules.
    # We need to readd them in the right order.
    # This means inserting them at the start, in reverse order.
    for var in reversed(KNOWN_QUOTA_TYPES):
        set_quota(user, var, *previous_state[var])

def set_quota(user, variant, packets, b_tes, total,
              destination = 1):
    """ Set a user's quota information.

    This will override any existing rules.
    Set the `destination` parameter if you want to control *where* the rule is inserted if it has to be created from scratch.
    """
    rule_num = get_rule_number(user, variant)

    if rule_num < 0:
        # No existing rule.
        # We insert one at the index specified by `destination`.
        iptables("-I", user, destination,
                 "-m", "quota", "--quota", int(total),
                 "-c", packets, b_tes, # Set the packets + bytes.
                 "-m", "comment", "--comment", variant,
                 "-j", "ACCEPT")

    else:
        # Try to replace the current rule.
        try:
            iptables("-R", user, rule_num,
                     "-m", "quota", "--quota", int(total),
                     "-c", packets, b_tes,
                     "-m", "comment", "--comment", variant,
                     "-j", "ACCEPT")

        except subprocess.CalledProcessError as er:
            print("Failed to set counters for {} - {}: {}"
                  .format(user, variant, er))

    if not check_iptables(user, "-j", "REJECT"):
        # If the user chain doesn't have a REJECT at the end, it's because we're adding quota to a previously un-quotad user.
        try:
            del_link(user, "ACCEPT")
        except InvalidRule as er: pass
        finally:
            add_link(user, "REJECT")

def add_quota(user, variant, b_tes):
    """ Give a user an extra amount of quota.

    The `b_tes` parameter must be an int.
    Note that negative numbers are accepted, and correspond to subtracting quota.

    This is a convenience function for `nc add ...`.
    """
    pk, bt, tot = read_quota(user, variant)
    new_tot = tot + b_tes
    set_quota(user, variant, pk, bt, new_tot)

def zero_quota(user, variant):
    """ Reset the "used" part of a user's quota.

    This can be used if e.g. you want to give someone an extra chunk of quota.
    It does *not* store the usage safely; if you're not using the Internode total counter, you *will* have inaccuracies in your monthly usage total. This needs to be fixed, but it's the sort of problem where it occurs everywhere.
    A convenience function for `nc zero ...`.
    """
    save_quota(user, variant)
    pk, bt, total = read_quota(user, variant)
    set_quota(user, variant, 0, 0, total)
    return total # Might be useful.

# This is no longer functional.
#def restore_quota(user, logdir = "/etc/net-control/counters/"):
#    """ Restore a user's quota by inspecting the saved counters.
#
#    Restores *every* quota rule.
#    This overwrites the current total, so it should only be run on startup, or immediately following a save (otherwise it won't be accurate).
#    """
#    for var in os.listdir(os.path.join(logdir, user)):
#        pk, bt, tot = load_quota(user, var, logdir)
#        set_quota(user, var, pk, bt, tot)

if __name__ == "__main__":
    # When run as a script, we want to store everyone's current usage stats.
    # This is useful so that we can restore from the last known state in case of power outages et al.
    for user in get_quota_groups():
        for var in KNOWN_QUOTA_TYPES:
            save_quota(user, var)
