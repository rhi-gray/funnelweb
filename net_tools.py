#!/bin/echo "This shouldn't be invoked! It's a python module! "
# -*- mode: python; -*-

import sys, os

import logging as log
log.basicConfig(format="(net_tools)\t%(asctime)s %(message)s",
                filename="/var/log/funnelweb.log")

# Various time-related imports.
import datetime as datet
import time
import calendar

# Getting information about other computers.
import subprocess
from subprocess import check_output

from socket import gethostbyaddr # Used to turn iptables stuff into nicer things.

import re

# Used for loading the (new format) config files.
from sexpy import *
import iptables
import save_quota
import locks
import configuration

from errors import *

# 1000 is the SI base for KB MB and GB, 1024 is the Traditional base
#base_K = 1024
base_K = 1000

TOTAL = 60.0   ### This ought to be loaded from the confit file
QUOTA_PERIOD = "daily" # "monthly" "weekly"
RESET_DATE = 1 # First of the month.

LIMIT = 12
ENDS = 4
GAP = "..."
MSTRLEN = 10  # Length of longest device/group name
GSTRLEN = 20  # Length of longest device/group name
DSTRLEN = 10  # Length of longest device/group name

def pruned_string(s, ends, gap, total):
    n = len(s)
    if 2*ends+len(gap) >= total: return s[:total]
    if n > total: return s[:ends] + gap + s[n-ends:n]
    return s

def GB(gigs):
    """ Turn gigabytes into bytes.
    RETURNS A STRING.
    """
    return str(int(gigs * base_K * base_K * base_K)) # No decimal place. >:|

def format_table(groupname, usage, total, children):
    childrenS = "\t".join(children)
    return "{gname:}{slock}\t{use}/{total}\t{childlist}".format(gname=groupname,
                                                                use=usage, total=total,
                                                                childlist=childrenS,
                                                                slock = "*" if locks.is_soft_locked(groupname) else " ")

def get_bytes(str_si, rbase = 1000):
    """ Turn a string into a number of bytes. """
    # First, if it's an int, it must be suffix style.
    if isinstance(str_si, int):
        return str_si

    # Otherwise, it might have a suffix.
    try:
        # Split into number and suffix.
        def split_num_suffix(string):
            num_part = ""
            suffix = ""
            for char in string:
                if char.isdigit() or char == "." or char == "-":
                    num_part += char
                else:
                    suffix = char
                    break
            return float(num_part), suffix

        # Ks, Ms, and Gs.
        num, suffix = split_num_suffix(str_si)

        if suffix == "K" or suffix == "KB":
            return int(num * rbase)
        elif suffix == "M" or suffix == "MB":
            return int(num * rbase * rbase)
        elif suffix == "G" or suffix == "GB":
            return int(num * rbase * rbase * rbase)

        # It's in straight bytes.
        else:
            return int(num)

    except ValueError as er:
        return 0

def human_readable(bytec, base = base_K, padding=True):
    """ Turn a raw byte-count into a nice human-readable value. """
    ret = float(bytec) or 0.0
    # Taken from hurry.filesize. Many thanks!
    suffixes = ["b", "K", "M", "G", "T", "P"]
    for i in suffixes:
        if ret < base_K:
            if padding:
                return "%5.1f%s" % (ret, i) # Break here. This should always happen.
            else:
                return "%.1f%s" % (ret, i) # Don't include padding.
        ret /= base_K

    return bytec # WTF happened, eh? This code path shouldn't be reached.

def get_usage(chain_name):
    """ Get the usage for a user.
    Returns a tuple of the packet count, byte count, and total quota.
    Note: this sums all the quota rules in the user's chain. There is currently no way to get individual rule usage without using iptables directly.
    """
    totals = [0, 0, 0] # Packets, bytes, total.
    for v in save_quota.KNOWN_QUOTA_TYPES:
        counts = save_quota.read_quota(chain_name, v)

        totals[0] += counts[0]
        totals[1] += counts[1]
        totals[2] += counts[2]

    return totals

def get_internode_remainder(user, passwd):
    import InternodeReader # The wrapper to read stuff from Internode's site.

    ii = InternodeReader.InternodeAccess(user, passwd)
    TOTAL, CURRENT_TOTAL = ii.get_today()
    return TOTAL, CURRENT_TOTAL

def get_logfile_usage(name):
    """ Get the usage information about a user from the log file.
    Note: this is only updated every 15 minutes, so it isn't perfectly accurate.
    """
    try:
        logfile = open("/var/log/usage.txt", "r")

    except IOError as er:
        # Either the file doesn't exist, or it's write-protected. Not much we can do, either way.
        return "0"

    for line in logfile.readlines():
        try:
            lname, value = line.split("\t : ", 1)
            if name == lname.strip():
                logfile.close()
                return value.strip()
        except:
            pass
    logfile.close()
    return "0"

#####################################################################
# Calculate the amount of quota a dynamic allocation should receive.#
#####################################################################
def calculate_quota(username, shares = 1,
                    use_running_total_as_base = "no",
                    period_quota = 400 * base_K * base_K,
                    remainder=None):
    """ Calculate the dynamic quota that a user should receive.

    This takes into account the total number of extant shares and the relative proportion of these belonging to the given user.
    It also removes from consideration any quota which has been allocated as part of a monthly static quota, but importantly NOT daily static.
    """

    # Work out how much monthly stuff we need to ignore.
    ignored_portion = 0
    for u in configuration.query_quota_users():
        # Any permanent quota specified in the config file.
        ignored_portion += get_bytes(configuration.get_user_option(u, "monthly-static", default="0"))

        # Also consider bonus quota (e.g. purchased)
        p, b, monthly_bonus = save_quota.read_quota(u, "fw:quota-bonus")
        ignored_portion += monthly_bonus

        # We need to then subtract the amount that this user has already used up.
        ignored_portion -= save_quota.load_quota(u, "fw:quota-bonus")[1]

        ## Note to Ryan: I think the calculation might be a bit screwy.
        ## You should work this algebra out on paper.

    try:
        total_shares = sum(float(configuration.get_user_option(x, "shares", 1.0))
                           for x in configuration.query_quota_users()
                           if configuration.get_user_option(x, "dynamic-quota", False))

        # Load the pool size from the log file.
        used, total = save_quota.get_pool()
        pool_b = total - used
        
        # Remove the extra quota that someone's bought.
        pool_b -= ignored_portion

        quota = int(pool_b / (days_remaining() + 1)) # +1 because we want to have quota left on the last day.

        # This user's quota is a proportion of the total shares.
        quota *= shares / total_shares

        if quota < 100 * base_K * base_K:
            print("BEWARE: There's not much quota left.")

        # And that's it. 1/5th of the remaining allowance daily, each.
        # We don't want this to fall into negatives. 0 can cause division problems too, I think.
        return max(quota, 1)

    except:
        # Specify this in the config file with:
        # (option fallback-quota 300M)
        # or similar.
        return get_bytes(configuration.get_global_option("fallback-quota", "0"))

def get_quota(username):
    """ Get the total quota for the user."""
    yy = get_usage(username)
    return int(yy[2])

def days_remaining(day_of_month=-1):
    """ How many days are remaining in the period?
    Pass day_of_month = -1 if the last day in the month is always the reset day.
    """
    today = datet.date.today()
    end_month = today.month

    if day_of_month == -1:
        lastday = calendar.monthrange(today.year, today.month)[1]
    else:
        lastday = day_of_month
        if lastday < today.day:
            end_month = today.month + 1

    delta = datet.date(today.year, end_month, lastday) - today
    return int(delta.days) # The number of days left until our quota ticks over.

def get_logfile(name):
    """ Get the logfile for a user. """
    return "/var/log/net-use/quota/" + name

def get_history(name):
    """ Get the last 10 days usage from this user. """
    # NOTE: this needs to take into account non-crond 'net-control zero'ing.
    # it doesn't yet.
    with open(get_logfile(name)) as ff:
        return [x.strip().split("\t")[-1] for x in ff.readlines()[:-10]]


### Functions to replace the Device/User/Group classes ###
def tabulate_device(devname, max_len = 12):
    # Sanity check.
    if devname not in configuration.query_devices():
        raise NotADeviceException(devname)

    locked = locks.is_locked(devname)
    return "{{padl}}{{name:{padlen}s}}{{padr}}"\
      .format(padlen=max_len)\
      .format(name=devname[:max_len],
              padl=" " if not locked else "[",
              padr=" " if not locked else "]")

def tabulate_user(username, max_len = 12):
    # Sanity.
    if username not in configuration.query_users():
        raise NotAUserException(username)

    slocked = locks.is_soft_locked(username)
    return "{{name:{padlen}s}}{{lock}}"\
      .format(padlen=max_len)\
      .format(name=username[:max_len],
              lock="*" if slocked else " ")

def tabulate(to_list = "all"):
    """ Print a table with quota and lock information.

    This returns a string. Pass "all" in to get a table for every user in the config file.
    """
    ret = ""
    if to_list == "all":
        # We'll just take them all.
         set_ = configuration.query_users()
    else:
        # Make sure we're only getting valid ones.
        valid = configuration.query_users()
        set_ = [u for u in to_list if u in valid]

    # Now, find the biggest names.
    longest_uname = max(len(name) for name in set_)
    user_devs = {user: configuration.query_devices(user)
                 for user in set_}
    longest_dname = min(12,
                        max(len(name)
                            for u in user_devs.values()
                            for name in u))
    # And format that shit.
    ret += "{{name:{ulen}s}}  {{usg}}         {{devs}}"\
      .format(ulen=longest_uname)\
      .format(name="Username", devs="Devices", usg="Usage") + "\n"

    for user in set_:
        try:
            quota = " {}/{} ".format(*map(human_readable, get_usage(user)[1:]))
        except InvalidChain as er:
            quota = " (NA) "
        except ChainNotFoundException as er:
            quota = " (n/f) "

        ret += "{u}{q:10s}{d}".format(
            u=tabulate_user(user, longest_uname),
            q=quota,
            d=" ".join(tabulate_device(dev, longest_dname)
                       for dev in user_devs[user])) + "\n"
    return ret

