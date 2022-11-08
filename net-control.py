#!/funnelweb/python-env/bin/python
# -*- mode: python; -*-

import sys, os
import commands # Unix commands in Python, woo!
import subprocess
import time

# Logging.
import logging as log

from net_tools import *
import save_quota
import locks
import iptables
import socket

import funnelcore

""" Net control script for owl."""

NOQUOTAS="/etc/NOQUOTAS"

USAGE="""net-control.py
Usage:
   net-control.py \t Show this help.
   net-control.py start\t Build the iptables.
   net-control.py stop \t Save the quotas to disk and stop. (Not implemented!)

   net-control.py status [users...]
   net-control.py table [users...]
\t\t\t Show the user(s) net access status, as well as their quota so far.

   net-control.py unlock|lock (--full) [users...]
\t\t\t Lock or unlock users. Pass --full to also block unmetered content.
   net-control.py soft-unlock|lock users...\tSoft-lock/unlock user(s). Note that soft locks can be removed by the user using the web interface.
   net-control.py zero [users...]\t Reset the quota for this user (or all users) to 0 bytes used.

   net-control.py add AMOUNT [users...]\t Add AMOUNT to this user's quota. Please note: this stays until the next daycycle/iptables -F. AMOUNT can have an SI suffix (K, M, G).

   net-control.py bonus AMOUNT [users...]\t Add bonus AMOUNT to this user's quota. Please note: this stays until the next month or iptables -F. AMOUNT can have an SI suffix (K, M, G).

   net-control.py daycycle [users...]\t Reset the cycle for a day. This zeros quotas. THIS ALSO UPDATES THE PER-USER QUOTA BASED ON HOW MUCH INTERNODE SAYS WE HAVE LEFT.

   net-control.py freeday\t Everyone gets a free quota day!

   If 'lock' or 'unlock' is very slow, this is because the /etc/resolv.conf is wrong, and is searching the internet for hostnames. Put nameserver 192.168.1.1 in first, and that should fix it.
"""

# Let the admin know how usage is going.
used, total = save_quota.get_pool()
print("{} remaining."
      "".format(human_readable(total - used, padding=False)))

# Set up the default logger.
LOGFMT = "(net-control)\t%(asctime)s %(message)s"
log.basicConfig(format=LOGFMT,
                filename="/var/log/funnelweb.log")
root_log = log.getLogger()
root_log.setLevel(log.DEBUG)

if __name__ == "__main__":
    args = sys.argv

    if len(args) == 1:
        print(USAGE)
        exit(0)

    if args[1] == "start":
        log.debug("Starting funnelweb")
        funnelcore.start()
        for u in configuration.query_quota_users():
            funnelcore.daycycle(u)
        exit(0)

    elif args[1] == "stop":
        log.debug("Stopping funnelweb")
        funnelcore.stop()
        exit(0)

    elif args[1] == "restart":
        log.debug("Restarting funnelweb")
        funnelcore.stop()
        funnelcore.start()
        for u in configuration.query_quota_users():
            funnelcore.daycycle(u)
        exit(0)

    unames = [x for x in args[2:] if x[:2] != "--"]
    opts = filter(lambda x: x[:2] == "--", args[2:])

    if args[1] == "lock":
        allow_unmetered = "control_metered"
        if "--full" in opts:
            allow_unmetered = "control_unmetered"

        log.debug("Locking {}".format(", ".join(unames)))
        for i in unames:
            devs = configuration.query_devices(i)
            for d in devs:
                locks.do_lock(d, allow_unmetered)

    elif args[1] == "unlock":
        log.debug("Unlocking {}".format(", ".join(unames)))
        if "all" in args[2:]:
            iptables.iptables("-F", "control_metered")
            iptables.iptables("-F", "control_unmetered")
        else:
            for i in unames:
                devs = configuration.query_devices(i)
                for d in devs:
                    locks.do_unlock(d, "control_metered")
                    locks.do_unlock(d, "control_unmetered")

    # Soft locks.
    # These shouldn't really be used by the admin much.
    elif args[1] == "soft-lock":
        for u in filter(configuration.is_user, unames):
            locks.do_soft_lock(u)
        for g in filter(configuration.is_group, unames):
            # Lock users in this group.
            for u in group_dict(get_group_description(g)[0])["users"]:
                locks.do_soft_lock(u)

    elif args[1] == "soft-unlock":
        for u in filter(configuration.is_user, unames):
            locks.do_soft_unlock(u)
        for g in filter(configuration.is_group, unames):
            for u in group_dict(get_group_description(g)[0])["users"]:
                locks.do_soft_unlock(u)

    elif args[1] == "table":
        if unames == [] or "all" in unames:
            print(tabulate("all"))
        else:
            print(tabulate(i for i in unames))

        if iptables.check_iptables("quota", "-j", "FreeDay"):
            print("** Free day today! **")

    elif args[1] == "add":
        amount = get_bytes(args[2])
        users = args[3:]
        log.debug("Adding {} of dynamic quota to {}"
                  .format(amount, ", ".join(users)))
        for user in users:
            save_quota.add_quota(user,
                                "fw:quota-dynamic",
                                amount)

    elif args[1] == "set":
        amount = get_bytes(args[2])
        users = args[3:]
        log.debug("Setting dynamic quota to {} for users {}"
                  .format(amount, ", ".join(users)))
        for user in users:
            save_quota.set_quota(user,
                                 "fw:quota-dynamic",
                                 0, 0, amount)

    elif args[1] == "bonus":
        # Note that this discards previous usage of any bonus quota.
        amount = get_bytes(args[2])
        users = args[3:]
        log.debug("Adding {} of monthly bonus quota to {}"
                  .format(amount, ", ".join(users)))
        for user in users:
            save_quota.set_quota(user,
                                 "fw:quota-bonus", # The extra quota slot.
                                 0, 0, amount)

    elif args[1] == "zero":
        if unames == [] or "all" in unames:
            for user in configuration.query_quota_users():
                save_quota.zero_quota(user, "fw:quota-dynamic")
        else:
            for user in unames:
                save_quota.zero_quota(user, "fw:quota-dynamic")

    elif args[1] == "daycycle":
        log.debug("Daycycling ({})".format(", ".join(unames)))
        # Clean up.
        try: os.remove("/etc/net-control/calculations")
        except OSError: pass

        # This should really only be called by our cron job.
        # This checks for the existance of the file "/etc/NOQUOTAS"
        funnelcore.free_day(os.path.isfile(NOQUOTAS))
        if unames == [] or "all" in unames:
            for i in configuration.query_quota_users():
                funnelcore.daycycle(i)
        else:
            for i in unames:
                funnelcore.daycycle(i)

    # Free quotas for a day.
    elif args[1] == "freeday":
        funnelcore.free_day(True)

    # update blacklist
    elif args[1] == "blacklist":
        funnelcore.update_blacklist("FORWARD")

    # update whitelist
    elif args[1] == "whitelist":
        funnelcore.update_whitelist("FORWARD")

    else:
        print(USAGE)
