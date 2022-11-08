# -*- mode: python; -*-
__doc__ = """Core Funnelweb functionality.

The important parts of Funnelweb are segmented off into this module. For actions which don't require full knowledge about the state of the table (e.g. locking users), this should not need to be imported. This module will contain things like all the setup logic (everything about how to start the software), as well as things like saving a running tally of usage (although this may be implemented in save_quota instead; haven't quite decided). Hopefully, this separation of command-parsing shell-scripty stuff (net-control.py) and logical, codey stuff (this module) will simplify maintenance, and speed up some frequently used actions.
"""

import sys, os
import commands # Unix commands in Python, woo!
import subprocess
import time

# Logging.
import logging as log

from net_tools import *
import save_quota
import locks, configuration
import iptables
import socket

# Set up the logging format.
log.basicConfig(format="(funnelcore)\t%(asctime)s %(message)s",
                filename="/var/log/funnelweb.log")


def start_nat():
    os.system("/root/nat start")
##    ADSL_MODEM_NAME = configuration.get_global_option("adsl-modem-name",  "adsl")
##    ADSL_PORT = configuration.get_global_option("adsl-port",  "eth1")
##
##    if not iptables.chain_exists("NAT_RUNNING"):
##          iptables.add_chain("NAT_RUNNING")
##          # Make resolv.conf right....
##          os.system("chmod +w /etc/resolv.conf")
##          os.system("cp /etc/resolve.conf.real /etc/resolv.conf")
##          os.system("chmod a-w /etc/resolv.conf")
##
##
##          # Set up the gateway
##
##          os.system("route del default gw" + ADSL_MODEM_NAME + " || true")
##          os.system("route del default gw" + ADSL_MODEM_NAME + " || true")
##
##          os.system("route add default gw " + ADSL_MODEM_NAME)
##
##          # Set up the NAT
##
##          os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
##
##          #This needs to be done by python iptables code...
##          os.system("iptables -t nat -F")
##
##          # again, for luck ;-)
##          os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
##          os.system("iptables -t nat -A POSTROUTING -o " + ADSL_MODEM_NAME + " -j MASQUERADE")
##
##          os.system("iptables -D FORWARD -i " + " ADSL_PORT " + " -m state --state NEW,INVALID  -j DROP 2> /dev/null >/dev/null || true")
##          os.system("iptables -D FORWARD -i " + " ADSL_PORT " + " -m state --state NEW,INVALID  -j DROP 2> /dev/null >/dev/null || true")
##          os.system("iptables -A FORWARD -i " + " ADSL_PORT " + " -m state --state NEW,INVALID  -j DROP")
##	  iptables.add_chain("NAT_RUNNING")
##          return True
    return False


def stop_nat():
    os.system("/root/nat stop")
##    ADSL_PORT = configuration.get_global_option("adsl-port",  "eth1")
##
##    if iptables.chain_exists("NAT_RUNNING"):
##        try:
##            os.system("iptables -t nat -D POSTROUTING -o" + ADSL_PORT + " -j MASQUERADE")
##            return iptables.del_chain("NAT_RUNNING")
##        except:
##            return # bad stuff ... 
    return True

def add_blacklist(name, filename="/etc/known-offenders", response = "REJECT"):
    """ Adds a blacklist chain to 'name'. """

    if iptables.chain_exists("blacklist"):
        try:
            iptables.iptables("-F", "blacklist")
        except subprocess.CalledProcessError as er:
            pass # We don't really care here.

    iptables.add_chain("blacklist")
    iptables.add_link(name, "blacklist")

    bads = [x for x in open(filename, "r").read().split("\n") \
                if len(x) > 4 and x[0] != "#"] # Sorry for the non-Pythonistas. Should be obvious.

    # Add each baddie to the chain.
    for evil in bads:
        iptables.add_link("blacklist", response, source=evil)

def update_blacklist(chain):
    add_blacklist(chain, "/etc/blacklist")

def add_armour(name, filename="/etc/known-offenders", response = "REJECT"):
    """ Adds an armour chain to 'name'. """

    ADSL_PORT = configuration.get_global_option("adsl-port",  "eth1")

    try:
        iptables.iptables("-F", "armour")
    except subprocess.CalledProcessError as er:
        pass

    batch = iptables.batch()

    if iptables.chain_exists("armour"):
        batch.add_link(name, "armour")

    else:
        batch.add_chain("armour")
        batch.add_link(name, "armour")

    # Allow a range of IP addresses in, despite the other blocks.
    #b_class_addrs = ["138.194", "140.79"," 140.81"," 146.118"," 150.229"," 152.83"]
    b_class_addrs  = []
    c_local = ["192.168.94"]
    c_sdf = ["192.94.73"]
    c_class_addrs = c_local + c_sdf

    allowed_ports = ["13","22","37","53","80","8080","110","113","123","126","143","177","194","443","873","989","990","993","994","995","1194","1494","6000","6010","6011","6012","6013"]

    # Add all of these allowed things.
    for ip in [b + ".0.0/16" for b in b_class_addrs]\
            + [c + ".0/24" for c in c_class_addrs]:
        for port in allowed_ports:
            # TCP traffic.
            batch.raw("-A", "armour", "-i", ADSL_PORT, "-p", "tcp",
                      "--dport", port, "-s", ip,
                      "-j", "ACCEPT")

            # UDP traffic.
            batch.raw("-A", "armour", "-i", ADSL_PORT, "-p", "udp",
                      "--dport", port, "-s", ip,
                      "-j", "ACCEPT")

    ## Forbidden addresses. ##
    bads = [x for x in open(filename, "r").read().split("\n") \
                if len(x) > 4 and x[0] != "#"] # Sorry for the non-Pythonistas. Should be obvious.

    # Add each baddie to the chain.
    for evil in bads:
        batch.add_link("armour", response, source=evil)

    # Stop strangers getting in on 22.
    batch.raw("-A", "armour", "-i", ADSL_PORT, "-p", "tcp",
              "--dport", "22", "-j", "REJECT")

    batch.raw("-A", "armour", "-i", ADSL_PORT,
              "-m", "state", "--state", "INVALID,NEW",
              "-j", "DROP")

    batch.commit()

def add_control(from_chain, tag=""):
    """ This is a chain designed to either contain REJECTs, or nothing.
    Nothing means the gate is open; REJECTS filter by source/destination.
    """
    iptables.add_chain("control_" + tag)
    iptables.add_link(from_chain, "control_" + tag)

def update_local_whitelist(filename="/etc/unmetered-locally.txt"):
    if iptables.chain_exists("local-whitelist"):
        iptables.iptables("-F","local-whitelist")
    else:
        iptables.add_chain("local-whitelist")

    iptables.add_link("whitelist", "local-whitelist")

    try:
        unmetered = [x for x in open(filename, "r").read().split("\n")\
                         if len(x) > 4 and x != "" and x[0] != "C"]
    except IOError:
        unmetered = []
    for i in unmetered:
        iptables.add_link("local-whitelist", "ACCEPT", source=i)
        iptables.add_link("local-whitelist", "ACCEPT", dest=i)

def add_whitelist(name, filename = "/etc/unmetered.txt"):

    if iptables.chain_exists("whitelist"):
        iptables.iptables("-F", "whitelist")

    else:
        iptables.add_chain("whitelist")

    batch = iptables.batch()

    batch.add_link(name, "whitelist")

    try:
        unmetered = [x for x in open(filename, "r").read().split("\n")\
                         if len(x) > 4 and x != "" and x[0] != "C"]
    except IOError:
        unmetered = []

    for i in unmetered:
        batch.add_link("whitelist", "ACCEPT", source=i)
        batch.add_link("whitelist", "ACCEPT", dest=i)

    batch.commit()

    update_local_whitelist()

def update_whitelist(chain):
    ret = os.system("/root/fix-unmetered-table")
    if ret != 0:
        log.warning("Error (%d) received while refreshing the whitelist file." % (ret))
    else:
        try:
            iptables.iptables("-F", "whitelist")
        except subprocess.CalledProcessError:
            pass # This will happen if the chain doesn't exist. Ignore it.

        finally:
            add_whitelist(chain)
            ## add_whitelist flushes the chain.  We'll append the unmetered locally

def add_quota_chain(name):
    """ Probably the most complex part of the whole affair. <-- Optimism from way ago.
    Each person may have 3-4 devices. Each device should count towards their total usage; both up- and down-loads.
    So, we need a per-person chain (to hold the quota information), and links to that person in the "quota" chain - which holds none of the actual counting itself, merely links to chains which do.
    """
    iptables.add_chain("quota")
    iptables.add_link(name, "quota")

    batch = iptables.batch()

    # Do stuff on each person, provided they need it.
    for user_item in configuration.query_users(full_spec=True):
        user = configuration.user_dict(user_item)
        name = user["username"]
        # Add a chain for this user.
        batch.add_chain(name)

        # Add links to the quota chain.
        for i in user["devices"]:
            try:
                IP = socket.gethostbyname(i)
            except socket.gaierror as er:
                log.error("We don't know any device by the name of {}; ignoring it.".format(i))
                continue

            # Add it to the list.
            batch.add_link("quota", name, source=IP)
            batch.add_link("quota", name, dest=IP)

        # Don't do anything if we don't need to.
        if user.get("quota"):
            # Restore the last saved quota state for the user.
            for var in save_quota.KNOWN_QUOTA_TYPES:
                pk, bt, tot = save_quota.load_quota(name, var)
                batch.quota_rule(name, var,
                                 pk, bt, tot)

        # And add the accept/reject rule at the end.
        # For quotad users, it's a REJECT at the end,
        # for others, a single ACCEPT rule in their chain.
        default_rule = "ACCEPT" if user.get("quota") else "REJECT"
        batch.add_link(name, default_rule)

        # Commit the changes.
        batch.commit()

        log.info("Added quota to " + name)

def daycycle(user):
    # Firstly, record how much they used.
    # We want this so that we can track the usage at the end of the day.
    for var in save_quota.KNOWN_QUOTA_TYPES:
        save_quota.save_quota(user, var)

    from configuration import get_user_option
    # Get the dynamically allocated quota.
    if get_user_option(user, "dynamic-quota", default=False):
        alloc_quota = calculate_quota(user, float(get_user_option(user, "shares", default=1.0)), use_running_total_as_base="yes")
    else:
        log.warning("No quota allocated for {}!".format(user))
        alloc_quota = 0

    static_alloc = get_bytes(get_user_option(user, "daily-static", "0M"))

    # Daily quotas should be reset daily (obviously...)
    save_quota.set_quota(user, "fw:quota-dynamic", 0, 0, alloc_quota)
    save_quota.set_quota(user, "fw:quota-static", 0, 0, static_alloc)
    
    # Monthly static/bonus quota is not overwritten until the end of the month.
    if datet.date.today().day == RESET_DATE:
        save_quota.set_quota(user, "fw:quota-bonus", 0, 0, 0)

    # Now, we need to write this to the log file, otherwise it will be borked if we suffer a power cut before the next write.
    # Keep the state consistent!
    for var in save_quota.KNOWN_QUOTA_TYPES:
        try:
            save_quota.save_quota(user, var)
        except ChainNotFoundException as er:
            log.warning("Ignoring ChainNotFound [{}]".format(er))

def free_day(is_free_day):
    """ Set the free-day status.
    "Free days" are not metered, and everyone gets unlimited quota.
    Passing False stops a free day.
    """
    try:
        if not iptables.rule_exists("quota", "-j FreeDay") and is_free_day:
            iptables.iptables("-I", "quota", "-j", "FreeDay") # Accept stuff straight away. No quotas are counted.
        else:
            if iptables.rule_exists("quota", "-j FreeDay"):
                iptables.del_link("quota", "FreeDay")
    except InvalidRule:
        pass

def start():
    ## Start ##
    if not iptables.chain_exists("FunnelWeb"):
        iptables.add_chain("FunnelWeb")
        log.debug("Adding armour...")
        add_armour("INPUT")#, "known-offenders") # Armour goes on INPUT.

        add_blacklist("FORWARD", "/etc/blacklist") # blacklist file

        log.debug("Adding unmetered lock...")
        add_control("FORWARD", tag="unmetered") # Block whitelisted stuff as well.

        log.debug("Adding whitelist...")
        update_whitelist("FORWARD")# Where is the whitelist file kept?

        log.debug("Adding metered lock...")
        add_control("FORWARD", tag="metered") # Only block metered stuff.

        log.debug("Adding quota chains...")
        add_quota_chain("FORWARD") # Add quotas to it, which handle accepts.

        log.debug("Guests do not have access by default.")
        iptables.add_link("FORWARD", "REJECT") # Can be ACCEPT if you want guests to have uncounted access automagically.

        iptables.del_chain("FreeDay")
        iptables.add_chain("FreeDay")
        iptables.add_link("FreeDay","ACCEPT")

        log.debug("Starting NAT.")
        start_nat()

def stop():
    # Save quotas for everyone.
    log.debug("Saving quota usage...")
    if iptables.chain_exists("FunnelWeb"):
        iptables.del_chain("FunnelWeb")
        for user in configuration.query_quota_users():
            save_quota.save_quota(user, "fw:quota-dynamic")
            save_quota.save_quota(user, "fw:quota-bonus")


    # Now, erase iptables.
    iptables.iptables("-F")
    iptables.iptables("-X")
    iptables.iptables("-vL")
    stop_nat()
