# -*- mode: python; -*-
import sys, os

import subprocess
from subprocess import check_output
import tempfile, shutil # For temporary fifos.

import re
import logging as log
log.basicConfig(format="(iptables)\t%(asctime)s %(message)s",
                filename="/var/log/funnelweb.log")

# We need this so we can limit how often the table is updated.
import time

from errors import *

# Get the entire chain from iptables-save.
#WHOLE_IPTABLE = #check_output(["/usr/bin/sudo", "/sbin/iptables-save", "-c"]).split("\n") # Split by lines.

class _iptable_list (object):
    """ A container class specifically for storing iptables-save output.

    This class will automatically call iptables-save if its contents become too stale.
    """
    def __init__(self):
        # Our contents.
        self.data = []
        self.text = ""

        # Keep track of how frequently we should update.
        self.update_interval = 30.0 # in seconds.

        # When we last updated the contents.
        self.last_refresh = 0.0

        # This is necessary for some reason; without it, we try to add the chains lots.
        # I think there's a bit of a nasty bug hidden by this, but I'm busy doing other things at the moment.
        self.refresh(time.time())

    def refresh(self, now):
        log.info("Updating cached table.")
        self.data = []
	# Note: a possible bug could occur when iptables-save's output is longer than 2^16 bytes.
	# See http://thraxil.org/users/anders/posts/2008/03/13/Subprocess-Hanging-PIPE-is-your-enemy/ for more information.
	# I don't know if this also affects check_output; it may be immune.
        self.text = check_output(["/usr/bin/sudo",
                                "/sbin/iptables-save",
                                "-c"])
        self.data = self.text.split("\n")

        self.last_refresh = now

    def __getitem__(self, k):
        now = time.time()
        # Update if necessary.
        if now - self.last_refresh < self.update_interval:
            self.refresh(now)
        return self.data[k]

    def __len__(self):
        return len(self.data)

    def __iter__(self):
        return iter(self.data)

    def __contains__(self, k):
        return k in self.data

# The table
WHOLE_IPTABLE = _iptable_list()

def refresh():
    WHOLE_IPTABLE.refresh(time.time())

def unique(listn):
    """ Strip a list of all non-unique elements, preserving order."""
    uq = []
    for i in listn:
        if i not in uq:
            uq.append(i)
    return uq

def iptables(*args):
    actual_args = ["/usr/bin/sudo", "/sbin/iptables"] # Always include sudo, and always include the full path if you aren't using shell=True
    for i in args: actual_args.append(str(i))
    log.info("calling raw iptables with {}".format(actual_args))
    return check_output(actual_args, stderr=subprocess.STDOUT)

def batch_iptables(tablestring):
    """ Use iptables-restore to add a large number of rules to the table.

    This will not replace the current table.
    """
    proc = subprocess.Popen(["/usr/bin/sudo", "/sbin/iptables-restore",
                             "-n", "-c"],
                             stdin=subprocess.PIPE)

    proc.stdin.write("*filter\n")
    proc.stdin.write(tablestring + "\n")
    proc.stdin.write("COMMIT\n")
    proc.stdin.close()

    proc.wait()
    log.debug("called batch_iptables as a function;")

class batch(object):
    """ A class for generating batch iptables commands.

    Once you've got a set of things lined up, call batch.commit() to actually call iptables-restore.
    """

    def __init__(self):
        self.cmd = ""

    def add_chain(self, name):
        mod = ":" + name + " - [0:0]\n"
        self.cmd += mod
        return mod

    def add_link(self, chain, target, packets = 0, b_tes = 0,
                 source = None, dest = None):
        filters = ""
        if source:
            filters += " -s " + source
        if dest:
            filters += " -d " + dest

        mod = "[{p}:{b}] -A {n} -j {d}{sd}\n".format(n = chain,
                                                     d = target,
                                                     p = packets,
                                                     b = b_tes,
                                                     sd = filters)
        self.cmd += mod
        return mod

    def quota_rule(self, chain, var, pk, bt, total):
        mod = "[{p}:{b}] -A {n} -m quota --quota {t} -m comment --comment {c} -j ACCEPT\n".format(
            n = chain,
            c = var,
            t = total,
            p = pk,
            b = bt
            )
        self.cmd += mod
        return mod

    def raw(self, *args, **kwargs):
        """ A nearly raw string representation of the args. """
        pk = bt = 0
        if "packets" in kwargs:
            pk = kwargs["packets"]
        if "bytes" in kwargs:
            bt = kwargs["bytes"]

        mod = "[{p}:{b}] {ar}\n".format(p = pk, b = bt,
                                        ar = " ".join(args))
        self.cmd += mod
        return mod

    def commit(self):
        """ Use iptables-restore to add a large number of rules to the table.

        This will not replace the current table.
        """
        if self.cmd == "": return

        proc = subprocess.Popen(["/usr/bin/sudo", "/sbin/iptables-restore",
                                 "-n", "-c"],
                                 stdin=subprocess.PIPE)

        proc.stdin.write("*filter\n")
        proc.stdin.write(self.cmd + "\n")
        proc.stdin.write("COMMIT\n")
        proc.stdin.close()

        proc.wait()
        log.debug("committed changes with batch.commit.")
        self.cmd = ""

    def DEBUG(self, fname = "batch-iptables.log"):
        with open(fname, "w") as ff:
            ff.write("*filter\n")
            ff.write(self.cmd + "\n")
            ff.write("COMMIT\n")

def get_from_iptablesave(name, field_regexp = ".*", field_num = 0):
    """ Get a part of the iptables-save output, basic filtering by name, using a regexp to filter further. """
    lines = [x for x in WHOLE_IPTABLE # loop over iptables-save.
             if name in x] # Only get matching things.

    relines = [re.match(field_regexp, x) for x in lines]
    rematches = [x.group(field_num) for x in relines if x != None] # list of matches.

    return unique(rematches)

def get_quota_groups(chain = "quota"):
    """ Get a list of usernames which have a quota associated with them.
    These will all be chains linked to 'chain' (quota),
    eg.   '-A quota -s 192.168.1.1/32 -j Username'
    """
    raw = [x.split(" ")[-1] # Last word
           for x in WHOLE_IPTABLE
           if "-A quota" in x]
    return sorted(set(raw))

def get_rule_number(chain, match):
    lines = [x for x in WHOLE_IPTABLE if "-A " + chain in x]
    for i, l in enumerate(lines):
        if match in l:
            return i + 1 # iptables is 1-indexed.
    return -1 # We could also return 0 here, but -1 is definitely an error.

def add_chain(name):
    log.info("adding chain {}".format(name))
    ret = os.system("iptables -N %s" % name)
    if ret != 0:
        log.error("Couldn't add %s, iptables returned %d." % (name, ret))

def flush_chain(name):
    try:
        return iptables("-F",name)
    except:
        return # No chain?

def del_chain(name):
    try:
        flush_chain(name)
        return iptables("-X", name)
    except subprocess.CalledProcessError as er:
        log.info("attempting to delete a chain; {}".format(name))
        return True # The chain didn't exist, so there was nothing to delete.

def add_link(name, target, source = "", dest = ""):
    log.info("linking; {} => {}; -s '{}' -d '{}'".format(name, target, source, dest))
    if source:
        iptables("-A", name, "-s", source, "-j", target)
    elif dest:
        iptables("-A", name, "-d", dest, "-j", target)

    else:
        iptables("-A", name, "-j", target)

def del_link(name, target, source="", dest=""):
    log.info("attempting to delete a link; {} => {}".format(name, target))
    try:
        call = ["-D", name, "-j", target]
        if source: call += ["-s", source]
        if dest: call += ["-d", dest]
        return iptables(*call)
    except subprocess.CalledProcessError as er:
        # The chain/rule didn't exist, so there was nothing to delete.
        return InvalidRule("-j {} (-s {}; -d {})".format(target, source, dest), name)

#######################################
# Check for chains or rules existing. #
#######################################
def chain_exists(name):
    return True if get_from_iptablesave(":" + name) else False

def rule_exists(chain, description = "", mode = "-A",
                extended = True):
    """ Test for rule existence.

    If `extended`, use regexps on the whole table.
    Also, returns list of matches rather than a boolean. [] for no matches/logical false.
    """
    if not extended:
        test = mode + " " + chain + " " + description
        return test in WHOLE_IPTABLE
    else:
        # We ignore the description, and only test chain.
        found = re.findall(chain, WHOLE_IPTABLE.text)
        return found

def check_iptables(*args):
    try:
        ret = iptables("-C", *args) or True
    except subprocess.CalledProcessError as er:
        ret = False
    return ret
