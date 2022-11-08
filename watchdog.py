#!/usr/bin/env python2
# -*- mode: python; -*-

import iptables   # So we can control when the cache is updated.
import locks      # To lock users who have exceeded their allocated limit.
import save_quota # To inspect usage.
import time       # To sleep with.
import os         # For making directories.
import configuration
import logging as log
from errors import *

frequency = 5 * 60.0
subjects = configuration.query_quota_users()

EXCESS_LOG_ROOT = "/var/log/fw/"

LOGFMT = "(watchdog)\t%(asctime)s %(message)s"
log.basicConfig(format=LOGFMT,
                filename="/var/log/funnelweb.log")

def process():
    """ Ensure no-one goes over their quota.

    This checks all the bequotad users and makes sure no-one exceeds their limit.
    """
    # Update the cached table.
    iptables.WHOLE_IPTABLE.refresh(time.time())

    # Check all our subjects.
    for user in subjects:
        total_allowed = total_used = 0
        for var in save_quota.KNOWN_QUOTA_TYPES:
            try:
                p, b, t = save_quota.read_quota(user, var)
                # Second condition because we usually exceed the sentinel value, due to packets being wrong size etc.
                if b > t and t != save_quota.QUOTA_EXCEEDED_SENTINEL:
                    # This rule has been exceeded.
                    # First, record how much we used.
                    try:
                        os.mkdir(EXCESS_LOG_ROOT)
                    except OSError as er: pass
                
                    with open(EXCESS_LOG_ROOT + user.name, "w") as ff:
                        ff.write(str(b))
    
                    log.info("{user} overflowed their quota (type {typ}). Nulling."
                             .format(user=user, typ=var))

                    # Set the quota to be (practically) 0.
                    save_quota.set_quota(user, var, 1,
                                        # Used too much.
                                        save_quota.QUOTA_EXCEEDED_SENTINEL,
                                        save_quota.QUOTA_EXCEEDED_SENTINEL)

            except ChainNotFoundException as er:
                log.warning("{user} was declared in the config file, but does not appear in the chains."
                            .format(user=user))
                
def main():
    import sys
    global frequency

    try:
        ind = sys.argv.index("-t")
        frequency = float(sys.argv[ind + 1])
    except ValueError:
        pass

    if "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: watchdog [-t interval] [-p/--persist]")
        print("-p\t Persist, checking every 5 minutes. Default is to run once")
        print("-t\t Seconds to sleep between checks")
        print("-h\t Show this help")
        exit(0)

    elif "-p" in sys.argv or "--persist" in sys.argv:
        while True:
            process()
            time.sleep(frequency)

    else:
        # Execute once.
        process()
            
if __name__ == "__main__":
    main()
