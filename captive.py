# -*- mode: python; -*-
__doc__ = """ Control the captive portal.

This module is used to control access by unregistered devices to the internet. It needs to be partnered with some sort of CGI login page which handles adding that device to the "accepted" list.
"""

import iptables
from auth import authenticate

CAPTIVE_PORTAL_ADDR = "192.168.1.1:6680"

def init_captive():
    """ Start up the captive portal rules.

    This mainly happens in the nat table, and should initialise the state so that every device is redirected to login. Later, all "known" devices in the config file should be skipped from the captive portal, so that users don't have to log in every time.

    Note: we only redirect TCP traffic on ports 80, 443, so other stuff will be missed. This is a user-friendliness design decision: if we redirect other traffic, the user may be unable to see what caused it. Of course, the default "DROP" rule in the `filter` table will kill those packets anyway, but it should be more obvious than a redirect to our server.
    """

    iptables.iptables("-t", "nat", "-N", "captive-portal")
    iptables.iptables("-t", "nat", "-A", "PREROUTING",
                      "-j", "captive-portal")

    # Plain HTTP.
    iptables.iptables("-t", "nat", "-A", "captive-portal",
                      "-p", "tcp", "--dport", "80",
                      "-j", "DNAT", "--to-destination", CAPTIVE_PORTAL_ADDR)

    # HTTPS.
    iptables.iptables("-t", "nat", "-A", "captive-portal",
                      "-p", "tcp", "--dport", "443",
                      "-j", "DNAT", "--to-destination", CAPTIVE_PORTAL_ADDR)

def register_device(ip_addr):
    """ Acknowledge a device.

    This adds a skip rule so that the captive portal no longer eats this device's traffic.
    """
    iptables.iptables("-t", "nat", "-I", "captive-portal",
                      "-s", ip_addr, "-j", "RETURN")


def unregister_device(ip_addr):
    """ Remove a device from the exceptions.
    """
    iptables.iptables("-t", "nat", "-D", "captive-portal",
                      "-s", ip_addr, "-j", "RETURN")
