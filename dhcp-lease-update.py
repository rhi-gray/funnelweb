#!/funnelweb/python-env/bin/python

import configuration, iptables

import sys

def add(mac, ip, hostname = None):
    """ Called when dnsmasq hands out a new DHCP lease.

    If the hostname (or IP address) is found in the config file, this adds a jump link in the quota chain to the user's chain.

    TODO:
      Otherwise, it should set up packet flagging so that the user is redirected to a login page.
    """
    if hostname is None: hostname = ip

    if hostname in configuration.query_devices():
        # We know you!
        # Find the user you belong to.
        user = configuration.get_device_owner(hostname)

        # Add rules iff necessary.
        if not iptables.check_iptables("quota", "-s", hostname,
                                       "-j", user):
            iptables.add_link("quota", user, source=hostname)

        if not iptables.check_iptables("quota", "-d", hostname,
                                       "-j", user):
            iptables.add_link("quota", user, dest=hostname)

    else:
        # TODO: some more processing here.
        pass

def remove(mac, ip, hostname = None):
    """ Called when a DHCP lease expires.

    We will remove any links to a user chain here.
    """
    if hostname is None: hostname = ip

    if hostname in configuration.query_devices():
        # If it's not in the config, we don't know who it belongs to. It will therefore not have any jumps in the quota chain (we think).
        user = configuration.get_device_owner(hostname)
        try:
            iptables.del_link("quota", user, source=hostname)
            iptables.del_link("quota", user, dest=hostname)
        except InvalidRule as er:
            # The rules didn't exist. We don't care, we just want them gone.
            pass

if __name__ == "__main__":
    args = sys.argv[1:]

    with open("/var/log/dhcp-script", "a") as f:
        f.write("Asked to {} a device. {}\n"
                .format(args[0], str(args[1:])))
    # Operation type. May be "add", "del", "old", or something else.
    if args[0] == "add" or args[0] == "old":
        # We handle "old" in the same way.
        add(*args[1:])
    elif args[0] == "del":
        remove(*args[1:])
    else:
        print("TODO: handle DHCP lease event '{}'"
              .format(args[0]))
