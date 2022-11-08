# -*- mode: python; -*-
__doc__ = """ Add devices to Funnelweb, live.

This should provide functionality for adding devices to Funnelweb's "known" set without rebooting.
Also included is code to find the MAC address of a computer on the local network based on its IP address. This might be useful for e.g. a login page.
"""

import socket
import subprocess
import iptables
import configuration

from errors import DeviceNotFoundException, UserNotFoundException

# Used to query the list of devices.
import sexpy

import logging as log
log.basicConfig(format="(devices)\t%(asctime)s %(message)s",
                filename="/var/log/funnelweb.log")

def host_exists(name):
    """ Query whether a host exists, by hostname or IP. """
    try:
        mac = get_mac_from_ip(name)
    except DeviceNotFoundException:
        return False
    return True

def get_mac_from_ip(ip_addr):
    """ Find a device's MAC address using ARP.

    This requires that devices be on the same network segment.
    """
    cmd = "arp -n {}".format(ip_addr)
    out = subprocess.check_output(cmd)
    if "no entry" in out:
        raise DeviceNotFoundException(ip_addr, " (MAC lookup by IP)")
    else:
        # The output of arp -n looks like:
        # Address                  HWtype  HWaddress           Flags Mask            Iface
        # 192.168.1.104            ether   8c:3a:e3:61:cc:53   C                     eth0
        # 192.168.1.62                     (incomplete)                              eth0
        second = out.split("\n")[1]
        if "(incomplete)" in second:
            raise DeviceNotFoundException(ip_addr, " (failed MAC lookup; incomplete)")
        return second.split()[2]

def _make_machine_map():
    try:
        subprocess.call(["/etc/make-machine-map"])
    except subprocess.CalledProcessError as er:
        print(er)

def recognise_device(hostname, ip_addr, mac_addr):
    """ Add a device.

    Append a device to dnsmasq.dhcp-hosts, which is then updated with /etc/make-machine-map.
    This should let all the network components know about the new device. Hopefully, it can then be added to Funnelweb in a way which doesn't break everything.
    """
    line = "dhcp-host={mac},{desired_ip},{hostname}\n".format(mac=mac_addr,
                                                            desired_ip=ip_addr,
                                                            hostname=hostname)

    with open("/etc/dnsmasq.dhcp-hosts", "a+") as dhcphosts:
        # We need to make sure that we're not overwriting an existing rule.
        cur = dhcphosts.readlines()
        preexisting_lines = [x for x in cur
                             if mac_addr in x
                             and "#" != x.strip()[0]]
        if preexisting_lines != []:
            print("The device with MAC address <{}> is already known!\n".format(mac_addr))
            print("It is currently known as: {}".format(x[2:] for x in preexisting_lines))
            return

        # Now, append to the dhcphosts file.
        dhcphosts.write(line)

    # Now, regenerate things with a call to make-machine-map.
    _make_machine_map()

    # And it should be added now.

def forget_device(hostname = None, ip_addr = None, mac_addr = None):
    """ Forget a device.

    Does the reverse of recognise_device.
    One of the three parameters must be specified!

    Also, this reads the whole file, removes the line containing the unwanted device, then rewrites the whole file sans that line.
    It would be more efficient to do this differently (e.g. line-by-line into a file that's moved into place), but that's a job for later.
    """
    if hostname is None and ip_addr is None and mac_addr is None:
        raise TypeError("You must provide one of [hostname, ip_addr, mac_addr]!")

    with open("/etc/dnsmasq.dhcp-hosts", "r") as ff:
        lines = ff.readlines()

    # Filter the lines, removing the one we don't want.
    if hostname is not None:
        lines = [x for x in lines if hostname not in x]
    if ip_addr is not None:
        lines = [x for x in lines if ip_addr not in x]
    if mac_addr is not None:
        lines = [x for x in lines if mac_addr not in x]

    # Now, rewrite the file without the lines referring to our soon-to-be-forgotten device.
    with open("/etc/dnsmasq.dhcp-hosts", "w") as ff:
        for line in lines:
            ff.write(line)

    # Update the conf files.
    _make_machine_map()

def add_device_to_user(device, user, uses_quota=True):
    """ Add a device to a user's quota chain.

    This also modifies the config file.
    Note: you only need to do this for devices which should count to a user's quota! Others can be ignored.
    """
    # Do the iptables add.
    if uses_quota:
        ip = socket.gethostbyname(device)
        iptables.add_link("quota", user, source=ip)
        iptables.add_link("quota", user, dest=ip)

    # And also add it to the configuration file.
    with configuration.read_config() as conf:
        configuration.add_device(conf, user, device)

def remove_device_from_user(device, user):
    """ The opposite of add_device_to_user.

    No semantic differences. We need the username because the device might appear in groups too.
    """
    ip = socket.gethostbyname(device)
    try:
        iptables.del_link("quota", user, source=ip)
        iptables.del_link("quota", user, dest=ip)
    except InvalidRule as er:
        # We don't really mind so much if this fails.
        pass

    # Update the config file too.
    with configuration.read_config() as conf:
        configuration.remove_device(conf, user, device)

def canonical_name(dev):
    """ Convert a name into a canonical form.

    This should map IP addresses, fully-qualified hostnames, and any aliases all to one single "real" hostname. Note that this may in fact return an IP address, but in that case, the device will *only* be known by that address.

    If no name could be found, return the given name, or None.
    """

    # First, get the corresponding IP.
    try:
        socket.inet_aton(dev)
        ip = dev # The name was a valid IP address.
    except socket.error:
        ip = socket.gethostbyname(dev)

    # Next, look up the "proper" name.
    # This will be the first alias that matches any device in
    # the config file.
    try:
        name, aliases, ipaddrs = socket.gethostbyaddr(ip)
        # Name might be a FQHN
        aliases.insert(0, name.split('.')[0])
    except socket.herror:
        name = ""
        aliases = []

    # Iterate over all these options.
    for thing in [name] + aliases:
        if thing in configuration.query_devices():
            return thing

    return dev or None
