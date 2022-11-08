#!/funnelweb/python-env/bin/python
# -*- mode: python; -*-

import web
 
import net_tools
import locks
import devices, configuration
from save_quota import QUOTA_EXCEEDED_SENTINEL

class Usage(object):
    def __init__(self):
        self.user = None
        self.usage = {"fw:quota-dynamic": [0, 0, 0],
                      "fw:quota-static": [0, 0, 0],
                      "fw:quota-bonus": [0, 0, 0]}

        self.sentinel = QUOTA_EXCEEDED_SENTINEL
        self.render = web.template.render("templates/", base="base")

    def GET(self):
        self.user = self.get_user()
        try:
            self.update()
        except:
            # This happens when it can't find the appropriately named user.
            # We'll just pretend we found some usage.
            pass

        return self.render.usage(
            user = self.user,
            
            msg_dyn = self.get_usage("fw:quota-dynamic"),
            msg_sta = self.get_usage("fw:quota-static"),
            msg_bon = self.get_usage("fw:quota-bonus"),
            
            lock = self.get_lock(),
            percent = self.get_percent(),
            )

    def get_user(self):
        IP = web.ctx["ip"] or "0.0.0.0"
        real_name = devices.canonical_name(IP)
        owner = configuration.get_device_owner(real_name)
        return owner or None

    def update(self):
        import save_quota
        self.usage = {"fw:quota-dynamic": [0, 0, 0],
                      "fw:quota-static": [0, 0, 0],
                      "fw:quota-bonus": [0, 0, 0]}

        for var in self.usage:
            m = save_quota.read_quota(self.user, var, True)
            self.usage[var][0] += m[0]
            self.usage[var][1] += m[1]
            self.usage[var][2] += m[2]
        
    def get_usage(self, var = "fw:quota-dynamic"):
        if self.user is None:
            return "0", "0"
        packets, b_tes, total = self.usage[var]
        stat = net_tools.human_readable(b_tes), net_tools.human_readable(total)
        if total == self.sentinel: # Sentinel value.
            with open("/var/log/fw/" + self.user) as ff:
                return net_tools.human_readable(ff.read()) + " - (exceeded limit)"
        else:
            return "{} / {}".format(*stat)

    def get_percent(self):
        if self.user is None:
            return "???%"

        b_tes = sum(self.usage[v][1] for v in self.usage)
        total = sum(self.usage[v][2] for v in self.usage)
        
        if total == 0: total = 1
        return "{:.1%}".format(float(b_tes) / total)

    def get_lock(self):
        IP = web.ctx["ip"] or "0.0.0.0"
        if locks.is_locked(IP, do_ip_lookup = False):
            return "You are locked."
        elif self.user is not None and locks.is_soft_locked(self.user):
            return "You are soft-locked."
        else:
            return "You are not locked."
