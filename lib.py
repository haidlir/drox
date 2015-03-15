# The MIT License (MIT)

# Copyright (c) 2015 haidlir

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""
This component stores libraries for the application.
"""

from __future__ import print_function
from bucket import bucket

def curr_to_capacity(curr):
    capacity = {
      1   : 10,
      2   : 10,
      4   : 100,
      8   : 100,
      16  : 1000,
      32  : 1000,
      64  : 10000
    }
    return capacity[127 & curr]

class PortDetail(object):
    def __init__(self, index, name, port_no, state, capacity):
        self.index = index
        self.name = name
        self.port_no = port_no
        self.state = state
        self.capacity = capacity
        self.upload = 0
        self.__name__ = name

    def set_load(self, load = 0):
        self.upload = load

    def _repr__(self):
        return "%s:%s:(%s/%sMbps)" % (self.name, self.port_no, self.upload,
                                                               self.capacity)

class LinkDetail(object):
    def __init__(self, dpid, capacity, interface):
        self.dpid = dpid
        self.capacity = capacity
        self.interface = interface
        self.update_load()

    def update_load(self):
        self.load = bucket.port_info[self.dpid][self.interface].upload
        self.metric = self.calc_metric()
        # print(self.__repr__())

    def calc_metric(self):
        return 10**2/float(self.capacity-self.load)

    def __repr__(self):
        return "capacity= %s; load = %s; metric = %s" % (self.capacity,
                                                         self.load,
                                                         self.metric)

class ARPDets(object):
    def __init__(self, dpid, port, mac_addr, time = 0):
        self.dpid = dpid
        self.port = port
        self.mac_addr = mac_addr
        # self.time = time

class OneWayPath(object):
    def __init__(self, path, source):
        self.path = path
        self.source = source
        # self.metric = self.calc_metric()

    def calc_metric(self):
        temp_metric = 0
        for i in range(len(self.path)):
            if i == 0:
                temp_metric = bucket.matrix_adj[self.source][self.path[i]].metric
            else:
                temp_metric += bucket.matrix_adj[self.path[i-1]][self.path[i]].metric
        return temp_metric  

    def get_metric(self):
        return self.calc_metric()

class FlowEntry(object):
    def __init__(self, nw_src, nw_dst, nw_proto, tp_src, tp_dst, in_port, out_port, path = [], **opts):
        self.nw_src = nw_src
        self.nw_dst = nw_dst
        self.nw_proto = nw_proto
        self.tp_src = tp_src
        self.tp_dst = tp_dst
        self.in_port = in_port
        self.out_port = out_port
        self.path = path
        if 'dpid' in opts:
            self.initial_dpid = opts['dpid']
        else:
            self.initial_dpid = bucket.arp_table[nw_src].dpid
        self.bps = 0.
        self.byte_count = 0.

    def __repr__(self):
        return "%s:%s >%s> %s:%s |%s| %s Mbps" % (self.nw_src, self.tp_src,\
                                               self.nw_proto, self.nw_dst, \
                                               self.tp_dst, self.path, self.bps/10.**6)
