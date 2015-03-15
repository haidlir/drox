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
This component provides forwarding function
"""

from __future__ import print_function
from random import randint

from pox.core import core
import pox.openflow.libopenflow_01 as of
from config import config
from bucket import bucket
import routing

import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr,EthAddr
from lib import *


class Forwarding(object):

    def send_flow_mod(self, dpid, msg):
        core.openflow.sendToDPID(dpid, msg)

    @classmethod
    def _handle_internal(cls, event):

        def getPath(src, dst):
            print('called')
            if config.LOCAL_ROUTING == 'DFS':
                print('DFS')
                return routing.DFS.getPath(src, dst)
            elif config.LOCAL_ROUTING == 'Djisktra':
                pass

        try: # coba dulu udah ada routing table-nya belum.
            if event.dpid == bucket.arp_table[event.parsed.next.dstip].dpid:
                path = [event.dpid]
            else:
                print('sip')
                path = [event.dpid] + getPath(event.dpid, bucket.arp_table[event.parsed.next.dstip].dpid)
        except:
            try:
                core.main._routing()
                print('here')
                path = [event.dpid] + getPath(event.dpid, bucket.arp_table[event.parsed.next.dstip].dpid)
            except:
                print('Tidak ada di tabel routing [%s]' % event.parsed)
                return

        msg = of.ofp_flow_mod()
        msg.priority = 42
        msg.match = of.ofp_match.from_packet(event.parsed)
        msg.idle_timeout = 10
        msg.hard_timeout = 20

        used = True
        while(used):
            cookie = randint(0,2**64-1) # ukuran cookie itu 64 bit, dengan all 1s is reserved
            for dpid_cek in bucket.flow_entry:
                if cookie in bucket.flow_entry[dpid_cek]:
                    used = True
                    break
                else:
                    used = False
            if not used:
                break

        msg.cookie = cookie

        for i in reversed(range(len(path))):
            msg.actions = []
            if i == 0:
                msg.in_port = event.port
                msg.data = event.ofp # terlalu beresiko
                # print('    keluarin data dari buffer')
            else:
                msg.in_port = bucket.matrix_adj[path[i]][path[i-1]].interface
                msg.data = None

            if not event.parsed.next.srcip.inNetwork('172.16.0.0/23'):
                msg.actions.append(of.ofp_action_dl_addr.set_dst(bucket.arp_table[event.parsed.next.dstip].mac_addr))

            if i == len(path)-1:
                msg.actions.append(of.ofp_action_output(port = bucket.arp_table[event.parsed.next.dstip].port))
                msg_outport = bucket.arp_table[event.parsed.next.dstip].port
            else:
                msg.actions.append(of.ofp_action_output(port = bucket.matrix_adj[path[i]][path[i+1]].interface))
                msg_outport = bucket.matrix_adj[path[i]][path[i+1]].interface

            core.openflow.sendToDPID(path[i], msg)
            if msg.match.nw_src in bucket.arp_table:
                bucket.flow_entry[path[i]][msg.cookie] = FlowEntry(msg.match.nw_src,\
                                                                   msg.match.nw_dst,\
                                                                   msg.match.nw_proto,\
                                                                   msg.match.tp_src,\
                                                                   msg.match.tp_dst,\
                                                                   msg.in_port,\
                                                                   msg_outport,\
                                                                   path)
            elif path[i] in bucket.gateway:
                bucket.flow_entry[path[i]][msg.cookie] = FlowEntry(msg.match.nw_src,\
                                                                   msg.match.nw_dst,\
                                                                   msg.match.nw_proto,\
                                                                   msg.match.tp_src,\
                                                                   msg.match.tp_dst,\
                                                                   msg.in_port,\
                                                                   msg_outport,\
                                                                   path,\
                                                                   dpid = path[i])                                    

    @classmethod
    def _handle_external(cls, event):

        gw = algorithm.get_gw(event.dpid)

        if gw == None: # Gateway is not available or there is no path from dpid_src onto the gateway
            return

        try: # coba dulu udah ada routing table-nya belum.
            if event.dpid == gw:
                path = [event.dpid]
            else:
                path = [event.dpid] + algorithm.get_path_01(event.dpid, gw)
        except:
            try:
                core.main._findPaths()
                path = [event.dpid] + algorithm.get_path_01(event.dpid, gw)
            except:
                print('Tidak ada di tabel routing')

        msg = of.ofp_flow_mod()
        msg.priority = 42
        msg.match = of.ofp_match.from_packet(event.parsed)
        msg.idle_timeout = 10
        msg.hard_timeout = 60

        used = True
        while(used):
            cookie = randint(0,2**64-1) # ukuran cookie itu 64 bit, dengan all 1s is reserved
            for dpid_cek in bucket.flow_entry:
                if cookie in bucket.flow_entry[dpid_cek]:
                    used = True
                    break
                else:
                    used = False
            if not used:
                break

        msg.cookie = cookie
        
        for i in reversed(range(len(path))):
            if i == 0:
                msg.in_port = event.port
                msg.data = event.ofp
            else:
                msg.in_port = bucket.matrix_adj[path[i]][path[i-1]].interface

            if i == len(path)-1:
                    msg.actions = [of.ofp_action_dl_addr.set_src(EthAddr('02:00:00:00:00:24')),\
                                   of.ofp_action_dl_addr.set_dst(bucket.arp_table[bucket.gateway[gw].next_hop].mac_addr),\
                                   of.ofp_action_output(port = bucket.gateway[gw].port_no)]
                    msg_outport = bucket.gateway[gw].port_no

            else:
                msg.actions = [of.ofp_action_output(port = bucket.matrix_adj[path[i]][path[i+1]].interface)]
                msg_outport = bucket.matrix_adj[path[i]][path[i+1]].interface

            core.openflow.sendToDPID(path[i], msg)
            bucket.flow_entry[path[i]][msg.cookie] = FlowEntry(msg.match.nw_src,\
                                                               msg.match.nw_dst,\
                                                               msg.match.nw_proto,\
                                                               msg.match.tp_src,\
                                                               msg.match.tp_dst,\
                                                               msg.in_port,\
                                                               msg_outport,\
                                                               path)