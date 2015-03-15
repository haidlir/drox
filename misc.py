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
This is the misc component of the application, which contains miscellaneous functions
to support the application.
"""
from __future__ import print_function
import time
from random import randint
from pox.core import core
import pox.openflow.libopenflow_01 as of
from bucket import bucket
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr,EthAddr
from lib import *

log = core.getLogger()

# DHCP Function
# Copyright 2013 James McCauley
# This file is derived from the proto in POX, which was developed by James McCauley.
# Modified by Haidlir Naqvi

class DHCPLease (object):
    """
    Raised when a lease is given

    Call nak() to abort this lease
    """
    def __init__ (self, host_mac, ip):
        super(DHCPLease, self).__init__()
        self.host_mac = host_mac
        self.ip = ip
        self._nak = False

    def nak (self):
        self._nak = True

class DHCP(object):

    server_addr = router_addr = IPAddr('172.16.0.1')
    dns_addr = IPAddr('8.8.8.8')

    lease_time = 60 * 60 # An hour
    pool = [IPAddr('172.16.0.'+ str(x)) for x in range(2,255)]
    pool += [IPAddr('172.16.1.'+ str(x)) for x in range(0,254)]
    subnet = IPAddr('255.255.0.0')


    offers = {} # Eth -> IP we offered
    leases = {} # Eth -> IP we leased

    @classmethod
    def _handle_dhcp(cls, event):
        # dhcp_packet = event.parsed.find('ipv4')
        # dhcp_segment = dhcp_packet.payload
        # dhcp_app = dhcp_segment.payload
        dhcp_app = event.parsed.find('dhcp')

        if not dhcp_app:
            log.debug("%s: no packet", str(event.connection))
            return
        if not isinstance(dhcp_app, pkt.dhcp):
            log.debug("%s: packet is not DHCP", str(event.connection))
            return
        if not dhcp_app.parsed:
            log.debug("%s: DHCP packet not parsed", str(event.connection))
            return

        if dhcp_app.op != dhcp_app.BOOTREQUEST:
            return

        t = dhcp_app.options.get(dhcp_app.MSG_TYPE_OPT)
        if t is None:
            return

        if t.type == dhcp_app.DISCOVER_MSG:
            cls.exec_discover(event, dhcp_app, cls.pool)
        elif t.type == dhcp_app.REQUEST_MSG:
            cls.exec_request(event, dhcp_app, cls.pool)
        elif t.type == dhcp_app.RELEASE_MSG:
            cls.exec_release(event, dhcp_app, cls.pool)

    @classmethod
    def fill(cls, wanted_opts, msg):
        """
        Fill out some options in msg
        """
        if msg.SUBNET_MASK_OPT in wanted_opts:
            msg.add_option(pkt.DHCP.DHCPSubnetMaskOption(cls.subnet))
        if msg.ROUTERS_OPT in wanted_opts and cls.router_addr is not None:
            msg.add_option(pkt.DHCP.DHCPRoutersOption(cls.router_addr))
        if msg.DNS_SERVER_OPT in wanted_opts and cls.dns_addr is not None:
            msg.add_option(pkt.DHCP.DHCPDNSServersOption(cls.dns_addr))
        msg.add_option(pkt.DHCP.DHCPIPAddressLeaseTimeOption(cls.lease_time))

    @classmethod
    def reply(cls, event, msg):
        orig = event.parsed.find('dhcp')
        broadcast = (orig.flags & orig.BROADCAST_FLAG) != 0
        msg.op = msg.BOOTREPLY
        msg.chaddr = event.parsed.src
        msg.htype = 1
        msg.hlen = 6
        msg.xid = orig.xid
        msg.add_option(pkt.DHCP.DHCPServerIdentifierOption(cls.server_addr))

        ethp = pkt.ethernet(src=EthAddr('02:00:00:00:00:24'), dst=event.parsed.src)
        ethp.type = pkt.ethernet.IP_TYPE
        ipp = pkt.ipv4(srcip=cls.server_addr)
        ipp.dstip = event.parsed.find('ipv4').srcip
        if broadcast:
            ipp.dstip = IPAddr('255.255.255.255')
            eth.dst = pkt.ETHERNET.ETHER_BROADCAST
        ipp.protocol = ipp.UDP_PROTOCOL
        udpp = pkt.udp()
        udpp.srcport = pkt.dhcp.SERVER_PORT
        udpp.dstport = pkt.dhcp.CLIENT_PORT
        udpp.payload = msg
        ipp.payload = udpp
        ethp.payload = ipp
        po = of.ofp_packet_out(data=ethp.pack())
        po.actions.append(of.ofp_action_output(port=event.port))
        event.connection.send(po)

    @classmethod
    def nak(cls, event, msg = None):
        if msg is None:
            msg = pkt.dhcp()
        msg.add_option(pkt.DHCP.DHCPMsgTypeOption(msg.NAK_MSG))
        msg.siaddr = cls.server_addr
        cls.reply(event, msg)

    @classmethod
    def exec_discover(cls, event, p, pool):
        reply = pkt.dhcp()
        reply.add_option(pkt.DHCP.DHCPMsgTypeOption(p.OFFER_MSG))
        src = event.parsed.src
        if src in cls.leases:
            offer = cls.leases[src]
            del cls.leases[src]
            cls.offers[src] = offer
        else:
            offer = cls.offers.get(src)
            if offer is None:
                if len(pool) == 0:
                    log.error("Out of IP addresses")
                    cls.nak(event)
                    return

                offer = pool[0]
                if p.REQUEST_IP_OPT in p.options:
                    wanted_ip = p.options[p.REQUEST_IP_OPT].addr
                    if wanted_ip in pool:
                        offer = wanted_ip
                pool.remove(offer)
                cls.offers[src] = offer
        reply.yiaddr = offer
        reply.siaddr = cls.server_addr

        wanted_opts = set()
        if p.PARAM_REQ_OPT in p.options:
            wanted_opts.update(p.options[p.PARAM_REQ_OPT].options)
        cls.fill(wanted_opts, reply)

        cls.reply(event, reply)

    @classmethod
    def exec_request(cls, event, p, pool):
        if not p.REQUEST_IP_OPT in p.options:
            # Uhhh...
            return
        wanted_ip = p.options[p.REQUEST_IP_OPT].addr
        src = event.parsed.src
        got_ip = None
        if src in cls.leases:
            if wanted_ip != cls.leases[src]:
                pool.append(cls.leases[src])
                del cls.leases[src]
            else:
                got_ip = cls.leases[src]
        if got_ip is None:
            if src in cls.offers:
                if wanted_ip != cls.offers[src]:
                    pool.append(cls.offers[src])
                    del cls.offers[src]
                else:
                    got_ip = cls.offers[src]
        if got_ip is None:
            if wanted_ip in pool:
                pool.remove(wanted_ip)
                got_ip = wanted_ip
        if got_ip is None:
            log.warn("%s asked for un-offered %s", src, wanted_ip)
            cls.nak(event)
            return

        reply = pkt.dhcp()
        reply.add_option(pkt.DHCP.DHCPMsgTypeOption(p.ACK_MSG))
        reply.yiaddr = wanted_ip
        reply.siaddr = cls.server_addr

        wanted_opts = set()
        if p.PARAM_REQ_OPT in p.options:
            wanted_opts.update(p.options[p.PARAM_REQ_OPT].options)
        cls.fill(wanted_opts, reply)

        cls.reply(event, reply)

        bucket.arp_table[got_ip] = ARPDets(event.dpid, event.port, src)

    @classmethod
    def exec_release(cls, event, p, pool):
        src = event.parsed.src
        if src != p.chaddr:
            log.warn("%s tried to release %s with bad chaddr" % (src,p.ciaddr))
            return
        if cls.leases.get(p.chaddr) != p.ciaddr:
            log.warn("%s tried to release unleased %s" % (src,p.ciaddr))
            return
        del cls.leases[p.chaddr]
        del bucket.arp_table[p.chaddr]
        pool.append(p.ciaddr)
        log.info("%s released %s" % (src,p.ciaddr))

class ARP(object):

    @classmethod
    def _handle_arp(cls, event):
        if event.parsed.payload.opcode == pkt.arp.REQUEST:
            if (event.dpid in bucket.gateway) and (event.port == bucket.gateway[event.dpid].port_no)\
                and (event.parsed.payload.protodst == bucket.gateway[event.dpid].ip_addr):
                mac_addr = EthAddr('02:00:00:00:00:24')   
            elif event.parsed.payload.protodst == IPAddr('172.16.0.1'):
                mac_addr = EthAddr('02:00:00:00:00:24')
            elif event.parsed.payload.protodst not in bucket.arp_table:
                return
            else:
                mac_addr = bucket.arp_table[event.parsed.payload.protodst].mac_addr
            cls.reply_arp(event, mac_addr)
        elif event.parsed.payload.opcode == pkt.arp.REPLY:
            # print('dapat reply dari ', event.parsed.payload.protosrc)
            bucket.arp_table[event.parsed.payload.protosrc] = ARPDets(event.dpid, event.port, \
                                                                      event.parsed.payload.hwsrc)

    @classmethod
    def reply_arp(cls, event, mac_addr):
        arp_reply = pkt.arp()
        arp_reply.hwsrc = mac_addr
        arp_reply.hwdst = event.parsed.src
        arp_reply.opcode = pkt.arp.REPLY
        arp_reply.protosrc = event.parsed.payload.protodst
        arp_reply.protodst = event.parsed.payload.protosrc
        ether = pkt.ethernet()
        ether.type = pkt.ethernet.ARP_TYPE
        ether.dst = event.parsed.src
        ether.src = mac_addr
        ether.payload = arp_reply
        #send this packet to the switch
        msg = of.ofp_packet_out()
        msg.data = ether.pack()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
        msg.in_port = event.port
        event.connection.send(msg)

    @classmethod
    def request_arp(cls, dstaddr, port_no, dpid, ip_addr, mac_addr):
        r = pkt.arp()
        r.hwtype = r.HW_TYPE_ETHERNET
        r.prototype = r.PROTO_TYPE_IP
        r.hwlen = 6
        r.protolen = r.protolen
        r.opcode = r.REQUEST
        r.hwdst = pkt.ETHERNET.ETHER_BROADCAST
        r.protodst = dstaddr
        r.hwsrc = mac_addr
        r.protosrc = ip_addr
        e = pkt.ethernet(type=pkt.ethernet.ARP_TYPE, src=mac_addr,
                     dst=pkt.ETHERNET.ETHER_BROADCAST)
        e.set_payload(r)
        #log.debug("%i %i ARPing for %s on behalf of %s" % (dpid, inport,
         #r.protodst, r.protosrc))
        msg = of.ofp_packet_out()
        msg.data = e.pack()
        msg.actions.append(of.ofp_action_output(port = port_no))
        # msg.in_port = event.port
        core.openflow.sendToDPID(dpid, msg)
