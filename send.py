#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers, get_if_addr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP
from scapy.fields import *
import readline

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SourceRoute(Packet):
   fields_desc = [ BitField("bos", 0, 1),
                   BitField("port", 0, 15)]

bind_layers(Ether, SourceRoute, type=0x1234)
bind_layers(SourceRoute, SourceRoute, bos=0)
bind_layers(SourceRoute, IP, bos=1)

def main():

    if len(sys.argv)<2:
        print 'pass 2 arguments: <destination>'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print "sending on interface %s to %s" % (iface, str(addr))

    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff');
    pkt.show2()
    if ("10.0.1.10" != sys.argv[1]):
        pkt = pkt / SourceRoute(bos=1, port=int(0))

    pkt = pkt / IP(src=get_if_addr(iface), dst=addr) / UDP(dport=4321, sport=1234)
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)



if __name__ == '__main__':
    main()
