#!/usr/bin/python2.7

import sys
from scapy.all import *

def packetHandler(pkt):
	if pkt.haslayer(Dot11):
		print pkt.summary()
	else:
		print "Not an 802.11 frame!"

sniff(iface=sys.argv[1], count=int(sys.argv[2]), prn=packetHandler)