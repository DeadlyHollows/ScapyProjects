#!/usr/bin/python2.7

# A script which shows the live packet flow and tells the devices is the packets sent by them ...

import sys
from scapy.all import *

def extractInfo(pkt):
	if pkt.haslayer(Dot11):    # Iff the frame is 802.11 type ...

		dot11_layer=pkt.getlayer(Dot11)

		###   We can also get the addr1 and addr2 simply by
		###   using pkt.addr1 and pkt.addr2 ...

		if dot11_layer.addr1 and dot11_layer.addr2:
			addr1=dot11_layer.addr1
			if addr1 == "ff:ff:ff:ff:ff:ff":
				addr1="Everyone on the channel ..."
			print "   => ", dot11_layer.addr2, " is sending ", "%24s" % dot11_layer.payload.name, " to ", addr1


print "=================================================================================================="
sniff(iface=sys.argv[1], count=int(sys.argv[2]), prn=extractInfo)
print "=================================================================================================="