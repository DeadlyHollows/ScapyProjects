#!/usr/bin/python2.7

# Script to simulate a spoofed soft AP which generates hidden SSID ...

### We can use the cloakSSID.py script along with this to set up a honeypot AP ...

import sys
from scapy.all import *

brdcstMAC='ff:ff:ff:ff:ff:ff'

def generateSpoofedBeacons():
	beacon_pkt=RadioTap() / Dot11(type=0, subtype=8, addr1=brdcstMAC, addr2=sys.argv[2], SC=RandShort(), addr3=sys.argv[2]) / Dot11Beacon() / Dot11Elt(ID=0, info=RandString(RandSingNum(1, 14))) / Dot11Elt(ID=1, info="\x02\x04\x0b\x16\x0c") / Dot11Elt(ID=3, info="\x08")
	sendp(beacon_pkt, iface=sys.argv[1], count=int(sys.argv[3]), inter=0.1)

if __name__=="__main__":
	generateSpoofedBeacons()