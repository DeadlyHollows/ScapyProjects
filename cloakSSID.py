#!/usr/bin/python2.7

# Script to cloak the hidden SSID from being detected ...
# We spoof reply from an Access Point are sent, we have successfully cloaked the SSID of that network ...

import sys
from scapy.all import *

def generateProbeResponse():

	probe_pkt=RadioTap() / Dot11(type=0, subtype=5, addr1=RandMAC(), addr2=sys.argv[2], SC=RandShort(), addr3=sys.argv[2]) / Dot11ProbeResp() / Dot11Elt(ID=0, info=RandString(RandSingNum(1, 14))) / Dot11Elt(ID=1, info="\x02\x04\x0b\x16\x0c") / Dot11Elt(ID=3, info="\x08")

	sendp(probe_pkt, iface=sys.argv[1], count=int(sys.argv[3]), inter=0.3)


if __name__=="__main__":
	generateProbeResponse()