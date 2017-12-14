#!/usr/bin/python2.7

# Script to pwn the hidden SSID by sending spoofed Probe Requests and listening for a reply ...
# If any of the spoof requests is able to get a reply from an Access Point, we have successfully uncovered the SSID of that network ...

import sys
from scapy.all import *

myMAC='00:ba:ff:e1:10:00'
brdcstMAC='ff:ff:ff:ff:ff:ff'

def generateProbeRequest(ssid):
	print "Generating a probe request with ssid: ", ssid

	probe_pkt=RadioTap() / Dot11(type=0, subtype=4, addr1=brdcstMAC, addr2=myMAC, addr3=brdcstMAC) / Dot11ProbeReq() / Dot11Elt(ID=0, info=ssid) / Dot11Elt(ID=1, info="\x02\x04\x0b\x16\x0c") / Dot11Elt(ID=3, info="\x08")

	sendp(probe_pkt, iface=sys.argv[1], count=3, inter=0.3)


def brutePwnSSID(ssid_dictionary):
	# with open(ssid_dictionary) as ssid_list:
	#	ssid_list=ssid_list.readlines()
	ssid_list=[]
	for ssid in open(ssid_dictionary).readlines():
		ssid_list.append(ssid[0:len(ssid)-1])
	# print ssid_list

	for ssid in ssid_list:
		ssid=ssid.strip()
		if ssid and ssid[0]!='#':
			### Implies its not a comment ...
			generateProbeRequest(ssid)


if __name__=="__main__":
	brutePwnSSID(sys.argv[2])