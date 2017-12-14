#!/usr/bin/python2.7

# Script to pwn (own) the SSID of the AP which had been obfuscated ...

import sys
from scapy.all import *

APList={}

def pwnSSID(pkt):
	if pkt.haslayer(Dot11Beacon):
		tmp=pkt.getlayer(Dot11Elt)
		while tmp:
			if tmp.ID==0:
				if tmp.len==0:     ###  Beacon Frame with hidden SSID ...
					APList[pkt.addr3]="########################################################################################"
					print pkt.addr3, " CHUPA KE RAKHA HAI SAALA ..."
				else:
					APList[pkt.addr3]=tmp.info
				break
			tmp=tmp.payload

	elif pkt.haslayer(Dot11ProbeResp) and (pkt.addr3 in APList and APList[pkt.addr3]=="########################################################################################"):
		bssid=pkt.addr3
		pkt=pkt.getlayer(Dot11Elt)
		while pkt:
			if pkt.ID==0:
				APList[bssid]=pkt.info
				break
			pkt=pkt.payload

		print "----------------------------------------      UPDATED AP LIST      ----------------------------------------"
		for bssid in APList:
			print "\t", bssid, " is associated with ", APList[bssid]
		print "-----------------------------------------------------------------------------------------------------------"

sniff(iface=sys.argv[1], count=sys.argv[2], prn=pwnSSID)