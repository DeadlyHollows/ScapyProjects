#!/usr/bin/python2.7

# Script to get all Wifi Devices around ...

# Tasks to do: Filter packets for Beacon frames ...
# If the Dot11 packet received has the receiver address ( i.e. the 2nd address) as the broadcast address (ff:ff:ff:ff:ff:ff), then it is the sender sending probe requests ...

import sys
from scapy.all import *

APList={}

def extractInfo(pkt):
	if pkt.haslayer(Dot11Beacon):
		beacon_frame=pkt.getlayer(Dot11)
		bssid=beacon_frame.addr3             # addr3 is the BSSID of the AP ...

		# If the APList already contains the bssid of the device, skip that packet ...
		if APList.has_key(bssid):
			return

		# The SSID is available as the info field in the first Dot11Elt frame inside the Dot11Beacon frame ...
		
		### Works only if the SSID is present as the first info element in the Dot11Elt frame ...
		#   ssid=beacon_frame.getlayer(Dot11Elt).info
		#################################################################

		ssid="The SSID cannot be extracted ..."

		### Get the Dot11Elt Layer ...
		pkt=beacon_frame.payload

		### A more general way ...
		while pkt:
			if pkt.ID==0:   ### It's the Dot11Elt frame containing the SSID ...
				if pkt.len==0:
					ssid="The SSID is prevented from being broadcasted ..."
				else:
					ssid=pkt.info  ### Got the SSID ...
				break
			pkt=pkt.payload
		APList[bssid]=ssid

print "\nListed below are some of the scanned Access Points:\n"
print "\n\t<%14s - %-17s>\n" % ("SSID", "BSSID")
print " ======================================================= "

print "\n"
sniff(iface=sys.argv[1], count=int(sys.argv[2]), prn=extractInfo)
#print APList

for bssid in APList:
	ssid=APList[bssid]
	print "\t%14s - %17s\n" % (ssid, bssid)

if len(APList)==0:
	print "\tNo Access Point found ...\n\tTry searching with more more no. of packets ..."

print "\n"
print " ======================================================= "