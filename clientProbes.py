#!/usr/bin/python2.7

# Script to grab the probes sent out by the client in Dot11 frames ...

import sys
from scapy.all import *

probes={}

def getProbes(pkt):
	if pkt.haslayer(Dot11ProbeReq):
		client_addr=pkt.addr2
		pkt=pkt.getlayer(Dot11ProbeReq)
		if not probes.has_key(client_addr):
			probes[client_addr]=set()
		while pkt:
			if pkt.ID==0 and pkt.info not in probes[client_addr]:
				### Got the SSID field ...
				if pkt.len==0:
					ssid="Someone Hideous or Broadcast"
				else:
					ssid=pkt.info
				print "New Probe Request Found: ", client_addr, " is looking for ", ssid
				probes[client_addr].add(ssid)

				if len(probes)==0:
					return
					
				print "\n\n-------------------------------------------------  Client Probe Request Table -------------------------------------------------\n"
				for client in probes:
					print '\t\t', client, ' is looking for ',
					for ssid in probes[client]:
						print ssid, ' ... ', 
					print "\n"
				print "-------------------------------------------------------------------------------------------------------------------------------\n\n"

				break
			pkt=pkt.payload

sniff(iface=sys.argv[1], count=int(sys.argv[2]), prn=getProbes)