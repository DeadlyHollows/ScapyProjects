#!/usr/bin/python2.7

import time
import sys
import subprocess
from random import randint


######## FOR FANCY AND COLORED OUTPUT ... ###########
formatter = {
	"RED":"\033[1;31m",
	"BLUE":"\033[1;34m",
	"CYAN":"\033[1;36m",
	"GREEN":"\033[0;32m",
	"RESET":"\033[0;0m",
	"BOLD":"\033[;1m",
	"REVERSE":"\033[;7m",
	"UP":"\033[F",
	"FLUSH":"\033[K"
}
#################################################

def RandColor():
	randColor=randint(0, 3)
	c=0
	for color in formatter:
		if c==randColor:
			return formatter[color]
		c+=1

def getFrequency(iface):
	p=subprocess.Popen(["iwconfig", iface], stdout=subprocess.PIPE)
	# print p.communicate()[0].split()[4]
	return p.communicate()[0].split()[4]

def changeChannel(iface, channel):
	subprocess.call(["iwconfig", iface, "channel", str(channel)])
	return channel

def hopChannel(iface, channels="1-14"):
	channels=channels.split("-")

	if len(channels)==1:
		lowerCh=int(channels[0])
		upperCh=int(channels[0])
	else:
		lowerCh=int(channels[0].strip())
		upperCh=int(channels[1].strip())

	if lowerCh<1 or upperCh>14:
		sys.stdout.write(formatter["BOLD"])
		sys.stdout.write(formatter["RED"])
		print "Error:", 
		sys.stdout.write(formatter["RESET"])

		sys.stdout.write(formatter["RED"])
		print "The channel must strictly be in the range 1 to 14 !!!"
		sys.stdout.write(formatter["RESET"])
		sys.exit()

	while True:
		# sys.stdout.flush()
		channel=randint(lowerCh, upperCh)

		sys.stdout.write(formatter["BOLD"])
		sys.stdout.write(RandColor())

		changeChannel(iface, channel)
		print "Currently in the channel", channel, "with", 
		# sys.stdout.write("Currently in the channel " + str(channel) + " with ")
		print getFrequency(iface)
		# sys.stdout.write(p.communicate()[0].split()[4])

		sys.stdout.write(formatter["RESET"])
		# sys.stdout.flush()
		time.sleep(1)
		sys.stdout.write(formatter["UP"])
		sys.stdout.write(formatter["FLUSH"])

if __name__=="__main__":

	sys.stdout.write(RandColor())
	print "\n\n### USAGE: ./channelHopper.py <iface> <channel_range (Ex: 1-14)> ###\r\n"
	sys.stdout.write(formatter["RESET"])
	time.sleep(1)
	# sys.stdout.write(formatter["UP"])
	# sys.stdout.write(formatter["UP"])
	# sys.stdout.write(formatter["FLUSH"])

	channels="1-14"
	if len(sys.argv)==3:
		channels=sys.argv[2]

	hopChannel(sys.argv[1], channels)