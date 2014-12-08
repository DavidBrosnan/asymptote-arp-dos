#!/usr/bin/env python

import click
from poison import DenialOfService
from hosts import scanTarget, getTargets
from sys import stderr, exit


@click.command()
@click.option('-i','--iface', default='prompt',help='use this network interface')
@click.option('-s','--scan', count=True, help="find online hosts (-ss for OS and MAC identification")
@click.option('-p','--poison', default='poison', help="Quarantine specified IP for IP's within givin range")
@click.option('-v','--verbose', count=True, help="increase verbosity (-vv for greater effect)")
@click.argument('iprange', default='subnet')
def cli(iface, scan, poison, verbose, iprange):
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
		subnet.printInterfaces()
		print "\nPlease select an interface"
		sys.exit(0)

	if scan == 0 and poison == 'poison':
		print("Please scan and/or poison the target")
		sys.exit(0)
	

	if iprange == 'subnet':
		iprange = subnet.getSubnet(iface)
 	
	victims = getTargets(iface, iprange, scan, verbose)
			

	if poison != 'poison':
		quarantine = scanTarget(iface, poison)
		
		try:
			DenialOfService(iface, victims, quarantine, verbose)
		except IndexError:
			sys.stderr.write("ERROR:Target does not exist or was not found in scan\n")

if __name__ == '__main__':
    cli()
