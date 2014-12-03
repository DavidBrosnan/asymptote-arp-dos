#!/usr/bin/env python

import click


@click.command()
@click.option('-i','--iface', default='eth0',help='use this network interface')
@click.option('-s','--scan', count=True, help="find online hosts (-ss for OS and MAC identification")
@click.option('-p','--poison', is_flag=True, help="attack target range")
@click.option('-v','--verbose', count=True, help="increase verbosity (-vv for greater effect)")
@click.argument('iprange', required=True)
def cli(iface, scan, poison, verbose, iprange):
    	"""Asymptote LAN DOS attacker"""
    	print "iface = %s\nscan = %s\npoison = %s\nverbose = %s\nipRange = %s" % (iface,scan,poison,verbose, iprange)
	    


if __name__ == '__main__':
    cli()
