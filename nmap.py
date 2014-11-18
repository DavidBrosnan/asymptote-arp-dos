#!/usr/bin/env python

import sys
from libnmap.parser import NmapParser
from libnmap.process import NmapProcess
from subnet import *
#import os
import netifaces
import subprocess
from netaddr import IPNetwork
from scapy.all import *


''' Get the Local IP address, Subnet Mask, and Local MAC of a given interface
'''
def getIPMaskMAC(interface):

	
	#print netifaces.interfaces()

	addrs = netifaces.ifaddresses(interface)
	x = addrs[netifaces.AF_INET]
	y = x.pop() #Temporary sloppy way of popping off the dictionary encapsulating
	x = addrs[netifaces.AF_LINK]
	z = x.pop()
	trip = (y["addr"], y["netmask"], z["addr"])

	return trip

''' Helps hostdiscover cut down the list of ip addresses
'''

def determine(x, host, interface):
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=x), iface=interface,verbose=0, timeout = 0.000000000000000000000000000000000000000000000001)
	if ans or x == host:
		 return True
	else:
		return False
	

def hostDiscover(interface, subnet, host):
	ipList = list(IPNetwork(subnet))

	for ip in range(0, len(ipList)):
		ipList[ip] = str(ipList[ip])


	ipList = [ip for ip in ipList if determine(ip, host, interface)]

	return ipList


def getNetwork(interface):
	ipMask = getIPMaskMAC(interface)
	
	print ipMask
		
	subnet = getSubnet(ipMask[0],ipMask[1]) #(IP, Mask, MAC)
	
	print subnet
	
	ipList = hostDiscover(interface, subnet, ipMask[0])
	print "process ran"

	nm = NmapProcess(ipList,"-sn","-Pn") #Run Nmap scan of LAN
	rc = nm.run()

	print rc


	print "Nmap ran..."
	
	machines = {}
	
	nmap_report = NmapParser.parse(nm.stdout)
	
	for hosts in nmap_report.hosts:
		print hosts


	for hosts in nmap_report.hosts:
        	if hosts.is_up():
			if len(hosts.hostnames) != 0:
				machines[hosts.address] = [hosts.mac, hosts.hostnames[0]]
 			else:
				machines[hosts.address] = [hosts.mac,"UNRESOLVED"]


			if hosts.address == ipMask[0]:
				machines[hosts.address][0] = ipMask[2]
				machines[hosts.address][1] = "**LocalHost**" + machines[hosts.address][1]
	print
	
	print "Subnet: " + subnet
	
	print "Hosts connected: " + str(len(machines))
	
	print
	
	print "{:>40}{:>20}{:>20}".format("Hostname","IP","MAC")
	print 
	for key, value in sorted(machines.iteritems()):
        	print "{:>40} {: >20} {:>20}".format(value[1],key,value[0])
	
	print 


getNetwork("eth0")
