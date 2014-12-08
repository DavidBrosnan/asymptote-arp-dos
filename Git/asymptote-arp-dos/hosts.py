#!/usr/bin/env python

from sys import stderr, exit
from libnmap.parser import NmapParser
from libnmap.process import NmapProcess
from subnet import getIPMaskMAC, getSubnet
import 	logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from netaddr import core, IPNetwork, IPAddress
'''
	Takes in a range of IP addresses and returns a list of individual IP's
'''
def parseTargets(IPstring, interface):

	targets = []

	if "/" in IPstring:
		
		targets = list(IPNetwork(IPstring))
			
		for ip in range(0, len(targets)):
			targets[ip] = str(targets[ip])
	
	elif "-" in IPstring:
		index = IPstring.find("-")

		minIP = IPAddress(IPstring[:index:])
		maxIP = IPAddress(IPstring[index+1::])

				
		hosts = list(IPNetwork(getSubnet(interface)))
			

		for IP in hosts:
			if IP >= minIP and IP <= maxIP:
				targets.append(IP)

		for ip in range(0, len(targets)):
			targets[ip] = str(targets[ip])

	elif "," in IPstring:	

		while "," in IPstring:
			index = IPstring.find(",")

			IP = IPstring[:index:]

			targets.append(IP)

			IPstring = IPstring[index+1::]

		targets.append(IPstring) #should contain the last IP address

	else:
		targets.append(IPstring)

	try:
		for target in targets:
			ip = IPNetwork(target)
	except core.AddrFormatError:
		sys.stderr.write("\nERROR: Invalid scan range\n\n")
		sys.exit(0)
		
	return targets


def scanTarget(interface, target):
	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target),iface= interface,verbose=0,timeout=3)

	result = ()	

	for s,r in ans:
		result=(r[ARP].psrc, r[Ether].src)

	return result
'''
	Uses arping style discovery to reduce list of subnet to guaranteed online hosts
	interface: string containing interface to check for hosts
		e.g. eth0, eth1, wlan0
	subnet: string containing subnet for LAN
		e.g. 192.168.56.0/24
	host: string representing localhost IP address
	Returns a list of IP addresses of online hosts
'''
def hostDiscover(interface, subnet, host):
	ipList = list(IPNetwork(subnet))		#List of IP addresses within range


	for ip in range(0, len(ipList)):
		ipList[ip] = str(ipList[ip])
	
	ipDict = {}

	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet),iface= interface,verbose=0,timeout=3)
	    
	for s,r in ans:

		ipDict[r[ARP].psrc] = [r[Ether].src,"Unknown"]
	
	return ipDict

'''
	List the hostnames, IP addresses, and MACs of all online hosts in the Local Area Network
	interface: interface to find online hosts on
	return void
'''
def getTargets(interface, targetString, scan, verbose):
	ipMaskMAC = getIPMaskMAC(interface)
	
	hostIP = ipMaskMAC[0]
	hostMask = ipMaskMAC[1]
	hostMAC = ipMaskMAC[2]
		
	subnet = getSubnet(interface) #(IP, Mask, MAC)
	
	ipMACList = hostDiscover(interface, subnet, hostIP)
	
	targets = parseTargets(targetString, interface)

	ipList = []

	for k, v in ipMACList.iteritems():
		if k in targets:
			ipList.append(k)
	
	if (scan == 2):
		nm = NmapProcess(ipList,"-O","-sS")
	
	else:
		nm = NmapProcess(ipList,"-sn") #Run Nmap scan of online hosts
	
	rc = nm.run()
	machines = {}
	
	nmap_report = NmapParser.parse(nm.stdout)
	
	for hosts in nmap_report.hosts:
        	if hosts.is_up():
			if len(hosts.hostnames) != 0: #If we got a hostName from Nmap
				if scan == 2:
					if len(hosts.os_match_probabilities()) != 0:
						machines[hosts.address] = [hosts.mac, hosts.hostnames[0], hosts.vendor, hosts.os_match_probabilities()[0].name]
					else:
						machines[hosts.address] = [hosts.mac, hosts.hostnames[0], hosts.vendor, "UNKNOWN"]

	
				else:
					machines[hosts.address] = [hosts.mac, hosts.hostnames[0]]
			else:	#If we didn't
				if scan == 2:
					if len(hosts.os_match_probabilities()) != 0:
						machines[hosts.address] = [hosts.mac,"UNRESOLVED", hosts.vendor, hosts.os_match_probabilities()[0].name]
					else:
						machines[hosts.address] = [hosts.mac,"UNRESOLVED", hosts.vendor, "UNKNOWN"]

				else:
					machines[hosts.address] = [hosts.mac,"UNRESOLVED"]
			
			if hosts.address == hostIP: #if it's the host
				machines[hosts.address][0] = hostMAC
				machines[hosts.address][1] = "**LocalHost**" + machines[hosts.address][1]

	if scan != 0:
		printHosts(machines, subnet, scan)
	
	return machines

def printHosts(machines, subnet, scan):
	
	print
	
	print "Subnet: " + subnet
	
	print "Online Hosts scanned: " + str(len(machines))
	
	print
	
	if scan == 2:
		print "{:>20}{:>20}{:>20}{:>30}{:>30}".format("Hostname","IP","MAC","MAC Manufacture","OS fingerprint")
		for key, value in sorted(machines.iteritems()):
			print "{:>20} {: >20} {:>20} {:>30} {:>30}".format(value[1],key,value[0],value[2],value[3])
	else:
		print "{:>40}{:>20}{:>20}".format("Hostname","IP","MAC")
		for key, value in sorted(machines.iteritems()):
        		print "{:>40} {: >20} {:>20}".format(value[1],key,value[0])
	
	print

