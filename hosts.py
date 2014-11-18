#!/usr/bin/env python

import sys
from libnmap.parser import NmapParser
from libnmap.process import NmapProcess
from subnet import *
import netifaces
import subprocess
from netaddr import IPNetwork
from scapy.all import *


''' Get the Local IP address, Subnet Mask, and Local MAC of a given interface
'''
def getIPMaskMAC(interface):
	
	addrs = netifaces.ifaddresses(interface) 	#ifconfig style information
	x = addrs[netifaces.AF_INET] 		#Layer 3
	
	#Used pop to knock off dictionary encapsulation
	
	y = x.pop()		#LAN IP and netmask
	x = addrs[netifaces.AF_LINK] 		#Layer 2
	z = x.pop()		#Mac Address
	trip = (y["addr"], y["netmask"], z["addr"])

	return trip

''' 
	Helps hostdiscover cut down the list of ip addresses

	x: string representing IP address of host were trying to contact

	host: string representing IP of localhost

	interface: 
	
'''

def determine(x, host, interface):

	#Equivalence of an arping, sends out a broadcast asking who the IP address is
	ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=x), iface=interface,verbose=0, timeout = 0.000000000000000000000000000000000000000000000001)
	if ans or x == host: 	#If we recieved an answer(its up) or its the host(we dont answer ourself)
		 return True
	else:
		return False
	
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


	ipList = [ip for ip in ipList if determine(ip, host, interface)]  #Create new list of online hosts

	return ipList

'''
	List the hostnames, IP addresses, and MACs of all online hosts in the Local Area Network

	interface: interface to find online hosts on

	return void
'''
def getNetwork(interface):
	ipMaskMAC = getIPMaskMAC(interface)
	
	hostIP = ipMaskMAC[0]
	hostMask = ipMaskMAC[1]
	hostMAC = ipMaskMAC[2]
		
	subnet = getSubnet(hostIP, hostMask) #(IP, Mask, MAC)
	
	ipList = hostDiscover(interface, subnet, hostIP)

	nm = NmapProcess(ipList,"-sn","-Pn") #Run Nmap scan of online hosts
	rc = nm.run()

	machines = {}
	
	nmap_report = NmapParser.parse(nm.stdout)
	
	for hosts in nmap_report.hosts:
		print hosts


	for hosts in nmap_report.hosts:
        	if hosts.is_up():
			if len(hosts.hostnames) != 0: #If we got a hostName from Nmap
				machines[hosts.address] = [hosts.mac, hosts.hostnames[0]]
 			else:	#If we didn't
				machines[hosts.address] = [hosts.mac,"UNRESOLVED"]


			if hosts.address == hostIP: #if it's the host
				machines[hosts.address][0] = hostMAC
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