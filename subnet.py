#!/usr/bin/env python

from random import getrandbits
import netifaces
'''
	Generates a random MAC address
'''
def MACgen():

	macList = []

	for i in range(0, 6):
		macList.append(dec2Hex(getrandbits(8)))
	
	MAC = ":".join([macList[0],macList[1],macList[2],macList[3],macList[4],macList[5]])
	
	if MAC == "ff:ff:ff:ff:ff:ff" or MAC == "00:00:00:00:00:00": #Don't want either of these MAC addresses
		MAC = MACgen()

	return MAC
'''
	Converts a 8 bit (0-255) decimal number to a 2 character hex representation
'''
def dec2Hex(dec):
	
	hexDict = {10:'a', 11:'b', 12:'c', 13:'d', 14:'e', 15:'f'}

	i = (int)(dec / 16)
	j = (int)(dec % 16)

	if i >= 10:
		i = str(hexDict[i])
	else:
		i = str(i)

	if j >= 10:
		j = str(hexDict[j])
	else:
		j = str(j)

	
	return i + j

'''
	Takes in a list of the seperate octets of an Ip/subnetmask
	e.g. ['192','168','0','0']
	and converts them to a list of those octets in binary
	listOct: list of octets represented as strings
	returns same list with octets represented in binary
'''
def makeBinList(listOct):
	binList = []

	for i in listOct:
		binList.append( bin ( int(i) )[2::])#[2::] removes the 0b prefix

	return binList
'''
	Takes in a list of binary octets and makes sure that leading zeroes are
	added to make them 8 bit numbers
	binList: list of octets represented in binary
	returns same list with the length of all octets being 8 (0's appended in front to force) 
'''
def leadZero(binList):
	

	for i in range(0, len(binList)):
		length = len(binList[i])
		if length < 8:
			for j in range(0, 8 - length):
				binList[i] = "0" + binList[i]
	

	return binList

'''
	Takes in a two binary strings and returns a binary string of a bitwise AND
	Under the assumption that both strings are 8 bits long including leading zeroes
	op1: binary string
	op2: binary string
	returns bitwise AND of binary numbers
'''
def bitWiseAdd( op1, op2 ):

	result = "";	
	for i in range(0, len(op1)):
		result = result + str(int(op1[i]) & int(op2[i])) #Appends answers one at a time

	return result


'''
	Computes the CIDR notation of the subnet utilizing the local IP and subnet mask
	mask: subnet mask
	returns the CIDR:
	e.g.
		192.168.56.104 
	      & 255.255.255.0
	      	returns 24
'''		
def getCIDR(mask):
	
	[oct1, oct2, oct3, oct4] = mask.split(".")

	octs = [oct1, oct2, oct3, oct4]

	for i in range(0, len(octs)):
		octs[i] = bin( int(octs[i]))[2::]
		
	octs = leadZero(octs)

	count = 0

	for i in range(0, 4):
		for j  in range(0, 8):
			if '1' == octs[i][j]:
				count += 1
	return count
	
'''
	prints available interfaces
'''

def printInterfaces():	
	for interface in netifaces.interfaces():
		print interface,

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
	Uses the Ip address and subnet mask to get a full CIDR representation of the LAN
	ip: localhost IP address (e.g. 192.168.56.104)
	mask: subnet mask
	returns CIDR as a string
	e.g.
		192.168.56.0/24
'''
def getSubnet(interface):
	
	ipMaskMAC = getIPMaskMAC(interface)
	
	ip = ipMaskMAC[0]
	mask = ipMaskMAC[1]
	
	[oct1, oct2, oct3, oct4] = mask.split(".")
	[ip1, ip2, ip3, ip4] = ip.split(".")

	octs = [oct1, oct2, oct3, oct4]
	ips = [ip1, ip2, ip3, ip4]

	binOcts = makeBinList(octs)
	binIps = makeBinList(ips)

	binOcts = leadZero(binOcts)
	binIps = leadZero(binIps)

	subs = []

	for i in range (0, 4):
		subs.append(bitWiseAdd(binOcts[i], binIps[i]))

	for i in range(0, len(subs)):
		subs[i] = str(int(subs[i],2))


	subnet = ".".join(subs)

	subnet = subnet + "/" + str(getCIDR(mask))

	return subnet
