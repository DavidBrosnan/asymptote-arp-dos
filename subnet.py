#!/usr/bin/env python

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
	Uses the Ip address and subnet mask to get a full CIDR representation of the LAN

	ip: localhost IP address (e.g. 192.168.56.104)
	mask: subnet mask

	returns CIDR as a string

	e.g.
		192.168.56.0/24
'''

def getSubnet(ip, mask):
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
