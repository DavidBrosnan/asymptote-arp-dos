#!/usr/bin/env python

'''
	Takes in a list of the seperate octets of an Ip/subnetmask
	e.g. ['192','168','0','0']
	and converts them to a list of those octets in binary
'''
def makeBinList(list):
	binList = []

	for i in list:
		binList.append( bin ( int(i) )[2::])#[2::] removes the 0b prefix

	return binList
'''
	Takes in a list of binary octets and makes sure that leading zeroes are
	added to make them 8 bit numbers
'''
def leadZero(binList):
	

	for i in range(0, len(binList)):
		length = len(binList[i])
		if length < 8:
			for j in range(0, 8 - length):
				binList[i] = "0" + binList[i]
	

	return binList

'''
	Takes in a two binary strings and returns a binary string of a bitwise add
	Under the assumption that both strings are 8 bits long including leading zeroes
'''
def bitWiseAdd( op1, op2 ):

	result = "";	
	#print "Op1: " + op1
	#print "Op2: " + op2
	for i in range(0, len(op1)):
		result = result + str(int(op1[i]) & int(op2[i]))

	return result
		
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


#mask = "255.255.255.0"
#ip = "192.168.56.104"

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
