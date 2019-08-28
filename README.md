# Asymptote

School project for my networks class, used to demonstrate the trusting nature of older protocols, how that can be leveraged to give a window for attackers, and how that window needs something as simple as your wifi password to occur. This tool in particular leverages gratuitous arp replies to specific victim machines, changing the MAC address of the local subnets gateway in their arp table to ff:ff:ff:ff:ff:fe resulting in a denial of service for the victim machines. 

## Install

```
sudo pip install click
sudo pip install netifaces
sudo pip install libnmap
sudo pip install python-libnmap
```

Download the scapy library from it's webset - www.scapy.net
unzip and change director into scapy
```
sudo python setup.py install
```

## Use
```
sudo ./asymptote.py --help
Usage: asymptote.py [OPTIONS] [IPRANGE]

  Asymptote LAN DOS attacker

  Examples:

       (Scan entire subnet of eth0 and report online hosts)
       asymptote -i eth0 -s

       (Aggresively scan .102 & .104, get MAC vendor and OS fingerprint)
       asymptote -i eth1 -ss 192.168.56.102,192.168.56.104

       (Quarantine 192.168.1.1 from all online hosts from ...12 to ...23)
       asymptote -i eth2 -p 192.168.1.1 192.168.1.12-192.168.1.23

Options:
  -i, --iface TEXT   use this network interface
  -s, --scan         find online hosts (-ss for OS and MAC identification
  -p, --poison TEXT  Quarantine specified IP for IP's within givin range
  -v, --verbose      increase verbosity (-vv for greater effect)
  -m, --MAC TEXT     Source MAC address for attack
                     'rand':random MAC
                     'frenzy':random MAC per packet
                     'local': local MAC
                     IP:Disguise as host
  --help             Show this message and exit.
```
