#!/bin/python3

from scapy.all import ARP, Ether, srp
import sys

target=sys.argv[1]

arp = ARP(pdst=target)

ether = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ether/arp

result = srp(packet, timeout=3)[0]
clients = []
for send, receive in result: 
    clients.append({'ip':receive.psrc, 'mac':receive.hwsrc})

print("Available devices found in the network")
print("ip" + " "*20 + "Mac")

for client in clients:
     print("{:16}    {}".format(client['ip'], client['mac']))
