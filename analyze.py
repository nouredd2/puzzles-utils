from scapy.all import *
import sys
import os

from scapy.layers.inet import TCP, IP

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

pz_cap = rdpcap("/Users/afawaz2/Misc/puzzles-exp/file.cap")

timing = {}
# handshake={}

for pkt in pz_cap:
    if TCP in pkt:
        # pkt.display()

        # First SYN packet
        if pkt[TCP].flags & SYN and not (pkt[TCP].flags & ACK):
            # pkt.display()
            src = pkt[IP].src
            # handshake[seq] = {h: src, ack: 0, t1: pkt.time}

            if src not in timing:
                timing[src] = {}
            else:
                # print pkt[TCP].seq, pkt[TCP].ack
                timing[src][pkt[TCP].seq] = [ pkt ]

        # Server response
        if pkt[TCP].flags & SYN and (pkt[TCP].flags & ACK):
            # handshake[ack - 1] = {ack:seq, t2: pkt.time }
            dst = pkt[IP].dst
            if dst in timing:  # if we do not have a SYN we ignore it
                if pkt[TCP].ack - 1 in timing[dst]:
                    # print pkt[TCP].seq, pkt[TCP].ack
                    timing[dst][pkt[TCP].ack - 1].append( pkt )

        # Client response
        if not (pkt[TCP].flags & SYN) and (pkt[TCP].flags & ACK):
            src = pkt[IP].src
            if src in timing:
                # Reconstruct initial seq number
                #
                if pkt[TCP].seq - 1 in timing[src]:
                    timing[src][pkt[TCP].seq - 1].append( pkt )

con_time_results = {}
retran = {}
# Compute connection time (time between last SYN and first ACK)
# Number of unanswered SYN (count retransmissions)
for host in timing.iterkeys():
    for seq in timing[host].iterkeys():
        data = timing[host][seq]
        syn_time = 0
        syn_ack_time = 0
        ack_time = 0
        if len(data) >= 3:
            for entry in data:
                pkt = entry
                if pkt[TCP].flags & SYN and not (pkt[TCP].flags & ACK):
                    # ###### Count the number of SYN retransmissions
                    if syn_time > 0:
                        # More than one SYN
                        if host not in retran:
                            retran[host] = 0
                        retran[host] = retran[host] + 1
                    syn_time = pkt.time
                if pkt[TCP].flags & SYN and (pkt[TCP].flags & ACK):
                    syn_ack_time = pkt.time
                if not(pkt[TCP].flags & SYN) and (pkt[TCP].flags & ACK) and ack_time==0:
                    ack_time = pkt.time

    if host not in con_time_results:
        con_time_results[host] = []
    if ack_time > 0:
        con_time_results[host].append(ack_time - syn_time)


