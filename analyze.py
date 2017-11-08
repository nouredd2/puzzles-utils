from scapy.all import *
import sys
import os
import numpy as np
import scipy.stats
import matplotlib.pyplot as plt

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
                timing[src][pkt[TCP].seq] = [pkt]

        # Server response
        if pkt[TCP].flags & SYN and (pkt[TCP].flags & ACK):
            # handshake[ack - 1] = {ack:seq, t2: pkt.time }
            dst = pkt[IP].dst
            if dst in timing:  # if we do not have a SYN we ignore it
                if pkt[TCP].ack - 1 in timing[dst]:
                    # print pkt[TCP].seq, pkt[TCP].ack
                    timing[dst][pkt[TCP].ack - 1].append(pkt)

        # Client response
        if not (pkt[TCP].flags & SYN) and (pkt[TCP].flags & ACK):
            src = pkt[IP].src
            if src in timing:
                # Reconstruct initial seq number
                #
                if pkt[TCP].seq - 1 in timing[src]:
                    timing[src][pkt[TCP].seq - 1].append(pkt)

connection_time = {}
retransmission_count = {}
# Compute connection time (time between first SYN and first ACK)
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
                        if host not in retransmission_count:
                            retransmission_count[host] = 0
                        retransmission_count[host] = retransmission_count[host] + 1
                    syn_time = pkt.time
                if pkt[TCP].flags & SYN and (pkt[TCP].flags & ACK):
                    if syn_time == 0:
                        syn_ack_time = pkt.time
                if not (pkt[TCP].flags & SYN) and (pkt[TCP].flags & ACK) and ack_time == 0:
                    ack_time = pkt.time

        if host not in connection_time:
            connection_time[host] = []
        if ack_time > 0:
            connection_time[host].append(ack_time - syn_time)

# Data analysis
# (source: https://matplotlib.org/devdocs/api/_as_gen/matplotlib.pyplot.hist.html)

for host in connection_time.iterkeys():
    data = connection_time[host]
    # test values for the bw_method option ('None' is the default value)
    bw_values = [None, 0.1, 0.01]

    # generate a list of kde estimators for each bw
    # kde = [scipy.stats.gaussian_kde(data, bw_method=bw) for bw in bw_values]

    # plot (normalized) histogram of the data
    plt.figure()
    plt.hist(data, normed=1, cumulative=True, facecolor='green', alpha=0.5); #,  histtype='step');

    # plot density estimates
    # t_range = np.linspace(-2, 8, 200)
    # for i, bw in enumerate(bw_values):
    #    plt.plot(t_range, kde[i](t_range), lw=2, label='bw = ' + str(bw))
    plt.xlim(min(data), max(data))
    # plt.legend(loc='best')
    plt.title("Connection time for "+str(host))
plt.show()
