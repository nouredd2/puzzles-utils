#!/usr/bin/python

from scapy.all import *
import numpy as np
import scipy.stats
import matplotlib.pyplot as plt
import argparse
from matplotlib.backends.backend_pdf import PdfPages

from scapy.layers.inet import TCP, IP


def set_up_arguments():
    parser = argparse.ArgumentParser(description="Analyze and dump plots.")
    parser.add_argument('--file', '-f', type=str, required=True,
                        help="The input pcap file")
    parser.add_argument('--out', '-o', type=str, required=True,
                        help="The out pdf file")
    parser.add_argument('--bins', '-b', type=int, default=50,
                        help="The number of bins to use for the histogram")
    parser.add_argument('--cdf', action='store_true',
                        help="Toggle plotting cdf vs histogram (default is histogram)")
    _args = parser.parse_args()

    return _args


def plot_cdf(_data, _num_bins, _ax, lbl):
    values, base = np.histogram(_data, bins=_num_bins, density=True)
    cumulative = np.cumsum(values) * (base[1] - base[0])
    _ax.plot(base[:-1], cumulative, label=lbl)


def plot_cdf(_data, _num_bins, _outfile):
    # plot the cumulative histogram
    fig = plt.figure()
    plt.hist(_data, _num_bins, normed=1, histtype='step', cumulative=True)

    # plt.legend(loc='best')
    plt.title("Connection time for " + str(host))

    with PdfPages(_outfile) as pdf:
        pdf.savefig(fig)

    plt.close()


def plot_histogram(_data, _num_bins, _outfile):

    # plot (normalized) histogram of the data
    fig = plt.figure()
    plt.hist(_data, _num_bins, normed=1, cumulative=True, facecolor='green', alpha=0.5)

    plt.xlim(min(data), max(data))
    plt.title("Connection time for " + str(host))

    with PdfPages(_outfile) as pdf:
        pdf.savefig(fig)

    plt.close()


def parse_file(fname):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    pz_cap = rdpcap(fname)

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

    return connection_time, retransmission_count


if __name__ == '__main__':

    args = set_up_arguments()
    infile = args.file
    outfile = args.out
    num_bins = args.bins
    do_cdf = args.cdf

    connection_time, retransmission_count = parse_file(infile)

    for host in connection_time.iterkeys():
        data = connection_time[host]

        if do_cdf:
            plot_cdf(data, num_bins, outfile)
        else:
            plot_histogram(data, num_bins, outfile)
