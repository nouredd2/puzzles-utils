#!/usr/bin/python

from scapy.all import *
import numpy as np
import scipy.stats
import time
import matplotlib.pyplot as plt
import argparse
from matplotlib.backends.backend_pdf import PdfPages
import dpkt
import socket
import sys

from scapy.layers.inet import TCP, IP


def ip_to_str(address):
    return socket.inet_ntop(socket.AF_INET, address)

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


def plot_cdf_ax(_data, _num_bins, _ax, lbl):
    values, base = np.histogram(_data, bins=_num_bins, density=True)
    cumulative = np.cumsum(values) * (base[1] - base[0])
    _ax.plot(base[:-1]*10e3, cumulative, label=lbl)


def plot_cdf(_data, _num_bins, _outfile):
    # plot the cumulative histogram
    fig = plt.figure()
    # plt.hist(_data, _num_bins, normed=1, histtype='step', cumulative=True)
    values, base = np.histogram(_data, bins=_num_bins, density=True)
    cumulative = np.cumsum(values) * (base[1] - base[0])

    # plt.legend(loc='best')
    plt.plot(base[:-1]*10e3, cumulative)
    plt.title("Connection time for " + str(host))

    with PdfPages(_outfile) as pdf:
        pdf.savefig(fig)

    plt.close()


def plot_histogram(_data, _num_bins, _outfile):

    # plot (normalized) histogram of the data
    fig = plt.figure()
    plt.hist(_data, _num_bins, normed=0, cumulative=False, facecolor='green', alpha=0.5)

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

    start_time = time.time()
    f = open(fname)
    pz_cap = dpkt.pcap.Reader(f)
    end_time = time.time()

    print "Time to read pcap file " + str(end_time - start_time)
    timing = {}

    for ts, buf in pz_cap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data

        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        tcp = ip.data

        # First SYN packet
        if tcp.flags & SYN and not (tcp.flags & ACK):
            # pkt.display()
            src = ip_to_str(ip.src)
            # handshake[seq] = {h: src, ack: 0, t1: pkt.time}

            if src not in timing:
                timing[src] = {}
            else:
                # print pkt[TCP].seq, pkt[TCP].ack
                timing[src][tcp.seq] = [(ip,ts)]

        # Server response
        if tcp.flags & SYN and (tcp.flags & ACK):
            # handshake[ack - 1] = {ack:seq, t2: pkt.time }
            dst = ip_to_str(ip.dst)
            if dst in timing:  # if we do not have a SYN we ignore it
                if tcp.ack - 1 in timing[dst]:
                    # print pkt[TCP].seq, pkt[TCP].ack
                    timing[dst][tcp.ack - 1].append((ip,ts))

        # Client response
        if (not (tcp.flags & SYN)) and (tcp.flags & ACK):
            src = ip_to_str(ip.src)
            if src in timing:
                # Reconstruct initial seq number
                if tcp.seq - 1 in timing[src]:
                    timing[src][tcp.seq - 1].append((ip,ts))


    connection_time = {}
    retransmission_count = {}
    num_connections = 0
    # Compute connection time (time between first SYN and first ACK)
    # Number of unanswered SYN (count retransmissions)
    for host in timing.iterkeys():
        for seq in timing[host].iterkeys():
            data = timing[host][seq]
            syn_time = 0
            syn_ack_time = 0
            ack_time = 0
            if len(data) == 4:
                for entry,ts in data:
                    ip = entry
                    tcp = ip.data
                    if tcp.flags & SYN and not (tcp.flags & ACK):
                        # ###### Count the number of SYN retransmissions
                        if syn_time > 0:
                            # More than one SYN
                            if host not in retransmission_count:
                                retransmission_count[host] = 0
                            retransmission_count[host] = retransmission_count[host] + 1
                        else:
                            syn_time = ts
                    if tcp.flags & SYN and (tcp.flags & ACK):
                        syn_ack_time = ts
                    if not (tcp.flags & SYN) and (tcp.flags & ACK) and ack_time == 0:
                        ack_time = ts
            else:
                print ("[ERROR]: len(data) = " + str(len(data)))
                continue

            if host not in connection_time:
                connection_time[host] = []
            if ack_time > 0:
                connection_time[host].append(ack_time - syn_time)
            num_connections += 1

    print "Total number of connections parsed ", num_connections
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
