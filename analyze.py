#!/usr/bin/python

from scapy.all import *
import numpy as np
import time
import matplotlib.pyplot as plt
import argparse
from matplotlib.backends.backend_pdf import PdfPages
import dpkt
import socket
from connection import TCPConnection


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


def plot_cdf_ax(_data, _num_bins, _ax, lbl, logx):
    values, base = np.histogram(_data, bins=_num_bins, density=True)
    cumulative = np.cumsum(values) * (base[1] - base[0])
    if (logx):
        _ax.semilogx(base[:-1]*10e3, cumulative, label=lbl)
    else:
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

            # print pkt[TCP].seq, pkt[TCP].ack
            if tcp.seq not in timing[src]:
                timing[src][tcp.seq] = TCPConnection(src, tcp.seq, ts)
            else:
                conn = timing[src][tcp.seq]
                conn.syn_retransmissions = np.append(conn.syn_retransmissions, ts)
                timing[src][tcp.seq] = conn

        # Server response
        if tcp.flags & SYN and (tcp.flags & ACK):
            # handshake[ack - 1] = {ack:seq, t2: pkt.time }
            dst = ip_to_str(ip.dst)
            if dst in timing:  # if we do not have a SYN we ignore it
                if (tcp.ack - 1) in timing[dst]:
                    # print pkt[TCP].seq, pkt[TCP].ack
                    conn = timing[src][tcp.ack-1]
                    conn.synack_received = ts
                    timing[src][tcp.ack-1] = conn
            else:
                print "[WARNING:] Received SYNACK packet from non tacked host %s" % dst

        # Client response
        if (not (tcp.flags & SYN)) and (tcp.flags & ACK):
            src = ip_to_str(ip.src)
            if src in timing:
                # Reconstruct initial seq number
                if (tcp.seq - 1) in timing[src]:
                    conn = timing[src][tcp.seq - 1]
                    conn.ack_sent = ts
                    timing[src][tcp.seq - 1] = conn

        # RST packets
        if tcp.flags & RST:
            dst = ip_to_str(ip.dst)
            if dst in timing:
                print "[Log:] Host %s received a RST packet from the server" % dst
            else:
                print "[WARNING:] Received RST packet from non tacked host %s" % dst


    connection_time = {}
    retransmission_count = {}
    dropped_count = {}
    num_connections = 0
    # Compute connection time (time between first SYN and first ACK)
    # Number of unanswered SYN (count retransmissions)
    for host in timing.iterkeys():
        # do this to reduce lookup time
        connection_time[host] = []
        retransmission_count[host] = 0
        dropped_count[host] = []
        for seq in timing[host].iterkeys():
            conn = timing[host][seq]
            if conn.IsRetransmitted():
                retransmission_count[host] = retransmission_count[host] + conn.GetNumberOfRetransmissions()

                # count retransmission in completed connections.
                if conn.ack_sent > 0:
                    connection_time[host].append (conn.ack_sent - conn.syn_sent)

            elif conn.IsDroppedByServer():
                dropped_count[host].append(conn.rst_received)
            else:
                # normal connection completion
                if conn.ack_sent > 0:
                    connection_time[host].append(conn.ack_sent - conn.syn_sent)
                else:
                    print "[WARNING:] Found an incomplete solution at time %d" %conn.syn_sent

            num_connections = num_connections + 1

        print "Statistics for host %s" %host
        print "Total number of completed connections: \t", len(connection_time[host])
        print "Total number of retransmissions:       \t", retransmission_count[host]
        print "Total number of dropped packets:       \t", len(dropped_count[host])
        
    print "Total number of connections parsed ", num_connections
    return connection_time, retransmission_count, dropped_count


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
