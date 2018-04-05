#!/usr/bin/python
import numpy as np
import time
import matplotlib.pyplot as plt
import argparse
from matplotlib.backends.backend_pdf import PdfPages
import dpkt
import socket
from connection import TCPConnection, ThroughputEntry

FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


def ip_to_str(address):
    return socket.inet_ntop(socket.AF_INET, address)


def plot_cdf_ax(_data, _num_bins, _ax, lbl, logx):
    values, base = np.histogram(_data, bins=_num_bins, density=True)
    cumulative = np.cumsum(values) * (base[1] - base[0])
    if (logx):
        _ax.semilogx(base[:-1]*10e3, cumulative, label=lbl)
    else:
        _ax.plot(base[:-1]*10e3, cumulative, label=lbl)


def plot_cdf(_data, _num_bins, _outfile, logx=False):
    # plot the cumulative histogram
    fig = plt.figure()
    # plt.hist(_data, _num_bins, normed=1, histtype='step', cumulative=True)
    values, base = np.histogram(_data, bins=_num_bins, density=True)
    cumulative = np.cumsum(values) * (base[1] - base[0])

    # plt.legend(loc='best')
    if (logx):
        plt.semilogx(base[:-1]*10e3, cumulative)
    else:
        plt.plot(base[:-1]*10e3, cumulative)
    plt.title("Connection time for " + str(host))
    plt.xlabel('Time (us)')
    plt.ylabel('Likelihood of occurrence')

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


def compute_throughput(fname, host, interval, should_switch):
    start_time = time.time()
    f = open(fname)
    rcap = dpkt.pcap.Reader(f)
    end_time = time.time()
    print "Time to read pcap file " + str(end_time - start_time)

    start_ts = 0.0
    curr_bucket = 0
    appbytes = np.array([0])
    for ts, buf in rcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data

        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        tcp = ip.data

        # takes care of SYN and SYNACK
        if tcp.flags & SYN:
            continue

        iptocheck = ip.dst
        if should_switch:
            iptocheck = ip.src

        if ip_to_str(iptocheck) != host:
            continue

        if start_ts == 0.0:
            start_ts = ts

        if (ts - start_ts) > interval:
            skipped = int((ts - start_ts)) / interval
            if skipped > 1:
                filling = [0] * (skipped-1)
                appbytes = np.append(appbytes, filling)
            curr_bucket += skipped-1

            appbytes = np.append(appbytes, len(tcp.data))
            curr_bucket += 1

            start_ts = start_ts + skipped*interval
            assert (ts - start_ts < interval)
        else:
            appbytes[curr_bucket] += len(tcp.data)

    return appbytes


def handle_ip(ip_addr, throughput, ts, tcp, interval):
    if ip_addr not in throughput:
        # create empty entry for this ip
        entry = ThroughputEntry(ts)
        throughput[ip_addr] = entry
    else:
        entry = throughput[ip_addr]

    start_ts = entry.start_ts
    curr_bucket = entry.curr_bucket
    inbytes = entry.inbytes

    if (ts - start_ts) > interval:
        skipped = int((ts - start_ts)) / interval
        if skipped > 1:
            filling = [0] * (skipped - 1)
            inbytes = np.append(inbytes, filling)
        curr_bucket += skipped - 1

        inbytes = np.append(inbytes, len(tcp.data))
        curr_bucket += 1

        start_ts = start_ts + skipped * interval
        assert (ts - start_ts < interval)
    else:
        inbytes[curr_bucket] += len(tcp.data)

    # update entry values
    entry.start_ts = start_ts
    entry.curr_bucket = curr_bucket
    entry.inbytes = inbytes


def compute_tcp_opt_count(pcapFile, client):
    start_time = time.time()
    f = open(pcapFile)
    rcap = dpkt.pcap.Reader(f)
    end_time = time.time()
    print "Time to read pcap file " + str(end_time - start_time)

    # each entry should have curr_bucket, start_ts, and appbytes
    entry = {}
    for ts, buf in rcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data

        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        tcp = ip.data

        src_ip = ip_to_str(ip.src)
        dst_ip = ip_to_str(ip.dst)

        # takes care of SYN and SYNACK
        if tcp.flags & SYN and tcp.flags & ACK:
            if dst_ip == client:
                option_list = dpkt.tcp.parse_opts ( tcp.opts )
                entry[ts]=len(option_list)

    return entry


def compute_global_throughput(pcapFile, interval, server_ip=None):
    start_time = time.time()
    f = open(pcapFile)
    rcap = dpkt.pcap.Reader(f)
    end_time = time.time()
    print "Time to read pcap file " + str(end_time - start_time)

    # each entry should have curr_bucket, start_ts, and appbytes
    throughput = {}
    for ts, buf in rcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip = eth.data

        if not isinstance(ip.data, dpkt.tcp.TCP):
            continue

        tcp = ip.data

        # takes care of SYN and SYNACK
        if tcp.flags & SYN:
            continue

        # take care of FIN
        if tcp.flags & FIN:
            continue

        src_ip = ip_to_str(ip.src)
        dst_ip = ip_to_str(ip.dst)

        # handle the client first
        handle_ip(dst_ip, throughput, ts, tcp, interval)

        # now also take care of the server
        if src_ip != server_ip:
            continue
        handle_ip(src_ip, throughput, ts, tcp, interval)

    return throughput


# From https://gist.github.com/vishalkuo/f4aec300cf6252ed28d3
def removeOutliers(data, outlierConstant=1.5):
    a = np.array(data)
    upper_quartile = np.percentile(a, 75)
    lower_quartile = np.percentile(a, 25)
    IQR = (upper_quartile - lower_quartile) * outlierConstant
    quartileSet = (lower_quartile - IQR, upper_quartile + IQR)
    resultList = []

    num_outliers = 0
    for y in a.tolist():
        if (y >= quartileSet[0]) and (y <= quartileSet[1]):
            resultList.append(y)
        else:
            num_outliers += 1

    print "Remove %d outliers from dataset..." % num_outliers
    return np.array(resultList)


def parse_file(fname, ignore_retrans=False):
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
                timing[src][tcp.seq] = TCPConnection(src, tcp.seq, ts, tcp.sport)
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
                    conn = timing[dst][tcp.ack-1]
                    conn.synack_received = ts
                    timing[dst][tcp.ack-1] = conn
            else:
                print "[WARNING:] Received SYNACK packet for non tracked host %s" % dst
                print "           Packet at received at time %lf" % ts

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
                # print "[Log:] Host %s received a RST packet from the server" % dst
                port = tcp.dport
                reused = 0
                for seq in timing[dst].iterkeys():
                    conn = timing[dst][seq]
                    if conn.sport == port:
                        # found it
                        conn.set_reset_flag(ts)
                        reused = reused + 1

                if reused > 1:
                    print "[WARNING:] Port %d have been reused. Results cannot be trusted!" % port

            else:
                print "[WARNING:] Received RST packet for non tracked host %s" % dst


    connection_time = {}
    retransmission_count = {}
    dropped_count = {}
    incomplete_connections = {}
    num_connections = 0
    # Compute connection time (time between first SYN and first ACK)
    # Number of unanswered SYN (count retransmissions)
    for host in timing.iterkeys():
        # do this to reduce lookup time
        connection_time[host] = []
        retransmission_count[host] = 0
        dropped_count[host] = []
        incomplete_connections[host] = 0
        for seq in timing[host].iterkeys():
            conn = timing[host][seq]
            if conn.is_retransmitted():
                retransmission_count[host] = retransmission_count[host] + conn.get_num_retransmissions()

                # count retransmission in completed connections.
                if conn.ack_sent > 0:
                    if not ignore_retrans:
                        connection_time[host].append(conn.ack_sent - conn.syn_sent)
                else:
                    incomplete_connections[host] = incomplete_connections[host] + 1

            elif conn.is_dropped_by_server():
                dropped_count[host].append(conn.rst_received)
            else:
                # normal connection completion
                if conn.ack_sent > 0:
                    connection_time[host].append(conn.ack_sent - conn.syn_sent)
                else:
                    print "[WARNING:] Found an incomplete connection at time %d" % conn.syn_sent

            num_connections = num_connections + 1

        print "+----------------------------------------------------+"
        print "Statistics for host %s" % host
        print "Total number of attempted connections: \t", len(timing[host])
        print "Total number of completed connections: \t", len(connection_time[host])
        print "Total number of retransmissions:       \t", retransmission_count[host]
        print "Total number of dropped connections:   \t", len(dropped_count[host])
        print "Total number of incomplete connections:\t", incomplete_connections[host]

        print "Maximum connection time:               \t", np.max(connection_time[host])
        print "Minimum connection time:               \t", np.min(connection_time[host])
        print "Standard deviation:                    \t", np.std(connection_time[host])
        print "+----------------------------------------------------+"
        
    # print "Total number of connections parsed ", num_connections
    return connection_time, retransmission_count, dropped_count, incomplete_connections


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
    parser.add_argument('--logx', '-l', action='store_true',
                        help="Toggle plotting with log scale on x-axis")
    parser.add_argument('--ignore_retrans', '-i', action='store_true',
                        help="Ignore retransmissions when computing connection times.")
    _args = parser.parse_args()

    return _args


if __name__ == '__main__':

    args = set_up_arguments()
    infile = args.file
    outfile = args.out
    num_bins = args.bins
    do_cdf = args.cdf

    connection_time, retransmission_count, dropped_count, incomplete_conn = parse_file(infile, args.ignore_retrans)

    for host in connection_time.iterkeys():
        data = connection_time[host]
        fname = outfile + '-' + host + '.pdf'

        data = removeOutliers(data,2.0)
        if do_cdf:
            plot_cdf(data, num_bins, fname, args.logx)
        else:
            plot_histogram(data, num_bins, fname)
