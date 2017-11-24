#!/usr/bin/python

import numpy as np
import time
import dpkt
import socket
import operator
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


def ANPrint(message, verbose):
    if verbose:
        print message


def populate_connections(pz_cap, verbose=False, target_ips=set()):
    """
    In this case, I will treat retransmissions as separate connection
    class since we need to account for them in the analysis. I will always
    add the ACK received to the last sent SYN.

    """
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

            # check if I am applying some filter over the nodes
            if len(target_ips) > 0 and src not in target_ips:
                continue

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

            # check if I am applying some filter over the nodes
            if len(target_ips) > 0 and dst not in target_ips:
                continue

            if dst in timing:  # if we do not have a SYN we ignore it
                if (tcp.ack - 1) in timing[dst]:
                    # print pkt[TCP].seq, pkt[TCP].ack
                    conn = timing[dst][tcp.ack-1]
                    conn.synack_received = ts
                    timing[dst][tcp.ack-1] = conn
            else:
                ANPrint("[WARNING:] Received SYNACK packet for non tracked host %s" % dst, verbose)
                ANPrint("           Packet at received at time %lf" % ts, verbose)

        # Client response
        if (not (tcp.flags & SYN)) and (tcp.flags & ACK):
            src = ip_to_str(ip.src)

            # check if I am applying some filter over the nodes
            if len(target_ips) > 0 and src not in target_ips:
                continue

            if src in timing:
                # Reconstruct initial seq number
                if (tcp.seq - 1) in timing[src]:
                    conn = timing[src][tcp.seq - 1]
                    conn.ack_sent = ts
                    timing[src][tcp.seq - 1] = conn

        # RST packets
        if tcp.flags & RST:
            dst = ip_to_str(ip.dst)

            # check if I am applying some filter over the nodes
            if len(target_ips) > 0 and dst not in target_ips:
                continue

            if dst in timing:
                # print "[Log:] Host %s received a RST packet from the server" % dst
                port = tcp.dport
                reused = 0
                for seq in timing[dst].iterkeys():
                    conn = timing[dst][seq]
                    if conn.sport == port:
                        # found it
                        conn.SetResetFlag(ts)
                        reused = reused + 1

                if reused > 1:
                    ANPrint("[WARNING:] Port %d have been reused. Results cannot be trusted!" % port, verbose)

            else:
                ANPrint("[WARNING:] Received RST packet for non tracked host %s" % dst, verbose)

    return timing


def compute_sending_rate(pcap_file, interval_s, verbose=False):
    """
    Compute the effective sending rate from an attackers
    pcap file.

    @pcap_file: The pcap file to parse
    @interval_s: The interval for which to compute the effective sending rate
    @verbose: Flood out the printing if true

    """

    start_time = time.time()
    f = open(pcap_file)
    rcap = dpkt.pcap.Reader(f)
    end_time = time.time()
    ANPrint("Time to read pcap file " + str(end_time - start_time), verbose)

    timing = populate_connections(rcap, verbose)

    sending_rates = {}
    for host, conn_dict in timing.items():
        effective_rate = np.array([0])
        start_ts = 0
        curr_bucket = 0
        num_sent = 0
        sorted_items = sorted(conn_dict.values(), key=operator.attrgetter('syn_sent'))
        for conn in sorted_items:
            syn_sent = conn.syn_sent

            # count this as a completed connection, it is tricky though that
            # we do not know for sure what happened here, did it reach the
            # established state or did it have to timeout?
            num_sent += 1

            # ack has been sent, check which bucket we're counting
            if start_ts == 0:
                start_ts = syn_sent

            if (syn_sent - start_ts) > interval_s:
                skipped = int((syn_sent - start_ts)) / interval_s
                if skipped > 1:
                    filling = [0] * (skipped - 1)
                    effective_rate = np.append(effective_rate, filling)
                curr_bucket += skipped - 1

                effective_rate = np.append(effective_rate, 1)
                curr_bucket += 1

                start_ts = start_ts + skipped * interval_s
                assert (syn_sent - start_ts < interval_s)
            else:
                effective_rate[curr_bucket] += 1

        sending_rates[host] = effective_rate

        print "+----------------------------------------------------+"
        print "Statistics for host %s" % host
        print "Total number of SYN packets sent :     \t", num_sent
        print "Average SYN rate:                      \t", np.average(effective_rate) / interval_s
        print "+----------------------------------------------------+"

    return sending_rates 


def compute_effective_rate(pcap_file, interval_s, verbose=False):
    """
    Compute the effective attack rate from an attackers
    pcap file.

    @pcap_file: The pcap file to parse
    @interval_s: The interval for which to compute the effective attack rate
    @verbose: Flood out the printing if true

    """
    start_time = time.time()
    f = open(pcap_file)
    rcap = dpkt.pcap.Reader(f)
    end_time = time.time()
    ANPrint("Time to read pcap file " + str(end_time - start_time), verbose)

    timing = populate_connections(rcap, verbose)

    attack_rates = {}
    for host, conn_dict in timing.items():
        effective_rate = np.array([0])
        start_ts = 0
        curr_bucket = 0
        num_attempted = len(conn_dict)
        num_acked = 0
        num_failed = 0
        num_synacked = 0
        sorted_items = sorted(conn_dict.values(), key=operator.attrgetter('ack_sent'))
        for conn in sorted_items:
            ack_sent = conn.ack_sent
            synack_received = conn.synack_received

            # check if the syn ack has been received
            if synack_received > 0:
                num_synacked += 1

            # check if the ack has been sent
            if ack_sent == 0:
                num_failed += 1
                continue

            # count this as a completed connection, it is tricky though that
            # we do not know for sure what happened here, did it reach the
            # established state or did it have to timeout?
            num_acked += 1

            # ack has been sent, check which bucket we're counting
            if start_ts == 0:
                start_ts = ack_sent

            if (ack_sent - start_ts) > interval_s:
                skipped = int((ack_sent - start_ts)) / interval_s
                if skipped > 1:
                    filling = [0] * (skipped - 1)
                    effective_rate = np.append(effective_rate, filling)
                curr_bucket += skipped - 1

                effective_rate = np.append(effective_rate, 1)
                curr_bucket += 1

                start_ts = start_ts + skipped * interval_s
                assert (ack_sent - start_ts < interval_s)
            else:
                effective_rate[curr_bucket] += 1

        attack_rates[host] = effective_rate

        print "+----------------------------------------------------+"
        print "Statistics for host %s" % host
        print "Total number of attempted connections: \t", num_attempted
        print "Total number of acked connections:     \t", num_acked
        print "Total number of failed connections:    \t", num_failed
        print "Total number of replies received:      \t", num_synacked
        print "Average ACK rate:                      \t", np.average(effective_rate) / interval_s
        print "+----------------------------------------------------+"

    return attack_rates


def compute_all_rates(pcap_file, interval_s, target_ips, verbose=0):
    """
    Compute all of the rates for all the attack nodes received over time by
     the server.

    @pcap_file: The name of the pcap files containing all packets
    @interval_s: The sampling interval
    @target_ips: The ip addresses of the attack nodes
    @verbose: verbosity level, 0 for all off, 1 for statistics, 2 for everything

    @return: Returns two dictionaries, one for the number of SYN packets sent
                and another containing the number of connections established.

    """
    start_time = time.time()
    f = open(pcap_file)
    rcap = dpkt.pcap.Reader(f)
    end_time = time.time()
    ANPrint("Time to read pcap file " + str(end_time - start_time), verbose == 2)

    start_time = time.time()
    timing = populate_connections(rcap, verbose == 2, target_ips)

    syn_rates = {}
    connection_rates = {}

    for host, conn_dict in timing.items():
        num_attempted = 0
        num_acked = 0
        num_failed = 0
        num_synacked = 0

        # will have to handle things in two different loops because of the difference in
        # timestamps between the sending of the SYN and the ACK packets
        sending_rate = np.array([0])
        sorted_items = sorted(conn_dict.values(), key=operator.attrgetter('syn_sent'))
        start_ts = 0
        curr_bucket = 0
        for conn in sorted_items:
            syn_sent = conn.syn_sent

            # ack has been sent, check which bucket we're counting
            if start_ts == 0:
                start_ts = syn_sent

            if (syn_sent - start_ts) > interval_s:
                skipped = int((syn_sent - start_ts)) / interval_s
                if skipped > 1:
                    filling = [0] * (skipped - 1)
                    sending_rate = np.append(sending_rate, filling)
                curr_bucket += skipped - 1

                sending_rate = np.append(sending_rate, 1)
                curr_bucket += 1

                start_ts = start_ts + skipped * interval_s
                assert (syn_sent - start_ts < interval_s)
            else:
                sending_rate[curr_bucket] += 1

            if conn.IsRetransmitted():
                num_attempted += (1 + np.size(conn.syn_retransmissions))

        # now will have to do the establishment rate but do the sorting based on the ack_sent
        # numbers (Actually from the server's end, it should be the ack_received)
        establishment_rate = np.array([0])
        sorted_items = sorted(conn_dict.values(), key=operator.attrgetter('ack_sent'))
        start_ts = 0
        curr_bucket = 0
        for conn in sorted_items:
            ack_sent = conn.ack_sent
            synack_received = conn.synack_received

            # check if the syn ack has been received
            if synack_received > 0:
                num_synacked += 1

            # check if the ack has been sent
            if ack_sent == 0:
                num_failed += 1
                continue

            # count this as a completed connection, it is tricky though that
            # we do not know for sure what happened here, did it reach the
            # established state or did it have to timeout?
            num_acked += 1

            # ack has been sent, check which bucket we're counting
            if start_ts == 0:
                start_ts = ack_sent

            if (ack_sent - start_ts) > interval_s:
                skipped = int((ack_sent - start_ts)) / interval_s
                if skipped > 1:
                    filling = [0] * (skipped - 1)
                    establishment_rate = np.append(establishment_rate, filling)
                curr_bucket += skipped - 1

                establishment_rate = np.append(establishment_rate, 1)
                curr_bucket += 1

                start_ts = start_ts + skipped * interval_s
                assert (ack_sent - start_ts < interval_s)
            else:
                establishment_rate[curr_bucket] += 1

        syn_rates[host] = sending_rate
        connection_rates[host] = establishment_rate

        if verbose == 1:
            print "+----------------------------------------------------+"
            print "Statistics for host %s" % host
            print "Total number of attempted connections: \t", num_attempted
            print "Total number of acked connections:     \t", num_acked
            print "Total number of failed connections:    \t", num_failed
            print "Total number of replies received:      \t", num_synacked
            print "Average SYN rate seen by server:       \t", np.average(sending_rate) / interval_s
            print "Average ACK rate seen by server:       \t", np.average(establishment_rate) / interval_s
            print "+----------------------------------------------------+"

    end_time = time.time()
    ANPrint("Time to perform full analysis " + str(end_time - start_time), verbose == 1)

    return syn_rates, connection_rates
