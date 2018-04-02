#!/usr/bin/env python

import time
import dpkt
from utils.utils import *
from connection import ThroughputEntry


def compute_single_ip_th(ip_addr, throughput, ts, tcp, interval):
    """
    Helper function for the throughput computation of a single host given
    its IP address.

    @ip_addr: The ip address of the host we are dealing with
    @throughput: The IP address to throughput entry mapping, dictionary
    @ts: The current timestamp for the observed packet
    @tcp: The observed TCP packet from dpkt
    @interval: The interval for which we are computing the throughput

    @returns nothing
    """
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


def compute_throughput(pcapFile, interval, server_ip=None):
    """
    Compute the throughput for all of the hosts observed in a single pcap file
    instance. This will cover all hosts. In case you also want to cover the server's
    throughput, then set the server_ip parameter to the IP address of the server.

    @pcapFile: The name of the pcap file to use for the computation
    @interval: The interval of time relative to which to compute the throughput
    @server_ip: [Optional] The server ip in case the throughput for the server is
        also to be computed

    @returns nothing
    """
    start_time = time.time()
    f = open(pcapFile)
    rcap = dpkt.pcap.Reader(f)
    end_time = time.time()

    logging.debug("Time to read pcap file {}".format(str(end_time - start_time)))

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
        compute_single_ip_th(dst_ip, throughput, ts, tcp, interval)

        # now also take care of the server
        if src_ip != server_ip:
            continue
        compute_single_ip_th(src_ip, throughput, ts, tcp, interval)

    return throughput
