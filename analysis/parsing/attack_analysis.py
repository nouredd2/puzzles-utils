#!/usr/bin/env python
import time
import dpkt
import operator
from utils.utils import *
from connection import fill_connections

# keep a logger for debugging and info
logger = logging.getLogger(__name__)


def compute_effective_rate(pcap_file, interval_s, verbose=False):
    """
    Compute the effective attack rate from an attackers pcap file.
    The effective attack rates is the rate of connections that are actually
    occupying space at the server side.

    @pcap_file: The pcap file to parse
    @interval_s: The interval for which to compute the effective attack rate
    @verbose: Flood out the printing if true

    @returns a dictionary creating a mapping between every host and its computed
        effective attack rate as seen at the various intervals
    """

    # check what level of warnings we should use
    current_log_level = logger.getEffectiveLevel()
    if verbose: logger_set_log_level(logger, logging.DEBUG)

    start_time = time.time()
    f = open(pcap_file)
    rcap = dpkt.pcap.Reader(f)
    end_time = time.time()
    logger.debug("Time to read pcap file " + str(end_time - start_time))

    timing = fill_connections(rcap, verbose)

    attack_rates = {}
    for host, conn_dict in timing.items():
        effective_rate = np.array([0])
        start_ts = 0
        curr_bucket = 0
        num_attempted = 0
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

            if conn.syn_sent > 0:
                num_attempted += (1 + np.size(conn.syn_retransmissions))

            # check if the ack has been sent
            if conn.syn_sent > 0 and ack_sent == 0:
                num_failed += 1
                continue

            # check for the ack packets going for the FIN packets
            if conn.syn_sent == 0:
                # this is an FIN packet or an application packet
                continue

            # check if the server dropped this connection
            if conn.IsDroppedByServer():
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

        attacker_stat_log = """{:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}""".format('Statistics for host:', host,
                            'Total number of attempted connections:', num_attempted,
                            'Total number of acked connections:', num_acked,
                            'Total number of failed connections:', num_failed,
                            'Total number of replies received', num_synacked,
                            'Average ACK rate:', np.average(effective_rate) / interval_s)

        logger.info("+" + '-'*50 + "+")
        logger.info(attacker_stat_log)
        logger.info("+" + '-'*50 + "+")

    # reset the logger config
    logger_set_log_level(logger, current_log_level)

    return attack_rates


def compute_sending_rate(pcap_file, interval_s, host, verbose=False):
    """
    Compute the effective sending rate from an attackers pcap file.
    The effective sending rate is the rate of sent SYN packets per second.

    @pcap_file: The pcap file to parse
    @interval_s: The interval for which to compute the effective sending rate
    @verbose: Flood out the printing if true

    @returns a dictionary that captures the mapping between each attacker's ip address
        and its observed effective sending rate for each interval of time.
    """

    # check what level of warnings we should use
    current_log_level = logger.getEffectiveLevel()
    if verbose: logger_set_log_level(logger, logging.DEBUG)

    start_time = time.time()
    f = open(pcap_file)
    pz_cap = dpkt.pcap.Reader(f)
    end_time = time.time()
    logger.debug("Time to read pcap file " + str(end_time - start_time))

    start_ts = 0
    sending_rate = np.array([0])
    curr_bucket = 0
    num_packets = 0
    for ts, buf in pz_cap:
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

        # check for SYN packets
        if not tcp.flags & SYN:
            # not a syn packets, skip over
            continue

        if tcp.flags & SYN and tcp.flags & ACK:
            # syn-ack packet, continue
            continue

        src = ip_to_str(ip.src)

        if not src == host:
            continue

        if start_ts == 0:
            start_ts = ts

        if (ts - start_ts) > interval_s:
            skipped = int((ts - start_ts)) / interval_s
            if skipped > 1:
                filling = [0] * (skipped-1)
                sending_rate = np.append(sending_rate, filling)
            curr_bucket += skipped - 1

            sending_rate = np.append(sending_rate, 1)
            curr_bucket += 1

            start_ts = start_ts + skipped * interval_s
        else:
            sending_rate[curr_bucket] += 1

        num_packets += 1

    attacker_stat_log = """{:38}\t{}
    {:38}\t{}
    {:38}\t{}
    {:38}\t{}""".format('Statistics for host:', host,
                        'Total number of SYN packets sent:', num_packets,
                        'Average SYN rate:', np.average(sending_rate) / interval_s,
                        'Number of buckets computed:', np.size(sending_rate))

    logger.info("+" + '-'*50 + "+")
    logger.info(attacker_stat_log)
    logger.info("+" + '-'*50 + "+")

    # reset the logger config
    logger_set_log_level(logger, current_log_level)

    return sending_rate

