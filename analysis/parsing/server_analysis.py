#!/usr/bin/env python
import logging
import dpkt
import time
import operator
import numpy as np
from utils.utils import logger_set_log_level
from connection import fill_connections

# keep a logger for debugging and info
logger = logging.getLogger(__name__)


def compute_all_rates(pcap_file, interval_s, target_ips, verbose=0):
    """
    Compute all of the rates for all the attack nodes received over time by
     the server.

    @pcap_file: The name of the pcap files containing all packets
    @interval_s: The sampling interval
    @target_ips: The ip addresses of the attack nodes
    @verbose: verbosity level, 0 for all off, 1 for statistics, 2 for everything

    @returns two dictionaries, one for the number of SYN packets sent
                and another containing the number of connections established.

    """

    # check what level of warnings we should use
    current_log_level = logger.getEffectiveLevel()
    if verbose: logger_set_log_level(logger, logging.DEBUG)

    start_time = time.time()
    f = open(pcap_file)
    rcap = dpkt.pcap.Reader(f)
    end_time = time.time()
    logger.debug("Time to read pcap file " + str(end_time - start_time))

    start_time = time.time()
    timing = fill_connections(rcap, verbose == 2, target_ips)

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

            if syn_sent == 0:
                continue

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

            # check for the ack packets going for the FIN packets
            if conn.syn_sent == 0:
                # this is an FIN packet or an application packet
                continue

            # check if the syn ack has been received
            if synack_received > 0:
                num_synacked += 1

            # check if the ack has been sent
            if conn.syn_sent > 0 and ack_sent == 0:
                num_failed += 1
                continue

            # check if the server dropped this connection
            if conn.IsDroppedByServer():
                num_failed += 1

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

        attacker_stat_log = """{:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}""".format('Statistics for host:', host,
                            'Total number of attempted connections:', num_attempted,
                            'Total number of acked connections:', num_acked,
                            'Total number of failed connections:', num_failed,
                            'Total number of replies received:', num_synacked,
                            'Average SYN rate seen by server:', np.average(sending_rate) / interval_s,
                            'Average ACK rate seen by server:', np.average(establishment_rate) / interval_s)

        # debug because we don't want to do this for every possible ip address
        logger.debug("+" + '-'*50 + "+")
        logger.debug(attacker_stat_log)
        logger.debug("+" + '-'*50 + "+")

    end_time = time.time()
    logger.debug("Time to perform full analysis " + str(end_time - start_time))

    # reset the logger config
    logger_set_log_level(logger, current_log_level)

    return syn_rates, connection_rates
