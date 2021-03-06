#!/usr/bin/env python

import numpy as np
import time
import dpkt
import operator
import logging
from utils.utils import get_col, logger_set_log_level
from connection import fill_connections

# keep a logger for debugging and info
logger = logging.getLogger(__name__)


def compute_client_percentage(pcap_file, interval_s, verbose=False, target_ips=set(), timing=None):
    """
    Compute the percentage of established connections for a given set of hosts or for
    all hosts seen in a certain in put pcap file.

    @pcap_file: the pcap file to parse
    @interval_s: the interval for which to compute the connection establishment rate
    @verbose: flood out the printing if true
    @target_ips: a set of ips targeted for the analysis. Runs for all ips if empty
    @timing: a dictionary generated by fill_connections prior to calling this routine.
        If it is None, the dictionary is generated locally.

    @returns A dictionary creating a mapping from each host to an array showing the
        observed connection establishment rate for each time interval
    """

    # check what level of warnings we should use
    current_log_level = logger.getEffectiveLevel()
    if verbose: logger_set_log_level(logger, logging.DEBUG)

    # Read the pcap file and then call the fill connections routine to obtain a classification
    # of the client (or all clients)' TCP connections observed in the file
    # check if the dictionary has already been computed
    if timing is None:
        start_time = time.time()
        f = open(pcap_file)
        rcap = dpkt.pcap.Reader(f)
        timing = fill_connections(rcap, verbose, target_ips)
        end_time = time.time()

        logger.debug("Time to read pcap file {}".format(str(end_time-start_time)))

    client_percentage_connections = {}
    for host, conn_dict in timing.items():
        arr_percentage = np.array([[0,0]])
        start_ts = 0
        curr_bucket = 0
        num_attempted = 0
        num_acked = 0
        num_failed = 0
        num_synacked = 0
        sorted_items = sorted(conn_dict.values(), key=operator.attrgetter('syn_sent'))

        for conn in sorted_items:
            syn_sent = conn.syn_sent
            ack_sent = conn.ack_sent
            synack_received = conn.synack_received

            # check if the syn ack has been received
            if synack_received > 0:
                num_synacked += 1

            # check for the ack packets going for the FIN packets
            if conn.syn_sent == 0:
                # this is an FIN packet or an application packet
                continue

            if conn.syn_sent > 0:
                num_attempted += (1 + np.size(conn.syn_retransmissions))

            # check if the server dropped this connection
            if conn.IsDroppedByServer() or (conn.syn_sent > 0 and ack_sent == 0):
                num_failed += 1
            else:
                # count this as a completed connection, it is tricky though that
                # we do not know for sure what happened here, did it reach the
                # established state or did it have to timeout?
                num_acked += 1

            # ack has been sent, check which bucket we're counting
            if start_ts == 0:
                start_ts = syn_sent

            if (syn_sent - start_ts) > interval_s:
                skipped = int((syn_sent - start_ts)) / interval_s
                if skipped > 1:
                    filling = [[0, 0]] * (skipped - 1)
                    arr_percentage = np.vstack((arr_percentage, filling))
                curr_bucket += skipped - 1

                entry = [1, 0]
                if (not conn.IsDroppedByServer()) and (conn.ack_sent > 0):
                    entry = [1, 1]
                arr_percentage = np.vstack((arr_percentage, entry))
                curr_bucket += 1

                start_ts = start_ts + skipped * interval_s
                assert (syn_sent - start_ts < interval_s)
            else:
                entry = arr_percentage[curr_bucket]
                entry[0] += 1
                if (not conn.IsDroppedByServer()) and (conn.ack_sent > 0):
                    entry[1] += 1
                arr_percentage[curr_bucket] = entry

        client_percentage_connections[host] = arr_percentage
        avg_estab_rate = np.average(get_col(arr_percentage, 1) / get_col(arr_percentage, 0))

        host_stat_log = """
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}""".format('Statistics for host:', host,
                            'Total number of attempted connections:', num_attempted,
                            'Total number of acked connections:', num_acked,
                            'Total number of failed connections:', num_failed,
                            'Total number of replies received', num_synacked,
                            'Average establishment rate:', avg_estab_rate)

        logger.info("+" + '-'*50 + "+" + host_stat_log)
        logger.info("+" + '-'*50 + "+")

    # reset the logger config
    logger_set_log_level(logger, current_log_level)

    return client_percentage_connections


def compute_connection_time(pcap_file, verbose=False, ignore_retrans=False, timing=None):
    """
    Compute the observed connection time, time connection initiated, number of retransmissions, number of dropped
        connections, and number of incomplete connections seen by every host given an input
        pcap file to be parsed using dpkt.

    @pcap_file: The input pcap file containing the packet information
    @verbose: The level of verbosity for this function
    @ignore_retrans: Flag whether to ignore retransmissions or include them in the computation.
    @timing: a dictionary generated by fill_connections prior to calling this routine.
        If it is None, the dictionary is generated locally.

    @returns five dictionaries, each containing a map from the host to its observed connection
        parameters, name, connection establishment time, syn sending time for each completed connection,
        number of retransmission, number of dropped connection, and number of incomplete connection.
    """

    # check what level of warnings we should use
    current_log_level = logger.getEffectiveLevel()
    if verbose: logger_set_log_level(logger, logging.DEBUG)

    # Read the pcap file and then call the fill connections routine to obtain a classification
    # of the client (or all clients)' TCP connections observed in the file
    if timing is None:
        start_time = time.time()
        f = open(pcap_file)
        rcap = dpkt.pcap.Reader(f)
        timing = fill_connections(rcap, verbose)
        end_time = time.time()

        logger.debug("Time to read pcap file {}".format(str(end_time-start_time)))

    connection_time = {}
    retransmission_count = {}
    dropped_count = {}
    incomplete_connections = {}
    syn_sent_time = {}
    num_connections = 0
    # Compute connection time (time between first SYN and first ACK)
    # Number of unanswered SYN (count retransmissions)
    for host in timing.iterkeys():
        # do this to reduce lookup time
        connection_time[host] = []
        syn_sent_time[host] = []
        retransmission_count[host] = 0
        dropped_count[host] = []
        incomplete_connections[host] = 0

        sorted_items = sorted(timing[host].values(), key=operator.attrgetter('syn_sent'))
        num_connections = 0
        for conn in sorted_items:
            if conn.syn_sent == 0:
                # skip over the ACKs that correspond to application information
                continue

            if conn.is_retransmitted():
                retransmission_count[host] = retransmission_count[host] + conn.get_num_retransmissions()

                # count retransmission in completed connections.
                if conn.ack_sent > 0:
                    if not ignore_retrans:
                        connection_time[host].append(conn.ack_sent - conn.syn_sent)
                        syn_sent_time[host].append(conn.syn_sent)
                else:
                    incomplete_connections[host] = incomplete_connections[host] + 1

            elif conn.is_dropped_by_server():
                dropped_count[host].append(conn.rst_received)
            else:
                # normal connection completion
                if conn.ack_sent > 0:
                    connection_time[host].append(conn.ack_sent - conn.syn_sent)
                    syn_sent_time[host].append(conn.syn_sent)
                else:
                    logger.warning("Found an incompleted connection at time {}".format(conn.syn_sent))

            num_connections = num_connections + 1

        host_stat_log = """
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}
        {:38}\t{}""".format('Statistics for host:', host,
                            'Total number of attempted connections:', num_connections,
                            'Total number of completed connections:', len(connection_time[host]),
                            'Total number of retransmission:', retransmission_count[host],
                            'Total number of dropped connections', len(dropped_count[host]),
                            'Total number of incomplete connections:', incomplete_connections[host],
                            'Maximum connection time:', np.max(connection_time[host]),
                            'Minimum connection time:', np.min(connection_time[host]),
                            'Average connection time:', np.average(connection_time[host]),
                            'Standard deviation:', np.std(connection_time[host]))

        logger.info("+" + '-'*50 + "+" + host_stat_log)
        logger.info("+" + '-'*50 + "+")

    # reset the logger config
    logger_set_log_level(logger, current_log_level)

    return connection_time, syn_sent_time, retransmission_count, dropped_count, incomplete_connections
