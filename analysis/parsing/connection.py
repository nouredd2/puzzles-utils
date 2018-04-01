#!/usr/bin/env python
from utils.utils import *


# keep a logger for debugging and info
logger = logging.getLogger(__name__)


class TCPConnection:
    def __init__(self, host, seq, ts, sport):
        self.host = host
        self.syn_sent = ts  # time of first sent syn
        self.synack_received = 0
        self.ack_sent = 0
        self.rst_received = 0
        self.seq = seq
        self.sport = sport
        self.isDroppedByDst = False
        self.syn_retransmissions = np.empty(0)
        self.isRetransmitted = False

    def isDroppedByServer(self):
        return self.isDroppedByDst

    def setResetFlag(self, _ts):
        self.rst_received = _ts
        self.isDroppedByDst = True

    def isRetransmitted(self):
        self.isRetransmitted = np.size(self.syn_retransmissions) > 0
        return self.isRetransmitted

    def getNumberOfRetransmissions(self):
        return np.size(self.syn_retransmissions)


class ThroughputEntry:
    def __init__(self, ts):
        self.inbytes = np.array([0])
        self.curr_bucket = 0
        self.start_ts = ts


def fill_connections(pz_cap, verbose=False, target_ips=set()):
    """
    In this case, I will treat retransmissions as separate connection
    class since we need to account for them in the analysis. I will always
    add the ACK received to the last sent SYN.

    @pz_cap: The pcap reader generated by dpkt
    @verbose: The level of logging to use
    @target_ips: A set containing some target ips to only generate connections for.
        If this set is empty, it is assumed that we should get the connections for
        everyone.

    @returns a multi-level dictionary that contains the connection for each of the
        ip addresses contained in target_ips, or everything if target_ips is empty.
        For each ip address, there is another dictionary indexed by the connection
        sequence number.
    """
    timing = {}
    expected_seq_num = {}

    # check what level of warnings we should use
    current_log_level = logger.getEffectiveLevel()
    if verbose: logger_set_log_level(logger, logging.DEBUG)

    duplicate_filter = DuplicateFilter()
    logger.addFilter(duplicate_filter)

    for ts, buf in pz_cap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        if eth.type != dpkt.ethernet.ETH_TYPE_IP or \
                not isinstance(eth.data, dpkt.ip.IP):
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
                conn = TCPConnection(src, tcp.seq, ts, tcp.sport)
                timing[src][tcp.seq] = conn
            else:
                conn = timing[src][tcp.seq]
                # account for out of order recording
                if conn.syn_sent == 0:
                    conn.syn_sent = ts
                else:
                    conn.syn_retransmissions = np.append(conn.syn_retransmissions, ts)
                # OCD put back
                timing[src][tcp.seq] = conn

            # initialize one entry per (ip,port) pair from the source, capture expected sequence number
            if (src, tcp.sport) not in expected_seq_num:
                expected_seq_num[(src, tcp.sport)] = {}

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
                    # account for out of order recording
                    # issue warning only one
                    logger.warning("Packets in cap file are out of order!")

                    conn = TCPConnection(dst, tcp.ack-1, 0, tcp.dport)
                    conn.synack_received = ts
                    timing[dst][tcp.ack-1] = conn
            else:
                logger.warning("Received SYNACK packet for non tracked host {}".format(dst))

        # Client response
        if (not (tcp.flags & SYN)) and (tcp.flags & ACK) and (not tcp.flags & FIN):
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

                    # save the expected sequence number from the server to make sure the connection was not reset
                    if (src, tcp.sport) in expected_seq_num:
                        expected_seq_num[src, tcp.sport][tcp.ack] = conn
                else:
                    # handle out of order cap file
                    # NOTE: THIS WORKS FOR ATTACKERS BECAUSE THERE ARE NO APPLICATIONS BUT NOT GOOD CLIENTS
                    # THIS DOES NOT WORK.
                    logger.warning("Packets in cap file are out of order!")

                    conn = TCPConnection(src, tcp.seq - 1, 0, tcp.sport)
                    conn.ack_sent = ts
                    timing[src][tcp.seq-1] = conn

        # RST packets
        if tcp.flags & RST:
            dst = ip_to_str(ip.dst)

            # check if I am applying some filter over the nodes
            if len(target_ips) > 0 and dst not in target_ips:
                continue

            if dst in timing:
                # print "[Log:] Host %s received a RST packet from the server" % dst
                logger.debug("Host {} received a RST packet from the server".format(dst))
                if (dst, tcp.dport) not in expected_seq_num:
                    logger.warning("Malformed RST packet received for host {}".format(dst))
                elif tcp.seq in expected_seq_num[(dst, tcp.dport)]:
                    logger.debug("""Server reset connection after ACK establishment for host {}
                        At port number {} with expected sequence number {}""".format(dst, tcp.dport, tcp.seq))
                    conn = expected_seq_num[(dst, tcp.dport)][tcp.seq]
                    conn.setResetFlag(ts)
                else:
                    logger.warning("""Received RST packet for a non tracked connection at host {}.
                        This message will be printed once per host""".format(dst))
            else:
                logger.warning("Detected RST packet for non tracked host {}".format(dst))

    # reset the logger config
    logger_set_log_level(logger, current_log_level)
    logger.removeFilter(duplicate_filter)
    del duplicate_filter

    return timing
