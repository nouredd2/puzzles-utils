import numpy as np


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
