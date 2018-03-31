#!/usr/bin/env python
import numpy as np
import socket


def get_col(arr, col):
    m = map(lambda x: x[col], arr)
    return np.array(m, dtype=np.float)


def ip_to_str(address):
    return socket.inet_ntop(socket.AF_INET, address)


class DuplicateFilter(object):
    """
    Filter class to be used for filtering warning message from the
    logger in case of a malformed pcap file.
    """
    def __init__(self):
        self.msgs = set()

    def filter(self, record):
        rv = record.msg not in self.msgs
        self.msgs.add(record.msg)
        return rv
