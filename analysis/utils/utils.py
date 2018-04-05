#!/usr/bin/env python
import numpy as np
import socket
import logging

# Constants
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


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


def logger_set_log_level(logger, level):
    """
    Set the logging level for the logger

    @logger: The input logger instance
    @level: The logging level to set

    @return nothing
    """
    logger.setLevel(level)


# From https://gist.github.com/vishalkuo/f4aec300cf6252ed28d3
def remove_outliers(data, outlier_cnst=1.5):
    a = np.array(data)
    upper_quartile = np.percentile(a, 75)
    lower_quartile = np.percentile(a, 25)
    IQR = (upper_quartile - lower_quartile) * outlier_cnst
    quartileSet = (lower_quartile - IQR, upper_quartile + IQR)
    resultList = []

    num_outliers = 0
    for y in a.tolist():
        if (y >= quartileSet[0]) and (y <= quartileSet[1]):
            resultList.append(y)
        else:
            num_outliers += 1

    logging.info("Removed {} outliers from dataset...".format(num_outliers))
    return np.array(resultList)


def get_col(arr, col):
    m = map(lambda x: x[col], arr)
    return np.array(m, dtype=np.float)


def ip_to_str(address):
    return socket.inet_ntop(socket.AF_INET, address)
