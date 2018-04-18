#!/usr/bin/env python

import dpkt
import re
import numpy as np
import logging

# local imports
from parsing.client_analysis import fill_connections
from utils.utils import remove_outliers


def get_host_ip(host, host_to_ip):
    """
    Get the ip address of a given host. use this if we don't know if we are getting an ip
    address or a domain name. The function will try to match it to an ip format, and if not
    it will look it up in the host_to_ip dictionary

    @host: The input host ip or domain name
    @host_to_ip: The hostname to ip mapping dictionary

    @returns the ip address of the host (returns the same value if input is already an ip address)
    """
    if re.match('[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', host):
        return host
    else:
        return host_to_ip[host]


# function that takes an input pcap file and gets the timing dictionary
def get_timing(fname, verbose=False):
    """
    Get the timing dictionary from fill_connections. This is wrapper for reading
    the pcap file and getting the reader to pass it along
    """
    with open(fname) as pcap_file:
        cap_reader = dpkt.pcap.Reader(pcap_file)
        return fill_connections(cap_reader, verbose)


def get_throughput_array(entry, interval_s):
    """
    Get the throughput values and the bins from a list of throughput entry structures.

    @entry: A list of throughput entries
    @interval: The interval of computation for the throughput

    @returns a list of time buckets, and the observed throughput in each bucket
    """
    num_buckets = np.size(entry.inbytes)
    buckets = np.arange(0, num_buckets * interval_s, interval_s)

    bps = 10e-6 * entry.inbytes * 8 / interval_s

    return buckets, bps


# function to plot the cdf of the connection time for a given host
def plot_host_connection_time(host_conn_dict, host, fig, colors, host_to_ip,
                              rows=1, cols=1, figidx=1, numbins=100, logx=False):
    """
    Plot the cdf of a host's connection time

    @host_conn_dict: A dictionary containing the mapping from host ip to connection time
    @host: The hostname or ip address of the host in question
    @fig: The input figure to add a subplot to
    @colors: The input color map to use for plotting
    @host_to_ip: The hostname to ip mapping dictionary
    @rows: The number of subplot rows in the figure
    @cols: The number of subplot columns in the figure
    @figidx: The index of the current in the subfigure
    @numbins: The number of bins to use for the cdf
    @logx: Flag to select using log scale on x-axis

    @returns the added axis if successful, None if failed
    """

    # figure out what the host ip is
    host_ip = get_host_ip(host, host_to_ip)

    if host_ip not in host_conn_dict:
        logging.error("Host {} is not in the connection time dictionary".format(host_ip))
        return None

    # start the actual work, get the subplot
    ax = fig.add_subplot(rows, cols, figidx)

    host_conn = host_conn_dict[host_ip]
    logging.info("Maximum connection time seen is {}".format(np.max(host_conn)))
    host_conn_ro = remove_outliers(host_conn, 100.0)
    values, base = np.histogram(host_conn_ro, bins=numbins, density=True)
    cumulative = np.cumsum(values) * (base[1] - base[0])
    base = base * 1e3
    lbl = "Host {}".format(host_ip)
    if logx:
        ax.semilogx(base[:-1], cumulative, markerfacecolor='none',
                    label=lbl, linewidth=2, color=colors[figidx])
    else:
        ax.plot(base[:-1], cumulative, markerfacecolor='none',
                label=lbl, linewidth=2, color=colors[figidx])

    ax.grid(axis='y', color="0.9", linestyle='-', linewidth=1)

    ax.set_ylim(-0.1, 1.05)
    ax.set_yticks([0, 0.3, 0.6, 1])

    ax.set_xlabel('Connection Time ($m$s)')

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    ax.get_xaxis().tick_bottom()
    ax.get_yaxis().tick_left()
    ax.tick_params(axis='x', direction='out')
    ax.tick_params(axis='y', length=0)

    ax.set_axisbelow(True)

    return ax


# function to plot the cdf of the connection time for a given host
def plot_host_throughput(throughput_dict, host, fig, interval, colors, host_to_ip,
                         rows=1, cols=1, figidx=1):
    """
    Plot the throughput of a given host as a function of time, for a given time interval.

    @throughput_dict: The input dictionary containing the throughput entries already computed.
    @host: The host for which we are printing, accepts both IP and hostname.
    @fig: The matplotlib figure
    @interval: The interval of time for which the throughput was computed.
        This must match the ones used to generate the dictionary.
    @colors: The coloring map to use
    @host_to_ip: The hostname to ip address mapping dictionary
    @rows: The number of rows of subfigures in this figure
    @cols: The number of columns of subfigures in this figure
    @figifx: The index of the subfigure in the overall figure.

    @returns the subplot object used by matplotlib
    """

    host_ip = get_host_ip(host, host_to_ip)
    if host_ip not in throughput_dict:
        logging.error("Host IP {} not seen in throughput dictionary!".format(host_ip))
        return None

    throughput_entries = throughput_dict[host_ip]

    host_bucket, host_bps = get_throughput_array(throughput_entries, interval_s=interval)
    lbl = "Host {}".format(host_ip)

    ax = fig.add_subplot(rows, cols, figidx)
    ax.plot(host_bucket, host_bps, marker=None, markerfacecolor='none', label=lbl,
            linewidth=2, color=colors[figidx - 1])

    ax.grid(axis='y', color="0.9", linestyle='-', linewidth=1)
    ax.set_ylim(-5, np.max(host_bps) + 0.5)
    # ax.set_yticks([0,10,20,30])
    # ax.set_xticks([0,40,80,120,160])

    ax.set_xlabel('Time (seconds)')
    ax.set_ylabel('Throughput (Mbps)')

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    ax.get_xaxis().tick_bottom()
    ax.get_yaxis().tick_left()
    ax.tick_params(axis='x', direction='out')
    ax.tick_params(axis='y', length=0)
    ax.set_axisbelow(True)

    return ax