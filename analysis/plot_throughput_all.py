#!/usr/bin/python

import matplotlib.pyplot as plt
import argparse
import time
from matplotlib.backends.backend_pdf import PdfPages
from analyze import compute_global_throughput
import numpy as np
from read_conf import ReadHosts
import sys


def prepare_arguments():
    parser = argparse.ArgumentParser(description="Analyze and dump plots side by side.")
    parser.add_argument('--file', '-f', type=str, required=True,
                        help="The input pcap file")
    parser.add_argument('--directory', '-d', type=str,
                        help="Dump output files in the specified directory")
    parser.add_argument('--interval', '-i', type=int, default=1.0,
                        help='The intervals in seconds')
    parser.add_argument('--hosts', '-n', type=str, nargs='*',
                        help='The host for which to plot the throughput for [Format: Hostname:iface]. Default is all.')
    parser.add_argument('--server', '-s', type=str,
                        help='The name of server node if any.')
    _args = parser.parse_args()

    return _args


def plot_entry(e, ip_to_host, d):
    fig, ax = plt.subplots(figsize=(8, 4))

    num_buckets = np.size(e.inbytes)
    buckets = np.arange(0, num_buckets * interval_s, interval_s)

    bps = 10e-6 * e.inbytes * 8 / interval_s
    max_value = np.max(bps)
    ax.plot(buckets, bps)
    ax.grid(True)

    ax.set_title('Throughput of host %s' % host)
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Throughput (Mbps)')
    ax.set_ylim(0, max_value + 2)

    if d is None:
        ofile = ip_to_host[host] + ".pdf"
    else:
        ofile = d + "/" + ip_to_host[host] + ".pdf"
    with PdfPages(ofile) as pdf:
        pdf.savefig(fig)

    plt.close()


if __name__ == '__main__':
    args = prepare_arguments()
    fname = args.file
    interval_s = args.interval
    hostnames = args.hosts
    servernode = args.server
    directory = args.directory

    hostToIp, ipToHost = ReadHosts()

    if hostnames is not None:
        hosts = np.array([])
        for host in hostnames:
            if host not in hostToIp:
                print "Hostname %s not found in file experiment_conf/experiment.conf" % host
                sys.exit()
            hosts = np.append(hosts, hostToIp[host])
    else:
        hosts = None

    server_ip = hostToIp[servernode]
    start_time = time.time()
    throughput = compute_global_throughput(fname, interval_s, server_ip)
    end_time = time.time()
    print "Time to compute the throughput is " + str(end_time - start_time)

    # got the map, now plot
    if hosts is None:
        for host, entry in throughput.iteritems():
            plot_entry(entry, ipToHost, directory)
    else:
        for host in hosts:
            entry = throughput[host]

            if entry is None:
                print "ERROR: Host %s not found in file %s..." % (ipToHost[host], fname)
                print "       Continuing to the rest!"
            else:
                plot_entry(entry, ipToHost, directory)
