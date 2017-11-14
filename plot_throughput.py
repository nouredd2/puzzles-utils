#!/usr/bin/python

import matplotlib.pyplot as plt
import argparse
from matplotlib.backends.backend_pdf import PdfPages
from analyze import compute_throughput
import numpy as np


def prepare_arguments ():
    parser = argparse.ArgumentParser(description="Analyze and dump plots side by side.")
    parser.add_argument('--file', '-f', type=str, required=True, nargs='+',
                        help="The input pcap file")
    parser.add_argument('--outfile', '-o', type=str, default='sidebyside.pdf',
                        help="The output file to save to.")
    parser.add_argument('--interval', '-i', type=int, default=1.0,
                        help='The intervals in s')
    parser.add_argument('--hosts', '-n', type=str, required=True, nargs='+',
                        help='The host for which to plot the throughput for')
    parser.add_argument('--labels', '-l', type=str, nargs='*',
                        help='The labels for each plot.')
    parser.add_argument('--switch', '-s', action='store_true',
                        help='Switch sides on checking host.')
    _args = parser.parse_args()

    return _args


if __name__ == '__main__':

    args = prepare_arguments()
    fname = args.file
    outfile = args.outfile + '.pdf'
    interval_s = args.interval
    hosts = args.hosts
    labels = args.labels
    switch = args.switch

    fig, ax = plt.subplots(figsize=(8, 4))

    if labels is None:
        labels = hosts

    if len(hosts) == 1 and len(fname) > 1:
        hosts = hosts*len(fname)
    assert (len(hosts) == len(fname))

    i = 0
    for f in fname:
        host = hosts[i]
        print "Computing throughput for host %s" % host
        throughput = compute_throughput(f, host, interval_s, switch)
        numBuckets = np.size(throughput)
        buckets = np.arange(0, numBuckets*interval_s, interval_s)

        bps = throughput / interval_s
        ax.plot(buckets, bps, label=labels[i])
        i += 1

    ax.grid(True)
    ax.legend(loc='best')
    ax.set_title('Throughput of host %s' % host)
    ax.set_xlabel('Time (s)')
    ax.set_ylabel('Throughput (bps)')

    with PdfPages(outfile) as pdf:
        pdf.savefig(fig)

    plt.close()
