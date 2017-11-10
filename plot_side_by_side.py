#!/usr/bin/python

import analyze as an
import matplotlib.pyplot as plt
import argparse
from matplotlib.backends.backend_pdf import PdfPages


def prepare_arguments ():
    parser = argparse.ArgumentParser(description="Analyze and dump plots side by side.")
    parser.add_argument('--files', '-f', type=str, required=True, nargs="+",
                        help="The input pcap file")
    parser.add_argument('--labels', '-l', type=str, nargs="+", required=True,
                        help="The labels on the plots")
    parser.add_argument('--bins', '-b', type=int, default=50,
                        help="The number of bins to use for the histogram")
    parser.add_argument('--outfile', '-o', type=str, default='sidebyside.pdf',
                        help="The output file to save to.")
    parser.add_argument('--logx', action='store_true',
                        help="Toggle switching to log scale on the x-axis")
    _args = parser.parse_args()

    return _args


if __name__ == '__main__':

    args = prepare_arguments()
    num_bins = args.bins
    files = args.files
    labels = args.labels
    outfile = args.outfile

    # pfile = "with-puzzles.cap"
    # npfile = "without-puzzles.cap"
    # outfile = 'sidebyside.pdf'

    fig, ax = plt.subplots(figsize=(8, 4))

    i = 0
    for f in files:
        print "Parsing ", f
        conn, prt = an.parse_file(f)
        lbl = labels[i]
        i += 1
        print ("Generating CDFs...")
        for host in conn.iterkeys():
            data = conn[host]
            an.plot_cdf_ax(data, num_bins, ax, lbl, args.logx)

    ax.grid(True)
    ax.legend(loc='best')
    ax.set_title('CDF of Connection Time')
    ax.set_xlabel('Time (us)')
    ax.set_ylabel('Likelihood of occurrence')

    with PdfPages(outfile) as pdf:
        pdf.savefig(fig)

    plt.close()
