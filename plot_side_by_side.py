#!/usr/bin/python

import analyze as an
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.backends.backend_pdf import PdfPages


if __name__ == '__main__':

    num_bins = 1000

    pfile = "with-puzzles.cap"
    npfile = "without-puzzles.cap"
    outfile = 'sidebyside.pdf'

    pconnection_time, prt = an.parse_file(pfile)
    npconnection_time, nprt = an.parse_file(npfile)

    fig, ax = plt.subplots(figsize=(8, 4))

    print ("Generating CDFs...")
    for host in pconnection_time.iterkeys():
        data = pconnection_time[host]
        an.plot_cdf_ax(data, num_bins, ax, 'With puzzles')

    for host in npconnection_time.iterkeys():
        data = npconnection_time[host]
        an.plot_cdf_ax(data, num_bins, ax, 'Without puzzles')

    ax.grid(True)
    ax.legend(loc='best')
    ax.set_title('CDF of Connection Time')
    ax.set_xlabel('Time (us)')
    ax.set_ylabel('Likelihood of occurrence')

    with PdfPages(outfile) as pdf:
        pdf.savefig(fig)

    plt.close()
