#!/usr/bin/env python

import numpy as np
import logging


def plot_cpu_usage(daemon_stats, host, sampling_rate, fig, colors, rows=1, cols=1,
                   figidx=1, coloridx=0):
    """
    Create a plot of the cpu usage of a certain host from the daemon stats dictionary.

    @daemon_stats: the dictionary containing the data points
    @host: the host for which we are plotting
    @sampling_rate: the daemon sampling rate
    @fig: the input figure to add a subplot to
    @colors: the colors array to use
    @rows: the number of rows in the figure
    @cols: the number of columns in the figure
    @figidx: the index of the axis in the figure
    @coloridx: the color index in the color array to use

    @return the axis containing the plot in the figure
    """

    # get the axis to start plotting
    ax = fig.add_subplot(rows, cols, figidx)

    ts_array = np.asarray(daemon_stats['Timestamp']) / sampling_rate
    cpu_array = daemon_stats['cpu_percent']

    ax.plot(ts_array, cpu_array, markerfacecolor='none',
            label=host, color=colors[coloridx])

    # the usual paper formatting options
    ax.grid(axis='y', color="0.9", linestyle='-', linewidth=1)

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    ax.get_xaxis().tick_bottom()
    ax.get_yaxis().tick_left()
    ax.tick_params(axis='x', direction='out')
    ax.tick_params(axis='y', length=0)

    ax.set_axisbelow(True)

    return ax


def plot_module_data(module_stats, label, sampling_rate, fig, colors, rows=1, cols=1,
                     figidx=1, coloridx=0, linewidth=2):
    """
    Create a plot of the module data coming out of the server node

    @module_stats: the dictionary containing the data points
    @label: the plot's label
    @sampling_rate: the module sampling rate
    @fig: the figure to add a subplot to
    @colors: the colors array to use
    @rows: the number of rows in the figure
    @cols: the number of columns in the figure
    @figidx: the index of the axis in the figure
    @coloridx: the color index in the color array to use

    @return the axis containing the plot in the figure
    """

    # get the axis to start plotting
    ax = fig.add_subplot(rows, cols, figidx)

    ts_array = module_stats['Timestamp']
    listen_q = module_stats['listen_q']
    accept_q = module_stats['accept_q']

    ax.plot(ts_array, listen_q, markerfacecolor='none',
            label='Listen Queue', color=colors[coloridx], linewidth=linewidth)
    ax.plot(ts_array, accept_q, markerfacecolor='none',
            label='Accept Queue', color=colors[coloridx+1], linewidth=linewidth)

    # the usual paper formatting options
    ax.grid(axis='y', color="0.9", linestyle='-', linewidth=1)

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    ax.get_xaxis().tick_bottom()
    ax.get_yaxis().tick_left()
    ax.tick_params(axis='x', direction='out')
    ax.tick_params(axis='y', length=0)

    ax.set_axisbelow(True)

    return ax