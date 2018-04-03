#!/usr/bin/env python


def get_daemon_stats_from_file(filename):
    """
    Read an argus output file and generated lists of the corresponding
    data

    @filename: the name of the input argus dump file

    @returns a dictionary mapping labels (Timestamp, cpu_percent, etc.)
        to their corresponding values in the data dump
    """
    with open(filename, 'r') as argus_file:
        header = argus_file.readline().split()
        stats_lists = [[cat] for cat in header]
        for lineno, line in enumerate(argus_file):
            for i, stat in enumerate(line.strip().split()):
                if i is 0:
                    stat = lineno
                elif i is 1:
                    stat = float(stat)
                else:
                    stat = int(stat)

                stats_lists[i].append(stat)

        file_stats = {l[0]: l[1:] for l in stats_lists}
        return file_stats


def get_module_stats_from_file(filename):
    """
    Read an argus module data dump and put the data into its appropriate format.

    @filename: the name of the input file containing the module data dump

    @returns a dictionary mapping labels to their corresponding values in the
        data dump
    """
    with open(filename, 'r') as argus_file:
        stats_list = {'Timestamp': [], 'listen_q': [], 'accept_q': []}
        for i, line in enumerate(argus_file):
            stats = line.strip().split(';')
            stats_list['Timestamp'].append(i)
            stats_list['listen_q'].append(int(stats[1]))
            stats_list['accept_q'].append(int(stats[2]))

        return stats_list
