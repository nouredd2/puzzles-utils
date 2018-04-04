#!/usr/bin/env python


def read_exp_config(expfile='../experiment_conf/experiment.conf'):
    """
    Read experiment configuration file from DETER and then create dictionaries
    that map the name of the machine to its ip address, and vice versa.

    @expFile: The experiment file to use

    @return a dictionary mapping hosts to ip addresses and another dictionary
        containing the reverse mapping.
    """
    with open(expfile) as f:
        content = f.readlines()

    content = [x.strip() for x in content]

    host_to_ip = {}
    ip_to_host = {}
    for line in content:
        values = line.split()

        hostname = values[0].split(':')[0]
        host_to_ip[hostname] = values[1]
        ip_to_host[values[1]] = hostname

    return host_to_ip, ip_to_host
