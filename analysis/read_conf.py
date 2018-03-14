#!/usr/bin/python


def ReadHosts(expFile='experiment_conf/experiment.conf'):
    with open(expFile) as f:
        content = f.readlines()

    content = [x.strip() for x in content]

    hostToIp = {}
    ipToHost = {}
    for line in content:
        values = line.split()

        hostname = values[0].split(':')[0]
        hostToIp[hostname] = values[1]
        ipToHost[values[1]] = hostname

    return hostToIp, ipToHost
