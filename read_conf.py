#!/usr/bin/python


def ReadHosts():
    expFile = 'experiment.conf'

    with open(expFile) as f:
        content = f.readlines()

    content = [x.strip() for x in content]

    hostToIp = {}
    for line in content:
        values = line.split()
        hostToIp[values[0]] = values[1]

    return hostToIp
