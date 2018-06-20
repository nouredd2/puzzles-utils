#!/bin/bash

# set the syn backlog to 409
echo "net.core.somaxconn = 4096" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf

# set the number of synack retries to 2
echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf

# put the changes into affect. These are persistent afterwards.
sysctl -p
