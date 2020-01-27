#!/bin/bash

# set the syn backlog to 409
echo "net.core.somaxconn = 2048" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf

# set the number of synack retries to 2
echo "net.ipv4.tcp_synack_retries = 5" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 2048" >> /etc/sysctl.conf

# put the changes into affect. These are persistent afterwards.
sysctl -p
