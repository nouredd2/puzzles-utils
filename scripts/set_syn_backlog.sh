#!/bin/sh

sudo sysctl -w net.ipv4.tcp_max_syn_backlog=$1
