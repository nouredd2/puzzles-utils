#!/bin/bash

TIMER=$1

sudo sysctl -w net.ipv4.tcp_challenge_timer=${TIMER}
