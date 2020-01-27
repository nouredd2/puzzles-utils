#!/bin/bash

CHALLENGE_NZ=$1
CHALLENGE_DIFF=$2

# sudo /proj/ILLpuzzle/scripts/set_up_server.sh

sudo sysctl -w net.ipv4.tcp_challenge_nz=${CHALLENGE_NZ}
sudo sysctl -w net.ipv4.tcp_challenge_diff=${CHALLENGE_DIFF}
