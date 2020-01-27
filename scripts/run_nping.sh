#!/bin/sh

RATE=$1
TIME=$2

if [ -z "$TIME" ]; then
  TIME=360s
fi

if ! type "nping" > /dev/null; then
  sudo apt install -y nmap
fi

set -x
timeout -k $TIME $TIME nping --tcp-connect -rate=$RATE -c 100000000 -p 80 -q servernode > /tmp/nping.log
