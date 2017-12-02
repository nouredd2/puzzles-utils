#!/bin/sh

RATE=$1

if ! type "nping" > /dev/null; then
  sudo apt install -y nmap
fi

nping --tcp-connect -rate=$RATE -c 100000000 -p 80 -q servernode > /tmp/nping.log
