#!/bin/sh

if ! type "sar" > /dev/null; then
  sudo apt install -y sysstat
fi

sar -u ALL 1 -o /proj/ILLpuzzle/logs/`hostname`-sar.out > /dev/null
