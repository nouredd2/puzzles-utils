#!/bin/sh

for i in `find ./ -maxdepth 1 -type d -name "results-profile_*"`
do
  echo "################################## Working on directory: $i"
  ./plot_throughput_all.py -f $i/servernode-log_agent-tcpdump.cap -d $i -i 10 --server servernode
done
