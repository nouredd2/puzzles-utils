#!/bin/sh

for i in `find ./ -maxdepth 1 -type d -name "results-profile_*"`
do
  for j in {1..10}
  do
    CLIENT=clientnode-$j
    CAPNAME=$i/$CLIENT-dump_agent-tcpdump.cap
    ./plot_throughput.py -f $CAPNAME -o $i/$CLIENT -i 5 --host $CLIENT:0
  done
  ./plot_throughput.py -f $i/servernode-log_agent-tcpdump.cap -o $i/servernode -i 5 --host servernode:0 --switch
done
