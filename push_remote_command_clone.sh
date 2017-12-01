#!/bin/bash

CMD=$1
EXP=$2
for ((i=11;i<=15;i++))
  do
    set -x 
    ssh clientnode-$i.$EXP.illpuzzle "nohup $CMD > /tmp/push_remote.log 2>&1 < /dev/null &" 
    set +x
done

for ((i=1;i<=10;i++))
  do 
    set -x 
    ssh attacknode-$i.$EXP.illpuzzle "nohup $CMD > /tmp/push_remote.log 2>&1 < /dev/null &" 
    set +x
done
