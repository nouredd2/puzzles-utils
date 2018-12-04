#!/bin/bash

for ((i=1;i<=15;i++))
  do
    set -x 
    ssh clientnode-$i.ccs.illpuzzle 'sudo service magi restart'
    set +x
done

for ((i=1;i<=10;i++))
  do 
    set -x 
    ssh attacknode-$i.ccs.illpuzzle 'sudo service magi restart'
    set +x
done

set -x
ssh servernode.ccs.illpuzzle 'sudo service magi restart'
ssh servernode.ccs.illpuzzle 'ps -ef | grep tcpdump'
