#!/bin/bash

for ((i=1;i<=15;i++))
  do
    set -x 
    ssh clientnode-$i.oak.illpuzzle 'sudo service magi restart'
    set +x
done

for ((i=1;i<=10;i++))
  do 
    set -x 
    ssh attacknode-$i.oak.illpuzzle 'sudo service magi restart'
    set +x
done

set -x
ssh servernode.oak.illpuzzle 'sudo service magi restart'
ssh servernode.oak.illpuzzle 'ps -ef | grep tcpdump'
