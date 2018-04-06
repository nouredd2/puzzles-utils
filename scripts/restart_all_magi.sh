#!/bin/bash

for ((i=1;i<=9;i++))
  do
    set -x 
    ssh clientnode-$i.happiermedium.illpuzzle 'sudo service magi restart'
    set +x
done

for ((i=1;i<=6;i++))
  do 
    set -x 
    ssh attacknode-$i.happiermedium.illpuzzle 'sudo service magi restart'
    set +x
done

set -x
ssh servernode.happiermedium.illpuzzle 'sudo service magi restart'
ssh servernode.happiermedium.illpuzzle 'ps -ef | grep tcpdump'
