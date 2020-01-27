#!/bin/bash

for ((i=1;i<=5;i++))
  do
    set -x 
    ssh clientnode-$i.dsn.illpuzzle 'sudo service magi restart'
    set +x
done

for ((i=1;i<=5;i++))
  do 
    set -x 
    ssh attacknode-$i.dsn.illpuzzle 'sudo service magi restart'
    set +x
done

set -x
ssh servernode.dsn.illpuzzle 'sudo service magi restart'
ssh servernode.dsn.illpuzzle 'ps -ef | grep tcpdump'
