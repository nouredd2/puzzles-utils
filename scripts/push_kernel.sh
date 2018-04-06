#!/bin/bash

for ((i=1;i<=15;i++))
  do
    set -x 
    ssh clientnode-$i.oak.illpuzzle 'sudo /proj/ILLpuzzle/scripts/install_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
    set +x
done

for ((i=1;i<=10;i++))
  do 
    set -x 
    ssh attacknode-$i.oak.illpuzzle 'sudo /proj/ILLpuzzle/scripts/install_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
    set +x
done

set -x
ssh servernode.oak.illpuzzle 'sudo /proj/ILLpuzzle/scripts/install_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
ssh amaginode.oak.illpuzzle 'sudo /proj/ILLpuzzle/scripts/install_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
