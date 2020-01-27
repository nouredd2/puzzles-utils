#!/bin/bash

EXP=$1

for ((i=1;i<=5;i++))
  do
    set -x 
    ssh clientnode-$i.$EXP.illpuzzle 'sudo /proj/ILLpuzzle/scripts/modify_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
    set +x
done

for ((i=1;i<=5;i++))
  do 
    set -x 
    ssh attacknode-$i.$EXP.illpuzzle 'sudo /proj/ILLpuzzle/scripts/modify_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
    set +x
done

set -x
ssh servernode.$EXP.illpuzzle 'sudo /proj/ILLpuzzle/scripts/modify_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
ssh amaginode.$EXP.illpuzzle 'sudo /proj/ILLpuzzle/scripts/modify_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
