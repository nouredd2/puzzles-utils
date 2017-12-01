#!/bin/bash

for ((i=1;i<=10;i++))
  do
    set -x 
    ssh clientnode-$i.oakclone.illpuzzle 'sudo /proj/ILLpuzzle/scripts/install_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
    set +x
done

#for ((i=1;i<=10;i++))
#  do 
#    set -x 
#    ssh attacknode-$i.oakclone.illpuzzle 'sudo /proj/ILLpuzzle/scripts/install_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
#    set +x
#done

set -x
ssh servernode.oakclone.illpuzzle 'sudo /proj/ILLpuzzle/scripts/install_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
ssh amaginode.oakclone.illpuzzle 'sudo /proj/ILLpuzzle/scripts/install_kernel.sh > /tmp/install`hostname`.log 2>&1 < /dev/null &'
