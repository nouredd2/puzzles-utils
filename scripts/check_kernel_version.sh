#!/bin/bash

EXP=$1

if [ -z "$EXP" ]
  then
  EXP=oak
fi

for ((i=1;i<=15;i++))
  do
    set -x 
    ssh clientnode-$i.$EXP.illpuzzle 'uname -a'
    set +x
done

for ((i=1;i<=10;i++))
  do 
    set -x 
    ssh attacknode-$i.$EXP.illpuzzle 'uname -a'
    set +x
done

set -x
ssh servernode.$EXP.illpuzzle 'uname -a'
ssh amaginode.$EXP.illpuzzle 'uname -a'
