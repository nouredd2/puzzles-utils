#!/bin/bash

EXP=$1

if [ -z "$EXP" ]
  then
  EXP=oak
fi

for ((i=1;i<=15;i++))
  do
    set -x 
    ssh clientnode-$i.$EXP.illpuzzle 'uname -r'
    set +x
done

for ((i=1;i<=10;i++))
  do 
    set -x 
    ssh attacknode-$i.$EXP.illpuzzle 'uname -r'
    set +x
done

set -x
ssh servernode.$EXP.illpuzzle 'uname -r'
ssh amaginode.$EXP.illpuzzle 'uname -r'
