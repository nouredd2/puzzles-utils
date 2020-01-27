#!/bin/bash

N=$1
DURATION=$2
HOST=$(hostname -s)

if ! type "ab" > /dev/null; then
  sudo apt install -y apache2-utils
fi

set +x
#ab -c $1 -t $DURATION http://servernode/gettext/10000 > /proj/ILLpuzzle/results/${HOSTNAME}_ab_output.txt 2>&1
ab -r -c 10 -n 5000 -g /proj/ILLpuzzle/results/${HOST}_data.txt http://servernode/gettext/10000  > /proj/ILLpuzzle/results/${HOST}_summary.txt
