#!/bin/sh

N=$1
DURATION=$2

if ! type "ab" > /dev/null; then
  sudo apt install -y apache2-utils
fi

set +x
ab -c $1 -t $DURATION -n 10000000 http://servernode/gettext/10000 > /proj/ILLpuzzle/ab_output.txt
