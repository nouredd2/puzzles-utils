#!/bin/sh

DURATION=$1

if ! type "ab" > /dev/null; then
  sudo apt install -y apache2-utils
fi

for ((i=50; i<=950; i+=50))
  do
    set -x
    ab -c $i -t $DURATION -n 10000000 http://servernode/gettext/10000 > /proj/ILLpuzzle/ab/ab_out_$i.txt
    set +x
done
