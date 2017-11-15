#!/bin/sh

AAL=$1
PROJ=ILLpuzzle
EXP=oak

ARCHIVE=$2

if [ -z "$1" ]
  then
  echo "[Usage:] ./experiment_loop.sh event_file [archive name]"
  exit 0
fi

if [ -z "$ARCHIVE" ]
  then
  ARCHIVE=-$(date +"%Y-%m-%d-%M-%S")
fi

while true; do
    read -p "Do you wish to clean up the results directory (yY/nN)?" yn
    case $yn in
        [Yy]* ) set -x; rm -f ~/proj/results/*.cap; set +x; break;;
        [Nn]* ) break;;
        * ) echo "Please answer yes or no.";;
    esac
done

set -x
cp $1 $1.bak
set +x
for k in 1 2 3 4 5
do
  for d in 2 4 8 10 16 20
  do
    set -x
    sed "s/set_difficulty.sh.*\"/set_difficulty.sh $k $d\"/" $1.bak > $1
    /share/magi/current/magi_orchestrator.py --experiment $EXP --project $PROJ --events $AAL
    sleep 10
    cd ~/proj/results
    tar -czvf results$2_k_${k}_d_{$d}.tar.gz *.cap
    rm -f ~/proj/results/*.cap
    cd
    set +x
  done
done
