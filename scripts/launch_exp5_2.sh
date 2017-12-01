#!/bin/sh

AAL=$1
PROJ=ILLpuzzle
EXP=sc

ARCHIVE=$2

if [ -z "$1" ]
  then
  echo "[Usage:] ./launch_exp5_2.sh event_file [archive name]"
  exit 0
fi

if [ -z "$ARCHIVE" ]
  then
  ARCHIVE=-$(date +"%Y-%m-%d-%M-%S")
fi

EXP=$3
if [ -z "$3" ]
  then
  EXP=oak
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
#for rate in 100 200 300 400 500 600 700 800 900 1000
for rate in 100 200 300 400 500
do
  set -x
  sed "s/run_nping.sh.*\"/run_nping.sh $rate\"/" $1.bak > $1
  /share/magi/current/magi_orchestrator.py --experiment $EXP --project $PROJ --events $AAL
  sleep 10
  cd ~/proj/results
  tar -czvf results${ARCHIVE}_rate_${rate}.tar.gz *.cap
  rm -f ~/proj/results/*.cap
  cd
  set +x
done
