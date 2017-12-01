#!/bin/sh

AAL=$1
PROJ=ILLpuzzle
EXP=sc

ARCHIVE=$2

if [ -z "$1" ]
  then
  echo "[Usage:] ./launch_exp5_1.sh event_file [archive name]"
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
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15
do
  set -x
  /share/magi/current/magi_orchestrator.py --experiment ${EXP} --project $PROJ --events ${AAL}_size${i}.yaml
  sleep 10
  cd ~/proj/results
  tar -czvf results${ARCHIVE}_size_${i}.tar.gz *.cap
  rm -f ~/proj/results/*.cap
  cd
  set +x
done
