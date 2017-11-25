#!/bin/sh

AAL=$1
PROJ=ILLpuzzle
EXP=oak

ARCHIVE=$2

if [ -z "$1" ]
  then
  echo "[Usage:] ./run_experiment event_file [archive name] [experiment name]"
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
/share/magi/current/magi_orchestrator.py --experiment $EXP --project $PROJ --events $AAL

sleep 10 
cd ~/proj/results/
tar -czvf results$ARCHIVE.tar.gz *.cap
rm -f *.cap
