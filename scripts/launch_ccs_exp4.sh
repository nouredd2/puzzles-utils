#!/bin/sh

AAL=$1
PROJ=ILLpuzzle
EXP=ccs

ARCHIVE=$2

if [ -z "$1" ]
  then
  echo "[Usage:] ./launch_ccs_exp4.sh event_file [archive name]"
  exit 0
fi

if [ -z "$ARCHIVE" ]
  then
  ARCHIVE=-$(date +"%Y-%m-%d-%M-%S")
fi

EXP=$3
if [ -z "$3" ]
  then
  EXP=ccs
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
for k in 1 2 3 4
do
  for d in 16 17 18
  do
    set -x
    sed "s/set_difficulty.sh.*\"/set_difficulty.sh $k $d\"/" $1.bak > $1
    bash /proj/ILLpuzzle/puzzles-utils/scripts/run_exp_incr_diff.sh $AAL $EXP ${ARCHIVE}_${k}_${d}
  done
done
