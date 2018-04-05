#!/bin/bash

AAL=$1
PROJ=ILLpuzzle
EXP=happiermedium

OUTPUT=$2

if [ -z "$1" ]
  then
  echo "[Usage:] ./run_exp_incr_diff event_file [archive name] [experiment name]"
  exit 0
fi

if [ -z "$OUTPUT" ]
  then
  OUTPUT=-$(date +"%Y-%m-%d-%M-%S")
fi

EXP=$3
if [ -z "$3" ]
  then
  EXP=happiermedium
fi

# while true; do
#     read -p "Do you wish to clean up the results directory (yY/nN)?" yn
#     case $yn in
#         [Yy]* ) set -x; rm -f ~/proj/results/*.cap; set +x; break;;
#         [Nn]* ) break;;
#         * ) echo "Please answer yes or no.";;
#     esac
# done

set -x
/share/magi/current/magi_orchestrator.py --experiment $EXP --project $PROJ --events $AAL

# Copy argus daemon output from all clients, attackers, and server to shared /proj/ILLpuzzle/results directory
cd /proj/ILLpuzzle/results
mkdir -p argusout
for (( i = 1; i < 10; i++ )); do
  scp -o StrictHostKeyChecking=no clientnode-$i.$EXP.$PROJ.isi.deterlab.net:/tmp/argus.out .
  mv argus.out argusout/clientnode$i.out
done
for (( i = 1; i < 7; i++ )); do
  scp -o StrictHostKeyChecking=no attacknode-$i.$EXP.$PROJ.isi.deterlab.net:/tmp/argus.out .
  mv argus.out argusout/attacknode$i.out
done
scp -o StrictHostKeyChecking=no servernode.$EXP.$PROJ.isi.deterlab.net:/tmp/argus.out .
mv argus.out argusout/servernode.out

# Tar the tcpdump cap files, argus daemon output files, and argus module output together
sleep 10
mkdir -p results$OUTPUT
mv *.cap results$OUTPUT
mv argusout results$OUTPUT
mv argus-module.txt results$OUTPUT

tar -czvf results$OUTPUT.tar.gz results$OUTPUT/
rm -rf results$OUTPUT
