#!/bin/bash

AAL=$1
PROJ=ILLpuzzle

if [ -z "$1" ]; then
  echo "[Usage:] ./run_exp_incr_diff event_file [experiment_name] [archive_name]"
  exit 0
fi

EXP=$2
if [ -z "$2" ]; then
  EXP=happiermedium
fi

ARCH_NAME=$3
if [ -z "$3" ]; then
  ARCH_NAME=-$(date +"%Y-%m-%d-%M-%S")
fi

set -x
/share/magi/current/magi_orchestrator.py --experiment $EXP --project $PROJ --events $AAL

# Copy argus daemon output from all clients, attackers, and server to shared /proj/ILLpuzzle/results directory
cd /proj/ILLpuzzle/results
mkdir -p argusout
set +x
for (( i = 1; i <= 15; i++ )); do
  set -x
  scp -o StrictHostKeyChecking=no clientnode-$i.$EXP.$PROJ.isi.deterlab.net:/tmp/argus/argus.out .
  mv argus.out argusout/clientnode$i.out
  set +x
done
for (( i = 1; i <= 10; i++ )); do
  set -x
  scp -o StrictHostKeyChecking=no attacknode-$i.$EXP.$PROJ.isi.deterlab.net:/tmp/argus/argus.out .
  mv argus.out argusout/attacknode$i.out
  set +x
done
set -x
scp -o StrictHostKeyChecking=no servernode.$EXP.$PROJ.isi.deterlab.net:/tmp/argus/argus.out .
mv argus.out argusout/servernode.out

# Tar the tcpdump cap files, argus daemon output files, and argus module output together
sleep 10
mkdir -p moduleout
mv argus-module.txt moduleout/argus-module.txt
tar -czvf results-$ARCH_NAME.tar.gz *.cap argusout/ moduleout/

yes | rm *.cap
yes | rm -rf argusout moduleout
