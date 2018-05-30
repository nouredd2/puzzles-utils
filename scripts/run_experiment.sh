#!/bin/bash

function usage {
  CMD_LINE_OPTIONS_HELP='\n
  Command line options:\n
      -h                 Print this help function and exit\n
      -e  event_file     Set the experiment event file to $event_file\n
      -x  experiment     Set the experiment name to $experiment\n
      -p  project        Set the project name to $project\n
      -a  archive        Set the output archive suffix to $archive\n
  '
  echo -e "\n Usage:"
  echo -e "    run_experiment.sh -e event_file -x experiment -a archive -p project"
  echo -e "$CMD_LINE_OPTIONS_HELP"
}


# parse the command line arguments 
while getopts ":he:x:a:p:" opt; do
  case ${opt} in
    h )
      usage
      exit 0
      ;;
    e )
      AAL=$OPTARG
      ;;
    p )
      PROJ=$OPTARG
      ;;
    x )
      EXP=$OPTARG
      ;;
    a )
      ARCH_NAME=$OPTARG
      ;;
    \? )
      echo "Invalid Option: -$OPTARG" 1>&2
      exit 1
      ;;
  esac
done
shift "$((OPTIND-1))"


if [ -z "$AAL" ]; then
  echo "ERROR: No input event file provided" 1>&2
  usage
  exit 1
fi

if [ -z "$EXP" ]; then
  echo "ERROR: No input experiment specified" 1>&2
  usage 
  exit 1
fi

if [ -z "$ARCH_NAME" ]; then
  ARCH_NAME=-$(date +"%Y-%m-%d-%M-%S")
  echo "WARNING: Setting default archive suffix to $ARCH_NAME"
fi

if [ -z "$PROJ" ]; then
  PROJ=ILLpuzzle
  echo "WARNING: Setting default project to $PROJ"
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
