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
  echo -e "    run_iterative_experiment.sh -e event_file -x experiment -a archive -p project"
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

TEMP_NAME="autogen_iterative"
for k in 1 2
do
  for d in 15 16 17 18
  do
    AAL_FILE_NAME="${TEMP_NAME}_${k}_${d}"
    set -x
    sed "s/set_difficulty.sh.*\"/set_difficulty.sh $k $d\"/" $AAL > $AAL_FILE_NAME
    bash /proj/ILlpuzzle/puzzles-utils/scripts/run_experiment.sh -e $AAL_FILE_NAME -x $EXP -p $PROJ -a ${ARCH_NAME}_${k}_${d}
  done
done
