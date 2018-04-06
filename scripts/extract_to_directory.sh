#!/bin/sh

PREFIX=$1
alias untar='tar -xzvf'

for i in `find . -maxdepth 1 -name "$PREFIX*.tar.gz"`
do
  DIRECTORY=`basename $i .tar.gz`
  if [ ! -d "$DIRECTORY" ]; then
	  mkdir -p ./$DIRECTORY
	  set -x
	  untar $i --directory ./$DIRECTORY
	  set +x
  else
	  echo "Skipping director $DIRECTORY"
  fi
done
