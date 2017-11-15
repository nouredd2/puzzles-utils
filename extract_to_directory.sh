#!/bin/sh

PREFIX=$1
alias untar='tar -xzvf'

for i in `find . -name "$PREFIX*.tar.gz"`
do
  set -x
  DIRECTORY=`basename $i .tar.gz`
  mkdir -p ./$DIRECTORY
  untar $i --directory ./$DIRECTORY
  set +x
done
