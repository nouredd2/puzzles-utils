#!/bin/bash

set -x

if [ ! -d "/tmp/argus" ];
then
  cp -R /proj/ILLpuzzle/development/argus /tmp
fi

cd /tmp/argus
sudo python hel.py start
