#!/bin/bash

set -x
python -c "import psutil" > /dev/null 2>&1

if [ "$?" -eq "1" ]; then
  cp -R /proj/ILLpuzzle/development/psutil /tmp/psutil
  cd /tmp/psutil
  sudo python setup.py install > /dev/null 2>&1
fi

rm -rf /tmp/argus
cp -R /proj/ILLpuzzle/development/argus /tmp

cd /tmp/argus
sudo python argus.py start
