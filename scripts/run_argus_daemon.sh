#!/bin/sh

set -x
python -c "import psutil" > /dev/null 2>&1

if [ "$?" -eq "1" ]; then
  cp -R /proj/ILLpuzzle/development/psutil /tmp/psutil
  cd /tmp/psutil
  sudo python setup.py install > /dev/null 2>&1
fi

cp /proj/ILLpuzzle/modules/argus.tar.gz /tmp
cd /tmp
tar -xvf argus.tar.gz

python /tmp/argus/argus.py start
