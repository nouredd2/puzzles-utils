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

# -p only makes directory if it doesn't already exist
mkdir -p logs
touch logs/argus.out
cd /tmp/argus
sudo python argus.py start
echo "STARTED ARGUS.PY"
