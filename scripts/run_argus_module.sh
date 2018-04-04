#!/bin/sh

cp /proj/ILLpuzzle/modules/module.tar.gz /tmp/
cd /tmp/
tar -xvf module.tar.gz
cd module
#cd /proj/ILLpuzzle/modules/argus
make
sudo insmod pmonitor.ko

 # Extracts the process id from whatever is using port 80
#lines=$(sudo ss -lptn | grep :80)
#processes=$(echo $lines | tr "," "\n")
#pid=""
#for i in $processes; do
#  if [[ $i = *"pid="* ]]; then
#    pid="$(echo $i | cut -d'=' -f2)"
#    echo $pid
#  fi
#done

# Passes the process ID into the module
PID=$(sudo netstat -nlp | grep :80 | sed -e "s/.*LISTEN\s*\([0-9]*\).*/\1/")
echo "P $PID" > /proc/pmonitor

# Activates the module
echo "1" > /proc/pmonitor
