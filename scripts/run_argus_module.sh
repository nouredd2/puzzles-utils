#!/bin/bash

cp /proj/ILLpuzzle/modules/module.tar.gz /tmp/
cd /tmp/
tar -xvf module.tar.gz

cd module
make
sudo insmod pmonitor.ko

# Passes the process ID into the module
PID=$(sudo netstat -nlp | grep :80 | sed -e "s/.*LISTEN\s*\([0-9]*\).*/\1/")
echo "P $PID" > /proc/pmonitor

# Activates the module
echo "1" > /proc/pmonitor
