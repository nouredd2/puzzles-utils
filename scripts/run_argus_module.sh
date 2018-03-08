#!/bin/sh

 # Extracts the process id from whatever is using port 80
lines=$(sudo ss -lptn | grep :80)
processes=$(echo $lines | tr "," "\n")
pid=""
for i in $processes; do
  if [[ $i = *"pid="* ]]; then
    pid="$(echo $i | cut -d'=' -f2)"
    echo $pid
  fi
done

# Passes the process ID into the module
echo "P $pid" > /proc/pmonitor

# Activates the module
echo "1" > /proc/pmonitor
