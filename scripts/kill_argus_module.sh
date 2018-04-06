#!/bin/bash

# Deactivates the module
echo "0" > /proc/pmonitor

# Save data to project "results" directory
cat /proc/pmonitor > /proj/ILLpuzzle/results/argus-module.txt

# Remove module
sudo rmmod pmonitor
