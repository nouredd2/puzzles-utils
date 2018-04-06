#!/bin/bash

# Save data to project "results" directory
cat /proc/pmonitor > /proj/ILLpuzzle/results/argus-module.txt

# Deactivates the module
echo "0" > /proc/pmonitor

# Remove module
sudo rmmod pmonitor
