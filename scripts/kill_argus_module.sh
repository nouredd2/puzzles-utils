#!/bin/sh

# Deactivates the module
echo "0" > /proc/pmonitor

# Save data to project "dumps" directory
cat /proc/pmonitor > /proj/ILLpuzzle/dumps/

# Remove module
rmmod pmonitor
