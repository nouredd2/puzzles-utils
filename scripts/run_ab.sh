#!/bin/sh

set +x
ab -c 150 -t 120 -c 1000000 http://servernode-1/ > /proj/ILLpuzzle/ab_output.txt
