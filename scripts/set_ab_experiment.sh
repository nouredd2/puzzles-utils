#!/bin/bash

set -x

ssh clientnode-1.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 1 10'
ssh clientnode-2.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 1 10'
ssh clientnode-3.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 1 10'
ssh clientnode-4.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 1 10'
ssh clientnode-5.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 1 10'

ssh servernode.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 1 10'
ssh amaginode.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 1 10'
