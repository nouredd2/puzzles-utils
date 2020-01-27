#!/bin/bash

set -x

ssh clientnode-1.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 15'
ssh clientnode-2.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 15'
ssh clientnode-3.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 16'
ssh clientnode-4.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 17'
ssh clientnode-5.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 17'

ssh attacknode-1.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 20'
ssh attacknode-2.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 16'
ssh attacknode-3.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 18'
ssh attacknode-4.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 17'
ssh attacknode-5.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 18'

ssh servernode.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 15'
ssh amaginode.dsn.illpuzzle 'sudo /proj/ILLpuzzle/scripts/set_difficulty.sh 2 15'
