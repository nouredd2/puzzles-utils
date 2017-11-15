#!/bin/sh

rsync -avP -e ssh deter:/proj/ILLpuzzle/results/$1 .
