#!/bin/sh

rsync -ahvP -e ssh deter:/proj/ILLpuzzle/results/$1 .
