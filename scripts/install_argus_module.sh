#!/bin/sh

ssh vijay@users.deterlab.net
ssh servernode.happymedium.ILLpuzzle.isi.deterlab.net
cd /proj/ILLpuzzle/modules/argus
make
sudo insmod pmonitor.ko
