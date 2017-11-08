#!/bin/sh

sudo hping3 -I eth5 --faster -c 10000 -S -p 80 -M 0 --rand-source --tcp-timestamp servernode-1
