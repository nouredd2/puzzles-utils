#!/bin/sh

echo "sudo cp /proj/ILLpuzzle/scripts/magi.service /etc/systemd/system/magi.service" >> /tmp/install-`hostname`.log
sudo cp /proj/ILLpuzzle/scripts/magi.service /etc/systemd/system/magi.service

echo "sudo systemctl daemon-reload" >> /tmp/install-`hostname`.log
sudo systemctl daemon-relaod

echo "sudo systemctl enable magi" >> /tmp/install-`hostname`.log
sudo systemctl enable magi >> /tmp/install-`hostname`.log

echo "sudo systemctl start magi" >> /tmp/install-`hostname`.log
sudo systemctl start magi
