#!/bin/sh

sudo apt remove -y linux-image-`(uname -r)` linux-headers-`(uname -r)`

sudo dpkg -i /proj/ILLpuzzle/linux-4.13.0/ccs/*.deb > /tmp/install-`hostname`.log 2>&1
#sudo python /share/magi/current/magi_bootstrap.py

echo "sudo apt install -y nmap" >> /tmp/install-`hostname`.log
sudo apt install -y nmap

echo "sudo cp /proj/ILLpuzzle/scripts/magi.service /etc/systemd/system/magi.service" >> /tmp/install-`hostname`.log
sudo cp /proj/ILLpuzzle/scripts/magi.service /etc/systemd/system/magi.service

echo "sudo systemctl daemon-reload" >> /tmp/install-`hostname`.log
sudo systemctl daemon-relaod

echo "sudo systemctl enable magi" >> /tmp/install-`hostname`.log
sudo systemctl enable magi >> /tmp/install-`hostname`.log

echo "sudo systemctl start magi" >> /tmp/install-`hostname`.log
sudo systemctl start magi

echo "sudo reboot"
sudo reboot
