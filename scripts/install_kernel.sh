#!/bin/sh

sudo dpkg -i /proj/ILLpuzzle/linux-4.13.0/*.deb > /proj/ILLpuzzle/install-`hostname`.log
#sudo python /share/magi/current/magi_bootstrap.py
echo "sudo cp /proj/ILLpuzzle/scripts/magi.service /etc/systemd/system/magi.service" >> /proj/ILLpuzzle/install-`hostname`.log
sudo cp /proj/ILLpuzzle/scripts/magi.service /etc/systemd/system/magi.service
echo "sudo systemctl daemon-reload" >> /proj/ILLpuzzle/install-`hostname`.log
sudo systemctl daemon-relaod
echo "sudo systemctl enable magi" >> /proj/ILLpuzzle/install-`hostname`.log
sudo systemctl enable magi >> /proj/ILLpuzzle/install-`hostname`.log
echo "sudo systemctl start magi" >> /proj/ILLpuzzle/install-`hostname`.log
sudo systemctl start magi
echo "sudo reboot"
sudo reboot
