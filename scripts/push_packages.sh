#!/bin/sh


sudo dpkg -i /proj/ILLpuzzle/linux-4.13.0/*.deb
#sudo python /share/magi/current/magi_bootstrap.py

echo "sudo apt install -y nmap"
sudo apt install -y nmap

echo "sudo cp /proj/ILLpuzzle/scripts/magi.service /etc/systemd/system/magi.service"
sudo cp /proj/ILLpuzzle/scripts/magi.service /etc/systemd/system/magi.service

echo "sudo systemctl daemon-reload"
sudo systemctl daemon-relaod

echo "sudo systemctl enable magi"
sudo systemctl enable magi

echo "sudo systemctl start magi"
sudo systemctl start magi

echo "sudo reboot"
sudo reboot
