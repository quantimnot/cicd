#!/bin/sh -Cue

sudo apt install --reinstall --fix-missing -y apt-transport-https openssh-server
sudo ufw allow ssh
sudo tee /etc/ssh/sshd_config <<"EOF"
ListenAddress 127.0.0.1
PasswordAuthentication no
PermitRootLogin yes
EOF
sudo sh -c 'echo "deb [arch=amd64] https://deb.torproject.org/torproject.org focal main" >> /etc/apt/sources.list.d/torproject.list'
wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
sudo apt update
sudo apt install tor deb.torproject.org-keyring
sudo tee /etc/tor/torrc <<"EOF"
DataDirectory /var/lib/tor
  HiddenServiceDir /var/lib/tor/hidden_service/
  HiddenServicePort 22 127.0.0.1:22
  HiddenServicePort 80 127.0.0.1:5000
EOF
