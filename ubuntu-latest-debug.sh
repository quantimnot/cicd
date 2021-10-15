#!/bin/sh

echo "${tor_keys}" > keys
sudo apt-get update
nimble install -Y
nim c -o:build_keys build_keys

sudo apt install --reinstall --fix-missing -y apt-transport-https openssh-server
sudo ufw allow ssh
sudo tee /etc/ssh/sshd_config <<"EOF"
ListenAddress 127.0.0.1
PasswordAuthentication no
EOF
./build_keys extract-ssh -f keys
ls -l ~/.ssh
sudo systemctl restart sshd

sudo sh -c 'echo "deb [arch=amd64] https://deb.torproject.org/torproject.org focal main" >> /etc/apt/sources.list.d/torproject.list'
wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
sudo apt update
sudo apt install tor deb.torproject.org-keyring
sudo tee /etc/tor/torrc <<"EOF"
#Log info file /var/lib/tor/tor.log
DataDirectory /var/lib/tor
  HiddenServiceDir /var/lib/tor/hidden_service
  HiddenServicePort 22 127.0.0.1:22
  HiddenServicePort 80 127.0.0.1:5000
EOF
sudo -u debian-tor mkdir -p /var/lib/tor/hidden_service
# sudo -u debian-tor touch /var/lib/tor/tor.log
# sudo -u debian-tor chmod 0600 /var/lib/tor/tor.log
sudo -u debian-tor ./build_keys extract-tor -f keys -p /var/lib/tor/hidden_service
sudo systemctl restart tor
time=1
while ! sudo cat /var/lib/tor/hidden_service/hostname >/dev/null 2>&1
do time=$((time*2)); sleep $time
done

curl -fsSL https://code-server.dev/install.sh | sh
sudo tee ~/.config/code-server/config.yaml <<"EOF"
---
bind-addr: "localhost:5000"
auth: none
cert: false
disable-telemetry: true
disable-update-check: true
install-extension:
  - nimsaem.nimvscode
EOF
code-server
