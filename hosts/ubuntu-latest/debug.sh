#!/bin/sh -u

# shellcheck disable=SC2154
echo "${debug_keys}" >debug_keys
unset debug_keys

if ./keys install-ssh -f debug_keys; then
	sudo apt install --reinstall --fix-missing -y apt-transport-https openssh-server
	sudo ufw allow ssh
	sudo tee /etc/ssh/sshd_config <<"EOF"
ListenAddress 127.0.0.1
PasswordAuthentication no
PermitRootLogin no
PubkeyAuthentication yes
EOF
	sudo systemctl restart sshd
fi

sudo sh -c 'echo "deb [arch=amd64] https://deb.torproject.org/torproject.org focal main" >> /etc/apt/sources.list.d/torproject.list'
wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --import
gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
sudo apt update
sudo apt install tor deb.torproject.org-keyring
sudo tee /etc/tor/torrc <<"EOF"
DataDirectory /var/lib/tor
  HiddenServiceDir /var/lib/tor/hidden_service
  HiddenServicePort 22 127.0.0.1:22
  HiddenServicePort 80 127.0.0.1:5000
EOF
sudo -u debian-tor mkdir -p /var/lib/tor/hidden_service
sudo -u debian-tor ./keys install-onion -f debug_keys -p /var/lib/tor/hidden_service
sudo systemctl restart tor
time=1
while ! sudo cat /var/lib/tor/hidden_service/hostname >/dev/null 2>&1; do
	time=$((time * 2))
	sleep               $time
done

rm debug_keys

export SERVICE_URL=https://open-vsx.org/vscode/gallery
export ITEM_URL=https://open-vsx.org/vscode/item
curl -fsSL https://code-server.dev/install.sh | sh
mkdir -p ~/.config/code-server
sudo tee ~/.config/code-server/config.yaml <<"EOF"
---
bind-addr: "localhost:5000"
auth: none
cert: false
disable-telemetry: true
disable-update-check: true
EOF
code-server --install-extension nimsaem.nimvscode
code-server
