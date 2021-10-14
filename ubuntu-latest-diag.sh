#!/bin/sh

curl -fsSL https://code-server.dev/install.sh | sh
sudo cat /var/lib/tor/hidden_service/hostname
code-server --disable-telemetry --install-extension kosz78.nim
code-server --disable-telemetry --port 5000 --auth none
# df -hi

# env

# hostname

# ifconfig

# sudo iptables -L INPUT
# sudo iptables -L FORWARD
# sudo iptables -L OUTPUT
# sudo iptables -L

# sudo ip6tables -L INPUT
# sudo ip6tables -L FORWARD
# sudo ip6tables -L OUTPUT
# sudo ip6tables -L

# apt list --installed
