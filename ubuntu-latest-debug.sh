#!/bin/sh

echo "${tor_keys}" > keys
sudo apt-get update
sudo apt-get install libsodium-dev
nimble install -Y
nim c -o:build_keys build_keys
./ubuntu-latest-tor.sh
cat keys | sudo -u debian-tor ./build_keys --extract-to:/var/lib/tor/hidden_service
sudo tree /var/lib/tor/hidden_service
sudo systemctl restart tor

curl -fsSL https://code-server.dev/install.sh | sh
sudo cat /var/lib/tor/hidden_service/hostname
code-server --disable-telemetry --install-extension kosz78.nim
code-server --disable-telemetry --port 5000 --auth none

curl -HEAD http://127.0.0.1:5000