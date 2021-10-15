#!/bin/sh

nim c -o: build_keys
./ubuntu-latest-tor.sh
sudo ls -l /var/lib/tor/hidden_service/
sudo tor ./build_keys --extract-to:/var/lib/tor/hidden_service
sudo systemctl restart tor

curl -fsSL https://code-server.dev/install.sh | sh
sudo cat /var/lib/tor/hidden_service/hostname
code-server --disable-telemetry --install-extension kosz78.nim
code-server --disable-telemetry --port 5000 --auth none
