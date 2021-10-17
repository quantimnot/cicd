#!/bin/sh -Cue

echo "${tor_keys}" > keys
sudo apt-get update
sudo apt-get install libsodium-dev xvfb

nimble install -Y
nim c -o:keys keys

export DISPLAY=:99

Xvfb :99 &

echo "Xvfb Listening on :99"
