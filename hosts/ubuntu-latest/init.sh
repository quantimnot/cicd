#!/bin/sh -Cue

sudo apt-get update
sudo apt-get install libsodium-dev xvfb

nimble install -Y

make

export DISPLAY=:99

Xvfb :99 &

echo "Xvfb Listening on :99"
