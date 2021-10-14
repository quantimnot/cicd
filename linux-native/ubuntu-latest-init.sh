#!/bin/sh -Cue

.github/workflows/ubuntu-latest-tor.sh

nimble install -Y

export DISPLAY=:99

Xvfb :99 &

echo "Xvfb Listening on :99"
