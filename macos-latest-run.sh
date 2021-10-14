#!/bin/sh -Cue

. .github/workflows/macos-latest-init.sh

nake --serve -d:${1} --browser:${2} tests ||
  { .github/workflows/macos-latest-diag.sh; exit 1; }
