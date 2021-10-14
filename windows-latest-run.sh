#!/bin/sh -Cue

. .github/workflows/windows-latest-init.sh

nake --serve -d:${1} --browser:${2} tests ||
  { .github/workflows/windows-latest-diag.sh; exit 1; }
