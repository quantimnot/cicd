#!/bin/sh -Cue

mkdir -p build
{
  . .github/workflows/ubuntu-latest-init.sh
  nake -d:${1} --browser:${2} tests &&
    nake -d:${1} -d:release --norun --package || {
      jq -rc .head_commit.comment "${GITHUB_EVENT_PATH}" | {
        grep -q '[debug ci]' && hub api repos/${GITHUB_REPOSITORY}/collaborators/${GITHUB_ACTOR} >/dev/null
      } && .github/workflows/ubuntu-latest-diag.sh
    }
} #>|build/build.stdout 2>|build/build.stderr

