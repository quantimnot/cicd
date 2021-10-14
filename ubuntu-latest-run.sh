#!/bin/sh -Cue

mkdir -p build
{
  . ./ubuntu-latest-init.sh
  "${1}" || {
      jq -rc .head_commit.comment "${GITHUB_EVENT_PATH}" | {
        grep -q '[debug ci]' && hub api repos/${GITHUB_REPOSITORY}/collaborators/${GITHUB_ACTOR} >/dev/null
      } && ./ubuntu-latest-diag.sh
    }
} #>|build/build.stdout 2>|build/build.stderr

