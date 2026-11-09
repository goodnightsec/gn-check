#!/usr/bin/env bash
# Fails when the nuclei or naabu pin in deploy/Dockerfile.scanner is behind
# the newest upstream release. The release gate skips the bundled binaries;
# this check is the control that they are the newest upstream releases.
set -euo pipefail

dockerfile="${1:-deploy/Dockerfile.scanner}"

pinned_version() {
  sed -n "s/^ARG $1=//p" "$dockerfile" | sed 's/[[:space:]]*#.*//' | head -n 1 | tr -d '\r'
}

latest_version() {
  gh api "repos/projectdiscovery/$1/releases/latest" --jq .tag_name | sed 's/^v//'
}

status=0
for pair in "nuclei:NUCLEI_VERSION" "naabu:NAABU_VERSION"; do
  repo="${pair%%:*}"
  arg="${pair##*:}"
  pinned="$(pinned_version "$arg")"
  if ! latest="$(latest_version "$repo")"; then
    echo "$repo: could not read the latest release" >&2
    status=1
    continue
  fi

  if [ -z "$pinned" ]; then
    echo "$repo: could not read $arg from $dockerfile" >&2
    status=1
  elif [ "$pinned" = "$latest" ]; then
    echo "$repo: pinned $pinned, latest $latest — ok"
  else
    echo "$repo: pinned $pinned, latest release $latest; bump $arg in $dockerfile" >&2
    status=1
  fi
done

exit "$status"
