#!/usr/bin/env bash
set -euo pipefail

# Read the distribution tags back off the registry, after a publish.
#
# Why this exists, and why the check that came before it was not enough.
#
# `assert-release-ready.sh` derives the npm tag from the manifest version and
# refuses to disagree with the workflow's own derivation. That is a real check
# and it holds. What it cannot do is verify the tag npm ACTUALLY APPLIED,
# because it runs before the publish. It proves what npm was told.
#
# The gap is not hypothetical. `0.1.0-rc.2` was published with `--tag rc`, the
# workflow log says so, and the registry answered:
#
#     { "rc": "0.1.0-rc.2", "latest": "0.1.0-rc.2" }
#
# npm assigns `latest` to the first version published to a new package whatever
# `--tag` said, because a package must always have a `latest`. So the README's
# promise that a bare `yarn add` could never reach a prerelease was false the
# moment the first prerelease shipped, and nothing in the pipeline noticed --
# every check had passed, and each was telling the truth about a different
# question than the one that mattered.
#
# This script asks the registry instead.
#
# usage: assert-published-tags.sh <package> <version> <expected-tag>

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <package> <version> <expected-dist-tag>" >&2
  echo "  e.g. $0 react-native-matrix-crypto 0.1.0-rc.2 rc" >&2
  exit 2
fi

PACKAGE="$1"
VERSION="$2"
EXPECTED_TAG="$3"

# A publish is not instantly visible to every registry read. Retry rather than
# fail on propagation, but bound it: a tag that never appears is a real defect,
# not a slow one.
#
# TEN MINUTES, AND THE MINUTE THIS USED TO ALLOW WAS WRONG. It read six attempts
# over a minute. On 26 September 2026 `npm publish` answered
# `+ react-native-matrix-crypto@0.8.0` at 19:57:50 UTC, this check gave up at
# 19:58:46, and the registry first listed 0.8.0 at 20:02:40: close to five
# minutes, for a publish that had landed. The release run went red on a release
# that was fine. Thirty attempts twenty seconds apart outlast what was seen by
# a margin, and a publish that has not shown in ten minutes is still one worth
# failing on. `--prefer-online` so that no cached answer is read as the
# registry's.
ATTEMPTS=30
TAGS=""
for attempt in $(seq 1 "$ATTEMPTS"); do
  if TAGS=$(npm view "$PACKAGE" dist-tags --json --prefer-online 2>/dev/null) && [ -n "$TAGS" ]; then
    if printf '%s' "$TAGS" | grep -q "\"$VERSION\""; then
      break
    fi
  fi
  echo "  registry does not yet report $VERSION (attempt $attempt/$ATTEMPTS); waiting"
  sleep 20
  TAGS=""
done

if [ -z "$TAGS" ]; then
  echo "FAIL: the registry never reported $PACKAGE@$VERSION under any tag."
  echo "      The publish claimed success. Either it did not land, or the"
  echo "      registry is not serving it. Do not treat this as a slow read:"
  echo "      ten minutes is twice the slowest propagation seen (see the"
  echo "      comment above the retries)."
  exit 1
fi

echo "Distribution tags now on the registry for $PACKAGE:"
printf '%s\n' "$TAGS" | sed 's/^/  /'

# `npm view <pkg> dist-tags --json` does not have one stable output shape: it
# answers with the object itself for some queries and with that object wrapped
# in an array for others. Reading the wrapped form as an object yields
# undefined for every tag, which this script reported as "tag points at
# nothing" -- a false failure indistinguishable from a real one. Caught by
# running the check against the package it was written for before trusting it,
# which is the standard this repository sets for its own checks.
read_tag() {
  printf '%s' "$TAGS" | node -e '
    let s = ""
    process.stdin.on("data", d => (s += d)).on("end", () => {
      let tags = JSON.parse(s)
      if (Array.isArray(tags)) tags = Object.assign({}, ...tags)
      process.stdout.write(tags[process.argv[1]] ?? "")
    })
  ' "$1"
}

ACTUAL_UNDER_EXPECTED=$(read_tag "$EXPECTED_TAG")
ACTUAL_LATEST=$(read_tag latest)

PROBLEMS=0

# 1. The version must be under the tag it was published to. This is the
#    assertion the pre-publish check could only predict.
if [ "$ACTUAL_UNDER_EXPECTED" != "$VERSION" ]; then
  echo "FAIL: tag '$EXPECTED_TAG' points at '${ACTUAL_UNDER_EXPECTED:-<nothing>}', not $VERSION."
  PROBLEMS=$((PROBLEMS + 1))
else
  echo "  ok  '$EXPECTED_TAG' -> $VERSION"
fi

# 2. What `latest` points at decides what a bare `yarn add` installs. A
#    prerelease there is only acceptable while no stable version exists,
#    which is npm's unavoidable first-publish behaviour rather than a
#    mistake anyone made.
IS_PRERELEASE=false
if printf '%s' "$ACTUAL_LATEST" | grep -qE -- '^[0-9]+\.[0-9]+\.[0-9]+-'; then
  IS_PRERELEASE=true
fi

if [ "$IS_PRERELEASE" = true ]; then
  STABLE_COUNT=$(npm view "$PACKAGE" versions --json 2>/dev/null | node -e '
    let s = ""
    process.stdin.on("data", d => (s += d)).on("end", () => {
      let v = []
      try { v = JSON.parse(s) } catch { v = [] }
      if (!Array.isArray(v)) v = [v]
      v = v.flat()  // same wrapping hazard as dist-tags above
      process.stdout.write(String(v.filter(x => !/^[0-9]+\.[0-9]+\.[0-9]+-/.test(x)).length))
    })
  ')

  if [ "${STABLE_COUNT:-0}" -gt 0 ]; then
    echo "FAIL: 'latest' points at the prerelease $ACTUAL_LATEST while $STABLE_COUNT stable"
    echo "      version(s) exist. A bare 'yarn add $PACKAGE' installs a prerelease."
    echo "      Repoint it:  npm dist-tag add $PACKAGE@<stable> latest"
    PROBLEMS=$((PROBLEMS + 1))
  else
    echo "  ok  'latest' -> $ACTUAL_LATEST (prerelease, and the only kind published)"
    echo ""
    echo "NOTE: a bare 'yarn add $PACKAGE' installs $ACTUAL_LATEST today."
    echo "      npm gives 'latest' to the first version of a new package whatever"
    echo "      --tag says, and refuses to let that tag be deleted. This resolves"
    echo "      when the first stable version is published and takes it over."
    echo "      Until then the README must not promise otherwise, and it does not."
  fi
else
  echo "  ok  'latest' -> ${ACTUAL_LATEST:-<nothing>} (stable)"
fi

if [ "$PROBLEMS" -gt 0 ]; then
  echo ""
  echo "REFUSING: $PROBLEMS problem(s) above, read back from the registry itself."
  exit 1
fi

echo ""
echo "PASS: the registry's tags are what this release intended."
