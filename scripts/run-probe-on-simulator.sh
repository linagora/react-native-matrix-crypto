#!/usr/bin/env bash
set -euo pipefail

# Runs the example app's probe on a booted iOS simulator and asserts the
# outcome, the way scripts/run-probe-on-emulator.sh does on Android and
# ci.yml's probe-android job calls it. The app side is unchanged on iOS:
# the probe harness prints PROBE_CHECK and PROBE_SUMMARY through
# console.log, which React Native forwards to the unified log at info
# level under subsystem com.facebook.react.log, measured on a booted
# simulator. What differs from Android is every piece of adb: the boot
# wait, the install and launch, and the log read, which is a live
# `log stream` because a booted simulator keeps no log archive to query
# afterwards.
#
# The one mechanism worth its own paragraph is the readiness beacon. The
# capture must be shown live before anything is launched into it: the
# script's own `simctl uninstall` produces an installd line naming the
# bundle id, and until one reaches the capture, nothing is installed or
# launched. A line the stream was not yet live to catch would be recorded
# as a lost callback, which is the one finding this channel must never
# manufacture. The beacon regex is anchored on the timestamp for the same
# reason scripts/measure-signal-latency-ios.sh anchors it: `log stream`
# echoes its own predicate back as a header, and the header contains the
# word "installd".
#
# Usage: ./scripts/run-probe-on-simulator.sh <path-to-ExampleApp.app>
# Environment overrides: SIM_UDID, LAUNCH_TIMEOUT_SECONDS (default 240),
# LATE_GRACE_SECONDS (default 15), STREAM_READY_TRIES (default 20).

EXPECTED_SUMMARY="PROBE_SUMMARY 12/12"
# The numerator is five checks from interop/suite.ts and six from
# interop/crypto-suite.ts plus real_crypto; the denominator is stated
# here so a check that disappears moves the number and fails the leg
# rather than passing quietly. Keep in sync with
# scripts/run-probe-on-emulator.sh, which asserts the same line on
# Android.

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

APP=${1:-}
[ -n "$APP" ] || fail "usage: $0 <path-to-ExampleApp.app>"
[ -d "$APP" ] || fail "no .app bundle at '$APP'."

command -v xcrun >/dev/null 2>&1 || fail "xcrun is not on PATH; this script needs Xcode."

PLIST="$APP/Info.plist"
[ -f "$PLIST" ] || fail "'$APP' has no Info.plist; not an app bundle."

BUNDLE_ID=$(plutil -extract CFBundleIdentifier raw "$PLIST" 2>/dev/null) \
  || fail "could not read CFBundleIdentifier from '$PLIST'."
[ -n "$BUNDLE_ID" ] || fail "CFBundleIdentifier in '$PLIST' is empty."

# A Debug configuration pulls JavaScript from Metro and ships no
# main.jsbundle; the probe leg installs a release-style bundle and starts
# no Metro. The same refusal exists in the measurement harness for the
# same reason.
[ -f "$APP/main.jsbundle" ] || fail "'$APP' carries no main.jsbundle.
      A Debug configuration bundles no JavaScript and would show a blank
      screen on a simulator with no Metro to pull from. Build the
      Release configuration: it embeds the bundle the probe then runs."

LAUNCH_TIMEOUT_SECONDS=${LAUNCH_TIMEOUT_SECONDS:-240}
LATE_GRACE_SECONDS=${LATE_GRACE_SECONDS:-15}
STREAM_READY_TRIES=${STREAM_READY_TRIES:-20}

# --- Simulator -------------------------------------------------------------
#
# SIM_UDID pins the choice; without it, a booted iPhone wins, then the
# first available one, booted and waited on with bootstatus so the
# install that follows does not race the boot.

UDID=${SIM_UDID:-}
if [ -z "$UDID" ]; then
  UDID=$(xcrun simctl list devices available | grep -i 'iPhone' | grep Booted | head -1 | sed -E 's/.*\(([A-F0-9-]+)\).*/\1/' || true)
fi
if [ -z "$UDID" ]; then
  UDID=$(xcrun simctl list devices available | grep -i 'iPhone' | head -1 | sed -E 's/.*\(([A-F0-9-]+)\).*/\1/' || true)
fi
[ -n "$UDID" ] || fail "no available iPhone simulator found."

xcrun simctl bootstatus "$UDID" -b >/dev/null 2>&1 \
  || fail "simulator $UDID did not finish booting."

# --- Capture, beacon, launch ----------------------------------------------

LOG_PREDICATE='(subsystem == "com.facebook.react.log") OR (process == "installd")'

WORK=$(mktemp -d /tmp/rnmc-probe-ios.XXXXXX)
CAPTURE="$WORK/capture"
: > "$CAPTURE"
trap 'kill "$STREAM_PID" 2>/dev/null || true; xcrun simctl terminate "$UDID" "$BUNDLE_ID" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

xcrun simctl spawn "$UDID" log stream --level info --style compact \
  --predicate "$LOG_PREDICATE" > "$CAPTURE" 2>&1 &
STREAM_PID=$!

# Prove the stream live before anything is launched into it. The uninstall
# is not a probe added for this: the run needs it anyway, to start from a
# process with no crypto store in it.
ready=""
for _ in $(seq 1 "$STREAM_READY_TRIES"); do
  xcrun simctl uninstall "$UDID" "$BUNDLE_ID" >/dev/null 2>&1 || true
  if grep -qE "^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.]+ +[A-Za-z]+ +installd\[.*$BUNDLE_ID" "$CAPTURE" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 1
done
[ -n "$ready" ] || fail "the log stream was never shown to be live.
      $STREAM_READY_TRIES uninstalls of '$BUNDLE_ID' went by without one
      installd line naming it reaching the capture. Nothing is launched
      into a stream that cannot be shown to have been attached first."

xcrun simctl install "$UDID" "$APP" >/dev/null
xcrun simctl launch "$UDID" "$BUNDLE_ID" >/dev/null

# `log stream --style compact` prefixes every line with a timestamp, a
# level and the process, so the probe lines cannot be anchored with `^`;
# they are cut out of the line instead, the same shape `logcat -v raw`
# gives the Android leg.
probe_lines() {
  tr -d '\r' < "$CAPTURE" 2>/dev/null | grep -oE 'PROBE_[A-Z0-9_]+ [^ ]+' || true
}

deadline=$(( $(date +%s) + LAUNCH_TIMEOUT_SECONDS ))
summary=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  summary=$(probe_lines | grep -E '^PROBE_SUMMARY [0-9]+/[0-9]+$' || true)
  [ -n "$summary" ] && break
  sleep 2
done

# A late line is still in flight when the summary prints; read once more
# after a grace period rather than immediately.
sleep "$LATE_GRACE_SECONDS"

summary=$(probe_lines | grep -E '^PROBE_SUMMARY [0-9]+/[0-9]+$' || true)
summary_count=$(printf '%s\n' "$summary" | grep -c . || true)

if [ -z "$summary" ]; then
  echo "---- capture tail ----" >&2
  tail -20 "$CAPTURE" >&2 || true
  fail "no PROBE_SUMMARY line arrived within ${LAUNCH_TIMEOUT_SECONDS}s.
      The capture tail above is the whole diagnosis a booted simulator
      keeps: there is no log archive to query after the fact."
fi
[ "$summary_count" -eq 1 ] || fail "expected exactly one PROBE_SUMMARY line, saw $summary_count:
      $summary"

[ "$summary" = "$EXPECTED_SUMMARY" ] || fail "expected '$EXPECTED_SUMMARY', saw '$summary'.
      A numerator that moved means a probe check failed or disappeared;
      the PROBE_CHECK lines above it in the capture say which."

echo "PASS: $summary on simulator $UDID"
