#!/usr/bin/env bash
set -euo pipefail

# The camera proof (issue #6), runnable by hand exactly as CI runs it.
#
# WHAT A RUN PROVES, AND WHAT IT COSTS
#
# That a verification code this library renders on a real screen is read by
# a real camera that has never seen it. The showing side is the example app
# on a booted Android emulator, in its CAMERA_PROOF mode, drawing
# `getVerificationCode`'s own modules fullscreen; the scanning side is an
# UNMODIFIED Element on a physical Android phone, fixed in a mount with its
# camera aimed at the machine's display. The assertion is the protocol: the
# library side's log must reach `done` (a pinned `CAMERA_PROOF_SUMMARY 5/5`
# line, asserted as found -- never as "no FAIL appeared"), and the account
# state over the client API must agree (the showing device's keys gain a
# cross-signing signature). If the optics fail -- glare, focus, distance --
# the scan never completes and the timeout fires: that timeout IS the
# optical assertion.
#
# WHY THIS SCRIPT IS THIN
#
# Everything after the rig declaration lives in
# packages/example-app/level-two/run_camera_proof_rig.py, and that is
# deliberate: the phone side is driven through uiautomator2 (a Python
# library), and the homeserver bring-up, the sweeps, the plan server and the
# adb helpers it reuses are the level 2 conductor's own Python. A bash
# reimplementation would be a second copy of all of it. This script is the
# leg's front door: it demands the rig, demands the tools it can check
# cheaply, and delegates -- so what CI runs and what a person runs by hand
# are byte-identical.
#
# WHAT IS VALIDATED AND WHAT IS NOT
#
# Every refusal path below works on any machine with no hardware at all.
# The phone-driving half of the Python program is written but UNVALIDATED:
# no rig exists as of this commit, so no Element screen has ever been tapped
# by it. See the design comment on issue #6 and the program's own header.
#
# THE RIG, DECLARED, NOT SNIFFED
#
# CAMERA_RIG=1 is the declaration. There is no reliable file or process a
# self-hosted runner leaves behind that proves a camera is mounted and
# aimed, so this script demands an explicit act instead of detecting a
# proxy for one. Set it in the workflow's env (camera-proof.yml does), or
# by hand on the rig, and nowhere else: a program that drives a physical
# phone and reconfigures a machine's display must not discover it was
# pointed at the wrong hardware after it has started.

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

[ "${CAMERA_RIG:-}" = "1" ] \
  || fail "CAMERA_RIG is not 1. This leg drives a physical phone and configures
      a machine's display, and it refuses to run anywhere that has not
      declared itself the camera rig. Remedy: set CAMERA_RIG=1 on the rig
      only. In CI that is the workflow's env (camera-proof.yml); by hand it
      is your own explicit act. Any other value -- including a runner label
      or a hostname that happens to look like the rig -- is refused: this
      check is the whole point of dispatch-only."

command -v python3 >/dev/null 2>&1 \
  || fail "python3 is not on PATH. The leg's driver
      (packages/example-app/level-two/run_camera_proof_rig.py) is Python:
      uiautomator2, the phone-side driver, is a Python library, and the
      conductor machinery it reuses is Python. Remedy: install Python 3."

command -v adb >/dev/null 2>&1 \
  || fail "adb is not on PATH. Both halves of the rig -- the booted emulator
      and the mounted phone -- are driven over adb. Remedy: install the
      Android platform tools on the rig."

command -v docker >/dev/null 2>&1 \
  || fail "docker is not on PATH. The throwaway homeserver runs in a
      container this leg starts and destroys. Remedy: install Docker on
      the rig."

APK=${1:-packages/example-app/android/app/build/outputs/apk/release/app-release.apk}
[ -f "$APK" ] || fail "no APK at '$APK'. Build one for the rig emulator's
      ABI first:
      (cd packages/example-app/android && ./gradlew :app:assembleRelease -PreactNativeArchitectures=<abi>)
      CI builds it in the camera-proof workflow; the ABI is whatever
      \`adb -s \$CAMERA_RIG_EMULATOR shell getprop ro.product.cpu.abi\` says."
[ -s "$APK" ] || fail "the APK at '$APK' is empty."

exec python3 packages/example-app/level-two/run_camera_proof_rig.py --apk "$APK"
