#!/usr/bin/env python3
"""The camera proof, run by a rig instead of a person.

WHAT THIS PROVES

That a verification code rendered by this library on a real screen is read
by a real camera that has never seen it. The showing side is the example app
on a booted Android emulator, in its CAMERA_PROOF mode (`App.tsx` ->
`CameraProofHarness.tsx`), drawing `getVerificationCode`'s own modules
fullscreen. The scanning side is an UNMODIFIED Element on a physical Android
phone, fixed in a mount with its camera aimed at the machine's display, the
whole driven over adb + UI Automator.

The assertion is the protocol, not pixels: the leg watches the library
side's log for the flow reaching `done` (a `CAMERA_PROOF_SUMMARY 5/5` line,
pinned below), and then reads the account state over the client API as a
second witness (the showing device gains a cross-signing signature from the
account's self-signing key). If the optics fail -- glare, focus, distance --
the scan never completes, the summary never appears, the timeout fires, and
the leg fails. That timeout IS the optical assertion: a decode of the wrong
bytes dies in the SAS long before `done`, and no scan at all dies at the
timeout, and both are red.

WHAT IS VALIDATED AND WHAT IS NOT

Everything up to and including the emulator-side log watching is host-side
machinery of the same shape as the level 2 conductor's, and every refusal
path below can be exercised without any hardware.

The rig exists (a Pixel 10 Pro Fold on Android 17 / API 37 as the scanner, a
booted emulator as the screen). MEASURED 2026-09-02, a run drives every step
below by itself, and a real camera has completed the scan:

  CAMERA_PROOF_CHECK run_started   PASS
  CAMERA_PROOF_CHECK flow_exists   PASS
  CAMERA_PROOF_CHECK code_shown    PASS   45x45, a 122-byte payload
  CAMERA_PROOF_CHECK scan_reported PASS   the peer sent m.key.verification.scanned
  CAMERA_PROOF_CHECK flow_done     PASS
  CAMERA_PROOF_SUMMARY 5/5
  witness: the showing device's keys are signed by the account's self-signing key

Every tap on the phone in that run came from this program: Element cleared
and signed in to the throwaway homeserver, the cross-signing identity
bootstrapped, the first-session prompts cleared, the incoming request banner
opened, "Accepter" answered and "Scanner avec cet appareil" chosen.

A PERSON AIMS THE PHONE, AND THAT IS NOT THE SAME AS A PERSON JUDGING. There
is no fixture: somebody picks the phone up and points it at the emulator's
window. What they contribute is a physical gesture, not a verdict. Nobody
reads a shield, nobody decides whether it worked; the run reads
`m.key.verification.scanned` off the protocol and then reads the account
state back as a second witness, and it fails on its own if either
disagrees. That distinction is why issue #6 closed on this: its grievance
was a person's judgement standing in for an assertion, and the assertion is
the machine's now.

What the missing fixture costs is repetition, not honesty, and it is issue
#29: with nobody to aim, this leg runs when somebody is at the rig, so the
`schedule:` block in the workflow stays commented and an optical regression
waits for the next person who runs it by hand. Note what this program cannot
do about that: it CANNOT tell a human aim from a fixture aim -- its output is
identical either way -- so the cron and the fixture are one change and never
two. It stays dispatch-only and joins no required check.

WHY THIS SIDE ASKS, WHICH IS THE FINDING THAT UNBLOCKED THE REST. The driver
used to navigate Element's settings to the showing device's session and tap
its verify action, and the navigation worked perfectly -- drawer, "Sécurité
et vie privée", "Afficher toutes les sessions", the session by name. The
destination was wrong. The only action that screen offers is "Vérifier de
façon interactive avec des émojis"; it starts SAS, the side that starts a
verification is the side that picks its method, and the library announces
SasV1 in SHOWING_ONLY deliberately -- so Element had a method it could use
and used it. Four runs ended at 3/5 with the code on screen and no camera
ever asked for. Asking from this side makes Element the RESPONDER, and a
responder is offered what the requester announced: its own UI then reads
"Scanner avec cet appareil".

HOW A RUN IS SEQUENCED

  1. refuse unless the rig is declared (CAMERA_RIG=1) and every tool and
     device is present, each with a named remedy;
  2. start the throwaway homeserver and create the two accounts, reusing
     run_level_two.py's machinery rather than forking it;
  3. log the emulator device into the shared account and serve the run plan
     (mode 'camera-proof') on the conductor port, as the person-driven
     run_camera_proof.py does;
  4. prepare the emulator's display for optics (brightness, stay-awake,
     immersive) and install the app without launching it;
  5. THE PHONE SIDE: drive Element on the phone -- sign in to the throwaway
     homeserver and bootstrap the account's cross-signing identity;
  6. launch the app on the emulator and wait for `CAMERA_PROOF` lines, and
     once the harness's ask is up, answer the incoming request banner on the
     phone so its camera faces the symbol;
  7. assert exactly one `CAMERA_PROOF_SUMMARY 5/5` within the timeout, then
     the second witness over /keys/query;
  8. assert nothing this run minted leaked into the emulator's log;
  9. tear everything down.

CREDENTIALS

Same posture as run_camera_proof.py, which this file deliberately mirrors:
one account on a homeserver bound to loopback that does not outlive the run,
a password generated per run and printed nowhere by this program (Element
types it on the phone, but that keyboard is driven, not logged). The access
token travels to the app inside a loopback HTTP response, never a file,
never an initial property, never a log line.
"""

import argparse
import atexit
import os
import re
import secrets
import shutil
import signal
import sys
import tempfile
import time
import xml.etree.ElementTree as xml_etree

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Reused rather than reimplemented, for the reason run_camera_proof.py gives:
# the container bring-up, the sweeps, the adb helpers and the plan server are
# the level 2 conductor's, and a second copy of them would be a second thing
# to keep correct. Both modules import cleanly (constants and class bodies
# only at import time).
from run_camera_proof import PlanServer  # noqa: E402
from run_level_two import (  # noqa: E402
    CONDUCTOR_PORT,
    DEFAULT_APK,
    LIBRARY_LOCALPART,
    NIO_LOCALPART,
    PACKAGE,
    SERVER_NAME,
    Homeserver,
    RunFailed,
    port_is_free,
    remove_container,
    require,
    run_command,
    start_homeserver,
    sweep_containers,
    sweep_workdirs,
)


def rig_log(message):
    """This driver's own output. Never carries a token or a password."""
    print(f"[camera-proof] {message}", flush=True)


# --- The rig ----------------------------------------------------------------
#
# CAMERA_RIG=1 is the declaration this is a rig. The bash leg
# (scripts/run-camera-proof.sh) demands it before anything else and CI sets
# it; this program re-asserts it because a driver that can be pointed at any
# two adb devices by accident is a driver that will someday drive the wrong
# ones.

EMULATOR_SERIAL = os.environ.get("CAMERA_RIG_EMULATOR", "emulator-5554")
ELEMENT_PACKAGE = os.environ.get("CAMERA_RIG_ELEMENT_PACKAGE", "im.vector.app")

# The display name the emulator's device is logged in with. Element's
# sessions list shows it, and the phone-side driver finds the right session
# by this exact text -- it is the one structural hook the UI automation has.
SHOWING_DEVICE_NAME = "CameraProof"

# How long the whole flow may take from app launch to the summary line. This
# number IS the optical assertion: a camera that never decodes the symbol is
# indistinguishable from a broken network inside this window, and both are
# red. Sized generously on purpose -- a fresh emulator boot of the app, key
# publication, Element's sync rounds and a person-free scan have no tight
# budget; a stuck run should fail as a timeout, not a race.
FLOW_TIMEOUT_SECONDS = int(os.environ.get("CAMERA_PROOF_TIMEOUT_SECONDS", "360"))

# The summary the harness prints and this program pins. Five checks, the
# same number cameraProofLog.ts promises; like EXPECTED_STEPS for
# LEVEL2_SUMMARY, the count lives out here so the artifact under test cannot
# move it.
SUMMARY_PATTERN = re.compile(r"^CAMERA_PROOF_SUMMARY (\d+)/(\d+)$")
EXPECTED_STEPS = 5

# How long to wait for Element to publish the account's cross-signing
# identity after sign-in. The structural gate: no identity, no code exists
# (a code carries cross-signing keys), so waiting out the UI is pointless.
IDENTITY_TIMEOUT_SECONDS = int(os.environ.get("CAMERA_PROOF_IDENTITY_TIMEOUT_SECONDS", "300"))


# adb's OWN name for a locally running AVD. Not a user-set string: the
# emulator is registered on its console port and adb names it from that,
# while a USB handset is listed by its hardware serial and an `adb connect`
# device by host:port. Matching this shape is therefore evidence, and it
# costs no adb call, which matters: see detect_phone_serial.
LOCAL_EMULATOR_SERIAL = re.compile(r"^emulator-\d+$")


def detect_phone_serial():
    """The phone is the one attached device that is not an emulator.

    Still deliberately strict about PHONES, which is what the strictness was
    ever for: zero candidates and two-or-more candidates are both refusals,
    because a driver that guesses which physical phone to drive is worse
    than a driver that declines.

    What changed, and why. MEASURED on the rig 2026-09-10: this leg died at
    "found 2: ['59021FDCG003NW', 'emulator-5556']" because a SECOND emulator
    was running for unrelated work, after the run had already spent ten
    minutes building an APK. The rig is somebody's daily Mac rather than
    dedicated hardware, so other AVDs on it are ordinary rather than a
    misconfiguration, and counting them as candidate phones refuses a rig
    that is in fact fine.

    Foreign devices are classified WITHOUT talking to them, and that is
    deliberate too. The first version of this fix asked every device
    `getprop ro.kernel.qemu`, which is better evidence; measured the same
    day, that call hung the full 60 seconds against the very emulator it
    was meant to skip, because another program on the machine was holding
    it with a long `uiautomator dump`. A rig that cannot start because
    somebody else's AVD is busy is the same failure wearing a new hat. So:
    shape for the ones being excluded, and one positive check below on the
    single device this run is actually going to drive.
    """
    listed = run_command(["adb", "devices"], timeout=60).stdout
    serials = []
    for line in listed.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and parts[1] == "device":
            serials.append(parts[0])
    emulators = [serial for serial in serials
                 if serial == EMULATOR_SERIAL or LOCAL_EMULATOR_SERIAL.match(serial)]
    candidates = [serial for serial in serials if serial not in emulators]
    require(len(candidates) == 1,
            f"expected exactly one physical phone on adb, found "
            f"{len(candidates)}: {candidates or 'none'}.\n"
            f"      adb listed {serials or 'none'}; emulators ignored: "
            f"{emulators or 'none'} (the rig's own is {EMULATOR_SERIAL}).\n"
            "      Connect the rig's phone by USB and make sure no OTHER "
            "PHONE is. Other emulators on this machine are fine.")
    phone = candidates[0]

    # The one probe, on the one device this run will drive. It catches an
    # emulator reached over `adb connect` (named host:port, so the shape
    # test above cannot see it), and a phone that cannot answer this cannot
    # be driven anyway, so a hang here is a genuine finding rather than
    # somebody else's AVD being busy.
    kind = adb_on(phone, "shell", "getprop", "ro.build.characteristics", timeout=60)
    require("emulator" not in kind.stdout.strip().split(","),
            f"{phone} is the only candidate for the mounted phone, but it "
            "reports itself as an emulator. This leg proves that a REAL "
            "camera reads the code, so it refuses to scan with a virtual "
            "one. Remedy: connect the rig's phone by USB.")
    return phone


def adb_on(serial, *args, timeout=300):
    """Serial-scoped adb.

    The level 2 helpers call bare `adb`, which is right there because they
    drive a single emulator. This run drives TWO devices from one host, and
    almost every bare-adb call would fail with 'more than one device' -- so
    everything here is scoped.
    """
    return run_command(["adb", "-s", serial, *args], timeout=timeout)


def require_online(serial, what):
    require(adb_on(serial, "shell", "true", timeout=30).returncode == 0,
            f"{what} ({serial}) does not answer adb. Remedy: check the cable, "
            "the adb daemon and that the serial names the right device.")


def login_when_ready(homeserver, localpart, password, display_name, timeout_s=90):
    """The login this run needs, retried until the account actually exists.

    start_homeserver returns as soon as /_matrix/client/versions answers,
    but continuwuity runs its --admin-execute account creation AFTER
    startup -- measured on this very container: /versions 200 while a login
    for the account it was told to create still returns 404, and continuwuity
    answers a not-yet-created user with 404 rather than 403. The bash
    sibling closes the same race with its wait_for_login
    (scripts/run-level-two-interop.sh: "a server answering /versions does
    not yet mean the account exists"); the Python conductor's own runners
    still race it, which is a pre-existing finding this driver refuses to
    inherit silently. Retrying the real login is safe: a refused attempt
    creates no device, and the first 200 is the token the run keeps.
    """
    deadline = time.time() + timeout_s
    while True:
        try:
            return homeserver.login(localpart, password, display_name)
        except RunFailed as failure:
            if time.time() > deadline:
                raise RunFailed(
                    f"{failure}\n      The homeserver never made the account "
                    f"login-able within {timeout_s}s of answering /versions; "
                    "see the --admin-execute errors in the container output "
                    "above."
                )
            time.sleep(2)


# --- The emulator side ------------------------------------------------------


# The AppleScript is written against System Events rather than the emulator
# app, because the emulator has no scripting dictionary: it is a bare qemu
# binary with a Cocoa window, and `tell application "qemu-system-..."` finds
# nothing to talk to. It is addressed by unix id and not by name: the process
# name is only the host architecture (qemu-system-aarch64 on this rig,
# qemu-system-x86_64 on an Intel one) and every AVD on the machine shares it,
# so a name selects an arbitrary emulator. rig_emulator_pid says why that is
# not good enough here.
RAISE_EMULATOR_WINDOW = """
tell application "System Events"
    set matches to (every process whose unix id is {pid})
    if matches is {{}} then return "none"
    set target to item 1 of matches
    set frontmost of target to true
    return name of target
end tell
"""


def rig_emulator_pid():
    """The host pid of the AVD this run drives, not merely of an emulator.

    The earlier version of this raised `item 1` of every qemu-system process.
    That is right exactly when one emulator is running, and this rig is
    somebody's daily Mac: on 2026-09-10 a second AVD was running here for
    unrelated work, which made `item 1` a coin toss between the window the
    camera must photograph and somebody else's. Picking wrong is worse than
    failing, because the leg then spends its entire optical budget on the
    wrong rectangle and reports the result as "no scan", which is the same
    thing it says about glare, focus and a dead network.

    The AVD name is asked of the emulator's own console rather than derived
    from the serial, so it names whatever actually answers EMULATOR_SERIAL.
    Matching is on the exact `-avd <name>` argument pair rather than a
    substring, so `messagr-lot1` cannot match a `messagr-lot10`.
    """
    named = adb_on(EMULATOR_SERIAL, "emu", "avd", "name", timeout=60)
    avd = next((line.strip() for line in named.stdout.splitlines()
                if line.strip() and line.strip() != "OK"), "")
    require(avd,
            f"{EMULATOR_SERIAL} did not answer `emu avd name`, so this run "
            "cannot tell which host window belongs to it. Remedy: check that "
            "the rig emulator is a local AVD reachable over its console port.")

    listed = run_command(["ps", "-ewwo", "pid,command"], timeout=60).stdout
    hits = []
    for line in listed.splitlines()[1:]:
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        fields = parts[1].split()
        # The EXECUTABLE, not the line. Anything merely mentioning the AVD in
        # its arguments would otherwise match, and the first thing that did
        # was the shell running this function's own test, whose command line
        # quoted both `qemu-system` and the AVD name.
        if not fields or "qemu-system" not in fields[0]:
            continue
        if any(flag == "-avd" and value == avd
               for flag, value in zip(fields, fields[1:])):
            hits.append(parts[0])
    require(len(hits) == 1,
            f"expected exactly one running qemu process for AVD {avd}, found "
            f"{len(hits)}: {hits or 'none'}.\n"
            "      Remedy: the rig emulator must be running headed (not "
            "-no-window) and exactly once.")
    return hits[0], avd


def raise_emulator_window():
    """Put the emulator's HOST window in front, where a camera can see it.

    MEASURED on the rig 2026-09-02: the emulator window was open but buried
    behind an ordinary desktop's other windows, and prepare_emulator's
    settings do not touch that -- brightness, stay-awake and immersive
    configure the emulator's VIRTUAL display, while what the mounted camera
    actually photographs is a rectangle of the Mac's screen. A buried window
    means the camera sees somebody's browser, the scan never completes, and
    the leg fails at the timeout with "optics" and no way to tell a covered
    window from a bad lamp. That is a failure this step can just remove.

    Refused loudly rather than skipped when the rig is a Mac and the raise
    does not work: an unraised window cannot produce a pass, so continuing
    would only spend the flow budget to reach a less informative failure. A
    rig that is not a Mac has no osascript, and arranging its own window is
    that rig's business -- said once, in the log, not treated as an error.

    One remedy in the refusal below is worth its specificity. MEASURED
    2026-09-10: from an interactive shell this call returns in 0.185s, and
    from the GitHub Actions job on the same machine minutes later it hit the
    60s timeout every time. The runner is a launchd service without an
    Accessibility grant, and macOS BLOCKS the Apple Event rather than
    refusing it, so the symptom is a hang and not the permission error the
    remedy text would lead you to expect.
    """
    if shutil.which("osascript") is None:
        rig_log("no osascript on this host: the rig itself must make sure the "
                "emulator's window is the thing the camera can see")
        return
    pid, avd = rig_emulator_pid()
    script = RAISE_EMULATOR_WINDOW.format(pid=pid)
    result = run_command(["osascript", "-e", script], timeout=60)
    raised = result.stdout.strip()
    require(result.returncode == 0 and raised and raised != "none",
            f"could not bring the window of AVD {avd} (pid {pid}) to the front "
            f"({result.stderr.strip() or raised or 'no such process'}).\n"
            "      The camera is aimed at a rectangle of this machine's "
            "screen, so a window it cannot see is an optical failure the "
            "flow timeout would report as 'no scan'. Remedies: start the "
            "emulator with a window (not -no-window), and grant this runner "
            "Accessibility permission in System Settings -> Privacy & "
            "Security so System Events may raise it. A 60s timeout here, "
            "rather than an error, is what a missing Accessibility grant "
            "looks like.")
    rig_log(f"emulator window raised to the front ({raised}, AVD {avd}, pid {pid})")


def prepare_emulator(serial):
    """Everything optics needs that the app cannot ask for itself.

    Brightness at max, the screen never sleeping, the status bar hidden for
    this package: a camera in a fixed mount gets one unchanging frame, and
    dimming or a keyguard mid-scan is a failure the mount cannot fix. These
    are settings changes on a throwaway emulator; on a real device this
    function would not be called.
    """
    require_online(serial, "the rig emulator")
    booted = adb_on(serial, "shell", "getprop", "sys.boot_completed").stdout.strip()
    require(booted == "1",
            f"the emulator {serial} never reported sys.boot_completed=1. "
            "Boot it -- a headed boot, not -no-window: the camera has to see "
            "its display.")
    model = adb_on(serial, "shell", "getprop", "ro.product.model").stdout.strip()
    api = adb_on(serial, "shell", "getprop", "ro.build.version.sdk").stdout.strip()
    rig_log(f"emulator: {model} (API {api})")

    for call in (
        ("shell", "settings", "put", "system", "screen_brightness", "255"),
        ("shell", "settings", "put", "system", "screen_off_timeout", "2147483647"),
        ("shell", "svc", "power", "stayon", "true"),
        ("shell", "settings", "put", "global", "policy_control",
         f"immersive.full={PACKAGE}"),
    ):
        result = adb_on(serial, *call)
        require(result.returncode == 0,
                f"preparing the emulator display failed at {' '.join(call)}: "
                f"{result.stderr.strip()}")
    adb_on(serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
    adb_on(serial, "shell", "wm", "dismiss-keyguard")
    rig_log("emulator display prepared: brightness max, stay-awake, immersive")
    # Last, because it is the only part of "prepare the display" that is about
    # the HOST rather than the device, and it should be the most recent window
    # activation when the app comes up.
    raise_emulator_window()


def install_on_emulator(serial, apk):
    """Installs the app fresh, and does NOT launch it.

    The launch waits until the phone side is ready (identity bootstrapped):
    the harness announces and publishes on launch, and there is no second
    machine allowed in the process to redo it with.
    """
    adb_on(serial, "uninstall", PACKAGE)
    result = adb_on(serial, "install", apk, timeout=600)
    require(result.returncode == 0,
            f"installing the APK on the emulator failed: {result.stderr.strip()}")
    rig_log("the app is installed on the emulator (not launched yet)")


def launch_app(serial):
    adb_on(serial, "logcat", "-c")
    result = adb_on(serial, "shell", "am", "start", "-n", f"{PACKAGE}/.MainActivity")
    require(result.returncode == 0,
            f"launching the app on the emulator failed: {result.stderr.strip()}")
    rig_log("the app is launched; it fetches the plan and waits for the phone")


def app_lines(serial):
    result = adb_on(serial, "logcat", "-d", "-v", "raw", "ReactNativeJS:V", "*:S",
                    timeout=120)
    return [line.strip("\r") for line in result.stdout.splitlines()]


def wait_for_app_line(serial, pattern, timeout_s, what):
    """One bounded log wait, shared by the run_started wait and the summary.

    The app is launched with `am start` and detaches immediately, so "the
    process is alive" says nothing; only a found line does. A dead process
    with a crash dump is reported as itself rather than waited out.
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        lines = app_lines(serial)
        found = [line for line in lines if pattern.search(line)]
        if found:
            return found, lines
        if run_command(["adb", "-s", serial, "shell", "pidof", PACKAGE],
                       timeout=30).returncode != 0:
            crash = adb_on(serial, "logcat", "-d", "-v", "brief",
                           "AndroidRuntime:E", "*:S").stdout
            if crash.strip():
                rig_log("--- AndroidRuntime ---")
                print(crash, flush=True)
                raise RunFailed(f"{PACKAGE} is no longer running and {what}")
        time.sleep(5)
    lines = app_lines(serial)
    rig_log("--- AndroidRuntime ---")
    print(adb_on(serial, "logcat", "-d", "-v", "brief", "AndroidRuntime:E", "*:S").stdout,
          flush=True)
    rig_log("--- CAMERA_PROOF lines so far ---")
    for line in lines:
        if line.startswith("CAMERA_PROOF"):
            print(line, flush=True)
    raise RunFailed(
        f"no {what} appeared within {timeout_s}s. This is NOT a pass: the app "
        "either never started, crashed before the run, or stopped forwarding "
        "console output."
    )


# --- The phone side ---------------------------------------------------------
#
#   VALIDATED (2026-09-02, on the rig's phone, a Pixel 10 Pro Fold running
#   Android 17 / API 37, serial 59021FDCG003NW, against the throwaway
#   homeserver): the adb-native primitives below -- uiautomator dump, XML
#   parse, input tap, scroll, input text -- and the whole Element flow from
#   a cleared app to a live verification: sign-in through the server
#   editor, the cross-signing bootstrap, the first-session prompts, then
#   the answer to this side's ask -- the incoming request banner ->
#   "Accepter" -> "Scanner avec cet appareil". That last path is the one
#   the 5/5 run measured end to end on 2026-09-02, every tap driven by
#   this program. Every label the screens actually show is recorded in
#   ELEMENT_CANDIDATE_SCREENS next to the guesses, the guesses kept but
#   the measured labels leading.
#
# Every UI step fails with a named error naming what it looked for, because
# an unmodified client's screens are exactly the kind of third-party surface
# that moves between versions -- the failure text is the maintenance manual.
# ASSUMPTION lines state what is trusted and how it is checked.

# MEASURED FACT, and the reason this section has two backends. The first
# physical rig phone is a Pixel 10 Pro Fold on Android 17 (API 37), and
# uiautomator2 is PARTLY broken on it. Exactly one RPC fails:
#   java.lang.IllegalStateException: ApplicationSharedMemory not initialized
#     at com.android.internal.os.ApplicationSharedMemory.getInstance(...)
#     at android.view.WindowManagerGlobal.getWindowManagerService(...)
#     at androidx.test.uiautomator.UiDevice.getDisplaySizeDp(UiDevice.java:312)
#     at com.wetest.uia2.stub.DeviceInfo.<init>(DeviceInfo.java:58)
# The path is the whole diagnosis: DeviceInfo asks UiDevice for the display
# size, which builds a window context, which needs shared memory that only a
# real instrumentation process initializes -- and the wetest stub runs as a
# bare app_process. So `d.info` and `d.screenOn` (which reads info) die, and
# nothing else does: MEASURED 2026-09-02, `dumpWindowHierarchy`, the selector
# RPCs, `app_start` and `window_size` all answer, 20 samples each, zero
# misses. An earlier revision of this file said "every RPC fails" and picked
# its backend by probing `info`; both were wrong, and the correction is why
# choose_ui_backend now takes the rig's word instead of guessing from one
# call.
#
# The second measured fact is about the SELECTORS, and it is why the two
# backends match text the same way: u2's `d(text=...)` is case-SENSITIVE,
# while Element renders its primary buttons through textAllCaps. On the rig
# phone, `d(text="ACTIVER").exists` is True and `d(text="Activer").exists` is
# False for the same button. Every candidate list below is written in the
# case a person would type, so both backends casefold; a backend that did
# not would miss every French button on this rig and report it as "the
# screen never appeared".
#
# The default backend is adb-native regardless: text search through
# `uiautomator dump` (a framework built-in, verified working on API 37),
# taps through `input tap`, scrolling through `input swipe`. Zero phone-side
# installs. That is the same reasoning this repository keeps elsewhere (the
# throwaway container rather than a hosted dependency, the pinned-by-digest
# image rather than a registry's goodwill): a leg whose phone dependency is
# zero-install survives every future Android version, because nothing on the
# phone can age out from under it. uiautomator2 stays as a declared option
# (CAMERA_RIG_UI_BACKEND) for a rig that wants it, never as a requirement.

# ASSUMPTION: the mounted phone runs Element Classic (im.vector.app). That is
# the one client observed completing this flow (run_camera_proof.py's header),
# and an unmodified mainstream client is the stronger claim. The package is
# overridable because it is the single most likely thing a rig will differ
# on: CAMERA_RIG_ELEMENT_PACKAGE names another package, and the driver checks
# at runtime that the package is actually installed rather than trusting the
# name:
#   adb shell pm path <package>
#
# ASSUMPTION: at run time, Element is SIGNED OUT. The validation phone holds
# a real account, so the sign-in screens were never exercised; a phone that
# opens Element already signed in fails at the first step naming the
# sign-in texts, which is the named signal to sign out on the rig.
ELEMENT_CANDIDATE_SCREENS = {
    # step -> (candidate texts, what the step is called). Texts are tried in
    # order until one is tappable; a step fails only when none appear.
    #
    # English first: those are the texts the selectors were written against.
    # French follows because the first physical rig runs a fr-FR phone (the
    # driver's locale ASSUMPTION names it): a candidate that does not appear
    # is skipped, so an added translation can only widen a step, never narrow
    # it -- and a step that matches nothing still fails naming everything it
    # looked for, which is the maintenance signal.
    "sign_in_entry": (["I already have an account", "Sign in",
                       "J'ai déjà un compte", "Se connecter"],
                      "the opening screen"),
    # MEASURED on the rig phone (2026-09-02, dump of the screen run #3
    # timed out on): this build has no "Other"/"Autre" choice at all; the
    # "Bon retour parmi nous" screen shows the selected server with a
    # "MODIFIER" button, and the server editor is behind it. The old
    # guesses stay trailing -- another build may still offer them.
    "choose_other_server": (["Modifier", "Edit", "Other", "Autre"],
                            "the control that opens the server editor"),
    # MEASURED same dump: the server editor ("Sélectionner votre serveur")
    # carries one EditText prefilled with "matrix.org" and a "SUIVANT"
    # submit, which server_confirm's candidates already cover.
    "server_confirm": (["OK", "Next", "Continue", "Suivant", "Continuer"],
                       "the server-confirm control"),
    # MEASURED same dump: the editor returns to the "Bon retour" screen,
    # whose own continue control is "Poursuivre"; the credentials form is
    # behind it. "Suivant" stays in the list because re-tapping the
    # editor's submit while server validation is still running is
    # harmless, and it keeps an editor-only build moving.
    "server_continue": (["Poursuivre", "Continue", "Continuer", "Next",
                         "Suivant"],
                        "the continue control once the server is chosen"),
    "username_confirm": (["Next", "Continue", "Suivant", "Continuer"],
                         "the username-confirm control"),
    "sign_in_submit": (["Sign in", "Log in", "Next",
                        "Se connecter", "S'identifier", "Suivant"],
                       "the sign-in control"),
    # Dismissive prompts that can block the first session until the account's
    # identity exists. "Verify this session" is deliberately NOT here: that
    # prompt is Element offering to verify the PHONE's own session, which is
    # a dead end on an account with no other device yet (the person-driven
    # flow's step 2 says to skip exactly this). element_bootstrap_identity
    # polls the homeserver instead of tapping through whatever it cannot
    # name.
    #
    # MEASURED on the rig phone (run #4bis, 2026-09-02), three overlays
    # stalled the bootstrap until a person tapped them:
    #   * the password manager's save prompt ("Non, merci"), an
    #     `android`-package overlay on the password form;
    #   * the system's notification-permission dialog ("Ne pas autoriser")
    #     -- also pre-granted structurally in Element.wake, the way CAMERA
    #     already is, so the dialog should not even appear;
    #   * Element's notification-method choice ("Google Services"), which
    #     is a selection, not a dismiss -- push is irrelevant on a rig
    #     whose homeserver dies with the run, so the first option is
    #     tapped simply to clear the screen.
    "bootstrap_dismiss": (["Skip", "Maybe later", "Not now", "Cancel",
                           "Set up recovery",
                           "Ignorer", "Passer", "Plus tard", "Pas maintenant",
                           "Annuler",
                           "Non, merci", "No, thanks",
                           "Ne pas autoriser", "Don't allow",
                           "Google Services", "Continue without"],
                          "a first-session prompt"),
    # The navigation that used to live here -- profile drawer, "Sécurité et
    # vie privée", "Afficher toutes les sessions", the session by name, and
    # its verify action -- is gone with the direction that needed it. It all
    # worked; the destination was wrong. See element_accept_verification.
    # The labels are in the commit that removed them if that path is ever
    # revisited, and out of this dict because a candidate nothing consults
    # is a claim about a screen this driver no longer visits.
    # Element receiving a verification request from this side. A miss is
    # reported with the screen's own texts (see tap_first_of), which is the
    # measurement that fixes this entry.
    # MEASURED on the rig 2026-09-02, first run in which this side asked:
    # Element announces the request as a banner carrying a TITLE and the
    # requesting user, and NO button text at all --
    #   'Demande de vérification'
    #   'libraryparty (@libraryparty:level-two.test)'
    # -- so the thing to tap is the banner itself, and every verb this
    # driver guessed first ("Accepter", "Vérifier", "Prêt") was absent. The
    # guesses stay trailing for a build that puts a button there.
    "incoming_request": (["Demande de vérification", "Verification Request",
                          "Vérifier", "Verify",
                          "Accepter", "Accept",
                          "Prêt", "Ready",
                          "Continuer", "Continue"],
                         "Element's incoming verification request"),
    # MEASURED on the rig 2026-09-02: tapping the banner opens a sheet that
    # asks whether to answer the request at all, and it is a separate screen
    # from the method choice -- 'Vérifier' as its title, then 'Accepter',
    # 'Refuser', 'Ce n'était pas moi'. Nothing about a code appears until
    # this is answered.
    "accept_request": (["Accepter", "Accept"],
                       "the control that answers the verification request"),
    # MEASURED on the rig 2026-09-02, on the screen behind 'Accepter', and
    # this is the screen four earlier runs never reached:
    #   'Scannez le code avec votre autre appareil, ou échangez et scannez'
    #   'Scanner avec cet appareil'                    <- this
    #   'Impossible de scanner'
    #   'Vérifier en comparant des émoticônes à la place'
    # The last two are deliberately NOT candidates: both are ways of NOT
    # scanning, and tapping either would end the run in the emoji fallback
    # this leg exists to avoid. Node text matches exactly (casefolded),
    # while content-desc matches by casefolded prefix -- which is precisely
    # why no bare "Scanner"/"Scan" entry remains in this list: a short
    # entry could prefix-match a longer row the driver did not mean to tap.
    "scan_choice": (["Scanner avec cet appareil", "Scan with this device",
                     "Scanner le code QR", "Scanner leur code QR",
                     "Scan QR code", "Scan their QR code"],
                    "the scan choice on the verification screen"),
}


DUMP_PATH = "/sdcard/window_dump.xml"


def texts_of(nodes):
    """Every label a person would see, from one window dump's nodes.

    Only for diagnostics: a UI step that cannot find what it was told to
    look for reports this, so the transcript of a failed run carries the
    measurement that fixes it instead of only the guess that missed. That
    is the maintenance loop this whole section is built around -- a named
    failure is worth more when it names the screen as well as the wish.
    Both backends pass their own FRESH dump: a stale one would describe a
    screen the step did not actually miss on.
    """
    seen = []
    for node in nodes:
        for value in ((node.get("text") or "").strip(),
                      (node.get("content-desc") or "").strip()):
            if value and value not in seen:
                seen.append(value[:60])
    return seen


def center_of(bounds):
    """The centre point of a dump node's `bounds` attribute.

    Module-level because both backends tap by node centre: the adb-native
    one has no choice, and the u2 one matches against the same hierarchy
    dump so it can match case-insensitively (see its click_first).
    """
    match = re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", bounds)
    x1, y1, x2, y2 = (int(part) for part in match.groups())
    return (x1 + x2) // 2, (y1 + y2) // 2


class Uiautomator2Backend:
    """The richer RPC backend, used only where its phone-side stub still
    works. Selected by probing (see choose_ui_backend): the probe is exactly
    the call the measured API-37 failure breaks, so a broken stub falls
    through to adb-native by itself.
    """

    def __init__(self, serial):
        import uiautomator2 as u2
        self.device = u2.connect(serial)
        # The probe is dump_hierarchy, NOT device.info. Two reasons, both
        # MEASURED on the rig phone (2026-09-02, API 37):
        #   * `info` goes to the stub's DeviceInfo RPC, which is broken here
        #     (see the MEASURED FACT block) -- probing with it rejects a
        #     backend whose every other RPC works, which is the wrong answer;
        #   * a probe must cross the RPC server to mean anything. `shell` and
        #     `window_size` do NOT: uiautomator2 routes both through adbutils,
        #     so they answer even with the RPC server down, and prove no more
        #     than require_online already proved. dumpWindowHierarchy is the
        #     RPC, and it is one this backend actually calls.
        self.device.dump_hierarchy()

    def start(self, package):
        # app_start, not an explicit activity name: monkey resolves the
        # launcher entry, so no activity-name assumption survives here.
        self.device.app_start(package)

    def click_first(self, candidates):
        # Matched case-insensitively, the way AdbNativeBackend matches, and
        # for the same MEASURED reason: Element renders its primary buttons
        # through textAllCaps and the tree carries the RENDERED case. u2's
        # own selectors are case-SENSITIVE -- measured on the rig phone
        # 2026-09-02, `d(text="ACTIVER").exists` is True where
        # `d(text="Activer").exists` is False -- so an exact match here
        # would silently miss every candidate this driver lists in title
        # case, and the two backends would not in fact share semantics the
        # way this class's docstring says they do. The hierarchy dump is one
        # RPC for the whole screen, which is also cheaper than a selector
        # round trip per candidate.
        try:
            nodes = list(xml_etree.fromstring(
                self.device.dump_hierarchy()).iter("node"))
        except xml_etree.ParseError:
            return None
        for text in candidates:
            for node in nodes:
                node_text = (node.get("text") or "").strip()
                node_desc = (node.get("content-desc") or "").strip()
                if (node_text.casefold() == text.casefold()
                        or node_desc.casefold().startswith(text.casefold())):
                    x, y = center_of(node.get("bounds"))
                    self.device.click(x, y)
                    return text
        return None

    def scroll_forward(self):
        try:
            scroller = self.device(scrollable=True)
            if scroller.exists:
                scroller.scroll.forward()
                return True
        except Exception:  # noqa: BLE001 -- a scroll that fails is "no more"
            pass
        return False

    def editable_count(self):
        return self.device(className="android.widget.EditText").count

    def type_in_editable(self, index, value):
        fields = self.device(className="android.widget.EditText")
        if index >= fields.count:
            return False
        # set_text replaces, so a prefilled field (the server editor's
        # "matrix.org") needs no clearing on this backend.
        fields[index].set_text(value)
        return True

    def type_in_first_editable(self, value):
        return self.type_in_editable(0, value)

    def visible_texts(self):
        try:
            return texts_of(xml_etree.fromstring(
                self.device.dump_hierarchy()).iter("node"))
        except xml_etree.ParseError:
            return ["<the window dump was not well-formed XML>"]


class AdbNativeBackend:
    """The zero-install backend: only adb shell primitives that ship in the
    Android framework itself. This is the backend that survives every future
    Android version, because nothing it needs is installed ON the phone
    (see the MEASURED FACT above). Every primitive below was verified live
    on the rig's Pixel 10 Pro Fold (API 37) on 2026-09-01.
    """

    def __init__(self, serial):
        self.serial = serial
        # Probe with a real dump: if the framework primitive is absent the
        # backend is refused here, named, rather than failing one UI step
        # in with a worse-shaped error.
        self._dump()

    def _adb_or_die(self, result, what):
        """Fail the step when adb says the command did not run.

        A nonzero rc from `input tap`/`swipe`/`text` means the touch or the
        keystrokes never landed, and reporting the candidate as tapped would
        send the next step at a screen the driver never reached. Raised
        rather than retried: a command adb refuses is a device failure, not
        a candidate the screen is missing.
        """
        if result.returncode != 0:
            raise RunFailed(
                f"adb refused the {what} on {self.serial} "
                f"(rc {result.returncode}): {result.stderr.strip()}")

    def _dump(self):
        """One window dump, parsed into a node list.

        Retried a bounded few times: a dump can be refused transiently
        (MEASURED on the rig phone: shell rc 137, SIGKILLed, with no
        output). Sustained 137s are the post-u2-probe wedge, which is the
        caller's problem to wait out, not this loop's.
        """
        last_error = ""
        for attempt in range(3):
            result = adb_on(self.serial, "shell", "uiautomator", "dump",
                            timeout=60)
            if result.returncode == 0 and "dumped" in result.stdout + result.stderr:
                break
            last_error = (result.stderr or f"shell rc {result.returncode}").strip()
            time.sleep(2)
        else:
            raise RunFailed(
                f"`uiautomator dump` failed on the phone: {last_error}.\n"
                "      The adb-native backend needs that framework primitive; "
                "its absence on a rig phone would be a finding about the "
                "device, not something this driver can work around."
            )
        xml = adb_on(self.serial, "shell", "cat", DUMP_PATH, timeout=60).stdout
        try:
            root = xml_etree.fromstring(xml)
        except xml_etree.ParseError as error:
            raise RunFailed(
                f"the phone's window dump was not well-formed XML ({error}).\n"
                "      A dump that cannot be read is the same failure shape "
                "as a screen that cannot be named: reported as itself."
            )
        return list(root.iter("node"))

    def start(self, package):
        # Same rule as the u2 backend: monkey resolves the launcher entry.
        result = adb_on(self.serial, "shell", "monkey",
                        "-p", package, "-c", "android.intent.category.LAUNCHER", "1")
        require(result.returncode == 0,
                f"launching {package} on the phone failed: {result.stderr.strip()}")

    def click_first(self, candidates):
        nodes = self._dump()
        for text in candidates:
            for node in nodes:
                node_text = (node.get("text") or "").strip()
                node_desc = (node.get("content-desc") or "").strip()
                # Exact on visible text, case-insensitively: Element renders
                # its primary buttons through textAllCaps, and the dump
                # carries the RENDERED case -- MEASURED on the rig phone,
                # the sign-in button dumps as "SE CONNECTER" where the
                # candidate list says "Se connecter". Matching case would
                # make every candidate carry both spellings; the styling
                # choice is Element's to change, not the driver's to know.
                # Content-desc matches by prefix, also case-insensitively:
                # descriptions carry instance detail after the label
                # (MEASURED: "Image de profile de l'utilisateur <name>"),
                # and an exact match there would force the driver to know
                # names it has no business knowing. Tapping the center of
                # the labelled node's bounds works even where the node
                # itself is not clickable: the touch lands on whatever row
                # holds it (MEASURED: the drawer's non-clickable labels).
                if (node_text.casefold() == text.casefold()
                        or node_desc.casefold().startswith(text.casefold())):
                    x, y = center_of(node.get("bounds"))
                    self._adb_or_die(
                        adb_on(self.serial, "shell", "input", "tap", str(x), str(y)),
                        "tap")
                    return text
        return None

    def scroll_forward(self):
        """One forward scroll of the first scrollable container, if any."""
        for node in self._dump():
            if node.get("scrollable") == "true":
                x1, y1, x2, y2 = (int(part) for part in
                                  re.match(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",
                                           node.get("bounds")).groups())
                middle = (x1 + x2) // 2
                # Swipe bottom-to-top inside the container's own bounds:
                # a full-screen swipe would drag the drawer or the system
                # bars instead of the list that held the missing text.
                self._adb_or_die(
                    adb_on(self.serial, "shell", "input", "swipe",
                           str(middle), str(y2 - 60), str(middle), str(y1 + 60), "300"),
                    "swipe")
                return True
        return False

    def _editable_nodes(self):
        return [node for node in self._dump()
                if node.get("class", "").endswith("EditText")]

    def editable_count(self):
        return len(self._editable_nodes())

    def type_in_editable(self, index, value):
        nodes = self._editable_nodes()
        if index >= len(nodes):
            return False
        x, y = center_of(nodes[index].get("bounds"))
        self._adb_or_die(
            adb_on(self.serial, "shell", "input", "tap", str(x), str(y)),
            "tap")
        # Clear any prefill before typing. MEASURED on the rig phone: the
        # server editor comes up prefilled with "matrix.org" and `input
        # text` APPENDS, so typing the URL there would have produced
        # "matrix.orghttp://127.0.0.1:...". MOVE_END plus a DEL sweep is
        # the framework-only way to empty a field; deleting from an empty
        # field is harmless, so the sweep is generous on purpose.
        self._adb_or_die(
            adb_on(self.serial, "shell", "input", "keyevent", "KEYCODE_MOVE_END",
                   *(["KEYCODE_DEL"] * 64)),
            "key sweep")
        # MEASURED on the rig phone: `input text` typed a homeserver
        # URL (http://127.0.0.1:8008) verbatim. Two encodings are
        # still applied because the values they protect are legal:
        # % and space are format characters to `input text` itself,
        # and the remote shell word-splits, so the value is quoted
        # for it. Passwords are hex and localparts plain, so the
        # encodings are belt and braces rather than load-bearing.
        encoded = value.replace("%", "%%").replace(" ", "%s")
        quoted = "'" + encoded.replace("'", "'\"'\"'") + "'"
        self._adb_or_die(
            adb_on(self.serial, "shell", "input", "text", quoted),
            "text input")
        return True

    def type_in_first_editable(self, value):
        return self.type_in_editable(0, value)

    def visible_texts(self):
        return texts_of(self._dump())


def wake_screen(serial):
    """Screen on and keyguard cleared.

    MEASURED on the rig phone: `wm dismiss-keyguard` alone leaves the
    swipe-only keyguard up (AlternateBouncerView); an upward swipe clears
    it when no PIN is set. Harmless when the screen is already unlocked.
    Every UI primitive below -- dump most of all -- needs the screen
    awake; this runs before the backend probe, not just before sign-in.
    """
    adb_on(serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
    adb_on(serial, "shell", "wm", "dismiss-keyguard")
    adb_on(serial, "shell", "input", "swipe", "540", "1800", "540", "600", "300")
    # Measured: a dump issued in the same instant as the unlock swipe fails
    # (empty-handed, before the lock screen has finished dismissing); one
    # second of settle makes the probe deterministic.
    time.sleep(1)


UI_BACKEND = os.environ.get("CAMERA_RIG_UI_BACKEND", "adb-native")


def choose_ui_backend(serial):
    """adb-native by default; uiautomator2 only when a rig asks for it.

    DECLARED, NOT PROBED, and the reason is measured. The obvious design --
    try uiautomator2, fall back -- was written first and replaced, because
    a probe answers the wrong question and costs something to ask:

      * WRONG QUESTION. The probe has to pick one RPC to stand for "u2
        works here", and no single RPC does. MEASURED on the rig phone
        (Pixel 10 Pro Fold, Android 17 / API 37, 2026-09-02): `deviceInfo`
        is broken and `dumpWindowHierarchy`, the selector RPCs and
        `app_start` are all fine, 20 samples each. A probe on `deviceInfo`
        rejects a working backend; a probe on `dumpWindowHierarchy` accepts
        one whose `info` will crash the first caller. Neither is the truth.
      * COSTS SOMETHING. A failed probe was measured (2026-09-01, on a
        phone with NO stub installed) to leave the framework's own
        uiautomator service refusing `uiautomator dump` -- SIGKILLed, shell
        rc 137 -- for a nondeterministic stretch, once past 600s. That did
        NOT reproduce on 2026-09-02 with the stub installed, so its trigger
        is not pinned down; a hazard nobody can characterise is a hazard
        worth not triggering on a schedule.

    So the rig says which backend it wants and the driver obeys. The
    default is adb-native because it is the one with nothing to go wrong:
    `uiautomator dump` + `input tap` are Android framework built-ins, so
    there is no phone-side install to age out from under this leg, which is
    the same reasoning this repository keeps elsewhere (the throwaway
    container over a hosted dependency, the pinned-by-digest image over a
    registry's goodwill). It is also the backend the phone-side flow below
    was measured against.

    CAMERA_RIG_UI_BACKEND=uiautomator2 opts a rig into the richer path. It
    is not the default and it is not required: nothing in this driver needs
    an RPC that adb-native cannot do.
    """
    if UI_BACKEND == "adb-native":
        return AdbNativeBackend(serial), "adb-native (uiautomator dump + input)"
    if UI_BACKEND == "uiautomator2":
        try:
            return Uiautomator2Backend(serial), "uiautomator2"
        except ImportError as error:
            raise RunFailed(
                f"CAMERA_RIG_UI_BACKEND is 'uiautomator2' but uiautomator2 is "
                f"not importable ({error}).\n"
                "      Remedy, on the rig's Python: python3 -m pip install "
                "uiautomator2 && python3 -m uiautomator2 init (with the phone "
                "on adb). Or unset CAMERA_RIG_UI_BACKEND: the default backend "
                "needs no phone-side install at all."
            )
        except Exception as error:  # noqa: BLE001 -- reported, not handled
            raise RunFailed(
                f"CAMERA_RIG_UI_BACKEND is 'uiautomator2' but the phone at "
                f"{serial} does not answer its RPC: {error}.\n"
                "      This is a declared choice, so it is refused rather "
                "than silently downgraded -- a run that quietly drove a "
                "different backend than the rig asked for would make every "
                "later measurement ambiguous. Remedy: re-run `python3 -m "
                "uiautomator2 init`, or unset CAMERA_RIG_UI_BACKEND to use "
                "the zero-install default."
            )
    raise RunFailed(
        f"CAMERA_RIG_UI_BACKEND is {UI_BACKEND!r}, which is not a backend this "
        "driver has. Remedy: 'adb-native' (the default, zero phone-side "
        "install) or 'uiautomator2'."
    )


class Element:
    """The unmodified Element on the phone, driven through whichever UI
    backend the phone supports.

    Why text-selected taps and not coordinates: the phone's screen faces
    the mount, away from anything a person can watch, so taps must be
    selected by what the UI says, not by where a coordinate happens to
    land; and the maintenance cost of coordinate taps against a
    third-party client is the worst kind. The step/candidate semantics are
    identical on both backends -- same lists, same failure texts.
    """

    def __init__(self, serial, package):
        wake_screen(serial)
        self.serial = serial
        self.backend, backend_name = choose_ui_backend(serial)
        rig_log(f"phone: UI backend: {backend_name}")
        self.package = package
        installed = adb_on(serial, "shell", "pm", "path", package)
        require(installed.returncode == 0 and installed.stdout.strip(),
                f"no package {package!r} on the phone.\n"
                "      ASSUMPTION: the rig phone runs Element Classic "
                "(im.vector.app). Install it, or set CAMERA_RIG_ELEMENT_PACKAGE "
                "to what the rig actually runs and re-check.")
        rig_log(f"phone reachable; {package} is installed")

    def reset(self, serial):
        # ASSUMPTION: the rig phone is dedicated to this leg, so wiping
        # Element's data loses nothing a person put there; what it buys is
        # a deterministic first launch. Two measured needs, one act:
        #   * the previous run's account dies with its homeserver, and an
        #     Element still signed in to a dead account returns to that
        #     stale session instead of the onboarding screens the sign-in
        #     flow taps for -- so the labels never appear and the run burns
        #     its timeouts;
        #   * MEASURED (run #4, 2026-09-02): launching an Element left
        #     mid-flow (the server editor from a previous attempt) brings
        #     the EXISTING task forward, and the driver then spends the
        #     sign_in_entry budget reading a screen it is not on. `pm
        #     clear` drops the task stack as well as the data, so the next
        #     launch is the welcome screen by construction -- which a
        #     force-stop alone does not guarantee.
        # pm clear also revokes the CAMERA grant, which is why this runs
        # BEFORE wake: wake is where the grant happens.
        cleared = adb_on(serial, "shell", "pm", "clear", self.package)
        require(cleared.returncode == 0,
                f"clearing {self.package}'s data failed: "
                f"{cleared.stderr.strip()}.\n"
                "      The next sign-in cannot start from a stale session, "
                "so the run refuses to continue on a half-reset phone.")
        rig_log("phone: Element's data cleared; sign-in starts from onboarding")

    def start(self):
        self.backend.start(self.package)

    def wake(self, serial):
        wake_screen(serial)
        # Keep the phone awake for the whole run, and put the old value back
        # on every way out (main's finally calls restore_display). MEASURED
        # on the first physical run 2026-09-01: the phone's ordinary 30 s
        # screen-off re-locked it mid sign-in, and the leg then spent its
        # whole 90 s step budget reading the lock screen, failing the
        # server-choice step with a text that was on the screen behind the
        # keyguard. A rig phone is a fixture, not a daily driver: the run
        # may set its sleep policy for the run's duration, the way the
        # emulator's display prep already does.
        previous = adb_on(serial, "shell", "settings", "get", "system",
                          "screen_off_timeout").stdout.strip()
        self._previous_screen_off_timeout = previous
        adb_on(serial, "shell", "settings", "put", "system",
               "screen_off_timeout", "1800000")
        camera = adb_on(serial, "shell", "pm", "grant", self.package,
                        "android.permission.CAMERA")
        require(camera.returncode == 0,
                f"granting CAMERA to {self.package} failed: {camera.stderr.strip()}.\n"
                "      The scanner cannot open without it, and the run refuses "
                "to time out for a permission prompt nobody can tap.")
        # Same treatment for the notification permission: MEASURED on the rig
        # phone (run #4bis), the system's POST_NOTIFICATIONS dialog stalled
        # the first-session bootstrap behind a prompt the driver could not
        # name. Push is irrelevant on a rig, so the grant is free -- and the
        # dialog never appears. (The candidates list keeps "Ne pas autoriser"
        # as the belt to this brace.)
        adb_on(serial, "shell", "pm", "grant", self.package,
               "android.permission.POST_NOTIFICATIONS")

    def restore_display(self, serial):
        """Put the phone's sleep policy back; called from main's finally."""
        previous = getattr(self, "_previous_screen_off_timeout", None)
        if previous:
            adb_on(serial, "shell", "settings", "put", "system",
                   "screen_off_timeout", previous)
            rig_log(f"phone screen_off_timeout restored to {previous}")

    def tap_first_of(self, candidates, timeout_s, what, clearing=(),
                     scrolling=True):
        """Taps the first of `candidates` that appears, within the deadline.

        ASSUMPTION: the rig phone's locale is covered by
        ELEMENT_CANDIDATE_SCREENS; every selector is an on-screen string
        (fr-FR and en are in the lists today, fr-FR measured). A locale
        change is a one-line addition to `candidates` once observed.

        A text that is absent scrolls the first scrollable container
        forward and looks again, bounded: some targets (a session deep in
        the sessions list) only exist off screen.

        `scrolling` is on by default and MUST be turned off on any screen a
        swipe can dismiss. Scrolling to find an off-screen label is safe on a
        list; on Element's verification sheet it is not, because the same
        gesture that reveals a row also drags the sheet away, taking the open
        scanner and the live flow with it.

        `clearing` names prompts to dismiss on every miss, and it is opt-in
        per step rather than always-on for a measured reason. Element's
        first-session prompts do not stop when the protocol does: MEASURED
        on the rig 2026-09-02, the account's cross-signing identity was
        published -- which is what element_bootstrap_identity gates on, and
        correctly so -- while Element was still two onboarding screens from
        its home, and it then sat on the analytics opt-in ("Aider a
        ameliorer Element Classic") until this step timed out looking for a
        drawer that was never on screen. Any step that waits for a screen
        during the first session has to keep clearing what Element puts in
        front of it. It is NOT always-on because the dismiss list contains
        "Annuler"/"Cancel", and a step that taps those while sign-in is on
        screen would cancel the sign-in: the steps that pass `clearing` are
        the ones after sign-in, where dismissing is always the right answer.
        """
        deadline = time.time() + timeout_s
        scrolls_left = 5
        while time.time() < deadline:
            hit = self.backend.click_first(candidates)
            if hit is not None:
                rig_log(f"phone: tapped {hit!r} ({what})")
                return
            if clearing and self.dismiss_any_of(clearing):
                time.sleep(1)
                continue
            if scrolling and scrolls_left > 0 and self.backend.scroll_forward():
                scrolls_left -= 1
                time.sleep(1)
                continue
            time.sleep(2)
        raise RunFailed(
            f"the phone side could not find {what}: none of {candidates} "
            f"appeared within {timeout_s}s.\n"
            f"      What WAS on screen: {self.backend.visible_texts()}\n"
            "      The rig's Element build differs from what this driver was "
            "written against. The list above is the measurement: add "
            f"the label that means {what} to ELEMENT_CANDIDATE_SCREENS."
        )

    def type_in_first_editable(self, value, what):
        """Types into the first editable on screen.

        ASSUMPTION: exactly one text field is focusable on each of Element's
        server/username/password screens, which held for the build this was
        written against and is checked by requiring the field to exist.
        """
        self.type_in_editable(0, value, what)

    def type_in_editable(self, index, value, what):
        """Types into the index-th editable on screen (dump order = reading
        order, so 0 is the top field)."""
        deadline = time.time() + 60
        while time.time() < deadline:
            if self.backend.type_in_editable(index, value):
                rig_log(f"phone: typed into the {what} field")
                return
            time.sleep(2)
        raise RunFailed(
            f"the phone side found no editable field for {what}. The rig's "
            "Element build differs from what this driver was written against; "
            "iterate on the rig (see ELEMENT_CANDIDATE_SCREENS)."
        )

    def wait_for_editable(self, tap_candidates, timeout_s, what):
        """Waits for at least one editable field, tapping the first of
        `tap_candidates` that appears meanwhile.

        Used where a continue control stands between the driver and a form
        whose exact shape is Element's to choose: the gate is the field --
        the thing the next step needs -- not the button, so a build that
        lands on the form directly is not derailed by a tap meant for a
        screen it skipped.
        """
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            if self.backend.editable_count() > 0:
                return
            hit = self.backend.click_first(tap_candidates)
            if hit is not None:
                rig_log(f"phone: tapped {hit!r} ({what})")
            time.sleep(2)
        raise RunFailed(
            f"no editable field appeared within {timeout_s}s, and none of "
            f"{tap_candidates} ({what}) moved the flow forward.\n"
            "      The rig's Element build differs from what this driver was "
            "written against. Iterate on the rig: run the flow by hand once, "
            "read the actual labels, and add them to ELEMENT_CANDIDATE_SCREENS."
        )

    def dismiss_any_of(self, candidates):
        """Taps the first of `candidates` that is on screen, if any.

        The inverse of tap_first_of: absence is success. Used for the
        first-session prompts, where what appears depends on Element's mood
        and the only fact that matters is gated structurally afterwards.
        """
        hit = self.backend.click_first(candidates)
        if hit is not None:
            rig_log(f"phone: tapped {hit!r} (a first-session prompt)")
            return True
        return False


def element_sign_in(element, serial, homeserver_url, localpart, password):
    """Element, from icon to a signed-in session on the throwaway homeserver.

    The homeserver URL is the phone's own view of this host: `adb reverse`
    maps the phone's loopback to the container port, so Element is told
    http://127.0.0.1:<port> exactly as a person on the rig would reach it
    (run_camera_proof.py established this pattern for a cabled device).
    """
    element.reset(serial)
    element.wake(serial)
    element.start()
    for step in ("sign_in_entry", "choose_other_server"):
        candidates = ELEMENT_CANDIDATE_SCREENS[step]
        element.tap_first_of(candidates[0], 90, candidates[1])
    element.type_in_first_editable(homeserver_url, "homeserver URL")
    candidates = ELEMENT_CANDIDATE_SCREENS["server_confirm"]
    element.tap_first_of(candidates[0], 30, candidates[1])
    # MEASURED on the rig phone (2026-09-02): confirming the server returns
    # to the "Bon retour parmi nous" screen, and the credentials form is
    # behind its "Poursuivre" control. Gate on the form (an editable field)
    # rather than on the button: a build that lands on the form directly is
    # not derailed by a tap meant for a screen it skipped.
    candidates = ELEMENT_CANDIDATE_SCREENS["server_continue"]
    element.wait_for_editable(candidates[0], 60, candidates[1])
    if element.backend.editable_count() >= 2:
        # ASSUMPTION, to be measured on the rig: a two-field credentials
        # form is username over password, in reading order, with a single
        # submit. A build that proves this wrong fails at the submit step
        # naming what it looked for.
        element.type_in_editable(0, localpart, "username")
        element.type_in_editable(1, password, "password")
        candidates = ELEMENT_CANDIDATE_SCREENS["sign_in_submit"]
        element.tap_first_of(candidates[0], 60, candidates[1])
    else:
        # The one-field-at-a-time flow this driver was written against.
        element.type_in_first_editable(localpart, "username")
        candidates = ELEMENT_CANDIDATE_SCREENS["username_confirm"]
        element.tap_first_of(candidates[0], 30, candidates[1])
        element.type_in_first_editable(password, "password")
        candidates = ELEMENT_CANDIDATE_SCREENS["sign_in_submit"]
        element.tap_first_of(candidates[0], 60, candidates[1])
    rig_log("phone: sign-in submitted; waiting for the session to settle")


def element_bootstrap_identity(element, homeserver, user_id, token):
    """Drives Element's post-sign-in bootstrap, gated on the protocol.

    The account needs a published cross-signing identity before any code can
    exist, and this app cannot mint one (it has no authentication loop -- see
    run_camera_proof.py). Element mints it during its first-session setup,
    behind prompts whose labels vary; the driver dismisses whatever of the
    known candidates appears and gates on the only fact that matters, read
    from the homeserver itself: /keys/query reporting the account's
    self-signing keys. UI text is a means; the protocol state is the
    assertion. A prompt that matches nothing is not fatal here -- it shows
    up as the identity never appearing, which is the failure this gate
    exists to name.
    """
    candidates = ELEMENT_CANDIDATE_SCREENS["bootstrap_dismiss"]

    deadline = time.time() + IDENTITY_TIMEOUT_SECONDS
    shape_logged = False
    while time.time() < deadline:
        element.dismiss_any_of(candidates[0])
        status, body = homeserver.call("POST", "/_matrix/client/v3/keys/query",
                                       token, {"device_keys": {user_id: []}})
        # The response nests by user id: self_signing_keys is
        # {user_id: {user_id, usage, keys: {"ed25519:...": "..."}}}. An
        # earlier revision of this check read .get("keys") one level too
        # high, which can only ever be absent -- a gate that cannot open
        # is not a gate. (Continuwuity follows the spec shape; MEASURED
        # wrong on run #5, which waited out its whole 300 s budget with
        # Element idle at the room list.)
        if status == 200 and not shape_logged:
            shape_logged = True
            rig_log("keys/query answered: "
                    + ", ".join(f"{section}={list(body.get(section, {}))}"
                                for section in ("master_keys",
                                                "self_signing_keys",
                                                "user_signing_keys")))
        if (status == 200
                and body.get("self_signing_keys", {}).get(user_id, {}).get("keys")):
            rig_log("the account's cross-signing identity is published")
            return
        time.sleep(3)
    raise RunFailed(
        f"no cross-signing identity appeared within {IDENTITY_TIMEOUT_SECONDS}s "
        "of sign-in. The code cannot exist without one, so waiting for the "
        "flow would only burn the scan budget.\n"
        "      What happened on the phone is on the rig's display; the "
        "prompts this driver knows how to dismiss are "
        "ELEMENT_CANDIDATE_SCREENS['bootstrap_dismiss'], and they are the "
        "list to extend."
    )


def element_accept_verification(element):
    """Element, from wherever it is to a scanner, driven by a request this
    side sent.

    MEASURED 2026-09-02, and this function is the whole of what that
    measurement changed. The previous shape navigated Element's own settings
    to the showing device's session and tapped its verify action, because
    that is the path a person had been observed completing. It cannot be
    driven: the only action that screen offers is "Vérifier de façon
    interactive avec des émojis", and the side that starts a verification is
    the side that picks its method, so Element picked SAS every time and the
    camera was never asked for. The navigation itself worked perfectly --
    drawer, "Sécurité et vie privée", "Afficher toutes les sessions", the
    session by name -- which is why it took four runs to see that the
    destination was wrong rather than the route.

    So this side asks (CameraProofHarness calls askOtherDevices) and Element
    answers. Element is the RESPONDER now, and a responder does not choose
    the method: it is offered what the requester announced, which here
    includes showing a code. Its own responder UI is the surface that offers
    to scan.

    A miss on any step below is reported with the screen's own texts, which
    is the measurement that fixes it.
    """
    prompts = ELEMENT_CANDIDATE_SCREENS["bootstrap_dismiss"][0]
    # 120s, not 60: this waits for a to-device event to cross a homeserver
    # and for Element to sync it, not for a screen to animate. `scrolling`
    # stays off for the same dismissible-surface reason the next steps
    # cite: the banner is delivered by the peer's to-device event, not
    # scrolled into view, and it is a one-shot transient -- a banner that
    # lands between the dump and the swipe would take the swipe and be
    # dismissed, so a miss must re-dump and re-tap rather than scroll the
    # room list under it.
    candidates = ELEMENT_CANDIDATE_SCREENS["incoming_request"]
    element.tap_first_of(candidates[0], 120, candidates[1], clearing=prompts,
                         scrolling=False)
    candidates = ELEMENT_CANDIDATE_SCREENS["accept_request"]
    # No `clearing` here, on purpose: clearing stops at the sheet because
    # the bootstrap_dismiss list contains "Annuler"/"Cancel" and the
    # verification sheet is dismissible, so a clearing tap inside it would
    # cancel the flow. First-session prompts are done by now anyway -- the
    # bootstrap gates on the published identity, and the prompts stand in
    # front of exactly that.
    element.tap_first_of(candidates[0], 60, candidates[1], scrolling=False)
    # scrolling=False for the reason the previous revision established: from
    # here Element is showing a verification in a dismissible sheet, and a
    # swipe on that throws the sheet away rather than looking further down it.
    # Required, not tolerated. An earlier revision let this one pass when
    # nothing matched, on the theory that a build might enter its scanner by
    # itself; what that actually bought was converting a nameable failure
    # into a 360s optical timeout, which reads as "the camera saw nothing"
    # and sends the next person to check the lamp. This screen has been
    # measured on the rig, and a build that changes it should say so here.
    candidates = ELEMENT_CANDIDATE_SCREENS["scan_choice"]
    element.tap_first_of(candidates[0], 60, candidates[1], scrolling=False)
    rig_log("phone: verification accepted; Element's camera should be up, "
            "pointed at the mount")


# --- The second witness -----------------------------------------------------


def wait_for_cross_signature(homeserver, user_id, device_id, token):
    """The account state the flow must leave behind, read over the client API.

    After a completed verification, the scanning device (Element, which holds
    the self-signing private key it bootstrapped) publishes a signature of
    the showing device's keys. Asserted structurally, and precisely: the
    showing device's key entry must carry a signature made by one of the
    account's own published self-signing keys -- not merely "a signatures
    block exists", which a half-written upload could also produce.
    """
    deadline = time.time() + 90
    while time.time() < deadline:
        status, body = homeserver.call("POST", "/_matrix/client/v3/keys/query",
                                       token, {"device_keys": {user_id: [device_id]}})
        if status == 200:
            # Same nesting as the bootstrap gate: self_signing_keys is keyed
            # by user id, the key ids live under [user_id]["keys"].
            self_signing = set(
                body.get("self_signing_keys", {}).get(user_id, {})
                    .get("keys", {}).keys())
            device = body.get("device_keys", {}).get(user_id, {}).get(device_id, {})
            signatures = set(device.get("signatures", {}).get(user_id, {}).keys())
            if self_signing and signatures & self_signing:
                rig_log("witness: the showing device's keys are signed by the "
                        "account's self-signing key")
                return
        time.sleep(5)
    raise RunFailed(
        "the flow reported done but the account state disagrees: the showing "
        "device carries no cross-signing signature from the account's "
        "self-signing key within 90s of the summary.\n"
        "      The two witnesses are the point of this leg; a done-log without "
        "the signature is not a pass."
    )


# --- The leak check ---------------------------------------------------------


def assert_nothing_leaked(serial, watched):
    """None of this run's values anywhere in the emulator's log.

    The rule from run_level_two.assert_nothing_leaked, scoped to the
    emulator serial: every value this run minted is searched across every
    buffer of the emulator's logcat, because React Native prints initial
    properties verbatim and this run hands the app a real credential.
    """
    missing = [label for label, value in watched if not value]
    require(not missing,
            "these values were empty and so could not be searched for: "
            + ", ".join(missing)
            + ".\n      This check cannot report on a value it was not given.")
    dump = adb_on(serial, "logcat", "-b", "all", "-d", "-v", "brief", timeout=180).stdout
    lines = dump.splitlines()
    leaked = []
    for label, value in watched:
        hits = sum(1 for line in lines if value in line)
        if hits:
            leaked.append(f"{label} ({hits} line(s))")
    require(not leaked,
            "values from this run reached the emulator's log: " + ", ".join(leaked)
            + ".\n      Nothing this run mints may be printable. Find what printed it.")
    rig_log(f"nothing leaked: none of this run's {len(watched)} values appears "
            f"anywhere in {len(lines)} emulator logcat lines, across every buffer")


# --- The run ----------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--apk", default=DEFAULT_APK)
    arguments = parser.parse_args()

    # The rig declaration comes first, before any tool check: on a machine
    # that is not the rig, that is the whole answer, and it must be the
    # answer in milliseconds rather than after a device search.
    require(os.environ.get("CAMERA_RIG") == "1",
            "CAMERA_RIG is not 1. This program drives a physical phone and "
            "configures a machine's display; it refuses to run anywhere that "
            "has not declared itself the camera rig. Set CAMERA_RIG=1 on the "
            "rig only, never in a shared environment.")

    require(shutil.which("docker") is not None, "docker is not on PATH")
    require(shutil.which("adb") is not None, "adb is not PATH")
    require(os.path.isfile(arguments.apk) and os.path.getsize(arguments.apk) > 0,
            f"no APK at {arguments.apk!r}. Build one first:\n"
            "      (cd packages/example-app/android && "
            "./gradlew :app:assembleRelease -PreactNativeArchitectures=<abi>)")
    require(port_is_free(CONDUCTOR_PORT),
            f"something is already listening on 127.0.0.1:{CONDUCTOR_PORT}, which is the "
            "port the app asks for its run plan on")

    # Signal handling and the sweeps, same as the sibling runners: SIGTERM
    # must become an exit for `finally`/atexit to run, and a previous run
    # killed mid-flight must not leave a homeserver or a credentials dir.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    atexit.register(remove_container)

    swept_containers = sweep_containers()
    swept_workdirs = sweep_workdirs()
    if swept_containers or swept_workdirs:
        rig_log(f"swept {swept_containers} orphaned container(s) and "
            f"{swept_workdirs} orphaned temporary director(ies) from an earlier run")

    workdir = tempfile.mkdtemp(prefix="rnmc-level-two-")
    atexit.register(shutil.rmtree, workdir, True)

    # Both accounts because start_homeserver creates both; the second is
    # left alone, exactly as run_camera_proof.py leaves it.
    passwords = {
        LIBRARY_LOCALPART: secrets.token_hex(24),
        NIO_LOCALPART: secrets.token_hex(24),
    }
    plan_server = None
    element = None
    phone_serial = None
    try:
        homeserver, homeserver_port = start_homeserver(workdir, passwords)

        token, user_id, device_id = login_when_ready(
            homeserver, LIBRARY_LOCALPART, passwords[LIBRARY_LOCALPART],
            SHOWING_DEVICE_NAME)
        rig_log("the showing device is logged in")

        # The plan the app fetches on launch. Same shape as the person-driven
        # camera-proof plan, with the mode the new App.tsx branch keys on.
        plan = {
            "mode": "camera-proof",
            "homeserver": f"http://127.0.0.1:{homeserver_port}",
            "conductor": f"http://127.0.0.1:{CONDUCTOR_PORT}",
            "userId": user_id,
            "deviceId": device_id,
            "accessToken": token,
            "roomId": "",
            "nioUserId": "",
            "mutation": "none",
        }
        plan_server = PlanServer(plan)
        plan_server.start()
        rig_log(f"the run plan is being served on 127.0.0.1:{CONDUCTOR_PORT}")

        # Both devices see this host through their own loopback: the
        # emulator through 10.0.2.2 (its alias for this host, which the
        # app's PLAN_URLS already try) and the phone through `adb reverse`.
        # The reverses make 127.0.0.1 work on both, the pattern
        # run_camera_proof.py established.
        require_online(EMULATOR_SERIAL, "the rig emulator")
        phone_serial = detect_phone_serial()
        rig_log(f"phone: {phone_serial}")
        require(adb_on(EMULATOR_SERIAL, "reverse", f"tcp:{CONDUCTOR_PORT}",
                       f"tcp:{CONDUCTOR_PORT}").returncode == 0,
                "adb reverse for the plan port on the emulator failed")
        require(adb_on(EMULATOR_SERIAL, "reverse", f"tcp:{homeserver_port}",
                       f"tcp:{homeserver_port}").returncode == 0,
                "adb reverse for the homeserver port on the emulator failed")
        require(adb_on(phone_serial, "reverse", f"tcp:{homeserver_port}",
                       f"tcp:{homeserver_port}").returncode == 0,
                "adb reverse for the homeserver port on the phone failed")
        atexit.register(lambda: (adb_on(EMULATOR_SERIAL, "reverse", "--remove-all"),
                                 adb_on(phone_serial, "reverse", "--remove-all")))

        prepare_emulator(EMULATOR_SERIAL)
        install_on_emulator(EMULATOR_SERIAL, arguments.apk)

        # --- THE PHONE SIDE: measured on the rig 2026-09-02, 5/5 ----------
        element = Element(phone_serial, ELEMENT_PACKAGE)
        element_sign_in(
            element, phone_serial, f"http://127.0.0.1:{homeserver_port}",
            LIBRARY_LOCALPART, passwords[LIBRARY_LOCALPART])
        element_bootstrap_identity(element, homeserver, user_id, token)
        # --- END OF THE PHONE SIDE ------------------------------------------

        launch_app(EMULATOR_SERIAL)
        wait_for_app_line(EMULATOR_SERIAL, re.compile(r"^CAMERA_PROOF run_started"),
                          120, "the harness's first line")

        # The harness dies here when the phone never answers its ask, and
        # its own FAIL lines stay in the emulator's logcat unless something
        # reads them. Surface them first, on the same stream as the FAIL
        # line so the order holds, then let the phone-side failure follow:
        # a miss otherwise reads as a phone-side selector miss after a full
        # 120 s banner burn.
        try:
            element_accept_verification(element)
        except RunFailed:
            camera_proof_lines = [
                line for line in app_lines(EMULATOR_SERIAL)
                if line.startswith("CAMERA_PROOF")
            ]
            if camera_proof_lines:
                print("[camera-proof] --- the emulator's CAMERA_PROOF lines "
                      "so far ---", file=sys.stderr)
                for line in camera_proof_lines:
                    print(line, file=sys.stderr)
                print("[camera-proof] --- end ---", file=sys.stderr)
            raise

        summaries, lines = wait_for_app_line(
            EMULATOR_SERIAL, SUMMARY_PATTERN, FLOW_TIMEOUT_SECONDS,
            "CAMERA_PROOF_SUMMARY line")

        print(flush=True)
        rig_log("--- what the app printed ---")
        for line in lines:
            if line.startswith("CAMERA_PROOF"):
                print(line, flush=True)
        rig_log("--- end ---")
        print(flush=True)

        require(len(summaries) == 1,
                f"expected exactly one CAMERA_PROOF_SUMMARY line, found {len(summaries)}:\n"
                + "\n".join(summaries)
                + "\n      The harness prints one summary per launch; more than one "
                "means something re-ran it and the result is ambiguous.")
        summary = summaries[0]
        rig_log(f"summary: {summary}")

        passed, total = (int(part) for part in summary.split()[1].split("/"))
        require(total == EXPECTED_STEPS,
                f"the run reported {total} steps and this program expects {EXPECTED_STEPS}.\n"
                "      The set of camera-proof checks changed. Update EXPECTED_STEPS in "
                "packages/example-app/level-two/run_camera_proof_rig.py in the same "
                "commit that changed it -- this failing until you do is the point.")
        require(passed == total,
                f"the harness reported '{summary}'. See the CAMERA_PROOF_CHECK lines "
                "above for which step failed.")

        # The second witness, before anything is called a pass.
        wait_for_cross_signature(homeserver, user_id, device_id, token)

        assert_nothing_leaked(EMULATOR_SERIAL, [
            ("the access token", token),
            ("the account password", passwords[LIBRARY_LOCALPART]),
            ("the user id", user_id),
            ("the showing device's id", device_id),
        ])

        rig_log("PASS: a real camera read the symbol this library drew, and "
                "both witnesses agree")
    except KeyboardInterrupt:
        print()
        rig_log("stopping at your request")
        return 130
    except RunFailed as failure:
        print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    finally:
        if element is not None and phone_serial is not None:
            element.restore_display(phone_serial)
        if plan_server is not None:
            plan_server.stop()
        adb_on(EMULATOR_SERIAL, "shell", "am", "force-stop", PACKAGE)
        remove_container()
        shutil.rmtree(workdir, ignore_errors=True)
        rig_log(f"the homeserver and the account on it are gone ({SERVER_NAME})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
