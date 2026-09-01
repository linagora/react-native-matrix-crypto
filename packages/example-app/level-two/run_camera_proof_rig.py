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
path below can be exercised without any hardware. Everything that drives the
physical phone -- marked with the header "THE PHONE SIDE" -- is written but
UNVALIDATED: no rig exists as of this commit, so no Element screen has ever
been tapped by this driver. Its assumptions are prefixed ASSUMPTION and
checked at runtime rather than trusted; the first real run is expected to
find work there, and it fails closed at every gap.

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
     homeserver, bootstrap the account's cross-signing identity, then open
     the verification of the emulator's session so its camera faces the
     symbol;
  6. launch the app on the emulator and wait for `CAMERA_PROOF` lines;
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


def detect_phone_serial():
    """The phone is every adb device that is not the declared emulator.

    Deliberately strict: zero candidates and two-or-more candidates are both
    refusals, because a driver that guesses which physical phone to drive is
    worse than a driver that declines.
    """
    listed = run_command(["adb", "devices"], timeout=60).stdout
    serials = []
    for line in listed.splitlines()[1:]:
        parts = line.split()
        if len(parts) == 2 and parts[1] == "device":
            serials.append(parts[0])
    candidates = [serial for serial in serials if serial != EMULATOR_SERIAL]
    require(len(candidates) == 1,
            f"expected exactly one non-emulator device on adb (the mounted phone), "
            f"found {len(candidates)}: {candidates or 'none'}.\n"
            "      Connect the rig's phone by USB and make sure no other device is.")
    return candidates[0]


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
#   VALIDATED:     nothing in this section. It is written, syntax-checked,
#                  and failure-named; no Element screen has ever been driven
#                  by it. The first run on the rig is its first execution.
#   AWAITS:        the rig.
#
# Every UI step below fails with a named error naming what it looked for,
# because an unmodified client's screens are exactly the kind of third-party
# surface that moves between versions -- the failure text is the maintenance
# manual. ASSUMPTION lines state what is trusted and how it is checked.

# ASSUMPTION: the mounted phone runs Element Classic (im.vector.app). That is
# the one client observed completing this flow (run_camera_proof.py's header),
# and an unmodified mainstream client is the stronger claim. The package is
# overridable because it is the single most likely thing a rig will differ
# on: CAMERA_RIG_ELEMENT_PACKAGE names another package, and the driver checks
# at runtime that the package is actually installed rather than trusting the
# name:
#   adb shell pm path <package>
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
    "choose_other_server": (["Other", "Autre"], "the server-choice screen"),
    "server_confirm": (["OK", "Next", "Continue", "Suivant", "Continuer"],
                       "the server-confirm control"),
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
    "bootstrap_dismiss": (["Skip", "Maybe later", "Not now", "Cancel",
                           "Set up recovery",
                           "Ignorer", "Passer", "Plus tard", "Pas maintenant",
                           "Annuler"],
                          "a first-session prompt"),
    "settings_entry": (["Settings", "Paramètres"], "the settings entry"),
    "security_screen": (["Security & Privacy", "Security",
                         "Sécurité et confidentialité", "Sécurité"],
                        "the security screen"),
    "verify_action": (["Verify", "Verify session", "Start verification",
                       "Vérifier", "Vérifier la session",
                       "Démarrer la vérification"],
                      "the verify action for the showing device"),
}


class Element:
    """The unmodified Element on the phone, driven over UI Automator.

    Why uiautomator2 and not `adb shell input`: the phone's screen faces the
    mount, away from anything a person can watch, so taps must be selected by
    what the UI says, not by where a coordinate happens to land; and the
    maintenance cost of coordinate taps against a third-party client is the
    worst kind. Why Python: uiautomator2 is a Python library, and this
    program already lives in the conductor's Python world.
    """

    def __init__(self, serial, package):
        try:
            import uiautomator2 as u2
        except ImportError as error:
            raise RunFailed(
                "uiautomator2 is not importable, and the phone side cannot be "
                "driven without it. Remedy, on the rig's Python:\n"
                "      python3 -m pip install uiautomator2\n"
                "      python3 -m uiautomator2 init   # with the phone on adb\n"
                f"      (import failed with: {error})"
            )
        self.device = u2.connect(serial)
        try:
            self.device.info
        except Exception as error:  # noqa: BLE001 -- reported, not handled
            raise RunFailed(
                f"uiautomator2 cannot talk to the phone at {serial}: {error}.\n"
                "      Remedy: re-run `python3 -m uiautomator2 init` with the "
                "phone connected, and check the phone is not at a lock screen "
                "that blocks instrumentation."
            )
        self.package = package
        installed = adb_on(serial, "shell", "pm", "path", package)
        require(installed.returncode == 0 and installed.stdout.strip(),
                f"no package {package!r} on the phone.\n"
                "      ASSUMPTION: the rig phone runs Element Classic "
                "(im.vector.app). Install it, or set CAMERA_RIG_ELEMENT_PACKAGE "
                "to what the rig actually runs and re-check.")
        rig_log(f"phone reachable; {package} is installed")

    def start(self):
        # app_start, not an explicit activity name: monkey resolves the
        # launcher entry, so no activity-name assumption survives here.
        self.device.app_start(self.package)

    def wake(self, serial):
        adb_on(serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
        adb_on(serial, "shell", "wm", "dismiss-keyguard")
        camera = adb_on(serial, "shell", "pm", "grant", self.package,
                        "android.permission.CAMERA")
        require(camera.returncode == 0,
                f"granting CAMERA to {self.package} failed: {camera.stderr.strip()}.\n"
                "      The scanner cannot open without it, and the run refuses "
                "to time out for a permission prompt nobody can tap.")

    def reset(self, serial):
        # ASSUMPTION: the rig phone is dedicated to this leg, so wiping
        # Element's data loses nothing a person put there; what it buys is
        # a deterministic first launch. The previous run's account dies
        # with its homeserver in `finally`, and an Element still signed in
        # to a dead account returns to that stale session on app_start
        # instead of the onboarding screens the sign-in flow taps for --
        # so the labels never appear and the run burns its timeouts.
        # pm clear also revokes the CAMERA grant, which is why this runs
        # BEFORE wake: wake is where the grant happens.
        cleared = adb_on(serial, "shell", "pm", "clear", self.package)
        require(cleared.returncode == 0,
                f"clearing {self.package}'s data failed: "
                f"{cleared.stderr.strip()}.\n"
                "      The next sign-in cannot start from a stale session, "
                "so the run refuses to continue on a half-reset phone.")
        rig_log("phone: Element's data cleared; sign-in starts from onboarding")

    def tap_first_of(self, candidates, timeout_s, what):
        """Taps the first of `candidates` that appears, within the deadline.

        ASSUMPTION: the rig phone runs in English; every selector here is an
        on-screen string. A locale change is a one-line addition to
        `candidates` once observed on the rig.
        """
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            for text in candidates:
                selector = self.device(text=text)
                if selector.exists:
                    selector.click()
                    rig_log(f"phone: tapped {text!r} ({what})")
                    return
            time.sleep(2)
        raise RunFailed(
            f"the phone side could not find {what}: none of {candidates} "
            f"appeared within {timeout_s}s.\n"
            "      The rig's Element build differs from what this driver was "
            "written against. Iterate on the rig: run the flow by hand once, "
            "read the actual labels, and add them to ELEMENT_CANDIDATE_SCREENS."
        )

    def type_in_first_editable(self, value, what):
        """Types into the first editable on screen.

        ASSUMPTION: exactly one text field is focusable on each of Element's
        server/username/password screens, which held for the build this was
        written against and is checked by requiring the field to exist.
        """
        deadline = time.time() + 60
        while time.time() < deadline:
            field = self.device(className="android.widget.EditText")
            if field.exists:
                field.set_text(value)
                rig_log(f"phone: typed into the {what} field")
                return
            time.sleep(2)
        raise RunFailed(
            f"the phone side found no editable field for {what}. The rig's "
            "Element build differs from what this driver was written against; "
            "iterate on the rig (see ELEMENT_CANDIDATE_SCREENS)."
        )

    def dismiss_any_of(self, candidates):
        """Taps the first of `candidates` that is on screen, if any.

        The inverse of tap_first_of: absence is success. Used for the
        first-session prompts, where what appears depends on Element's mood
        and the only fact that matters is gated structurally afterwards.
        """
        for text in candidates:
            selector = self.device(text=text)
            if selector.exists:
                selector.click()
                rig_log(f"phone: tapped {text!r} (a first-session prompt)")
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
    while time.time() < deadline:
        element.dismiss_any_of(candidates[0])
        status, body = homeserver.call("POST", "/_matrix/client/v3/keys/query",
                                       token, {"device_keys": {user_id: []}})
        if status == 200 and body.get("self_signing_keys", {}).get(user_id, {}).get("keys"):
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


def element_verify_showing_device(element, device_name):
    """Element: verify the emulator's session, ending in the scanner.

    This is the person-driven flow's steps 2-3 (run_camera_proof.py's
    `announce`) with a person replaced by selectors: open the sessions list,
    find the session named after the showing device, start verification, and
    let Element choose the mode -- our side announced show-only, so Element
    presents its scanner. From here the camera does the work: the phone is
    in the mount, aimed at the display, and the symbol appears when the
    library has it ready.
    """
    for step in ("settings_entry", "security_screen"):
        candidates = ELEMENT_CANDIDATE_SCREENS[step]
        element.tap_first_of(candidates[0], 60, candidates[1])
    element.tap_first_of([device_name], 120,
                         f"the {device_name!r} session in the sessions list")
    candidates = ELEMENT_CANDIDATE_SCREENS["verify_action"]
    element.tap_first_of(candidates[0], 60, candidates[1])
    # ASSUMPTION: for an incoming show-only peer, Element enters its scanner
    # on its own; where a build instead offers an explicit choice, the
    # candidate below takes it. Absence is fine either way -- the scan
    # budget below is what actually decides.
    try:
        element.tap_first_of(["Scan QR code", "Scan"], 15,
                             "the explicit scan choice, if Element offers one")
    except RunFailed:
        rig_log("phone: no explicit scan choice appeared; assuming Element "
                "entered the scanner by itself")
    rig_log("phone: verification started; Element's camera should be up, "
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
            self_signing = set(
                body.get("self_signing_keys", {}).get(user_id, {}).get("keys", {}).keys())
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

        # --- THE PHONE SIDE: unvalidated, awaits the rig -------------------
        element = Element(phone_serial, ELEMENT_PACKAGE)
        element_sign_in(
            element, phone_serial, f"http://127.0.0.1:{homeserver_port}",
            LIBRARY_LOCALPART, passwords[LIBRARY_LOCALPART])
        element_bootstrap_identity(element, homeserver, user_id, token)
        # --- END OF THE PHONE SIDE ------------------------------------------

        launch_app(EMULATOR_SERIAL)
        wait_for_app_line(EMULATOR_SERIAL, re.compile(r"^CAMERA_PROOF run_started"),
                          120, "the harness's first line")

        element_verify_showing_device(element, SHOWING_DEVICE_NAME)

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
        if plan_server is not None:
            plan_server.stop()
        adb_on(EMULATOR_SERIAL, "shell", "am", "force-stop", PACKAGE)
        remove_container()
        shutil.rmtree(workdir, ignore_errors=True)
        rig_log(f"the homeserver and the account on it are gone ({SERVER_NAME})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
