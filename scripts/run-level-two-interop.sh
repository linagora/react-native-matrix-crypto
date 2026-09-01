#!/usr/bin/env bash
set -euo pipefail

# Runs all five level 2 interoperability proofs (design doc section 8)
# against a Matrix homeserver this script starts, provisions, and destroys.
#
#   * `level_two_interop` -- a third-party client decrypts what this library
#     encrypts, and this library decrypts what it sends. M2's final exit
#     criterion.
#   * `level_two_verification` -- a third-party client opens a device
#     verification against this library, this library announces it and
#     agrees to it, and the exchange runs to the point where the third
#     party's own defect stops it. M3's.
#
#     Read that literally: **no third-party verification completes here, and
#     no third-party refusal of a mismatched string is driven anywhere.**
#     matrix-nio 0.26.0 writes the SAS commitment as hexadecimal where the
#     specification requires unpadded base64, so it rejects every
#     spec-compliant peer and can never reach a short authentication string.
#     The test proves what it can and attributes the halt from inside nio's
#     own process; the completion and the refusal are proven at level 1, in
#     rust/matrix-crypto-core/tests/sas_two_party.rs, against a machine this
#     library does not control. That file's header has the whole of it.
#
#   * `level_two_identity` -- this library mints a signing identity, a real
#     homeserver accepts it and serves it back, and a decrypted event then
#     reports what it reports about its sender. M4's.
#
#     Read that literally too: **an event from the third-party client reads
#     `unsigned_device`, and nothing here can move it.** matrix-nio 0.26.0
#     implements no cross-signing at all -- it never publishes a master key
#     and drops the ones it is sent -- so it cannot be constructed as a
#     cross-signed peer, and `unverified_identity` is out of reach against
#     it. The test attributes that from inside nio's own process, the same
#     way the verification proof attributes its halt, and carries its own
#     control: an event from a device that IS signed, in the same run,
#     reading something else. `unverified_identity` from a cross-signed peer
#     is proven at level 1 in
#     rust/matrix-crypto-core/tests/cross_signed_peer.rs, and `verified` in
#     rust/matrix-crypto-core/tests/verified_sender.rs.
#
#   ./scripts/run-level-two-interop.sh
#
# That is the whole invocation. It needs Docker, a Rust toolchain, a Python 3
# and a Go toolchain, and nothing else -- no account on anybody's homeserver, no
# credential, no CI secret. CI runs this same script, so what a contributor
# runs locally and what stands behind the milestone's headline claim are the
# same code path rather than two things that look alike.
#
#   HOMESERVER_IMPL=synapse ./scripts/run-level-two-interop.sh
#
# runs the same five proofs against a throwaway Synapse instead of the default
# throwaway Continuwuity; see the image pins below for what each one is and
# what its bring-up costs. Every other line of this header applies to both.
#
# WHY A THROWAWAY HOMESERVER RATHER THAN CI SECRETS
#
# The alternative was a secret in this public repository's CI pointing at a
# homeserver somebody owns. That puts Matrix credentials in a public
# repository, sends test traffic to real infrastructure on every pull request
# including from outside contributors, and leaves debris behind when a run
# fails. A container started, used and destroyed inside the job has none of
# those properties, and it is checkable by a third party: anyone who clones
# this repository can run the identical proof.
#
# WHAT THIS ASSERTS, AND WHY NOT AN EXIT CODE
#
# `cargo test` exits 0 when it matches no test at all. A filter typo, a
# renamed test, or a missing `--ignored` all produce `0 passed; 0 failed` and
# a successful exit -- which is the exact shape of check this milestone has
# now found seven times: a green report that never examined its target. So
# this script requires, from cargo's own output:
#
#   * TWO `test level_two_interoperability_over_a_real_homeserver ... ok`
#     lines, and TWO `test result: ok. 1 passed; 0 failed; 0 ignored`
#     summaries -- the parent process and the phase-two child it spawns of
#     itself to reopen the store;
#   * ONE of each for
#     `test a_third_party_clients_verification_reaches_the_short_authentication_string`,
#     which spawns no child.
#
# Exactly those counts, asserted per test; see `run_proof` for what a smaller
# and what a larger number each mean.
#
# and it requires the homeserver to have answered a real login before cargo
# is invoked at all. A container that never started, a test that never ran,
# and a process that died mid-run all fail here rather than passing quietly.
#
# CREDENTIALS
#
# None exist to leak. The account is created by this script, inside the
# container it just started, with a password generated per run by
# `openssl rand`. Nothing is read from a file, an environment secret or a CI
# secret. The container listens on loopback only and is removed on every exit
# path. Under GitHub Actions the generated password is registered with
# `::add-mask::` before it is used anywhere, so it cannot appear in a job log
# even if the container's own output is dumped after a failure -- which this
# script does only when the run has already failed.
#
# POINTING IT AT A REAL HOMESERVER INSTEAD
#
# Set MATRIX_INTEROP_HOMESERVER, MATRIX_INTEROP_USER,
# MATRIX_INTEROP_PASSWORD and MATRIX_INTEROP_CHALLENGE_USER and no container
# is started: the tests run against what they name, exactly as they did before
# this script existed. That path is unchanged and still supported; it is
# simply no longer the only one.
#
# The fourth variable names a SECOND account, sharing the one password, that
# has never published a cross-signing identity. `level_two_identity_challenge`
# needs it and says why in its own header. It is required rather than
# optional: a proof this script would otherwise decline to run is the failure
# this milestone keeps finding.

# --- what a run is made of -------------------------------------------------

# Pinned by digest, not by tag: a tag is a mutable pointer, and "the job runs
# whatever that name points at today" is not a repeatable proof. Both pins
# below are multi-architecture indexes, so the same line works on a
# linux/amd64 CI runner and on an arm64 developer machine.
#
# Two homeserver implementations can stand behind these proofs, selected by
# HOMESERVER_IMPL further down. Neither is a stand-in for the other, and the
# proofs depend on nothing either of them does specifically:
# `level_two_interop`'s step 5 used to assert a fact about the *initial*
# /sync -- which Continuwuity reports and Synapse does not, Synapse populates
# `device_lists` only on incremental syncs -- so that assertion now loops
# until the account appears and both implementations pass it. The comment at
# that assertion in rust/matrix-crypto-core/tests/level_two_interop.rs has
# the whole of it.
#
# Continuwuity is the default. It is what this project's own infrastructure
# runs and what the test was originally proven against (task-12-report.md),
# it boots in about two seconds, its image is 128 MB with no database server
# to bring up alongside it, and it can be configured purely through
# environment variables -- which keeps its bring-up a single `docker run`.
# This is the multi-architecture index for v26.7.2.
CONTINUWUITY_IMAGE=${CONTINUWUITY_IMAGE:-forgejo.ellis.link/continuwuation/continuwuity@sha256:b5f5d7454a3e8dda041fc82084088409f2c34905ff51274955d52050203a87af}

# Synapse is the reference implementation and the other server family a real
# deployment is likely to run, which is why the proofs also stand behind it
# (issue #8). Its bring-up is heavier than Continuwuity's: the official image
# cannot be configured purely through environment variables, so the synapse
# path below runs the image's documented `generate` step and edits the
# generated homeserver.yaml, and account creation with registration closed
# goes over the shared-secret registration endpoint rather than Continuwuity's
# `--execute`. This is the multi-architecture index for v1.159.0, the current
# stable release at the time of pinning (v1.160.0 was still a release
# candidate).
SYNAPSE_IMAGE=${SYNAPSE_IMAGE:-docker.io/matrixdotorg/synapse@sha256:edf259d2b575b669a3e81024918ab8d5cfb7d2fba5a53c9e09695f1abc5645cb}

# Which implementation the throwaway container runs: continuwuity (the
# default) or synapse. Anything else is refused before anything is started,
# because a typo silently selecting the server a proof runs against is the
# kind of check-shaped hole this repository keeps finding. The manual path
# (MATRIX_INTEROP_HOMESERVER) starts no container, so it is unaffected.
HOMESERVER_IMPL=${HOMESERVER_IMPL:-continuwuity}

# The homeserver's `server_name`, which is also the domain half of the MXID.
# `localhost` is legal, needs no DNS and no certificate, and cannot be
# confused with anybody's real deployment.
SERVER_NAME=localhost
LOCALPART=interop

# A second account, for `level_two_identity_challenge` alone. It needs one to
# itself and the reason is structural: it has to begin on an account holding no
# cross-signing identity, and `level_two_identity` leaves the shared account
# holding one. An account's identity cannot be deleted afterwards, so sharing
# would make the two proofs order-dependent in a way no reader of either could
# see. Same generated password, so a run still has exactly one secret in it.
LOCALPART_CHALLENGE=interop-challenge

# Three more, for the scanned-code proof alone, and none of them can be one of
# the accounts above.
#
#   * SCANNED is the library's own. It needs an account whose cross-signing
#     identity THIS LIBRARY mints, so that the device holds the private half;
#     `level_two_identity` leaves the shared account holding one that a fresh
#     store cannot hold.
#   * SCANNER is the other person in the cross-user mode, and mints an
#     identity of its own, which mode 0x00 needs on both sides.
#   * SHOWN is the other person in the two phases that leave a flow which
#     cannot finish. Upstream allows one live verification per person, so such
#     a flow blocks every later one with the same person; keeping those phases
#     on their own account is what contains it. The test's header has the whole
#     of why a flow this library shows does not finish against this
#     counterparty.
LOCALPART_SCANNED=interop-scanned
LOCALPART_SCANNER=interop-scanner
LOCALPART_SHOWN=interop-shown

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
REQUIREMENTS="$REPO_ROOT/rust/matrix-crypto-core/tests/interop/requirements.txt"

# How long to wait for the container to answer, and then for the account it
# was told to create to accept a login.
HOMESERVER_TIMEOUT_SECONDS=${HOMESERVER_TIMEOUT_SECONDS:-90}

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# --- teardown, on every path out -------------------------------------------

# Every container this script starts carries these two labels, which is what
# makes the sweep below possible: the first says whose it is, the second says
# when it was started.
CONTAINER_LABEL=org.linagora.rnmc.level-two-interop
STARTED_LABEL=org.linagora.rnmc.level-two-interop.started

# How old a labelled container must be before the sweep will remove it.
# Comfortably longer than this job's own CI timeout of 45 minutes, so a
# concurrent run of this script -- two shells, or two jobs on one self-hosted
# runner -- can never have its homeserver killed underneath it. A sweep that
# removes a live run's container would be a worse bug than the debris it
# exists to clear.
STALE_AFTER_SECONDS=7200

CONTAINER=""
WORKDIR=""
RUN_FAILED=0

# Idempotent, and every step of it is allowed to fail: this runs from a trap,
# including on the path where something has already gone wrong, and a
# teardown that can itself fail is not a teardown. The same rule the test's
# own `Teardown` guard follows in `Drop`, for the same reason.
cleanup() {
  if [ -n "$CONTAINER" ]; then
    # Only on a failure, and only after the container is already doomed. A
    # passing run prints none of this: continuwuity echoes the password it
    # was told to set into its own startup output, and while that password
    # dies with the container -- and is masked under Actions -- there is no
    # reason to put it on screen at all.
    if [ "$RUN_FAILED" != "0" ]; then
      echo "--- homeserver output ---" >&2
      docker logs "$CONTAINER" 2>&1 | tail -60 >&2 || true
      echo "--- end homeserver output ---" >&2
    fi
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    CONTAINER=""
  fi
  if [ -n "$WORKDIR" ]; then
    # `chmod` first, and it is not belt and braces: Go writes its module
    # cache read-only, so a `rm -rf` over one fails file by file. The build
    # above removes that cache itself; this is what makes the teardown
    # infallible on the paths where it did not get that far.
    chmod -R u+w "$WORKDIR" 2>/dev/null || true
    rm -rf "$WORKDIR" || true
    WORKDIR=""
  fi
  return 0
}

# EXIT covers the ordinary path, every `fail` and every errexit abort. The
# three signals cover a developer's Ctrl-C and a CI runner cancelling the job:
# they exit rather than clean up directly, so the EXIT trap does the work once
# and there is exactly one teardown path to reason about.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

WORKDIR=$(mktemp -d)

# --- 1. the homeserver -----------------------------------------------------

if [ -n "${MATRIX_INTEROP_HOMESERVER:-}" ]; then
  # The manual path, unchanged. Everything the test needs is already in the
  # environment, so start nothing and destroy nothing.
  [ -n "${MATRIX_INTEROP_USER:-}" ] \
    || fail "MATRIX_INTEROP_HOMESERVER is set but MATRIX_INTEROP_USER is not.
      Set all three of HOMESERVER, USER and PASSWORD to run against a real
      homeserver, or none of them to run against a throwaway container."
  [ -n "${MATRIX_INTEROP_PASSWORD:-}" ] \
    || fail "MATRIX_INTEROP_HOMESERVER is set but MATRIX_INTEROP_PASSWORD is not.
      Set all three of HOMESERVER, USER and PASSWORD to run against a real
      homeserver, or none of them to run against a throwaway container."
  [ -n "${MATRIX_INTEROP_CHALLENGE_USER:-}" ] \
    || fail "MATRIX_INTEROP_HOMESERVER is set but MATRIX_INTEROP_CHALLENGE_USER is not.
      level_two_identity_challenge needs a SECOND account, sharing the password
      in MATRIX_INTEROP_PASSWORD, and it must be one that has never published a
      cross-signing identity: it starts by asserting the account has none. The
      other proofs' account is not usable, because level_two_identity leaves it
      holding one and an identity cannot be deleted afterwards.
      Refusing to run rather than skipping that proof, because a proof this
      script quietly declines to run is the failure this milestone keeps
      finding."
  for named in MATRIX_INTEROP_SCANNED_USER MATRIX_INTEROP_SCANNER_USER \
               MATRIX_INTEROP_SHOWN_USER; do
    eval "value=\${$named:-}"
    [ -n "$value" ] || fail "MATRIX_INTEROP_HOMESERVER is set but $named is not.
      level_two_scanned needs three MORE accounts, sharing the password in
      MATRIX_INTEROP_PASSWORD, and none of them may be one of the two above.
      The reasons are in the LOCALPART_SCANNED block near the top of this file
      and in that test's own header; they come down to which account may hold a
      cross-signing identity minted by whom, and to containing a flow that
      cannot be cleared up.
      Required rather than optional, because a proof this script quietly
      declines to run is the failure this repository keeps finding."
  done
  echo "Using the homeserver named by MATRIX_INTEROP_HOMESERVER; starting no container."
else
  command -v docker >/dev/null 2>&1 \
    || fail "docker is not on PATH, and no MATRIX_INTEROP_HOMESERVER was set.
      This script needs one or the other: a container runtime to start a
      throwaway homeserver in, or an existing homeserver to point at."
  docker info >/dev/null 2>&1 \
    || fail "the Docker daemon is not reachable. Start it and try again."
  command -v openssl >/dev/null 2>&1 || fail "openssl is not on PATH."
fi

# Asked here rather than where it is used, which is where it used to be.
# The scanned-code proof builds a Go counterparty about two hundred and sixty
# lines below this point, and a machine without a toolchain used to discover
# that only after pulling an image, starting a homeserver and running four
# other proofs. A prerequisite that announces itself late costs a run; this
# repository has paid that twice. Every other prerequisite is demanded above,
# so this one is too, and the escape hatch is named in the same breath.
if [ -n "${MATRIX_INTEROP_MAUTRIX_PARTY:-}" ]; then
  [ -x "$MATRIX_INTEROP_MAUTRIX_PARTY" ] \
    || fail "MATRIX_INTEROP_MAUTRIX_PARTY does not name an executable file."
else
  command -v go >/dev/null 2>&1 \
    || fail "go is not on PATH, and no MATRIX_INTEROP_MAUTRIX_PARTY was set.
      The scanned-code proof needs a second counterparty, and matrix-nio
      cannot be it: the installed wheel contains no QR vocabulary and no
      cross-signing vocabulary at all. Install a Go toolchain, or point
      MATRIX_INTEROP_MAUTRIX_PARTY at a binary built from
      rust/matrix-crypto-core/tests/interop/mautrix_party with -tags goolm.
      Nothing has been started yet, so there is nothing to clean up."
fi
if true; then
  :

  # The one hole the traps cannot close: a `kill -9` of this script, or a
  # machine losing power, leaves the container running with nothing left to
  # remove it. So each run first removes any container carrying this label
  # that is older than STALE_AFTER_SECONDS, which can only be debris from
  # exactly that. A homeserver holding a loopback port for the rest of a
  # developer's week is a small thing, but it is the sort of small thing that
  # makes people stop running a test.
  #
  # Bounded by age rather than swept wholesale, and the age is what matters:
  # an unbounded sweep would kill the homeserver of a *concurrent* run of this
  # same script. `docker ps` has no `until` filter (checked -- it is a
  # `container prune` filter only), so each container records its own start
  # time in a label and this compares it.
  NOW=$(date +%s)
  while read -r stale_id stale_started; do
    [ -n "$stale_id" ] || continue
    case "$stale_started" in
      '' | *[!0-9]*) continue ;;
    esac
    [ "$(( NOW - stale_started ))" -gt "$STALE_AFTER_SECONDS" ] || continue
    echo "Removing a homeserver left behind by a killed run ($stale_id)."
    docker rm -f "$stale_id" >/dev/null 2>&1 || true
  done <<EOF
$(docker ps -a --filter "label=$CONTAINER_LABEL" \
    --format "{{.ID}} {{.Label \"$STARTED_LABEL\"}}" 2>/dev/null || true)
EOF

  # Generated per run, used once, and destroyed with the container. It is
  # registered with the Actions log masker before it is passed to anything,
  # so it cannot reach a job log.
  PASSWORD=$(openssl rand -hex 24)
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::add-mask::$PASSWORD"
  fi

  case "$HOMESERVER_IMPL" in
    continuwuity | synapse) ;;
    *) fail "HOMESERVER_IMPL must be 'continuwuity' or 'synapse', not '$HOMESERVER_IMPL'.
      The two bring-ups below are different code and assert different things
      about their server; a value that fell through to one of them would be a
      run that proved something other than what was asked for." ;;
  esac

  STARTED_AT=$(date +%s)
  CONTAINER="rnmc-level-two-$$-$STARTED_AT"

  if [ "$HOMESERVER_IMPL" = "synapse" ]; then
    # --- synapse: image, generated configuration, container ----------------
    #
    # Pulled explicitly, with retries, rather than left to `docker run`, the
    # same rule the continuwuity pull follows below: a dependency this job has
    # is named here rather than discovered as an unexplained failure. Docker
    # Hub is the image's own registry -- there is no third-party mirror
    # involved the way there is with continuwuity's forgejo.
    PULLED=""
    for attempt in 1 2 3; do
      if docker image inspect "$SYNAPSE_IMAGE" >/dev/null 2>&1; then
        PULLED=1
        break
      fi
      echo "Pulling the homeserver image (attempt $attempt)..."
      if docker pull --quiet "$SYNAPSE_IMAGE" >/dev/null 2>&1; then
        PULLED=1
        break
      fi
      sleep $(( attempt * 5 ))
    done
    [ -n "$PULLED" ] || fail "could not pull $SYNAPSE_IMAGE after three attempts.
      Docker Hub is the image's own registry. If it is down, this job cannot
      run, and that is a dependency rather than a defect in this library."

    # Synapse cannot be configured purely through environment variables the
    # way continuwuity can: the official image expects a homeserver.yaml, and
    # the documented way to produce one is the image's own `generate` step.
    # What runs below is that generated file with exactly the deliberate
    # changes this script documents -- not a configuration invented here.
    #
    # The generate step writes into /data, which for a throwaway server must
    # be a tmpfs. A stopped container's tmpfs cannot be read back with
    # `docker cp` -- checked: a tmpfs mount never reaches the container's
    # filesystem layers, so cp reports the generated file absent -- so the
    # generation runs inside a short-lived container kept alive on `sleep`
    # while `docker exec` drives the image's own /start.py, and the two files
    # the run needs are copied out with `docker exec cat` before it is
    # removed. Everything the server then writes -- the sqlite database, the
    # media store, the signing key it regenerates because the generated one
    # died with the generation container's tmpfs -- lands in the run
    # container's own fresh tmpfs and dies with it.
    docker run -d \
      --name "$CONTAINER-generate" \
      --entrypoint /bin/sleep \
      --tmpfs /data:rw,size=512m \
      "$SYNAPSE_IMAGE" infinity >/dev/null \
      || fail "the configuration container could not be started."
    if ! docker exec \
        -e SYNAPSE_SERVER_NAME="$SERVER_NAME" \
        -e SYNAPSE_REPORT_STATS=no \
        "$CONTAINER-generate" /start.py generate >/dev/null 2>&1; then
      RUN_FAILED=1
      fail "synapse could not generate its configuration. The container said:
$(docker logs "$CONTAINER-generate" 2>&1 | tail -20 || true)"
    fi
    docker exec "$CONTAINER-generate" cat /data/homeserver.yaml \
        > "$WORKDIR/homeserver.yaml" 2>/dev/null \
      || { RUN_FAILED=1; fail "the generated homeserver.yaml could not be read
      out of the configuration container."; }
    docker exec "$CONTAINER-generate" cat /data/localhost.log.config \
        > "$WORKDIR/localhost.log.config" 2>/dev/null \
      || { RUN_FAILED=1; fail "the generated log configuration could not be read
      out of the configuration container."; }
    docker rm -f "$CONTAINER-generate" >/dev/null 2>&1 || true

    # Two deliberate changes to the image's own template, both appended at
    # the end of the file:
    #
    #   * registration_shared_secret, first removed and then set to a value
    #     generated for this run. The template already carries a random one,
    #     but it is never shown to anything, and parsing YAML back out is more
    #     fragile than writing a value this script chose. The shared-secret
    #     endpoint below is how the five accounts are created with
    #     registration closed, which makes this secret the run's second
    #     credential: it is masked like the password and never appears on a
    #     command line, existing only in this file and inside the one
    #     `openssl dgst` pipeline that computes a MAC with it.
    #   * enable_registration: false, stated even though false is already
    #     synapse's default, because the posture of this run -- registration
    #     is closed and every account came from the endpoint -- is asserted
    #     here rather than assumed from a default.
    #
    # Everything else the proofs rely on is left exactly as `generate` wrote
    # it, and synapse's own strictness vouches for it: unlike continuwuity,
    # synapse REFUSES to start on a configuration key it does not recognise,
    # so a renamed or misspelled setting dies at startup with the key named
    # (see the check the continuwuity path needs below for the contrast). The
    # listener on 8008 has no bind_addresses, which synapse/config/server.py
    # fills with every interface including 0.0.0.0; the database is sqlite at
    # /data/homeserver.db, which the run container's tmpfs covers; and
    # report_stats is false because SYNAPSE_REPORT_STATS=no said so above.
    # Federation is left on, as the image ships it: the published port is
    # loopback-only, so nothing off the machine can reach it either way --
    # the same posture the continuwuity path sets with ALLOW_FEDERATION=false.
    grep -q '^registration_shared_secret:' "$WORKDIR/homeserver.yaml" \
      || fail "the generated homeserver.yaml carries no registration_shared_secret
      line -- the image's template changed, and the account creation below
      would be inventing a secret the server does not hold."
    REGISTRATION_SECRET=$(openssl rand -hex 24)
    if [ -n "${GITHUB_ACTIONS:-}" ]; then
      echo "::add-mask::$REGISTRATION_SECRET"
    fi
    grep -v '^registration_shared_secret:' "$WORKDIR/homeserver.yaml" \
      > "$WORKDIR/homeserver.yaml.new"
    mv "$WORKDIR/homeserver.yaml.new" "$WORKDIR/homeserver.yaml"
    {
      printf 'registration_shared_secret: "%s"\n' "$REGISTRATION_SECRET"
      printf 'enable_registration: false\n'
      # Login rate limiting, effectively off for this throwaway server.
      # Synapse's default rc_login allows a burst of five logins from one
      # address and then one more every six seconds; a single run of these
      # proofs logs in far more often than that -- five readiness probes
      # below, then a login per test and per phase-two child -- and the
      # sixth rapid login is refused with 429, which the harness reads as a
      # credential failure. Brute-force protection means nothing on a
      # loopback-only server whose accounts and password die with the
      # container, and continuwuity imposes no such limit, so the two
      # implementations are held to the same posture here.
      printf 'rc_login:\n'
      printf '  address:\n'
      printf '    per_second: 1000000\n'
      printf '    burst_count: 1000000\n'
      printf '  account:\n'
      printf '    per_second: 1000000\n'
      printf '    burst_count: 1000000\n'
      printf '  failed_attempts:\n'
      printf '    per_second: 1000000\n'
      printf '    burst_count: 1000000\n'
    } >> "$WORKDIR/homeserver.yaml"

    # `-p 127.0.0.1::8008` publishes on loopback only, on a port Docker
    # chooses, so a run cannot collide with anything else on the machine and
    # cannot be reached from off it.
    #
    # `--tmpfs /data` covers everything the server writes. The two read-only
    # binds carry the configuration in over that tmpfs: the file a bind
    # mounts is never written by the server, so nothing about the run's only
    # non-tmpfs state can move underneath it.
    docker run -d \
      --name "$CONTAINER" \
      --label "$CONTAINER_LABEL" \
      --label "$STARTED_LABEL=$STARTED_AT" \
      -p 127.0.0.1::8008 \
      --tmpfs /data:rw,size=512m \
      -v "$WORKDIR/homeserver.yaml:/data/homeserver.yaml:ro" \
      -v "$WORKDIR/localhost.log.config:/data/localhost.log.config:ro" \
      "$SYNAPSE_IMAGE" >/dev/null \
      || fail "the homeserver container could not be started."
  else
    # --- continuwuity: image, pure-env configuration, container ------------
    #
    # Pulled explicitly, with retries, rather than left to `docker run`. The
    # image is published only from continuwuity's own Forgejo instance -- there
    # is no ghcr.io or Docker Hub mirror, checked -- so this job depends on one
    # third-party host being up. That is a real dependency and it is named here
    # rather than discovered as an unexplained failure: three attempts, and a
    # message that says which host did not answer.
    PULLED=""
    for attempt in 1 2 3; do
      if docker image inspect "$CONTINUWUITY_IMAGE" >/dev/null 2>&1; then
        PULLED=1
        break
      fi
      echo "Pulling the homeserver image (attempt $attempt)..."
      if docker pull --quiet "$CONTINUWUITY_IMAGE" >/dev/null 2>&1; then
        PULLED=1
        break
      fi
      sleep $(( attempt * 5 ))
    done
    [ -n "$PULLED" ] || fail "could not pull $CONTINUWUITY_IMAGE after three attempts.
      Continuwuity publishes only to its own registry (forgejo.ellis.link);
      there is no ghcr.io or Docker Hub mirror. If that host is down, this
      job cannot run, and that is a dependency rather than a defect in this
      library."

    # `--entrypoint` because the image declares the binary as CMD with no
    # ENTRYPOINT, so bare arguments would replace it rather than be passed to
    # it.
    #
    # `--execute` runs one admin console command after startup. That is what
    # creates the account, and it is why registration is left disabled: the
    # first account on a fresh continuwuity cannot be registered over the
    # client API without the one-time bootstrap token the server generates and
    # prints, and scraping a credential out of a log to feed it back in is both
    # brittle and the opposite of what this script is for.
    #
    # `-p 127.0.0.1::8008` publishes on loopback only, on a port Docker
    # chooses, so a run cannot collide with anything else on the machine and
    # cannot be reached from off it.
    #
    # `--tmpfs` for the database: nothing this run creates should outlive it,
    # not even on disk.
    docker run -d \
      --name "$CONTAINER" \
      --label "$CONTAINER_LABEL" \
      --label "$STARTED_LABEL=$STARTED_AT" \
      -p 127.0.0.1::8008 \
      --tmpfs /db:rw,size=512m \
      --entrypoint /sbin/conduwuit \
      -e CONDUWUIT_SERVER_NAME="$SERVER_NAME" \
      -e CONDUWUIT_DATABASE_PATH=/db \
      -e CONDUWUIT_ADDRESS=0.0.0.0 \
      -e CONDUWUIT_PORT=8008 \
      -e CONDUWUIT_ALLOW_FEDERATION=false \
      -e CONDUWUIT_ALLOW_REGISTRATION=false \
      -e CONDUWUIT_ALLOW_CHECK_FOR_UPDATES=false \
      "$CONTINUWUITY_IMAGE" \
      --execute "users create-user $LOCALPART $PASSWORD" \
      --execute "users create-user $LOCALPART_CHALLENGE $PASSWORD" \
      --execute "users create-user $LOCALPART_SCANNED $PASSWORD" \
      --execute "users create-user $LOCALPART_SCANNER $PASSWORD" \
      --execute "users create-user $LOCALPART_SHOWN $PASSWORD" >/dev/null \
      || fail "the homeserver container could not be started."
  fi

  HOST_PORT=$(docker port "$CONTAINER" 8008/tcp 2>/dev/null | head -1 | sed 's/.*://')
  [ -n "$HOST_PORT" ] \
    || { RUN_FAILED=1; fail "the container published no host port for 8008."; }

  export MATRIX_INTEROP_HOMESERVER="http://127.0.0.1:$HOST_PORT"
  export MATRIX_INTEROP_USER="@$LOCALPART:$SERVER_NAME"
  export MATRIX_INTEROP_CHALLENGE_USER="@$LOCALPART_CHALLENGE:$SERVER_NAME"
  export MATRIX_INTEROP_SCANNED_USER="@$LOCALPART_SCANNED:$SERVER_NAME"
  export MATRIX_INTEROP_SCANNER_USER="@$LOCALPART_SCANNER:$SERVER_NAME"
  export MATRIX_INTEROP_SHOWN_USER="@$LOCALPART_SHOWN:$SERVER_NAME"
  export MATRIX_INTEROP_PASSWORD="$PASSWORD"

  echo "Homeserver: $MATRIX_INTEROP_HOMESERVER (container $CONTAINER, $HOMESERVER_IMPL)"

  if [ "$HOMESERVER_IMPL" = "synapse" ]; then
    # --- synapse: create the five accounts with registration closed --------
    #
    # Continuwuity creates its accounts in the same `docker run` that starts
    # it (`--execute` above). Synapse has no equivalent, and registration is
    # closed, so the accounts are created over the admin API with the
    # registration_shared_secret this run generated: GET the endpoint for a
    # nonce, then POST the username, password and admin=false with a MAC --
    # HMAC-SHA1, hex digest, over nonce\0user\0pass\0notadmin, the exact
    # construction synapse/rest/admin/users.py checks against (read at
    # v1.159.0; it is the literal strings "admin"/"notadmin", not "yes"/"no").
    # No admin account is needed or created.
    #
    # Refusing to pass having created nothing, the same rule the continuwuity
    # path keeps through wait_for_login below: any error from the endpoint
    # fails the run here, with the server's answer, rather than surfacing
    # several minutes later as five login failures inside the tests. Synapse
    # does not echo the password into its own output the way continuwuity
    # does, so what a failure dumps here is not redacted any further.
    #
    # The endpoint answers only once the server is actually up, so it is
    # waited for the same bounded way the logins are waited for below.
    register_ready=""
    register_deadline=$(( $(date +%s) + HOMESERVER_TIMEOUT_SECONDS ))
    while [ "$(date +%s)" -lt "$register_deadline" ]; do
      if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
        RUN_FAILED=1
        fail "the homeserver container exited before it was ready."
      fi
      if curl -s -m 5 "$MATRIX_INTEROP_HOMESERVER/_synapse/admin/v1/register" \
          | grep -q '"nonce"'; then
        register_ready=1
        break
      fi
      sleep 2
    done
    [ -n "$register_ready" ] || { RUN_FAILED=1; fail "the shared-secret
      registration endpoint never answered within ${HOMESERVER_TIMEOUT_SECONDS}s.
      Either the server did not finish starting, or it started without the
      registration_shared_secret this script wrote into its configuration."; }

    synapse_create_user() {
      local localpart="$1"
      local nonce mac response
      # A fresh nonce per account: synapse deletes a nonce when it is used,
      # so one fetched here cannot be shared across the five calls.
      nonce=$(curl -s -m 5 "$MATRIX_INTEROP_HOMESERVER/_synapse/admin/v1/register" \
        | sed -n 's/.*"nonce":"\([^"]*\)".*/\1/p')
      [ -n "$nonce" ] || { RUN_FAILED=1; fail "the registration endpoint gave no
        nonce for '$localpart', though it answered moments ago."; }
      mac=$(printf '%s\0%s\0%s\0notadmin' "$nonce" "$localpart" "$PASSWORD" \
        | openssl dgst -sha1 -hmac "$REGISTRATION_SECRET" -hex \
        | sed 's/^.* //')
      response=$(curl -s -m 5 -X POST \
        -H 'Content-Type: application/json' \
        --data-binary @- \
        "$MATRIX_INTEROP_HOMESERVER/_synapse/admin/v1/register" <<JSON || true
{"nonce":"$nonce","username":"$localpart","password":"$PASSWORD","admin":false,"mac":"$mac"}
JSON
)
      # Matched on the field name, the same way wait_for_login matches a
      # login: the access token in the response is a live credential and is
      # not what this check is about.
      if ! printf '%s' "$response" | grep -q '"access_token"'; then
        RUN_FAILED=1
        fail "synapse refused to create the account '$localpart' over its
      shared-secret registration endpoint. With registration closed the
      account cannot exist any other way, and a run that would log in as
      nothing proves nothing. The endpoint answered: ${response:-no response}"
      fi
    }

    synapse_create_user "$LOCALPART"
    synapse_create_user "$LOCALPART_CHALLENGE"
    synapse_create_user "$LOCALPART_SCANNED"
    synapse_create_user "$LOCALPART_SCANNER"
    synapse_create_user "$LOCALPART_SHOWN"
    echo "All five accounts the proofs need exist, created over the shared-secret endpoint."
  fi

  # Wait for the API, then for the account. These are two different facts and
  # the second is the one that matters: `--execute` runs asynchronously after
  # startup, so a server answering /versions does not yet mean the account
  # exists. Requiring a real login here means a provisioning failure is
  # reported as itself, rather than surfacing several minutes later as an
  # unexplained test failure.
  # Both accounts, because `--execute` runs them one after another and the
  # second can fail on its own. Checking only the first would leave a missing
  # challenge account to surface several minutes later as a login failure
  # inside a test.
  wait_for_login() {
    local who="$1"
    local deadline=$(( $(date +%s) + HOMESERVER_TIMEOUT_SECONDS ))
    local login token
    while [ "$(date +%s)" -lt "$deadline" ]; do
      if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
        RUN_FAILED=1
        fail "the homeserver container exited before it was ready."
      fi
      login=$(curl -s -m 5 -X POST \
        -H 'Content-Type: application/json' \
        --data-binary @- \
        "$MATRIX_INTEROP_HOMESERVER/_matrix/client/v3/login" <<JSON || true
{"type":"m.login.password",
 "identifier":{"type":"m.id.user","user":"$who"},
 "password":"$MATRIX_INTEROP_PASSWORD",
 "initial_device_display_name":"level-two-readiness-probe"}
JSON
)
      # Matched on the field name rather than on any value: the token is a live
      # credential for as long as the next two lines take, and must not be
      # echoed, compared against a pattern that could print it, or kept.
      if printf '%s' "$login" | grep -q '"access_token"'; then
        # Log the probe device straight out again. The library shares its room
        # key with every device on the account, so a stray device left here
        # would be one more withheld notice in the test's own batches for no
        # reason.
        token=$(printf '%s' "$login" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
        curl -s -m 5 -o /dev/null -X POST \
          -H "Authorization: Bearer $token" \
          -H 'Content-Type: application/json' \
          -d '{}' \
          "$MATRIX_INTEROP_HOMESERVER/_matrix/client/v3/logout" || true
        unset token
        return 0
      fi
      sleep 2
    done
    RUN_FAILED=1
    fail "the homeserver never accepted a login as $who within
      ${HOMESERVER_TIMEOUT_SECONDS}s. Either it did not finish starting, or the
      account this script told it to create was not created."
  }

  wait_for_login "$MATRIX_INTEROP_USER"
  wait_for_login "$MATRIX_INTEROP_CHALLENGE_USER"
  wait_for_login "$MATRIX_INTEROP_SCANNED_USER"
  wait_for_login "$MATRIX_INTEROP_SCANNER_USER"
  wait_for_login "$MATRIX_INTEROP_SHOWN_USER"
  echo "Homeserver ready, and all five accounts it was told to create can log in."

  # Continuwuity does not reject a configuration key it does not recognise. It
  # logs `Config parameter "x" is unknown to conduwuit, ignoring.` and starts
  # anyway -- so a renamed or misspelled setting above would silently do
  # nothing, and this script would go on asserting that federation is off and
  # registration is closed while neither was actually applied. A setting that
  # looks applied and is not is exactly the shape of defect this repository
  # keeps finding, so it is checked rather than assumed.
  #
  # The synapse path has no equivalent check because it needs none: Synapse
  # REFUSES to start on a key it does not recognise, so a renamed or
  # misspelled setting there dies at startup with the key named in the log --
  # this check's whole purpose, achieved by the server itself.
  #
  # Only the key names are reproduced, never the log line and never the log:
  # continuwuity echoes the generated password into its own startup output.
  if [ "$HOMESERVER_IMPL" = "continuwuity" ]; then
    IGNORED=$(docker logs "$CONTAINER" 2>&1 \
      | sed -n 's/.*Config parameter "\([a-z_0-9]*\)" is unknown to conduwuit.*/\1/p' \
      | sort -u | tr '\n' ' ')
    if [ -n "$IGNORED" ]; then
      RUN_FAILED=1
      fail "the homeserver ignored configuration this script relies on: $IGNORED
        Continuwuity warns and carries on rather than refusing to start, so these
        settings did nothing. Either the image moved and the keys were renamed, or
        one is misspelled above. Fix the names rather than the assertion."
    fi
  fi
fi

# --- 2. the counterparty's Python ------------------------------------------

if [ -n "${MATRIX_INTEROP_NIO_PYTHON:-}" ]; then
  echo "Using the interpreter named by MATRIX_INTEROP_NIO_PYTHON."
else
  BASE_PYTHON=${PYTHON:-python3}
  command -v "$BASE_PYTHON" >/dev/null 2>&1 \
    || fail "$BASE_PYTHON is not on PATH. Set PYTHON to a Python 3 interpreter,
      or MATRIX_INTEROP_NIO_PYTHON to one that already has matrix-nio[e2e]."
  [ -f "$REQUIREMENTS" ] || fail "missing $REQUIREMENTS"

  echo "Installing the pinned matrix-nio[e2e] into a throwaway virtualenv..."
  "$BASE_PYTHON" -m venv "$WORKDIR/venv" \
    || fail "could not create a virtualenv with $BASE_PYTHON."
  "$WORKDIR/venv/bin/python" -m pip install --quiet --upgrade pip \
    || fail "could not upgrade pip in the virtualenv."
  # --no-deps with a fully resolved requirements file: pip installs exactly
  # the pinned set and nothing else, so a transitive dependency cannot move
  # underneath this proof between one run and the next.
  "$WORKDIR/venv/bin/python" -m pip install --quiet --no-deps -r "$REQUIREMENTS" \
    || fail "could not install $REQUIREMENTS."
  export MATRIX_INTEROP_NIO_PYTHON="$WORKDIR/venv/bin/python"
fi

# Asserted, not assumed. Without this a missing counterparty surfaces as the
# test failing to start a subprocess, several minutes in.
"$MATRIX_INTEROP_NIO_PYTHON" - <<'PY' || fail "the interpreter at MATRIX_INTEROP_NIO_PYTHON cannot import matrix-nio's e2e stack."
import nio, vodozemac
from nio import AsyncClient, MegolmEvent
from importlib.metadata import version
print(f"matrix-nio {version('matrix-nio')}, vodozemac {version('vodozemac')}")
PY

# --- 2bis. the second counterparty, in Go -----------------------------------
#
# `matrix-nio` serves every proof but one. It cannot serve the scanned-code
# proof, and that was established from its own wheel rather than assumed:
# zero occurrences of the QR vocabulary and zero of the cross-signing
# vocabulary. A code carries cross-signing keys, so an implementation with
# neither cannot scan even in principle.
#
# mautrix-go v0.30.0 can, and `rust/matrix-crypto-core/tests/level_two_scanned.rs`
# names the four files in it that do. It is built here rather than vendored so
# that what the proof runs against is a released module resolved from its own
# checksummed source, and `-tags goolm` selects mautrix's pure-Go Olm rather
# than the C libolm binding: no C toolchain is needed, and the two sides then
# share no cryptographic implementation at all.

if [ -n "${MATRIX_INTEROP_MAUTRIX_PARTY:-}" ]; then
  echo "Using the counterparty binary named by MATRIX_INTEROP_MAUTRIX_PARTY."
  [ -x "$MATRIX_INTEROP_MAUTRIX_PARTY" ] \
    || fail "MATRIX_INTEROP_MAUTRIX_PARTY does not name an executable file."
else
  command -v go >/dev/null 2>&1 \
    || fail "go is not on PATH, and no MATRIX_INTEROP_MAUTRIX_PARTY was set.
      The scanned-code proof needs a second counterparty, and matrix-nio
      cannot be it: the installed wheel contains no QR vocabulary and no
      cross-signing vocabulary at all. Install a Go toolchain, or point
      MATRIX_INTEROP_MAUTRIX_PARTY at a binary built from
      rust/matrix-crypto-core/tests/interop/mautrix_party with -tags goolm."

  echo "Building the mautrix-go counterparty..."
  # Everything Go writes goes inside this run's own working directory, so a
  # run leaves nothing in the caller's module or build cache.
  (
    # `-mod=readonly`, which is the default and is stated anyway: a build
    # that needed to change `go.mod` or `go.sum` must fail here rather than
    # rewrite a committed file, which is the same rule `yarn install
    # --frozen-lockfile` follows elsewhere in this repository.
    cd "$REPO_ROOT/rust/matrix-crypto-core/tests/interop/mautrix_party" \
      && GOFLAGS=-mod=readonly \
         GOMODCACHE="$WORKDIR/go/mod" \
         GOCACHE="$WORKDIR/go/build" \
         go build -tags goolm -o "$WORKDIR/mautrix-party" .
  ) || fail "could not build the mautrix-go counterparty. If this is a network
      failure, the module proxy is a dependency of this job rather than a
      defect in this library."
  # Removed here rather than left to the teardown, and not for tidiness: Go
  # writes its module cache read-only, so `rm -rf` on the working directory
  # fails file by file and leaves both the cache and a screenful of
  # `Permission denied` behind. `go clean` is the supported way to remove it.
  GOMODCACHE="$WORKDIR/go/mod" go clean -modcache 2>/dev/null || true
  export MATRIX_INTEROP_MAUTRIX_PARTY="$WORKDIR/mautrix-party"
fi

# Asserted, not assumed, the same way the Python counterparty is: a
# counterparty that cannot start must fail here rather than several minutes
# later as a subprocess that died.
printf '%s\n' '{"op":"quit"}' | "$MATRIX_INTEROP_MAUTRIX_PARTY" \
  | grep -q '"ok":true' \
  || fail "the binary at MATRIX_INTEROP_MAUTRIX_PARTY does not answer the
      counterparty protocol."

# --- 3. the tests ----------------------------------------------------------
#
# FIVE proofs, one homeserver. `level_two_interop` asks whether a third-party
# client decrypts what this library encrypts; `level_two_verification` asks
# whether one will complete a device verification with it; `level_two_identity`
# asks what a decrypted event says about its sender once this library has a
# signing identity a real homeserver accepted; `level_two_identity_challenge`
# asks whether the user-interactive authentication loop that publishing an
# identity needs can actually be driven, against a refusal this homeserver
# wrote. They are separate test binaries because this library holds one crypto
# machine per process and Cargo gives each file under tests/ its own -- see
# level_two_verification.rs's header.
#
# The first three share one account, and the third publishes a cross-signing
# identity for it. That is why it runs LAST of the three: an account's identity
# can be minted once, and a run of it leaves the account with one. The other
# two neither read nor write it, so the order below costs them nothing, but
# reversing it would leave `level_two_identity` facing an account whose
# identity a previous run had already published -- which is the case its own
# phase-two child constructs deliberately, and would be an accident in its
# parent.
#
# The fourth has an account to itself, for that same reason taken one step
# further: it begins by asserting the account holds no identity, which the
# shared one no longer does by the time it would run. See LOCALPART_CHALLENGE.
#
# The fifth, `level_two_scanned`, asks whether all three modes of verification
# by scanning a code work against an implementation that shares no protocol
# code and no Olm implementation with this one, and whether a code carrying a
# changed key is refused. It has three accounts to itself and a counterparty
# of its own, for reasons its header and the LOCALPART_SCANNED block give.

# --- 4. what actually happened ---------------------------------------------
#
# Everything below reads cargo's output rather than trusting its exit status.
#
# `--exact` means a renamed test matches nothing, and libtest then prints
# `0 passed; 0 failed; ...; 1 filtered out` and exits 0. So does a run where
# the test is still `#[ignore]`d and `--ignored` was dropped. Both are the
# seven-times-repeated failure of this milestone, and both are caught by
# insisting on the count.
#
# The expected count is PINNED per test rather than printed, the same way
# scripts/run-probe-on-emulator.sh pins PROBE_SUMMARY 12/12: if a test stops
# spawning a child, or starts spawning one, this fails until somebody changes
# the number on purpose.
#
# That number was once in a comment and in no check. The comment claimed "what
# matters is that neither of them is a nought, which the two checks above have
# already established for both", and those checks are `-lt 1` on a `grep -c`,
# which establishes it for one. Fed a stream where the parent passed and the
# child matched no test, this script printed "1 libtest summaries" and exited
# 0 -- and the child is the cross-process restore proof, the whole reason the
# second process exists. Reproduced 2026-08-28 by the verification-
# infrastructure review, and again here after the fix.
#
#   run_proof <test target> <test name> <expected libtest runs> <what they are>
run_proof() {
  local target="$1"
  local name="$2"
  local expected="$3"
  local shape="$4"
  local output="$WORKDIR/$target-output.txt"
  local status ok_lines summaries

  echo
  echo "Running $name..."
  set +e
  cargo test --manifest-path "$REPO_ROOT/rust/Cargo.toml" \
    -p matrix-crypto-core --test "$target" \
    -- --ignored --exact "$name" 2>&1 | tee "$output"
  # A plain assignment, on its own line and before any other command: every
  # command run in between -- `local` included -- replaces PIPESTATUS.
  status=${PIPESTATUS[0]}
  set -e

  if [ "$status" != "0" ]; then
    RUN_FAILED=1
    fail "cargo test exited $status running $name. See the output above."
  fi

  ok_lines=$(grep -c "^test $name \.\.\. ok\$" "$output" || true)
  if [ "$ok_lines" -lt 1 ]; then
    RUN_FAILED=1
    fail "cargo test exited 0 but never reported '$name ... ok'.
      That is not a pass. The test was filtered out, renamed, or the process
      died before libtest could report on it."
  fi

  summaries=$(grep -c '^test result: ok\. 1 passed; 0 failed; 0 ignored' "$output" || true)
  if [ "$summaries" -lt 1 ]; then
    RUN_FAILED=1
    fail "cargo test exited 0 but printed no 'test result: ok. 1 passed; 0 failed;
      0 ignored' summary for $name. libtest reported:
$(grep '^test result:' "$output" || echo '      (no test result line at all)')"
  fi

  if [ "$ok_lines" -ne "$expected" ] || [ "$summaries" -ne "$expected" ]; then
    RUN_FAILED=1
    fail "this run reported $ok_lines '$name ... ok' lines and $summaries
      libtest summaries; exactly $expected of each are expected -- $shape.
      Fewer means a libtest process matched no test at all. More means
      something re-ran and the result is ambiguous.
libtest reported:
$(grep '^test result:' "$output" || echo '      (no test result line at all)')"
  fi

  echo "PASS: $name ($summaries libtest summaries, asserted)"
}

# The encryption proof spawns a second copy of itself to show that
# `openCryptoStore` restores a session across processes:
# `std::env::current_exe()` re-invoked with `--exact <this test> --ignored
# --test-threads=1`, inheriting stdout. So the child runs libtest too, and its
# `... ok` line and its own summary land in the same stream. TWO of each.
run_proof level_two_interop \
  level_two_interoperability_over_a_real_homeserver \
  2 \
  "the parent process and the phase-two child it spawns of itself to reopen the store"

# The verification proof spawns nothing: it needs no second process, because
# what it proves happens between two live devices rather than across a
# restart. ONE of each.
run_proof level_two_verification \
  a_third_party_clients_verification_reaches_the_short_authentication_string \
  1 \
  "this test spawns no child, so there is exactly one libtest process"

# The identity proof spawns a second copy of itself for the same structural
# reason the encryption proof does: what it checks is a fact about a machine
# that holds NO private signing identity, and this process's machine holds one
# by the time it gets there. TWO of each.
run_proof level_two_identity \
  a_signing_identity_published_to_a_real_homeserver_and_what_a_sender_then_reads \
  2 \
  "the parent process and the phase-two child it spawns of itself as a fresh login"

# The authentication proof, on its own account and with no counterparty: the
# signing-keys upload refused by a challenge this homeserver wrote, the
# challenge answered, and the identity then published. It spawns nothing.
# ONE of each.
#
# It runs after `level_two_identity` for readability rather than necessity --
# they are the two halves of the same publication story and this is the second
# half -- and it could run anywhere, because it touches an account of its own.
run_proof level_two_identity_challenge \
  a_signing_keys_upload_refused_by_a_real_challenge_answered_and_published \
  1 \
  "this test spawns no child, so there is exactly one libtest process"

# The scanned-code proof spawns nothing either. ONE of each.
#
# It runs last of the five because it is the only one with a second
# counterparty and three accounts of its own, so a failure in it is
# unambiguous about which half of the run it came from. Nothing about the
# order is load-bearing: it shares no account with any other proof, which is
# what the three extra accounts buy.
run_proof level_two_scanned \
  a_third_party_client_and_this_library_verify_each_other_by_scanning_a_code \
  1 \
  "this test spawns no child, so there is exactly one libtest process"

echo
echo "PASS: all five level 2 proofs."
echo "      A third-party matrix-nio client decrypted what this library encrypted,"
echo "      and this library decrypted what matrix-nio sent."
echo "      A verification matrix-nio opened was announced by this library, agreed"
echo "      to, and carried to a short authentication string. It goes no further,"
echo "      and the reason is the commitment encoding matrix-nio 0.26.0 uses; the"
echo "      second test attributes that from inside nio rather than assuming it."
echo "      See rust/matrix-crypto-core/tests/level_two_verification.rs."
echo "      A signing identity this library minted was accepted by the homeserver and"
echo "      served back with this device's key signed by it, and a fresh login then"
echo "      refused to mint over it. An event from matrix-nio still reads"
echo "      unsigned_device, because matrix-nio 0.26.0 implements no cross-signing at"
echo "      all; the third test establishes that from inside nio and carries a signed"
echo "      sender in the same run as its control."
echo "      See rust/matrix-crypto-core/tests/level_two_identity.rs."
echo "      A signing-keys upload was refused by a user-interactive authentication"
echo "      challenge this homeserver wrote, the challenge was read out of the refusal,"
echo "      the same body was sent again with an auth object merged in, and the"
echo "      identity that ended up published is the one the pump handed over. That is"
echo "      the one path this library hands to a product whole, and it now has a run"
echo "      behind it rather than only documentation."
echo "      See rust/matrix-crypto-core/tests/level_two_identity_challenge.rs."
echo "      All three modes of verification by scanning a code completed against a"
echo "      mautrix-go counterparty, which shares no protocol code and no Olm"
echo "      implementation with this library, and a code carrying one changed byte of"
echo "      a master key was refused by it with m.key_mismatch. A flow this library"
echo "      SHOWS is accepted by that counterparty and does not then finish, because"
echo "      it sends m.key.verification.done before the showing side has confirmed;"
echo "      the fifth test measures that off the wire rather than asserting it."
echo "      See rust/matrix-crypto-core/tests/level_two_scanned.rs."
if [ -n "$CONTAINER" ]; then
  echo "      Proven against a throwaway $SERVER_NAME homeserver this script started"
  echo "      and is about to destroy. No credential was read from anywhere."
fi
