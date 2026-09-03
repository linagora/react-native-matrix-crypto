//! Level 2 for M4: this account's signing identity published to a real
//! homeserver, and what a decrypted event then says about its sender.
//!
//! # The question, and why the two host tests cannot answer it
//!
//! `tests/verified_sender.rs` drives the whole seven-step chain to
//! `Verified`, and `tests/cross_signed_peer.rs` decrypts an event from a
//! cross-signed peer and gets `UnverifiedIdentity`. Both are two machines in
//! one process, and every `/keys/*` response either of them reads is a body
//! the test itself wrote. So a consistent misreading of what a homeserver
//! actually stores and serves back -- ours, or upstream's -- passes both and
//! looks like success, and until this file nothing outside this repository's
//! own tests had exercised any part of M4.
//!
//! This file asks the level 2 question that catches that: **does an identity
//! this library mints survive a real homeserver, and what does a decrypted
//! event report about its sender when the sender is a real third-party
//! client over that homeserver.** It is the standard M2 set for encryption
//! (`level_two_interop.rs`) and M3 for verification
//! (`level_two_verification.rs`), applied to M4.
//!
//! # THE ANSWER, AND THE CEILING IT RUNS INTO
//!
//! A decrypted event from `matrix-nio` reports
//! [`SenderVerification::UnsignedDevice`], before and after this library
//! publishes an identity of its own, and **that is the best value reachable
//! against this counterparty.**
//!
//! `UnverifiedIdentity` is not reachable, and the reason is entirely in the
//! counterparty. Upstream's first gate is
//! `Device::is_cross_signed_by_owner`, which asks whether the **sending**
//! device carries a signature from a self-signing key its own owner
//! published. Nothing this library holds enters into it. So the value
//! depends on the counterparty having cross-signing, and **matrix-nio
//! 0.26.0 does not implement cross-signing at all**: it never publishes a
//! master key, it has no endpoint for one, and it discards the cross-signing
//! halves of every `/keys/query` answer it receives.
//!
//! That is asserted rather than claimed, from inside nio's own process, by
//! `nio_party.py`'s `identity_probe` -- the same job `sas_commitment_probe`
//! does for the verification proof. Four facts, all computed at run time
//! from the pinned install rather than read off a version number:
//!
//! * the homeserver really did return `master_keys` for this account to
//!   nio's own `/keys/query`, so the keys are on the wire in front of it;
//! * nio's own `KeysQueryResponse` retains `device_keys` and `failures` and
//!   nothing else, read off the dataclass;
//! * no file in the installed package mentions
//!   `/keys/device_signing/upload`, so nothing in it can publish an
//!   identity;
//! * the whole package mentions `master_key`, `self_signing`,
//!   `user_signing` or `cross_signing` **zero times**, across forty-two
//!   source files.
//!
//! So the request in the milestone -- "a cross-signed peer may be
//! constructible; if it is, an event from it should read
//! `unverified_identity`, and signing that identity should move it" -- rests
//! on a premise that is false for this counterparty. There is no
//! cross-signed peer to construct out of nio, and therefore no identity to
//! sign. Substituting a counterparty this repository builds itself would
//! answer a different question, which is the one `cross_signed_peer.rs`
//! already answers.
//!
//! **The second half is blocked twice over.** Even with a cross-signed peer,
//! moving it to `Verified` needs our user-signing key over their master key,
//! and the only thing that produces that is a completed comparison. nio
//! 0.26.0 cannot complete one: it writes the SAS commitment as hexadecimal
//! where the specification requires unpadded base64, which
//! `level_two_verification.rs` attributes from inside nio and which is filed
//! upstream as an unmerged pull request. So `Verified` for a *third party*
//! is out of reach here for a reason that predates this milestone.
//!
//! # WHAT IS REACHABLE, AND IS PROVEN HERE
//!
//! 1. **The gate refuses, on a real machine**, before any key query has been
//!    answered: [`MachineError::AccountKeysNotFetched`], with the query that
//!    lifts it queued by the refusal itself.
//! 2. **A refused request is reported as refused, against a refusal a
//!    homeserver wrote.** The account key query is posted with the token of
//!    a device that has been logged out; the homeserver answers `401` with a
//!    real `M_UNKNOWN_TOKEN` body. `mark_request_sent` refuses that body,
//!    `mark_request_failed` accepts it, and **the gate is still shut
//!    afterwards** -- which is the whole point of the pair, and the case
//!    `signing.rs` says destroys an account's identity when a product gets
//!    it wrong.
//! 3. **The identity is minted, published and accepted by a homeserver
//!    neither side controls**, and served back on `/keys/query` with this
//!    device's own key carrying the new self-signing key's signature. The
//!    same query, run before the bootstrap, carried none of it.
//! 4. **An event from a real third-party client over that homeserver reads
//!    `UnsignedDevice`,** and still reads it after all of the above.
//! 5. **An event from this library's own device, in the same run, reads
//!    something else.** That is the control, and it is the same shape
//!    `cross_signed_peer.rs` uses: two senders, identical in every respect
//!    except which of them carries a signature from its owner. Without it
//!    (4) would pass just as well against a build that answered
//!    `UnsignedDevice` for everything, which is one value away from the
//!    defect this whole value exists to prevent.
//! 6. **A fresh login on an account that already has an identity refuses to
//!    mint over it**, in a genuinely separate process:
//!    [`MachineError::IdentityAlreadyExists`]. That is the ordinary shape of
//!    a second device, it is the case `signing.rs`'s gate exists for, and it
//!    can only be built where the identity is really on a server.
//!
//! # WHAT THIS RUN DOES NOT EXERCISE, AND WHY IT IS NOT AN OMISSION
//!
//! [`bootstrap_identity`]'s documentation says to expect the signing-keys
//! upload to be refused with a user-interactive authentication challenge and
//! to send the same body again with an `auth` object merged in.
//! **Continuwuity does not challenge.** Measured, not assumed:
//! `POST /_matrix/client/v3/keys/device_signing/upload` on the pinned image
//! answers `200 {}` on the first attempt, with no `flows` anywhere. The
//! challenge is a homeserver's policy rather than something the endpoint
//! guarantees, so the loop is not driven here and this file does not pretend
//! it is. Step 9 below asserts the 2xx it actually gets and says, in the
//! failure message, what to do if a homeserver ever answers otherwise.
//!
//! The refusal-reporting pair is exercised regardless, at step 6, on the
//! account key query -- which is the request where reporting a refusal as a
//! success is actually dangerous.
//!
//! # WHAT THIS WAS WATCHED FAILING AGAINST
//!
//! Every claim above was checked by breaking the thing it rests on and
//! observing the failure, because a green run of a test nobody has seen fail
//! is a green run of nothing. Six mutations, each reverted:
//!
//! * `sender_verification` answering `Verified` for every event: caught at
//!   step 12, `left: Some(Verified)`, `right: Some(UnsignedDevice)`.
//! * `sender_verification` answering `UnsignedDevice` for every event:
//!   caught at step 13, which is the collapsed-mapping defect the control
//!   exists for.
//! * `may_mint` serving every bootstrap: caught at step 6.
//! * `mark_request_failed` setting the answered flag, which is the shape of
//!   a product that reports a refusal through `mark_request_sent`: caught at
//!   step 7 by the gate-is-still-shut assertion, not by anything earlier.
//! * `identity_probe` reporting a non-zero cross-signing vocabulary: caught
//!   at step 11. Reporting zero because it swept no files at all: caught by
//!   the separate assertion that it read the package, which is the "an
//!   absence is not a finding" guard.
//! * The `signature_upload` never sent: caught at step 10 by the
//!   homeserver's own view. With step 10 also neutered, the control at step
//!   13 drops to `UnsignedDevice` -- so the value it reports is produced by
//!   the real chain over the real homeserver and not by anything this test
//!   arranged.
//!
//! One mutation was **not** caught, and it is recorded at its own site
//! rather than here: removing the explicit re-query loop in step 13 changes
//! nothing, because step 12's sync loop answers an account key query anyway.
//!
//! # The floor, which is the same one the other two proofs have
//!
//! matrix-nio 0.26 moved its ratchet to `vodozemac`, the crate
//! `matrix-sdk-crypto` uses, and both sides are pinned at 0.10.0. A defect
//! below the protocol line passes both. What two independent
//! implementations genuinely check here is everything above it: the
//! `/keys/*` payloads, what a homeserver stores of them, and the event
//! shapes. The cross-signing decision this file is about is entirely above
//! that line -- it is signatures over canonical JSON, made and checked in
//! Rust here and, at nio, not made at all.
//!
//! # Running it
//!
//! `./scripts/run-level-two-interop.sh`, which starts a throwaway
//! homeserver, installs the pinned counterparty and runs this test and its
//! two siblings. See `level_two_interop.rs`'s header for the environment
//! variables the manual path takes.
//!
//! `#[ignore]`, so an ordinary `cargo test` needs no network, no container
//! and no credential.

use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use matrix_crypto_core::{
    bootstrap_identity, create_identity, create_machine, decrypt_event, encrypt_event,
    identity_status, mark_request_failed, mark_request_sent, receive_sync_changes, share_scope_key,
    take_outgoing_requests, MachineConfig, MachineError, OutgoingRequest, SenderTrustRequirement,
    SenderVerification, SessionError,
};
use serde_json::{json, Value};

// The homeserver, the login, the pump and the counterparty subprocess, none
// of which is what this file proves. See its own header for why it is a
// module rather than a third copy.
#[path = "interop/harness.rs"]
mod harness;
use harness::{
    encode_segment, encryption_slice, endpoint, login, pump_and_send, required_env, run,
    Homeserver, NioParty, Teardown, HOMESERVER_ENV, PASSWORD_ENV, PYTHON_ENV, USER_ENV,
};

/// Not a credential: the store this test creates lives in a temporary
/// directory it also deletes, and the passphrase only has to be the same in
/// both phases.
const STORE_PASSPHRASE: &str = "level-two-identity";

/// The counterparty's payload. Distinct from every other level 2 payload so
/// no assertion here can be satisfied by the wrong event.
const NIO_PAYLOAD_BODY: &str = "sent by matrix-nio, which has no signing identity";
/// This library's own, sent after the bootstrap. See step 11.
const OWN_PAYLOAD_BODY: &str = "sent by this device, after it published an identity";

/// Set only on the phase-two child this test spawns of itself.
const PHASE_TWO_ENV: &str = "MATRIX_INTEROP_IDENTITY_PHASE_TWO";
const PHASE_TWO_STORE: &str = "MATRIX_INTEROP_IDENTITY_PHASE_TWO_STORE";
const PHASE_TWO_USER: &str = "MATRIX_INTEROP_IDENTITY_PHASE_TWO_USER";
const PHASE_TWO_DEVICE: &str = "MATRIX_INTEROP_IDENTITY_PHASE_TWO_DEVICE";
const PHASE_TWO_TOKEN: &str = "MATRIX_INTEROP_IDENTITY_PHASE_TWO_TOKEN";
const PHASE_TWO_MARKER: &str = "MATRIX_INTEROP_IDENTITY_PHASE_TWO_MARKER";

/// How long any "advance both sides until X" loop below gets. Generous
/// rather than tight: each ends in an assertion naming what did not happen,
/// so a slow homeserver costs time and a broken one still fails readably.
const PATIENCE: Duration = Duration::from_secs(120);

fn transaction_id(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_nanos();
    format!("rnmc-identity-{label}-{nanos}")
}

/// Every `keys_query` in a batch whose body names this account.
///
/// Read off the request's own body rather than off its `kind`: `keys_query`
/// is one wire tag for every key query, and the only thing that makes one
/// of them the *account* key query the bootstrap gate waits on is which
/// users it asks about.
fn account_key_queries<'a>(
    batch: &'a [OutgoingRequest],
    user_id: &str,
) -> Vec<&'a OutgoingRequest> {
    batch
        .iter()
        .filter(|request| request.kind == "keys_query")
        .filter(|request| {
            serde_json::from_str::<Value>(&request.body)
                .ok()
                .and_then(|body| Some(body.get("device_keys")?.get(user_id).is_some()))
                .unwrap_or(false)
        })
        .collect()
}

/// Drains the pump once, posts and reports everything **except** key
/// queries, and returns the whole batch so the caller can see what was in
/// it.
///
/// Key queries are withheld on purpose, and the purpose is the gate. The
/// first fact [`bootstrap_identity`] needs is "a `/keys/query` naming this
/// account has been sent *and answered* in this process", and the only way
/// to observe that gate shut is to arrive at it with none answered. A
/// product is free to send its requests in any order and to have one of
/// them fail, which is exactly the state this reproduces; withholding here
/// is a choice about sequencing, not a change to what the library is asked.
fn pump_and_send_holding_key_queries(homeserver: &Homeserver, token: &str) -> Vec<OutgoingRequest> {
    let batch = run(take_outgoing_requests()).expect("the pump must be drainable");
    for request in &batch {
        if request.kind == "keys_query" {
            continue;
        }
        let response = harness::send_outgoing(homeserver, token, request);
        run(mark_request_sent(&request.id, &response)).unwrap_or_else(|error| {
            panic!(
                "the homeserver's own response to a {} request was rejected by \
                 mark_request_sent: {error:?}",
                request.kind
            )
        });
    }
    batch
}

/// One `/keys/query` for this account, asked of the homeserver directly.
///
/// Not through the library: this is the homeserver's own view, used as the
/// before-and-after control on whether the publication actually landed
/// somewhere neither side controls.
fn homeserver_view(homeserver: &Homeserver, token: &str, user_id: &str) -> Value {
    homeserver.ok(
        "POST",
        "/_matrix/client/v3/keys/query",
        Some(token),
        Some(&json!({ "device_keys": { user_id: [] } }).to_string()),
    )
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// M4's claim, over a real homeserver and against a real third-party client.
///
/// One `#[test]` fn, not several: the machine registry and the pump's
/// bookkeeping are process-wide, and an integration test cannot reach the
/// `#[cfg(test)]` reset helpers. Cargo gives this file its own process.
///
/// It is also its own phase-two child, for the same reason
/// `level_two_interop.rs` is: the refusal at step 12 is a fact about a
/// *fresh* machine that holds no private identity, and this process's
/// machine holds one by then.
#[test]
#[ignore = "needs a real homeserver, a credential in the environment, and matrix-nio; \
            run ./scripts/run-level-two-interop.sh"]
fn a_signing_identity_published_to_a_real_homeserver_and_what_a_sender_then_reads() {
    if std::env::var(PHASE_TWO_ENV).is_ok() {
        return phase_two_a_fresh_login_refuses_to_mint();
    }

    let homeserver = Homeserver::new(required_env(HOMESERVER_ENV));
    let user = required_env(USER_ENV);
    let password = required_env(PASSWORD_ENV);
    let python = std::env::var(PYTHON_ENV).unwrap_or_else(|_| "python3".to_string());
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("interop")
        .join("nio_party.py");
    assert!(
        script.is_file(),
        "the nio counterparty script is missing from {}",
        script.display()
    );

    let dir = tempfile::tempdir().expect("temp dir");
    let library_store = dir.path().join("library-store");
    let nio_store = dir.path().join("nio-store");
    std::fs::create_dir_all(&nio_store).expect("the nio store directory must be creatable");

    // ---- 1. The library's device --------------------------------------
    let library = login(&homeserver, &user, &password, "level-two-identity-library");
    // Declared before anything else exists on the homeserver, and before
    // `nio` below, so an unwind kills the subprocess first and this then
    // removes what the run created. Every resource is registered with it
    // the moment its identifier is in hand.
    let mut teardown = Teardown::new(&homeserver, &library, &password);

    // ---- 2. An encrypted room both devices are in ----------------------
    // One account, so membership is already shared: there is nobody to
    // invite and nothing to join.
    let room = homeserver.ok(
        "POST",
        "/_matrix/client/v3/createRoom",
        Some(&library.token),
        Some(
            &json!({
                "preset": "private_chat",
                "name": "react-native-matrix-crypto level 2 identity",
                "initial_state": [{
                    "type": "m.room.encryption",
                    "state_key": "",
                    "content": { "algorithm": "m.megolm.v1.aes-sha2" }
                }],
            })
            .to_string(),
        ),
    );
    let scope = room["room_id"]
        .as_str()
        .expect("createRoom returns a room id")
        .to_string();
    let scope_path = encode_segment(&scope);
    teardown.owns_room(&scope);

    // ---- 3. The homeserver's view, before anything is published --------
    // The control for step 10. Taken now, when the account provably has no
    // identity, so that the assertion there is about a change rather than
    // about a state that might always have held.
    let before = homeserver_view(&homeserver, &library.token, &library.user_id);
    assert!(
        before["master_keys"].get(&library.user_id).is_none(),
        "this account must start with no published identity, or step 10 asserts \
         nothing: the homeserver already reports {}",
        before["master_keys"]
    );

    // ---- 4. The counterparty's device ----------------------------------
    let mut nio = NioParty::start(&python, &script, &nio_store);
    let nio_login = nio.call(json!({ "op": "login" }));
    let nio_user_id = nio_login["user_id"]
        .as_str()
        .expect("the counterparty reports its user id")
        .to_string();
    let nio_device_id = nio_login["device_id"]
        .as_str()
        .expect("the counterparty reports its device id")
        .to_string();
    // Ownership the moment the id exists, before the assertions below,
    // either of which would otherwise abandon a device already created on
    // somebody else's homeserver.
    teardown.owns_device(&nio_device_id);
    assert_eq!(
        nio_user_id, library.user_id,
        "both devices must belong to the same account, which is what makes this a \
         one-credential test"
    );
    assert_ne!(
        nio_device_id, library.device_id,
        "the counterparty must be a second device, not the same one"
    );

    // ---- 5. The library's machine, and its keys on the wire -------------
    run(create_machine(MachineConfig {
        user_id: library.user_id.clone(),
        device_id: library.device_id.clone(),
        store_path: library_store.to_string_lossy().into_owned(),
        store_passphrase: Some(STORE_PASSPHRASE.to_string()),
    }))
    .expect("the library's machine must be creatable");

    let mut published_device_keys = false;
    let mut published_one_time_keys = false;
    for _ in 0..6 {
        let batch = pump_and_send_holding_key_queries(&homeserver, &library.token);
        if batch.is_empty() {
            break;
        }
        for request in &batch {
            if request.kind == "keys_upload" {
                let body: Value = serde_json::from_str(&request.body)
                    .expect("the pump's own body is well-formed JSON");
                published_device_keys |= body.get("device_keys").is_some();
                published_one_time_keys |= body
                    .get("one_time_keys")
                    .and_then(Value::as_object)
                    .is_some_and(|keys| !keys.is_empty());
            }
        }
    }
    assert!(
        published_device_keys,
        "a fresh machine must publish its device identity keys before anything below \
         can mean anything"
    );
    assert!(
        published_one_time_keys,
        "and its one-time keys, or the counterparty cannot claim one, cannot build an \
         Olm session to this device, and can never deliver it a room key -- which \
         would make step 12 fail for a reason that has nothing to do with signing \
         identities"
    );

    // ---- 6. THE GATE, SHUT ----------------------------------------------
    // Asserted on the state first and then on the refusal, so that a
    // refusal arriving for some other reason cannot be read as this one.
    let status = run(identity_status()).expect("the machine is live");
    assert!(
        !status.account_keys_fetched,
        "no key query naming this account has been answered yet -- this test held \
         them back for exactly this assertion -- so the gate below is being observed \
         in the state it exists for. It reported {status:?}"
    );
    assert!(
        !status.identity_known && !status.private_keys_held,
        "a machine on a fresh store knows no identity and holds no private keys: {status:?}"
    );
    assert_eq!(
        run(bootstrap_identity())
            .expect_err("nothing may be minted before the server has been asked"),
        MachineError::AccountKeysNotFetched,
        "the first refusal is the recoverable one, and it must be this one rather than \
         the destructive-mint refusal"
    );

    // ---- 7. A REFUSED REQUEST, REPORTED AS REFUSED ----------------------
    // The refusal is a real one from a real homeserver, not a body this
    // test wrote: a second device is logged in and immediately logged out,
    // and the account key query is posted with its dead token.
    //
    // This is the request where getting the pair wrong is destructive.
    // `signing.rs`: a refused key query reported through `mark_request_sent`
    // reads as "the server answered and this account has no identity", which
    // is the one fact that authorises minting a new identity over whatever
    // the account already had.
    let expired = login(&homeserver, &user, &password, "level-two-identity-expired");
    homeserver.ok(
        "POST",
        "/_matrix/client/v3/logout",
        Some(&expired.token),
        Some("{}"),
    );

    // Drained once, here, and the id used is the one this drain handed out.
    //
    // Not one carried over from step 5, and the reason is a real property of
    // the pump rather than tidiness. An unanswered key query is re-offered
    // on every drain, under a *fresh* id each time, and the drain that
    // offers it evicts the previous entry -- `PendingKind::eviction_group`
    // says so, and `SessionError::UnknownRequest` names the eviction case.
    // A first draft of this file held an id from step 5 across the drains
    // below and got `UnknownRequest` here, which is the library behaving
    // exactly as documented and the test asking the wrong question.
    //
    // So: one drain, and nothing between it and the two reports below may
    // drain again. `bootstrap_identity` queueing another query does not,
    // because queueing is not draining.
    let batch = run(take_outgoing_requests()).expect("the pump must be drainable");
    let account_query = account_key_queries(&batch, &library.user_id)
        .last()
        .copied()
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "the refused bootstrap must queue a key query naming this account, or \
                 its refusal is a dead end rather than a step. The batch held {:?}",
                batch
                    .iter()
                    .map(|request| &request.kind)
                    .collect::<Vec<_>>()
            )
        });
    for request in &batch {
        if request.kind == "keys_query" {
            continue;
        }
        let response = harness::send_outgoing(&homeserver, &library.token, request);
        run(mark_request_sent(&request.id, &response))
            .expect("a real homeserver response must be acceptable");
    }

    let (method, path, body) = endpoint(&account_query);
    let (status_code, refusal_body) =
        homeserver.call(method, &path, Some(&expired.token), Some(&body));
    assert_eq!(
        status_code, 401,
        "a request carrying a logged-out device's token must be refused; the \
         homeserver answered {status_code}"
    );
    let refusal_json: Value =
        serde_json::from_str(&refusal_body).expect("a Matrix error response is a JSON object");
    assert!(
        refusal_json.get("errcode").is_some(),
        "the refusal must be a standard Matrix error, or the library's own refusal of \
         it below would be passing for the wrong reason: {refusal_body}"
    );

    // The library refuses to be told a refusal is an answer.
    assert_eq!(
        run(mark_request_sent(&account_query.id, &refusal_body))
            .expect_err("a homeserver error body is not a key query answer"),
        SessionError::MalformedPayload,
        "reporting this body as a success is the mistake that mints a second identity \
         over an account's existing one. It carries an errcode, which is what the \
         library can see: {refusal_body}"
    );
    // And it refuses the swap in the other direction, which it can see in
    // its own argument rather than in a body.
    assert_eq!(
        run(mark_request_failed(&account_query.id, 200))
            .expect_err("a 2xx is not a status a refused request can carry"),
        SessionError::NotAFailureStatus,
        "a caller passing a success status here has confused the pair, and a refusal \
         changes no state, so being told nothing would let the confusion stand"
    );
    // What a product must call instead.
    run(mark_request_failed(&account_query.id, status_code))
        .expect("a refused request must be reportable as refused");

    // THE CONSEQUENCE, which is the reason the pair exists.
    let status = run(identity_status()).expect("the machine is live");
    assert!(
        !status.account_keys_fetched,
        "a refused key query must teach the library nothing: {status:?}"
    );
    assert_eq!(
        run(bootstrap_identity())
            .expect_err("a refused key query leaves the gate exactly as shut as it was"),
        MachineError::AccountKeysNotFetched,
        "this is the assertion the whole of step 7 is for. If a refusal opened the \
         gate, a product whose key query was rate-limited would mint a new identity \
         over its account's existing one and invalidate every verification anyone had \
         made of it"
    );

    // ---- 8. The same request, sent again, and answered ------------------
    // `mark_request_sent` looks its entry up without removing it and
    // `mark_request_failed` changes nothing, so the retry is an ordinary
    // second send of the same id and the same body. Asserted here rather
    // than taken on trust from the documentation.
    let (status_code, answer) = homeserver.call(method, &path, Some(&library.token), Some(&body));
    assert_eq!(
        status_code, 200,
        "the same request with a live token must be accepted: {answer}"
    );
    run(mark_request_sent(&account_query.id, &answer)).expect(
        "the id must have survived the refusal, or a product could not retry a request \
         that failed for a transport reason",
    );
    let status = run(identity_status()).expect("the machine is live");
    assert!(
        status.account_keys_fetched,
        "an answered key query is what lifts the first refusal: {status:?}"
    );
    assert!(
        !status.identity_known,
        "the server has just said this account has no identity, which is the one fact \
         that authorises minting one: {status:?}"
    );

    // ---- 9. The identity, minted and published --------------------------
    run(create_identity()).expect("an account the server says has no identity may mint one");

    let batch = run(take_outgoing_requests()).expect("the pump must be drainable");
    let kinds: Vec<&str> = batch.iter().map(|request| request.kind.as_str()).collect();
    let position = |wanted: &str| kinds.iter().position(|kind| *kind == wanted);
    let signing_keys = position("signing_keys_upload")
        .unwrap_or_else(|| panic!("the bootstrap must queue the signing keys: {kinds:?}"));
    let signature = position("signature_upload")
        .unwrap_or_else(|| panic!("the bootstrap must queue the device signature: {kinds:?}"));
    assert!(
        signing_keys < signature,
        "signing keys, then the signature over this device. The order is the whole \
         reason the pump stamps a sequence: the signature references a key that is not \
         published until the request before it lands, and a homeserver is entitled to \
         reject one that does. It handed out {kinds:?}"
    );
    // No `keys_upload` in this batch, and its absence is the documented case
    // rather than a surprise. `bootstrap_identity` records what a bootstrap
    // on a *fresh* machine hands out, where this device's keys are still
    // unpublished; step 5 published them here, so upstream's
    // `upload_device_keys()` owes nothing and offers nothing. Asserted
    // positively, because the invariant that matters is the one above and a
    // silent disappearance of a request is what this repository keeps
    // finding: if a `keys_upload` IS present it has to sort first, for the
    // same reason the signature sorts last.
    if let Some(keys_upload) = position("keys_upload") {
        assert!(
            keys_upload < signing_keys,
            "a device-keys upload the bootstrap queues must sort ahead of the signing \
             keys: {kinds:?}"
        );
    }

    // A sync cursor, taken before either upload below lands. It exists for
    // Synapse, and for the same reason `level_two_interop.rs` step 1 holds
    // one: Synapse reports a device-list change only on an incremental sync,
    // and only to a cursor that predates it. Either upload below changes
    // this account's device list, and step 13 needs that change to be
    // reportable so the machine re-queries the account and learns its own
    // device is signed. Continuwuity reports the change on an initial sync
    // and never reads this. The payload is not fed to the machine: it
    // changes nothing the steps below do not establish on their own terms.
    let before_upload = homeserver.ok(
        "GET",
        "/_matrix/client/v3/sync?timeout=0",
        Some(&library.token),
        None,
    );
    let cursor_before_upload = before_upload["next_batch"]
        .as_str()
        .expect("a /sync response carries a next_batch")
        .to_string();

    for request in &batch {
        if request.kind == "signing_keys_upload" {
            // The one request this file sends by hand, because it is the one
            // whose refusal is documented and does not happen here. See this
            // file's header.
            let (method, path, body) = endpoint(request);
            let (status_code, response) =
                homeserver.call(method, &path, Some(&library.token), Some(&body));
            assert!(
                (200..300).contains(&status_code),
                "this homeserver answered {status_code} to the signing-keys upload.\n\
                 \n\
                 READ THIS BEFORE TREATING IT AS A DEFECT. That endpoint is \
                 user-interactive, and `bootstrap_identity`'s own documentation says \
                 to expect a 401 with a challenge, merge an `auth` object into this \
                 same body, and send it again. Continuwuity, which this proof runs \
                 against, does not challenge -- it answers 200 on the first attempt \
                 -- so that loop is deliberately not written here and this assertion \
                 is what says so out loud. A homeserver that does challenge lands \
                 exactly on this line. The fix is to write the loop, not to relax the \
                 assertion: the challenge body must go to mark_request_failed and only \
                 the eventual success to mark_request_sent. The response was: \
                 {response}"
            );
            run(mark_request_sent(&request.id, &response))
                .expect("the success response of a signing-keys upload is an empty object");
        } else {
            let response = harness::send_outgoing(&homeserver, &library.token, request);
            run(mark_request_sent(&request.id, &response)).unwrap_or_else(|error| {
                panic!(
                    "the homeserver's own response to a {} request was rejected by \
                     mark_request_sent: {error:?}",
                    request.kind
                )
            });
        }
    }

    let status = run(identity_status()).expect("the machine is live");
    assert!(
        status.identity_known && status.private_keys_held,
        "after a served bootstrap this machine holds the account's identity and can \
         sign with it: {status:?}"
    );

    // ---- 10. THE HOMESERVER'S OWN VIEW, AFTER -----------------------------
    let after = homeserver_view(&homeserver, &library.token, &library.user_id);
    let master = after["master_keys"]
        .get(&library.user_id)
        .unwrap_or_else(|| {
            panic!("the homeserver must serve this account's master key back: {after}")
        });
    let self_signing = after["self_signing_keys"]
        .get(&library.user_id)
        .unwrap_or_else(|| panic!("and its self-signing key: {after}"));
    assert!(
        after["user_signing_keys"].get(&library.user_id).is_some(),
        "and its user-signing key, which a homeserver serves only to the account \
         itself: {after}"
    );
    assert!(
        master["keys"]
            .as_object()
            .is_some_and(|keys| !keys.is_empty()),
        "a published master key carries a key: {master}"
    );

    // The signature is what makes the identity mean anything, so it is read
    // rather than assumed: the self-signing key's own key id must appear
    // among this device's signatures, in what the homeserver hands back.
    let self_signing_id = self_signing["keys"]
        .as_object()
        .and_then(|keys| keys.keys().next().cloned())
        .unwrap_or_else(|| panic!("a published self-signing key carries a key: {self_signing}"));
    let device_signatures = after["device_keys"][&library.user_id][&library.device_id]
        ["signatures"][&library.user_id]
        .as_object()
        .cloned()
        .unwrap_or_else(|| panic!("this device must still be published: {after}"));
    assert!(
        device_signatures.contains_key(&self_signing_id),
        "the homeserver must have accepted the signature this bootstrap uploaded and \
         serve it back on the device it signs. Without that, no client anywhere -- \
         including this one on its next launch -- can tell that this account vouches \
         for this device. It serves {:?}",
        device_signatures.keys().collect::<Vec<_>>()
    );

    // ---- 11. WHAT THE COUNTERPARTY MAKES OF ALL THAT ----------------------
    // Attribution from inside nio's own process. See this file's header for
    // why this is the fact the whole ceiling rests on.
    let probe = nio.call(json!({ "op": "identity_probe", "user_id": library.user_id }));
    assert_eq!(
        probe["raw_carries_master_key"],
        json!(true),
        "the homeserver must serve this account's master key to the counterparty too, \
         or the finding below is about a key that never reached it: {probe}"
    );
    let parsed_fields: Vec<String> = probe["parsed_fields"]
        .as_array()
        .expect("the probe reports what the counterparty's own response type retains")
        .iter()
        .filter_map(|field| field.as_str().map(str::to_owned))
        .collect();
    assert!(
        parsed_fields.contains(&"device_keys".to_string()),
        "the probe must have read a real response type: {probe}"
    );
    for dropped in ["master_keys", "self_signing_keys", "user_signing_keys"] {
        assert!(
            !parsed_fields.contains(&dropped.to_string()),
            "matrix-nio's own key query response is expected to retain none of the \
             cross-signing halves, and it kept {dropped}. If that has changed, this \
             counterparty may finally be constructible as a cross-signed peer, and \
             this file's whole framing needs rewriting: {probe}"
        );
    }
    assert_eq!(
        probe["publishes_from"],
        json!([]),
        "no file in the installed counterparty may reference the cross-signing upload \
         endpoint. One does, so it can publish an identity after all: {probe}"
    );
    assert!(
        probe["source_files_read"].as_u64().unwrap_or(0) > 10,
        "the probe must have actually read the package; a probe that found no files \
         would report zero mentions and look like a finding: {probe}"
    );
    assert_eq!(
        probe["vocabulary_mentions"],
        json!(0),
        "**this is the ceiling.** matrix-nio 0.26.0 does not mention master_key, \
         self_signing, user_signing or cross_signing anywhere in its source, so it \
         cannot be a cross-signed peer and no event from it can read anything above \
         UnsignedDevice. If this is no longer zero, the counterparty has grown \
         cross-signing and this proof should be extended to unverified_identity: \
         {probe}"
    );

    // ---- 12. THE ANSWER: an event from the third party --------------------
    // The counterparty is settled first, and it has to be: it logged in
    // before this library published anything, and it only learns of a device
    // through a sync that reports the account's device list as changed. A
    // `room_send` from a client that has not seen this device cannot claim a
    // one-time key from it, so the room key never leaves nio and the
    // decryption below would fail for a reason that has nothing to do with
    // signing identities. `level_two_interop.rs` gets this for free because
    // the library shares a key to nio long before nio sends; this file
    // cannot, because its own outbound session must not exist until step 13.
    // The cursor is opened BEFORE the counterparty sends, and the order is
    // not incidental: a `/sync` with no `since` returns everything that has
    // happened and advances the cursor past it, so an initial sync taken
    // after the send consumes both the room key and the event and leaves the
    // loop below waiting for things it has already been handed. A first
    // draft did exactly that and timed out reporting zero of each.
    let initial = homeserver.ok(
        "GET",
        "/_matrix/client/v3/sync?timeout=0",
        Some(&library.token),
        None,
    );
    run(receive_sync_changes(
        &encryption_slice(&initial).to_string(),
    ))
    .expect("a real /sync payload must be accepted");
    pump_and_send(&homeserver, &library.token);
    let mut since = initial["next_batch"]
        .as_str()
        .expect("a /sync response carries a next_batch")
        .to_string();

    nio.call(json!({ "op": "settle", "rounds": 6 }));
    let sent = nio.call(json!({
        "op": "send",
        "room_id": scope,
        "body": NIO_PAYLOAD_BODY,
    }));
    let nio_event_id = sent["event_id"]
        .as_str()
        .expect("the counterparty reports the id it sent")
        .to_string();

    let mut nio_raw_event: Option<Value> = None;
    let mut new_sessions = 0u32;
    let mut to_device_events = 0u32;
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline && (nio_raw_event.is_none() || new_sessions == 0) {
        let sync = homeserver.ok(
            "GET",
            &format!(
                "/_matrix/client/v3/sync?timeout=8000&since={}",
                encode_segment(&since)
            ),
            Some(&library.token),
            None,
        );
        since = sync["next_batch"]
            .as_str()
            .expect("a /sync response carries a next_batch")
            .to_string();
        let outcome = run(receive_sync_changes(&encryption_slice(&sync).to_string()))
            .expect("a real /sync payload must be accepted");
        new_sessions += outcome.new_session_count;
        to_device_events += outcome.to_device_event_count;
        pump_and_send(&homeserver, &library.token);

        if let Some(events) = sync["rooms"]["join"][&scope]["timeline"]["events"].as_array() {
            for event in events {
                if event["event_id"].as_str() == Some(nio_event_id.as_str()) {
                    nio_raw_event = Some(event.clone());
                }
            }
        }
    }
    assert!(
        new_sessions > 0,
        "receiveSyncChanges must have recovered the counterparty's room key, or the \
         decryption below would fail for a reason that has nothing to do with signing \
         identities. It processed {to_device_events} to-device events and recovered \
         {new_sessions} sessions, and the counterparty's own event {}",
        if nio_raw_event.is_some() {
            "did arrive in the timeline"
        } else {
            "never arrived in the timeline either"
        }
    );
    let nio_raw_event =
        nio_raw_event.expect("the counterparty's own encrypted event must arrive in /sync");

    let from_nio = run(decrypt_event(
        &scope,
        &nio_raw_event.to_string(),
        SenderTrustRequirement::Any,
    ))
    .expect("the library must decrypt what matrix-nio encrypted");
    let plaintext: Value = serde_json::from_slice(&from_nio.ciphertext)
        .expect("a decrypted content is well-formed JSON");
    assert_eq!(
        plaintext["body"],
        json!(NIO_PAYLOAD_BODY),
        "the library must recover the counterparty's payload exactly, or the value \
         below describes some other event"
    );
    assert_eq!(
        from_nio.sender_verification,
        Some(SenderVerification::UnsignedDevice),
        "**this is the answer.** An event from a real third-party client over a real \
         homeserver says the sending device is one this machine has heard of and \
         nothing more, and it says so even though this machine has, by now, minted an \
         identity, published it, and had a homeserver accept it. That is not a defect \
         and it is the point: upstream's first gate reads the SENDER's signature over \
         the SENDER's device, and nothing this library holds enters into it. Step 11 \
         establishes, from inside the counterparty, that there is no such signature to \
         read"
    );

    // ---- 13. THE CONTROL: an event from a device that is signed -----------
    // Two senders, identical in every respect except which of them carries a
    // signature from the identity its owner published. Same shape as
    // `cross_signed_peer.rs`'s Bob and Carol, with the difference that both
    // devices here are real logins on a real homeserver and the signature is
    // one that homeserver accepted and served back.
    //
    // This device's own signature has to be in this machine's own store
    // before it can be read, and nothing caches an outgoing one -- the store
    // learns it from a key query, which is the same silent step
    // `verified_sender.rs` calls step seven. So the account is queried again
    // first, and that query is asserted rather than assumed.
    //
    // WHAT REMOVING THIS LOOP DOES, MEASURED. Nothing: the run still passes.
    // Step 12's sync loop pumps as well, and the signing-keys upload changes
    // this account's device list, so a key query naming it is handed out and
    // answered there whether or not this loop exists. That is a fact about
    // the loop above rather than about the requirement, and it is written
    // down because the alternative is a reader assuming this block is what
    // produces the value below. What does produce it was measured too:
    // skipping the `signature_upload` at step 9 drops the assertion at the
    // end of this section from `Verified` to `UnsignedDevice`, which is the
    // same value the counterparty gets. The chain is load-bearing; this loop
    // makes its ordering explicit and independent of what step 12 happens to
    // do.
    //
    // The initial-sync-first shape of the loop is Continuwuity's. On Synapse
    // an initial sync never carries `device_lists` at all, and step 12's
    // cursor postdates the uploads, so after one fruitless pass the loop
    // goes back to the cursor step 9 took before either upload landed --
    // the only window from which Synapse reports the change -- and then
    // chains incrementals off each payload's `next_batch`. Without that
    // fallback this loop spins on Synapse's response cache until patience
    // runs out, having learned nothing: measured, 2026-09-01.
    let mut queried_after_signing = false;
    let mut probe_since: Option<String> = None;
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline && !queried_after_signing {
        let query = match &probe_since {
            Some(cursor) => format!(
                "/_matrix/client/v3/sync?timeout=0&since={}",
                encode_segment(cursor)
            ),
            None => "/_matrix/client/v3/sync?timeout=0".to_string(),
        };
        let sync = homeserver.ok("GET", &query, Some(&library.token), None);
        run(receive_sync_changes(&encryption_slice(&sync).to_string()))
            .expect("a real /sync payload must be accepted");
        let batch = pump_and_send(&homeserver, &library.token);
        queried_after_signing = !account_key_queries(&batch, &library.user_id).is_empty();
        if !queried_after_signing {
            probe_since = Some(if probe_since.is_none() {
                cursor_before_upload.clone()
            } else {
                sync["next_batch"]
                    .as_str()
                    .expect("a /sync response carries a next_batch")
                    .to_string()
            });
        }
    }
    assert!(
        queried_after_signing,
        "this machine must fetch its own account's keys again after uploading the \
         signature, or its own store never learns that its own device is signed. \
         Omitting this step is silent: every call returns Ok and the value below sits \
         one rung lower with nothing reporting a problem"
    );

    // The outbound session is created here, after all of the above, and
    // that ordering is load-bearing: upstream fixes an inbound session's
    // sender data when the session is created and never revisits it
    // upwards, which `verified_sender.rs`'s third test asserts directly.
    run(share_scope_key(
        &scope,
        std::slice::from_ref(&library.user_id),
    ))
    .expect("sharing a scope key must not fail");
    pump_and_send(&homeserver, &library.token);

    let envelope = run(encrypt_event(
        &scope,
        "m.room.message",
        &json!({ "msgtype": "m.text", "body": OWN_PAYLOAD_BODY }).to_string(),
    ))
    .expect("encryption must succeed once a session exists");
    let content: Value = serde_json::from_slice(&envelope.ciphertext)
        .expect("an encrypted content is well-formed JSON");
    let posted = homeserver.ok(
        "PUT",
        &format!(
            "/_matrix/client/v3/rooms/{scope_path}/send/m.room.encrypted/{}",
            encode_segment(&transaction_id("own"))
        ),
        Some(&library.token),
        Some(&content.to_string()),
    );
    let own_event_id = posted["event_id"]
        .as_str()
        .expect("a sent event has an id")
        .to_string();

    // Read back off `/sync` rather than reassembled here, so the event this
    // library decrypts is the one the homeserver actually stored.
    let mut own_raw_event: Option<Value> = None;
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline && own_raw_event.is_none() {
        let sync = homeserver.ok(
            "GET",
            &format!(
                "/_matrix/client/v3/sync?timeout=8000&since={}",
                encode_segment(&since)
            ),
            Some(&library.token),
            None,
        );
        since = sync["next_batch"]
            .as_str()
            .expect("a /sync response carries a next_batch")
            .to_string();
        run(receive_sync_changes(&encryption_slice(&sync).to_string()))
            .expect("a real /sync payload must be accepted");
        pump_and_send(&homeserver, &library.token);
        if let Some(events) = sync["rooms"]["join"][&scope]["timeline"]["events"].as_array() {
            for event in events {
                if event["event_id"].as_str() == Some(own_event_id.as_str()) {
                    own_raw_event = Some(event.clone());
                }
            }
        }
    }
    let own_raw_event = own_raw_event.expect("this device's own event must arrive in /sync");

    let from_own = run(decrypt_event(
        &scope,
        &own_raw_event.to_string(),
        SenderTrustRequirement::Any,
    ))
    .expect("the library must decrypt an event it encrypted itself");
    let plaintext: Value = serde_json::from_slice(&from_own.ciphertext)
        .expect("a decrypted content is well-formed JSON");
    assert_eq!(
        plaintext["body"],
        json!(OWN_PAYLOAD_BODY),
        "the control must be the event it says it is"
    );
    assert_eq!(
        from_own.sender_verification,
        Some(SenderVerification::Verified),
        "**this is the control, and it is what makes the answer above mean anything.** \
         The two events crossed the same homeserver, in the same room, under the same \
         group-session machinery, and this one comes from a device whose owner signed \
         it with an identity that homeserver accepted. If this ever reads \
         UnsignedDevice too, then this run says nothing about the counterparty at all: \
         it says only that this build answers UnsignedDevice for everything"
    );
    assert_ne!(
        from_own.sender_verification, from_nio.sender_verification,
        "and the two must differ, which is the assertion a build with a collapsed \
         mapping fails"
    );

    // ---- 14. A fresh login, in a genuinely separate process ---------------
    a_second_device_refuses_to_mint_over_this(
        &homeserver,
        &user,
        &password,
        dir.path(),
        &mut teardown,
    );

    // ---- Tidy up ---------------------------------------------------------
    nio.call(json!({ "op": "quit" }));
    teardown.counterparty_logged_itself_out();
}

/// Logs in a third device, then re-runs this test binary as a child holding
/// its credential and a store of its own, and requires that child to have
/// been refused a bootstrap.
///
/// A separate process because that is what the claim is about: a machine
/// that holds no private identity. This process holds one by now, and
/// `create_machine` no-ops against an already-registered config, so nothing
/// here could construct the case.
///
/// The child writes what it observed to a marker file and this process
/// asserts on the contents. An exit status alone would not do: a child that
/// matched no test also exits zero, and "passed without examining its
/// target" is the failure this milestone keeps finding.
fn a_second_device_refuses_to_mint_over_this(
    homeserver: &Homeserver,
    user: &str,
    password: &str,
    working_dir: &std::path::Path,
    teardown: &mut Teardown<'_>,
) {
    let second = login(homeserver, user, password, "level-two-identity-second");
    teardown.owns_device(&second.device_id);

    let marker = working_dir.join("identity-phase-two-marker");
    let store = working_dir.join("second-device-store");
    let status = Command::new(std::env::current_exe().expect("the test binary knows its own path"))
        .args([
            "--exact",
            "a_signing_identity_published_to_a_real_homeserver_and_what_a_sender_then_reads",
            "--ignored",
            "--test-threads=1",
        ])
        .env(PHASE_TWO_ENV, "1")
        .env(PHASE_TWO_STORE, &store)
        .env(PHASE_TWO_USER, &second.user_id)
        .env(PHASE_TWO_DEVICE, &second.device_id)
        // The token, not the password: the child needs to talk to the
        // homeserver and needs no credential to do it with, and removing
        // the password below is also what stops it recursing into the
        // parent path.
        .env(PHASE_TWO_TOKEN, &second.token)
        .env(PHASE_TWO_MARKER, &marker)
        .env_remove(PASSWORD_ENV)
        .status()
        .expect("the phase-two child must be startable");

    assert!(
        status.success(),
        "the phase-two child failed: a fresh device did not refuse to mint over the \
         identity this process published"
    );
    let observed = std::fs::read_to_string(&marker).unwrap_or_else(|error| {
        panic!(
            "the phase-two child exited successfully but wrote no marker at {}, so it \
             never ran its check at all ({error})",
            marker.display()
        )
    });
    let observed: Value = serde_json::from_str(&observed).expect("the marker holds JSON");
    assert_eq!(
        observed["first_refusal"],
        json!("AccountKeysNotFetched"),
        "a fresh process has asked the server nothing, whatever the process before it \
         did, so its first refusal must be the recoverable one: {observed}"
    );
    assert_eq!(
        observed["identity_known"],
        json!(true),
        "and its key query must have found the identity this process published, or the \
         refusal below would be about an account with none: {observed}"
    );
    assert_eq!(
        observed["private_keys_held"],
        json!(false),
        "and it must not hold the private half, which is what makes this the \
         destructive case rather than a republication: {observed}"
    );
    assert_eq!(
        observed["refusal"],
        json!("IdentityAlreadyExists"),
        "**a fresh login on an account that already has an identity must refuse to \
         mint over it.** This is the ordinary shape of a second device, and a library \
         that minted here would replace the account's identity and reset the trust of \
         every device and every user who had verified it: {observed}"
    );
}

/// The child half of the above. A machine on an empty store, for an account
/// whose identity is already published, driven through the same recovery
/// loop a product would write.
fn phase_two_a_fresh_login_refuses_to_mint() {
    let homeserver = Homeserver::new(required_env(HOMESERVER_ENV));
    let token = required_env(PHASE_TWO_TOKEN);
    let user_id = required_env(PHASE_TWO_USER);
    let device_id = required_env(PHASE_TWO_DEVICE);
    let marker = required_env(PHASE_TWO_MARKER);

    run(create_machine(MachineConfig {
        user_id: user_id.clone(),
        device_id,
        store_path: required_env(PHASE_TWO_STORE),
        store_passphrase: Some(STORE_PASSPHRASE.to_string()),
    }))
    .expect("a machine on an empty store must be creatable");

    for _ in 0..6 {
        if pump_and_send_holding_key_queries(&homeserver, &token).is_empty() {
            break;
        }
    }

    // The recovery loop `bootstrap_identity` documents: refused once with
    // the key query it needs already queued, then drained, sent, reported,
    // and called again.
    let first_refusal =
        run(bootstrap_identity()).expect_err("a fresh process has asked this server nothing yet");
    let batch = pump_and_send(&homeserver, &token);
    assert!(
        !account_key_queries(&batch, &user_id).is_empty(),
        "the refusal must queue the key query that lifts it, or the refusal is a dead \
         end rather than a step"
    );

    let status = run(identity_status()).expect("the machine is live");
    let refusal = run(bootstrap_identity())
        .expect_err("this device does not hold the identity this account already has");

    std::fs::write(
        &marker,
        json!({
            "first_refusal": format!("{first_refusal:?}"),
            "account_keys_fetched": status.account_keys_fetched,
            "identity_known": status.identity_known,
            "private_keys_held": status.private_keys_held,
            "refusal": format!("{refusal:?}"),
        })
        .to_string(),
    )
    .expect("the marker must be writable");
}
