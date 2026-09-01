//! Level 2 interoperability: a real homeserver and a third-party client
//! (design doc section 8).
//!
//! # The question this file answers, and why `two_parties.rs` cannot
//!
//! Level 1 has two `OlmMachine`s decrypting each other in one process. Both
//! are `matrix-sdk-crypto`, so a consistent misreading of the Matrix E2EE
//! protocol -- ours or upstream's -- passes it cleanly and looks like
//! success. This file asks the only question that catches that: **does a
//! real Matrix client decrypt what this library encrypts, and can this
//! library decrypt what it sends**, over a homeserver neither side controls.
//!
//! The counterparty is `matrix-nio`, driven as a subprocess
//! (`tests/interop/nio_party.py`, whose header records what its independence
//! is and is not worth).
//!
//! # What runs where
//!
//! The library performs no networking, so this test owns login, room
//! creation, `/sync`, every `/keys/*` call, `/sendToDevice` and the room
//! `/send` -- and hands the library only cryptography. That is the same
//! division of labour a product has, which is the point: every request below
//! is one this library handed out through `take_outgoing_requests` and this
//! test merely addressed and posted.
//!
//! `ureq` is a `[dev-dependencies]` entry for that reason and no other; see
//! the comment on it in `Cargo.toml`.
//!
//! # One account, two devices
//!
//! Matrix end-to-end encryption is device-to-device. One account logged in
//! twice gives two devices and exercises the identical cryptographic path,
//! so this needs one credential, not two. `EncryptionSettings::default()`'s
//! `CollectStrategy::AllDevices` (spec section 7.2) shares with every
//! unblacklisted device and requires no verification, which is what M2 has;
//! nio is held to the same standard through `ignore_unverified_devices`.
//!
//! # Running it
//!
//! ```text
//! MATRIX_INTEROP_HOMESERVER=https://<host> \
//! MATRIX_INTEROP_USER=@<localpart>:<host> \
//! MATRIX_INTEROP_PASSWORD=<from the operator's own store, never a file here> \
//! MATRIX_INTEROP_NIO_PYTHON=/path/to/python-with-matrix-nio \
//! cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core \
//!   --test level_two_interop -- --ignored --nocapture
//! ```
//!
//! `#[ignore]`, so an ordinary `cargo test` needs no network and no
//! credential. No credential value is read from, or written to, any file in
//! this repository: all four arrive in the environment, and the password is
//! passed to the nio subprocess by environment inheritance rather than on a
//! command line, where `ps` would show it.

use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use matrix_crypto_core::{
    create_machine, decrypt_event, encrypt_event, open_store, receive_sync_changes,
    share_scope_key, take_outgoing_requests, MachineConfig, OutgoingRequest, SessionError,
};
use serde_json::{json, Value};

// The homeserver, the login, the pump and the counterparty subprocess, none
// of which is what this file proves. See its own header for why it is a
// module rather than a second copy in `level_two_verification.rs`.
#[path = "interop/harness.rs"]
mod harness;
use harness::{
    addresses, declared_event_type, encode_segment, encryption_slice, login, pump_and_send,
    required_env, run, Homeserver, LoggedIn, NioParty, Teardown, HOMESERVER_ENV, PASSWORD_ENV,
    PYTHON_ENV, USER_ENV,
};

/// Not a credential: the store this test creates lives in a temporary
/// directory it also deletes, and the passphrase only has to be the same in
/// both phases. Written here rather than generated so phase two, which runs
/// in its own process, needs one fewer environment variable.
const STORE_PASSPHRASE: &str = "level-two-interop";

/// Distinct per direction, deliberately: one payload for both directions
/// could pass while only ever proving one machine's self-round-trip.
const LIBRARY_PAYLOAD_BODY: &str = "encrypted by react-native-matrix-crypto";
const NIO_PAYLOAD_BODY: &str = "encrypted by matrix-nio";
/// The corrupted-ciphertext control's own payload. Distinct from
/// `LIBRARY_PAYLOAD_BODY` so the control is a fresh megolm message index --
/// see the comment at its send site for why that is the point.
const CONTROL_PAYLOAD_BODY: &str = "the control that must never decrypt";

/// How `matrix-nio` words a refusal that came from the ratchet rather than
/// from bookkeeping around it.
///
/// `olm_machine.py`'s `decrypt_megolm_event` raises three different
/// `EncryptionError`s, and only this one means "the ciphertext did not
/// authenticate":
///
/// * `"Error decrypting megolm event: {vodozemac error}"` -- `session.decrypt`
///   threw. **This one**, and the colon is what distinguishes it.
/// * `"Error decrypting megolm event, no session found with session id ..."` --
///   the key never arrived. A comma, and a different fact entirely.
/// * `"Duplicate message index, possible replay attack from ..."` -- raised
///   *after* a successful decrypt, and the false pass the control was
///   rewritten to escape.
///
/// Matching on a counterparty's message text is brittle by nature. It is
/// worth it here because the alternative -- asserting only that the control
/// did not decrypt -- cannot tell the three apart, and telling them apart is
/// the entire value of the control. A reworded upstream breaks this loudly,
/// which is the correct failure.
const NIO_RATCHET_REFUSAL: &str = "Error decrypting megolm event: ";

/// Set only on the phase-two child this test spawns of itself. See
/// `reopen_the_store_in_a_second_process`.
const PHASE_TWO_ENV: &str = "MATRIX_INTEROP_PHASE_TWO";
const PHASE_TWO_STORE: &str = "MATRIX_INTEROP_PHASE_TWO_STORE";
const PHASE_TWO_USER: &str = "MATRIX_INTEROP_PHASE_TWO_USER";
const PHASE_TWO_DEVICE: &str = "MATRIX_INTEROP_PHASE_TWO_DEVICE";
const PHASE_TWO_SCOPE: &str = "MATRIX_INTEROP_PHASE_TWO_SCOPE";
const PHASE_TWO_EVENT: &str = "MATRIX_INTEROP_PHASE_TWO_EVENT";
const PHASE_TWO_MARKER: &str = "MATRIX_INTEROP_PHASE_TWO_MARKER";

fn transaction_id(label: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_nanos();
    format!("rnmc-{label}-{nanos}")
}

/// Flips one character of a base64 ciphertext.
///
/// The control this whole test needs: an event that differs from a valid one
/// by a single character must not decrypt anywhere. Without it, a green run
/// says nothing about whether the cryptography was ever checked.
fn corrupt_one_character(text: &str) -> String {
    let mut characters: Vec<char> = text.chars().collect();
    assert!(
        characters.len() > 8,
        "a megolm ciphertext is never this short; refusing to 'corrupt' it"
    );
    let index = characters.len() / 2;
    characters[index] = if characters[index] == 'A' { 'B' } else { 'A' };
    let corrupted: String = characters.into_iter().collect();
    assert_ne!(corrupted, text, "the corruption must change the ciphertext");
    corrupted
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// The milestone's last exit criterion, in one test: an event this library
/// encrypted, decrypted by `matrix-nio` over a real homeserver, and an event
/// `matrix-nio` encrypted, decrypted by this library -- with a one-character
/// corruption of each, in both directions, observed failing.
///
/// One `#[test]` fn, not several: the machine registry and the pump's
/// bookkeeping are process-wide, and an integration test cannot reach the
/// `#[cfg(test)]` reset helpers. Cargo gives this file its own process.
///
/// It is also its own phase-two child. `open_store` can only be shown to
/// restore a session across processes by there being a second process, and
/// `create_machine`/`open_store` both no-op against an already-registered
/// identical config, so re-opening in *this* process would prove nothing.
/// The child is this same binary, re-invoked with `PHASE_TWO_ENV` set, which
/// keeps it from being a second `#[test]` that silently no-ops when run
/// without its environment -- the exact shape of check this milestone has
/// already been bitten by.
#[test]
#[ignore = "needs a real homeserver, a credential in the environment, and matrix-nio; \
            see this file's header for the invocation"]
fn level_two_interoperability_over_a_real_homeserver() {
    if std::env::var(PHASE_TWO_ENV).is_ok() {
        return phase_two_reopen_the_store();
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
    let library = login(&homeserver, &user, &password, "level-two-interop-library");

    // A sync cursor, taken before anything else exists on this account. It
    // exists for Synapse, and the reason is a gap in what Synapse reports:
    // it populates `device_lists` only on incremental syncs, and only with
    // changes that postdate the sync cursor -- a change that happened before
    // a device's first /sync is never reported to that device at all.
    // Step 5 needs "the server eventually tells us this account's device
    // list changed" to be a real event on Synapse too, and every device-list
    // change this run will ever make -- the counterparty's device appearing,
    // this machine's keys reaching the wire -- happens after this point and
    // before step 5's own first sync, which is one cursor too late to ever
    // see them. Holding a cursor from here makes them reportable; step 5's
    // loop reaches back to it after a fruitless initial sync. Continuwuity
    // reports the change on the initial sync regardless and never reads it.
    // The payload itself is not fed to the machine: there is nothing in it
    // for step 5 to assert a consequence of.
    let before_anything = homeserver.ok(
        "GET",
        "/_matrix/client/v3/sync?timeout=0",
        Some(&library.token),
        None,
    );
    let cursor_before_anything = before_anything["next_batch"]
        .as_str()
        .expect("a /sync response carries a next_batch")
        .to_string();

    // Declared here, before anything else exists on the homeserver, and
    // *before* `nio` below, so that on an unwind `nio`'s own `Drop` kills the
    // subprocess first and this one then removes what the run created. Every
    // resource is registered with it the moment its identifier is in hand, and
    // before anything that could fail in between. A review found this claim
    // overstated once: the counterparty's device was registered six lines and
    // two assertions after it existed, so a failing assertion would have
    // abandoned it. That is fixed. The residue that cannot be closed by
    // reordering is narrow and worth naming: a homeserver replying 2xx with a
    // body we cannot parse leaves a resource created but unidentified, and one
    // cannot own an id one was never given.
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
                "name": "react-native-matrix-crypto level 2",
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

    // ---- 3. The counterparty's device ----------------------------------
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
    // Ownership is taken the moment the id exists, before anything that can
    // fail. The assertions below are exactly such a thing: either one firing
    // would abandon a device that had already been created on someone else's
    // homeserver, with no teardown recourse, because the guard would never
    // have been told about it. Six lines is a small window and a real one.
    teardown.owns_device(&nio_device_id);

    assert_eq!(
        nio_user_id, library.user_id,
        "both devices must belong to the same account: Matrix encryption is \
         device-to-device, and one account logged in twice is what makes this a \
         one-credential test"
    );
    assert_ne!(
        nio_device_id, library.device_id,
        "the counterparty must be a second device, not the same one"
    );

    // ---- 4. The library's machine, and its keys on the wire -------------
    run(create_machine(MachineConfig {
        user_id: library.user_id.clone(),
        device_id: library.device_id.clone(),
        store_path: library_store.to_string_lossy().into_owned(),
        store_passphrase: Some(STORE_PASSPHRASE.to_string()),
    }))
    .expect("the library's machine must be creatable");

    // Design doc section 3bis. Skip this and the device is invisible to
    // every other client: nobody can claim a one-time key from it, so nobody
    // can ever be sent a room key by it.
    let mut published_device_keys = false;
    let mut published_one_time_keys = false;
    for _ in 0..6 {
        let batch = pump_and_send(&homeserver, &library.token);
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
        "a fresh machine must publish its device identity keys"
    );
    assert!(
        published_one_time_keys,
        "a fresh machine must publish one-time keys, or no other device can ever \
         claim one and no room key can reach it"
    );
    assert!(
        run(take_outgoing_requests())
            .expect("the pump must be drainable")
            .is_empty(),
        "the pump must go quiet once every request it handed out has been answered; \
         the assertion below distinguishes 'the machine learned something from a sync' \
         from 'the machine was going to ask anyway', and it can only do that from a \
         quiet start"
    );

    // ---- 5. receiveSyncChanges, against a payload a homeserver made -----
    // Nothing outside a host test has ever driven this function, and its own
    // documentation warns that a wrongly-cased payload parses fine and
    // teaches the machine nothing. So this asserts on a consequence, never
    // on the call resolving.
    //
    // Synapse and Continuwuity report a new device's `device_lists.changed`
    // differently: Continuwuity puts it in the account's initial /sync
    // payload, Synapse only in a later incremental one -- and Synapse only
    // reports changes that postdate the sync cursor, which is why step 1
    // took one before anything existed. What this step needs is "the server
    // eventually tells us this account's device list changed" -- that is
    // what makes the `receiveSyncChanges` assertion a test of the library
    // rather than of a query the machine was going to make anyway, and it
    // does not care which payload carried the news. So this syncs in a
    // bounded loop -- the initial sync, then incrementals -- until the
    // account appears, and fails after a fixed number of attempts. The
    // first incremental after a fruitless initial sync goes back to
    // `cursor_before_anything` rather than chaining off the initial sync's
    // `next_batch`: on Synapse the initial sync's cursor already postdates
    // every change this run will make, and a cursor from before any of them
    // is the only place the news can surface. The window that incremental
    // covers contains no to-device traffic -- nothing sends any before step
    // 6 -- so the only fact in its payload is the one this step asserts.
    // After that the chain advances off each payload's own `next_batch`,
    // the same cursor machinery direction 2 below uses. `sync` is the
    // payload the loop ended on: the one that carried the news, and the
    // freshest `next_batch` either way.
    let mut since: Option<String> = None;
    let mut sync;
    let mut syncs = 0;
    let account_reported = loop {
        let query = match &since {
            Some(cursor) => format!(
                "/_matrix/client/v3/sync?timeout=0&since={}",
                encode_segment(cursor)
            ),
            None => "/_matrix/client/v3/sync?timeout=0".to_string(),
        };
        sync = homeserver.ok("GET", &query, Some(&library.token), None);
        syncs += 1;
        let changed: Vec<&str> = sync["device_lists"]["changed"]
            .as_array()
            .map(|users| users.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        if changed.contains(&library.user_id.as_str()) {
            break true;
        }
        if syncs >= 10 {
            break false;
        }
        since = Some(if since.is_none() {
            cursor_before_anything.clone()
        } else {
            sync["next_batch"]
                .as_str()
                .expect("a /sync response carries a next_batch")
                .to_string()
        });
    };
    assert!(
        account_reported,
        "the homeserver's own /sync must eventually report this account's device \
         list as changed -- Continuwuity on the initial sync, Synapse on an \
         incremental one -- before this step can tell whether the machine \
         learned from the payload; it still had not after {syncs} syncs"
    );

    // Nothing is asserted about the returned counts here, deliberately: a
    // freshly created device has no to-device backlog, so both are zero
    // whether or not the call did anything, which is precisely the useless
    // assertion this step exists to avoid. The counts are asserted in
    // direction 2 below, where the homeserver has actually delivered
    // something for them to describe. What is asserted here is a consequence
    // the machine could not have produced on its own.
    run(receive_sync_changes(&encryption_slice(&sync).to_string()))
        .expect("a real /sync payload must be accepted");

    let after_sync = pump_and_send(&homeserver, &library.token);
    let queried: Vec<String> = after_sync
        .iter()
        .filter(|request| request.kind == "keys_query")
        .filter_map(|request| serde_json::from_str::<Value>(&request.body).ok())
        .filter_map(|body| {
            Some(
                body.get("device_keys")?
                    .as_object()?
                    .keys()
                    .cloned()
                    .collect::<Vec<String>>(),
            )
        })
        .flatten()
        .collect();
    assert!(
        queried.contains(&library.user_id),
        "receiveSyncChanges must have taught the machine that this account's devices \
         changed: the pump was quiet immediately before the call and must now be asking \
         who exists. It asked about {queried:?}"
    );

    // ---- 6. Share the scope key, in section 3ter's order ----------------
    // First share: the machine knows the devices exist, but has an Olm
    // session with none of them, so all it can produce is withheld notices
    // and the /keys/claim that fixes that.
    run(share_scope_key(
        &scope,
        std::slice::from_ref(&library.user_id),
    ))
    .expect("sharing a scope key must not fail");
    let before_claim = pump_and_send(&homeserver, &library.token);
    assert!(
        before_claim
            .iter()
            .any(|request| request.kind == "keys_claim"),
        "sharing to devices with no Olm session must queue a /keys/claim -- without it \
         every to-device request this produces is an m.room_key.withheld notice, and \
         that failure looks exactly like success from inside the process (design doc \
         section 3ter)"
    );
    let delivered_before_claim: Vec<&OutgoingRequest> = before_claim
        .iter()
        .filter(|request| {
            request.kind == "to_device"
                && declared_event_type(&request.body) == "m.room.encrypted"
                && addresses(&request.body, &library.user_id, &nio_device_id)
        })
        .collect();
    assert!(
        delivered_before_claim.is_empty(),
        "before a one-time key is claimed there is no Olm session to the counterparty, \
         so nothing can carry the key to it yet; if this ever fires, section 3ter's \
         ordering has changed and the second share below is no longer the load-bearing \
         one"
    );

    // Second share: this is the one that can deliver, and the reason spec
    // section 7 says the first call to a never-seen device delivers nothing
    // by construction.
    run(share_scope_key(
        &scope,
        std::slice::from_ref(&library.user_id),
    ))
    .expect("sharing a scope key must not fail");
    let after_claim = pump_and_send(&homeserver, &library.token);
    let carrying_the_key: Vec<&OutgoingRequest> = after_claim
        .iter()
        .filter(|request| {
            request.kind == "to_device"
                && declared_event_type(&request.body) == "m.room.encrypted"
                && addresses(&request.body, &library.user_id, &nio_device_id)
        })
        .collect();
    let withheld: Vec<String> = after_claim
        .iter()
        .filter(|request| request.kind == "to_device")
        .map(|request| declared_event_type(&request.body))
        .collect();
    assert!(
        !carrying_the_key.is_empty(),
        "after the claim, a to-device request must carry the session key to the \
         counterparty's device {nio_device_id}. The to-device requests in this batch \
         declared {withheld:?}. Withheld notices only, or nothing at all, both mean \
         the key never left this process, and every decryption below would then fail \
         for a reason that has nothing to do with the wire format"
    );

    // ---- 7. Direction 1: the library encrypts, matrix-nio decrypts ------
    let envelope = run(encrypt_event(
        &scope,
        "m.room.message",
        &json!({ "msgtype": "m.text", "body": LIBRARY_PAYLOAD_BODY }).to_string(),
    ))
    .expect("encryption must succeed once a session exists");
    assert!(
        !envelope.algorithm.is_empty(),
        "the envelope must carry the algorithm tag its own content declares"
    );
    let content: Value = serde_json::from_slice(&envelope.ciphertext)
        .expect("an encrypted content is well-formed JSON");

    let intact = homeserver.ok(
        "PUT",
        &format!(
            "/_matrix/client/v3/rooms/{scope_path}/send/m.room.encrypted/{}",
            encode_segment(&transaction_id("intact"))
        ),
        Some(&library.token),
        Some(&content.to_string()),
    );
    let intact_event_id = intact["event_id"]
        .as_str()
        .expect("a sent event has an id")
        .to_string();

    // The control: a *second, distinct* event from the same session, with
    // one character of its ciphertext flipped.
    //
    // Encrypted afresh rather than copied from the event above, and the
    // difference is the whole worth of the control. A corrupted copy of an
    // already-sent event carries an already-seen megolm message index, and
    // `matrix-nio` rejects a repeated index outright as a replay
    // (`olm_machine.py`'s `message_index_ok`, "Duplicate message index,
    // possible replay attack") without the ciphertext entering into it. A
    // first draft of this test did exactly that, and a mutation run proved
    // it worthless: replacing the corrupted ciphertext with the *intact*
    // one still passed, because nio refused the duplicate either way. The
    // control has to be an event nio would otherwise have accepted, so that
    // the single flipped character is the only thing that can account for
    // the refusal.
    let control = run(encrypt_event(
        &scope,
        "m.room.message",
        &json!({ "msgtype": "m.text", "body": CONTROL_PAYLOAD_BODY }).to_string(),
    ))
    .expect("encryption must succeed once a session exists");
    let control_content: Value = serde_json::from_slice(&control.ciphertext)
        .expect("an encrypted content is well-formed JSON");
    let mut corrupted_content = control_content.clone();
    corrupted_content["ciphertext"] = json!(corrupt_one_character(
        control_content["ciphertext"]
            .as_str()
            .expect("a megolm content's ciphertext is a base64 string")
    ));
    let corrupted = homeserver.ok(
        "PUT",
        &format!(
            "/_matrix/client/v3/rooms/{scope_path}/send/m.room.encrypted/{}",
            encode_segment(&transaction_id("corrupt"))
        ),
        Some(&library.token),
        Some(&corrupted_content.to_string()),
    );
    let corrupted_event_id = corrupted["event_id"]
        .as_str()
        .expect("a sent event has an id")
        .to_string();

    let collected = nio.call(json!({
        "op": "collect",
        "room_id": scope,
        "event_ids": [intact_event_id, corrupted_event_id],
        "require_decrypted": [intact_event_id],
        "timeout_s": 120,
    }));
    assert_eq!(
        collected["missing"],
        json!([]),
        "the counterparty never saw one of the events this test sent: {}",
        collected["missing"]
    );

    // ---- THE PROOF -------------------------------------------------------
    let intact_outcome = &collected["events"][&intact_event_id];
    assert_eq!(
        intact_outcome["decrypted"],
        json!(true),
        "matrix-nio must decrypt what this library encrypted. It reported: {intact_outcome}"
    );
    assert_eq!(
        intact_outcome["body"],
        json!(LIBRARY_PAYLOAD_BODY),
        "matrix-nio must recover this library's payload exactly"
    );

    let corrupted_outcome = &collected["events"][&corrupted_event_id];
    assert_eq!(
        corrupted_outcome["decrypted"],
        json!(false),
        "the corrupted-ciphertext control must NOT decrypt. It did, which means this \
         test would pass whether or not the cryptography is correct: {corrupted_outcome}"
    );
    // Asserted positively, on what the reason must *be*.
    //
    // This used to assert negatively -- that the reason was not the
    // duplicate-index one -- over `reason.as_str().unwrap_or_default()`. That
    // passes when `reason` is absent, and passes on `op_collect`'s own
    // `"never attempted"` fallback. Neither is reachable through today's
    // loop, but nothing here defended that, and a check that passes because
    // something is missing is the same shape as the replay trap this control
    // was rewritten to escape. Asking for the field and requiring what it
    // says closes both at once.
    let refusal = corrupted_outcome["reason"].as_str().unwrap_or_else(|| {
        panic!("the counterparty must say why it refused the control: {corrupted_outcome}")
    });
    assert!(
        refusal.contains(NIO_RATCHET_REFUSAL),
        "the control must have been refused by the megolm ratchet itself, not by \
         bookkeeping around it. matrix-nio words the three refusals differently and \
         only one of them is the right answer here: {NIO_RATCHET_REFUSAL:?} when \
         `session.decrypt` threw, \"Error decrypting megolm event, no session found\" \
         (comma, not colon) when the key never arrived, and \"Duplicate message \
         index\" when the index was replayed -- which is exactly the false pass this \
         control was rewritten to escape. It said: {refusal}"
    );

    // ---- 8. Direction 2: matrix-nio encrypts, the library decrypts -------
    let sent = nio.call(json!({
        "op": "send",
        "room_id": scope,
        "body": NIO_PAYLOAD_BODY,
    }));
    let nio_event_id = sent["event_id"]
        .as_str()
        .expect("the counterparty reports the id it sent")
        .to_string();

    // Continuing from the last payload step 5 saw: its `next_batch` is the
    // freshest cursor this account has synced to, wherever the loop stopped.
    let mut since = sync["next_batch"]
        .as_str()
        .expect("a /sync response carries a next_batch")
        .to_string();
    let mut new_sessions = 0u32;
    let mut to_device_events = 0u32;
    let mut nio_raw_event: Option<Value> = None;
    let deadline = Instant::now() + Duration::from_secs(120);
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

        // Every sync goes through the library, including the ones carrying
        // nothing: that is what a product does, and an empty sync must be
        // accepted rather than rejected as malformed.
        let outcome = run(receive_sync_changes(&encryption_slice(&sync).to_string()))
            .expect("a real /sync payload must be accepted");
        new_sessions += outcome.new_session_count;
        to_device_events += outcome.to_device_event_count;

        if let Some(events) = sync["rooms"]["join"][&scope]["timeline"]["events"].as_array() {
            for event in events {
                if event["event_id"].as_str() == Some(nio_event_id.as_str()) {
                    nio_raw_event = Some(event.clone());
                }
            }
        }
    }

    // The strongest thing that can be said about receiveSyncChanges: the
    // machine turned a homeserver-delivered, Olm-encrypted to-device message
    // from an independent implementation into a usable inbound group
    // session. No payload this test wrote itself could produce this.
    assert!(
        to_device_events > 0,
        "the homeserver must have delivered the counterparty's to-device messages \
         through /sync, and receiveSyncChanges must have processed them"
    );
    assert!(
        new_sessions > 0,
        "receiveSyncChanges must have recovered at least one inbound group session \
         from the counterparty's room key; it reported {new_sessions} across \
         {to_device_events} processed to-device events"
    );
    let nio_raw_event =
        nio_raw_event.expect("the counterparty's own encrypted event must arrive in /sync");

    let recovered = run(decrypt_event(&scope, &nio_raw_event.to_string()))
        .expect("the library must decrypt what matrix-nio encrypted");
    let plaintext: Value = serde_json::from_slice(&recovered.ciphertext)
        .expect("a decrypted content is well-formed JSON");
    assert_eq!(
        plaintext["body"],
        json!(NIO_PAYLOAD_BODY),
        "the library must recover matrix-nio's payload exactly"
    );
    assert_eq!(recovered.event_type, "m.room.message");
    assert_eq!(recovered.scope, scope);
    assert_eq!(
        recovered.sender, library.user_id,
        "unauthenticated transport metadata, per spec section 7.1, but it must at \
         least be the value the event carried"
    );

    // The same control in this direction: one character of the
    // counterparty's ciphertext, and the library must refuse it.
    let mut corrupted_from_nio = nio_raw_event.clone();
    corrupted_from_nio["content"]["ciphertext"] = json!(corrupt_one_character(
        nio_raw_event["content"]["ciphertext"]
            .as_str()
            .expect("a megolm content's ciphertext is a base64 string")
    ));
    let refusal = run(decrypt_event(&scope, &corrupted_from_nio.to_string()))
        .expect_err("a corrupted ciphertext must not decrypt");
    assert_eq!(
        refusal,
        SessionError::Undecryptable,
        "a one-character ciphertext corruption is a MAC failure, which \
         classify_megolm_error maps to Undecryptable"
    );

    // ---- 9. openCryptoStore, in a genuinely separate process -------------
    reopen_the_store_in_a_second_process(
        &library,
        &library_store,
        &scope,
        &nio_raw_event,
        dir.path(),
    );

    // ---- Tidy up ---------------------------------------------------------
    // The room, this device and the counterparty's device are removed by
    // `teardown`'s `Drop`, which runs on this path and on every failing one
    // alike. All that is left here is the counterparty's own protocol
    // shutdown: `quit` logs nio out and closes its HTTP session cleanly,
    // which is nicer than being killed, and having succeeded it makes the
    // guard's `/delete_devices` fallback unnecessary.
    nio.call(json!({ "op": "quit" }));
    teardown.counterparty_logged_itself_out();
}

/// Re-runs this same test binary as a child, with the phase-two environment
/// set, and requires it to have decrypted from the store this process wrote.
///
/// The child writes the plaintext it recovered to a marker file and this
/// process asserts on the contents. An exit status alone would not do: a
/// child that matched no test also exits zero, and "passed without examining
/// its target" is the failure mode this milestone keeps finding.
fn reopen_the_store_in_a_second_process(
    library: &LoggedIn,
    store_path: &std::path::Path,
    scope: &str,
    event: &Value,
    working_dir: &std::path::Path,
) {
    let marker = working_dir.join("phase-two-marker");
    let status = Command::new(std::env::current_exe().expect("the test binary knows its own path"))
        .args([
            "--exact",
            "level_two_interoperability_over_a_real_homeserver",
            "--ignored",
            "--test-threads=1",
        ])
        .env(PHASE_TWO_ENV, "1")
        .env(PHASE_TWO_STORE, store_path)
        .env(PHASE_TWO_USER, &library.user_id)
        .env(PHASE_TWO_DEVICE, &library.device_id)
        .env(PHASE_TWO_SCOPE, scope)
        .env(PHASE_TWO_EVENT, event.to_string())
        .env(PHASE_TWO_MARKER, &marker)
        // The child must not try to log in, spawn nio, or recurse.
        .env_remove(PASSWORD_ENV)
        .status()
        .expect("the phase-two child must be startable");

    assert!(
        status.success(),
        "the phase-two child failed; the store this process wrote could not be reopened \
         and read back"
    );
    let recovered = std::fs::read_to_string(&marker).unwrap_or_else(|error| {
        panic!(
            "the phase-two child exited successfully but wrote no marker at {}, so it \
             never ran the reopen at all ({error})",
            marker.display()
        )
    });
    let recovered: Value =
        serde_json::from_str(&recovered).expect("the marker holds the recovered content");
    assert_eq!(
        recovered["body"],
        json!(NIO_PAYLOAD_BODY),
        "a second process opening this store with openCryptoStore must recover the \
         same plaintext from the same inbound session"
    );
}

/// The child half of the above. Opens the store this run's first process
/// wrote, with no network and no counterparty, and decrypts the
/// counterparty's event out of the session that survived.
fn phase_two_reopen_the_store() {
    let store_path = required_env(PHASE_TWO_STORE);
    let scope = required_env(PHASE_TWO_SCOPE);
    let event = required_env(PHASE_TWO_EVENT);
    let marker = required_env(PHASE_TWO_MARKER);

    run(open_store(MachineConfig {
        user_id: required_env(PHASE_TWO_USER),
        device_id: required_env(PHASE_TWO_DEVICE),
        store_path,
        store_passphrase: Some(STORE_PASSPHRASE.to_string()),
    }))
    .expect("openCryptoStore must reopen a store an earlier process wrote");

    let recovered = run(decrypt_event(&scope, &event))
        .expect("the inbound group session must have survived in the store");
    let plaintext: Value = serde_json::from_slice(&recovered.ciphertext)
        .expect("a decrypted content is well-formed JSON");
    std::fs::write(&marker, plaintext.to_string()).expect("the marker must be writable");
}
