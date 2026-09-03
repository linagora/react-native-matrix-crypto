//! Level 2 interoperability, federated: three devices, two users, two
//! federating homeservers, one encrypted room, and a late joiner
//! (design doc section 8, issue #7).
//!
//! # The question this file answers
//!
//! `level_two_interop.rs` proves that a third-party client decrypts what
//! this library encrypts when every device sits on ONE homeserver. This
//! file asks the next question: does that still hold when the room spans
//! TWO federating homeservers, with a third device joining AFTER the
//! first message? Every key-exchange step the single-server proof took
//! through its homeserver's client API now has a cross-server leg:
//!
//! * `/keys/query` for the late joiner's account -- server A must fetch
//!   the device keys from server B;
//! * `/keys/claim` for the late joiner's device -- the one-time key has
//!   to be claimed ACROSS federation, which is the step that actually
//!   proves federation is carrying the exchange rather than merely the
//!   room timeline;
//! * `/sendToDevice` in both directions -- the room key to the late
//!   joiner leaves through A's federation sender, and the late joiner's
//!   key for the pre-existing devices leaves through B's.
//!
//! What federation actually exercises is exactly those three endpoints
//! in their cross-server form. The Olm/Megolm cryptography on top is
//! unchanged, which is what makes this a transport proof and not a
//! second copy of `level_two_interop.rs`.
//!
//! # Why the second user is a nio subprocess and not a second library machine
//!
//! The same reason `two_parties.rs` does not create its second party
//! through `create_machine`: this library holds ONE crypto machine per
//! process, behind the process-wide registry in `machine.rs` (the
//! `HELD: RwLock<Option<Arc<Held>>>` single slot at `machine.rs:526-529`;
//! a second `create_machine` with a different config is refused with
//! `AlreadyInitialised`, `machine.rs:626-631`). The pump's bookkeeping,
//! the verification flow registry, the held private keys and the event
//! observer are process-global on top of that, so two library machines in
//! one process would be a library-design change, not a test. The proven
//! shape is therefore the one this file uses: the library machine
//! in-process, plus `matrix-nio` counterparty subprocesses for every
//! other participant. The first counterparty logs in as the SAME account
//! as the library (one credential, two devices -- the established trick
//! from `level_two_interop.rs:29-36`); the second logs in as a different
//! user on the second server.
//!
//! # What is asserted about the late joiner's history
//!
//! The pinned, spec-compliant answer is that the late joiner CANNOT decrypt
//! pre-join messages, and this test asserts exactly that -- on what the
//! pinned matrix-nio + vodozemac install actually reports, not on an
//! assumption about its internals. The mechanism, observed in the runs this
//! test pins: matrix-sdk-crypto shares the outbound megolm session at its
//! current ratchet position, so the late joiner receives the session from
//! message index 1 while the pre-join message occupies index 0 -- and
//! megolm is a forward-only ratchet, so index 0 is undecryptable even with
//! the key in hand (the same session decrypts the post-join messages fine).
//! vodozemac words that refusal "The message was encrypted using an unknown
//! message index", raised from inside `session.decrypt` -- which this test
//! distinguishes from the corrupted-ciphertext control's MAC failure by
//! pinning the full wording, the same attribution discipline
//! `level_two_interop.rs`'s control comment catalogues for nio's three
//! refusal variants. A deliberate re-share would be a behaviour change, and
//! this assertion is what catches it.
//!
//! # Running it
//!
//! ```text
//! MATRIX_INTEROP_HOMESERVER=http://127.0.0.1:<port of server A> \
//! MATRIX_INTEROP_USER=@interop:a.rnmc.test \
//! MATRIX_INTEROP_PASSWORD=<from the operator's own store, never a file here> \
//! MATRIX_INTEROP_FEDERATED_HOMESERVER=http://127.0.0.1:<port of server B> \
//! MATRIX_INTEROP_FEDERATED_USER=@interop-other:b.rnmc.test \
//! MATRIX_INTEROP_NIO_PYTHON=/path/to/python-with-matrix-nio \
//! cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core \
//!   --test level_two_federated -- --ignored --nocapture
//! ```
//!
//! Both servers must already federate with each other; the two
//! `scripts/run-level-two-interop.sh` mode stands them up (see its
//! header). `#[ignore]`, so an ordinary `cargo test` needs no network
//! and no credential, and no credential value is read from or written to
//! any file in this repository.

use std::time::{Duration, Instant};

use matrix_crypto_core::{
    create_machine, decrypt_event, encrypt_event, mark_request_sent, receive_sync_changes,
    share_scope_key, take_outgoing_requests, MachineConfig, OutgoingRequest,
    SenderTrustRequirement,
};
use serde_json::{json, Value};

// The homeserver, the login, the pump and the counterparty subprocess, none
// of which is what this file proves. Included through the same module the
// other level 2 proofs use; see its header for why it is a module.
#[path = "interop/harness.rs"]
mod harness;
use harness::{
    addresses, declared_event_type, encode_segment, encryption_slice, login, pump_and_send,
    required_env, run, Homeserver, NioParty, Teardown, HOMESERVER_ENV, NIO_STORE_ENV, PASSWORD_ENV,
    PYTHON_ENV, USER_ENV,
};

/// Not a credential: the store this test creates lives in a temporary
/// directory it also deletes. Written here rather than generated so a
/// hypothetical second process would need one fewer variable.
const STORE_PASSPHRASE: &str = "level-two-federated";

/// Names a second account on the second homeserver. The script creates it
/// and exports it; it is required, because a proof this test would quietly
/// decline to run is the failure this milestone keeps finding.
const FEDERATED_HOMESERVER_ENV: &str = "MATRIX_INTEROP_FEDERATED_HOMESERVER";
const FEDERATED_USER_ENV: &str = "MATRIX_INTEROP_FEDERATED_USER";

/// Distinct per direction and per phase, deliberately: one payload for
/// everything could pass while only ever proving one machine's
/// self-round-trip, and a post-join payload identical to a pre-join one
/// could not tell "the existing session survived the membership change"
/// from "a fresh session was silently established".
const LIBRARY_PAYLOAD_BODY: &str = "encrypted by react-native-matrix-crypto for both devices";
const NIO1_PAYLOAD_BODY: &str = "encrypted by matrix-nio on the first counterparty device";
const POST_JOIN_PAYLOAD_BODY: &str =
    "encrypted by react-native-matrix-crypto after the third device joined";
const FEDERATED_PAYLOAD_BODY: &str = "encrypted by matrix-nio on the federated device";
/// The corrupted-ciphertext control's own payload. Distinct from every
/// other payload so the control is a fresh megolm message index -- see the
/// comment at its send site for why that is the point.
const CONTROL_PAYLOAD_BODY: &str = "the federated control that must never decrypt";

/// How `matrix-nio` words the ratchet refusal, copied with its rationale
/// from `level_two_interop.rs`: the colon variant is the only one of nio's
/// refusal wordings that means "vodozemac's decrypt threw".
const NIO_RATCHET_REFUSAL: &str = "Error decrypting megolm event: ";

/// The refusal this test EXPECTS for pre-join history, pinned from what the
/// pinned matrix-nio + vodozemac install actually reports. The late joiner
/// DOES receive the room key -- it decrypts the post-join messages of the
/// same session -- but the share hands it the session from index 1
/// (matrix-sdk-crypto shares the ratchet at its current position, and the
/// pre-join message consumed index 0). Megolm is a forward-only ratchet, so
/// index 0 is mathematically undecryptable even with the key in hand, and
/// vodozemac words that "The message was encrypted using an unknown message
/// index". This is the spec-compliant answer for a late joiner, and it is
/// STRONGER than mere withholding: the key arrived, and the history is
/// unreadable anyway. Asserted together with [`NIO_RATCHET_REFUSAL`] so
/// "unknown message index" must come from vodozemac's decrypt itself, not
/// from bookkeeping around it.
const NIO_UNKNOWN_INDEX_REFUSAL: &str = "unknown message index";

fn transaction_id(label: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_nanos();
    format!("rnmc-{label}-{nanos}")
}

/// Flips one character of a base64 ciphertext. The control the whole proof
/// needs: an event that differs from a valid one by a single character must
/// not decrypt anywhere.
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

/// Drains the pump once and posts everything, like
/// `harness::pump_and_send`, but also returns the parsed bodies of any
/// `keys_query` and `keys_claim` responses. The federated phase asserts on
/// what the homeserver actually ANSWERED -- that A's response carries the
/// remote user's devices, that the claim resolved a one-time key across
/// federation -- which `pump_and_send` cannot express because it hands the
/// response straight to `mark_request_sent` and forgets it.
///
/// One entry per `keys_query` request, not one per batch: a single sync's
/// `device_lists.changed` routinely names several users (Synapse reports
/// both the inviter and the invitee after an invite), the machine then
/// issues one query per user, and keeping only the last response let the
/// library's own-user query shadow the federated one in an earlier draft of
/// this test -- the failure looked like "A never answered" when it had.
fn pump_capturing_keys(
    homeserver: &Homeserver,
    token: &str,
) -> (Vec<OutgoingRequest>, Vec<Value>, Option<Value>) {
    let batch = run(take_outgoing_requests()).expect("the pump must be drainable");
    let mut query_responses = Vec::new();
    let mut claim_response = None;
    for request in &batch {
        let response = harness::send_outgoing(homeserver, token, request);
        if request.kind == "keys_query" {
            query_responses.push(
                serde_json::from_str(&response)
                    .expect("a /keys/query response the pump accepted is well-formed JSON"),
            );
        }
        if request.kind == "keys_claim" {
            claim_response = serde_json::from_str(&response)
                .expect("a /keys/claim response the pump accepted is well-formed JSON");
        }
        run(mark_request_sent(&request.id, &response)).unwrap_or_else(|error| {
            panic!(
                "the homeserver's own response to a {} request was rejected by \
                 mark_request_sent: {error:?}",
                request.kind
            )
        });
    }
    (batch, query_responses, claim_response)
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// Three devices, two users, two federating homeservers, one encrypted
/// room: the library's device and a first nio device on server A exchange
/// messages; a second nio device on server B joins afterwards; the room
/// key crosses to it over federation, the late joiner's key crosses back,
/// and both pre-existing devices keep decrypting throughout.
///
/// One `#[test]` fn, not several: the machine registry and the pump's
/// bookkeeping are process-wide, and Cargo gives this file its own process.
/// Unlike `level_two_interop.rs` this test spawns no phase-two child: what
/// it proves happens between live devices, not across a restart.
#[test]
#[ignore = "needs two federating homeservers, a credential in the environment, and matrix-nio; \
            see this file's header for the invocation"]
fn three_devices_across_two_federating_homeservers() {
    let homeserver = Homeserver::new(required_env(HOMESERVER_ENV));
    let user = required_env(USER_ENV);
    let password = required_env(PASSWORD_ENV);
    let federated_homeserver = required_env(FEDERATED_HOMESERVER_ENV);
    let federated_user = required_env(FEDERATED_USER_ENV);
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
    let nio1_store = dir.path().join("nio1-store");
    let nio2_store = dir.path().join("nio2-store");
    std::fs::create_dir_all(&nio1_store).expect("the first nio store directory must be creatable");
    std::fs::create_dir_all(&nio2_store).expect("the second nio store directory must be creatable");

    // ---- 1. The library's device on server A ----------------------------
    let library = login(&homeserver, &user, &password, "level-two-federated-library");

    // The same cursor discipline `level_two_interop.rs` step 1 keeps for
    // Synapse: its `device_lists` only reports changes that postdate the
    // sync cursor. Everything this run will ever change -- both nio
    // devices appearing, keys reaching the wire -- happens after this
    // point, so a cursor from here makes every change reportable on both
    // implementations.
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

    // Declared before the counterparties, so on an unwind they die first
    // and this guard then removes what the run created on server A. See
    // `level_two_interop.rs` for the full ordering argument. What the
    // guard deliberately does NOT own: the federated counterparty's
    // device, which belongs to a different user on a different server and
    // cannot be reached through this guard's `/delete_devices` (which runs
    // against server A with the library's token). The happy path below
    // asks that child to log itself out, which deletes its device, and
    // the script's container teardown is the backstop; on the manual path
    // against somebody's real servers, a FAILING run can leave that one
    // device behind, and this comment is the record of that residue.
    let mut teardown = Teardown::new(&homeserver, &library, &password);

    // ---- 2. An encrypted room on server A -------------------------------
    let room = homeserver.ok(
        "POST",
        "/_matrix/client/v3/createRoom",
        Some(&library.token),
        Some(
            &json!({
                "preset": "private_chat",
                "name": "react-native-matrix-crypto level 2 federated",
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

    // ---- 3. The first counterparty: same account, second device ---------
    let mut nio1 = NioParty::start(&python, &script, &nio1_store);
    let nio1_login = nio1.call(json!({ "op": "login" }));
    let nio1_user_id = nio1_login["user_id"]
        .as_str()
        .expect("the counterparty reports its user id")
        .to_string();
    let nio1_device_id = nio1_login["device_id"]
        .as_str()
        .expect("the counterparty reports its device id")
        .to_string();
    teardown.owns_device(&nio1_device_id);

    assert_eq!(
        nio1_user_id, library.user_id,
        "the first counterparty must be a second device of the library's account: \
         Matrix encryption is device-to-device, and one account logged in twice is what \
         makes this a one-credential test"
    );
    assert_ne!(
        nio1_device_id, library.device_id,
        "the counterparty must be a second device, not the same one"
    );

    // ---- 4. The library's machine, its keys on the wire, and the sync
    //         loop that teaches it who exists ------------------------------
    run(create_machine(MachineConfig {
        user_id: library.user_id.clone(),
        device_id: library.device_id.clone(),
        store_path: library_store.to_string_lossy().into_owned(),
        store_passphrase: Some(STORE_PASSPHRASE.to_string()),
    }))
    .expect("the library's machine must be creatable");

    // Identical to `level_two_interop.rs` step 4: skip the device-key
    // publication and the machine is invisible -- nobody can claim a
    // one-time key from it, so nobody can ever be sent a room key by it.
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
         the device-list assertion below distinguishes 'the machine learned something \
         from a sync' from 'the machine was going to ask anyway'"
    );

    // The account-appearance loop from `level_two_interop.rs` step 5,
    // verbatim in shape: Continuwuity reports the new device on the
    // initial sync, Synapse only on an incremental one and only for
    // changes past the cursor, so this loops bounded-ly until the account
    // appears, going back to `cursor_before_anything` after a fruitless
    // initial sync. What it proves -- receiveSyncChanges teaching the
    // machine that its own account's devices changed -- is stated there
    // and not repeated into this file's diff.
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
         incremental one -- before this step can tell whether the machine learned \
         from the payload; it still had not after {syncs} syncs"
    );

    run(receive_sync_changes(&encryption_slice(&sync).to_string()))
        .expect("a real /sync payload must be accepted");
    let after_sync = pump_and_send(&homeserver, &library.token);
    let queried_own: Vec<String> = after_sync
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
        queried_own.contains(&library.user_id),
        "receiveSyncChanges must have taught the machine that this account's devices \
         changed: the pump was quiet immediately before the call and must now be asking \
         who exists. It asked about {queried_own:?}"
    );

    // ---- 5. Share the scope key to the first counterparty, in section
    //         3ter's order: first share yields withheld notices plus the
    //         /keys/claim that fixes them, second share delivers -----------
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
         that failure looks exactly like success from inside the process"
    );
    run(share_scope_key(
        &scope,
        std::slice::from_ref(&library.user_id),
    ))
    .expect("sharing a scope key must not fail");
    let after_claim = pump_and_send(&homeserver, &library.token);
    assert!(
        after_claim.iter().any(|request| {
            request.kind == "to_device"
                && declared_event_type(&request.body) == "m.room.encrypted"
                && addresses(&request.body, &library.user_id, &nio1_device_id)
        }),
        "after the claim, a to-device request must carry the session key to the first \
         counterparty's device {nio1_device_id}; without it every decryption below \
         fails for a reason that has nothing to do with the wire format"
    );

    // ---- 6. Message 1, both directions, BEFORE the third device exists ---
    // This phase is the control for the late joiner: everything sent here
    // predates the membership change, so the assertions on it later --
    // nio1 still decrypts, the library still decrypts -- are what
    // "joining a third device did not break the existing session" means.
    let envelope = run(encrypt_event(
        &scope,
        "m.room.message",
        &json!({ "msgtype": "m.text", "body": LIBRARY_PAYLOAD_BODY }).to_string(),
    ))
    .expect("encryption must succeed once a session exists");
    let content: Value = serde_json::from_slice(&envelope.ciphertext)
        .expect("an encrypted content is well-formed JSON");
    let sent = homeserver.ok(
        "PUT",
        &format!(
            "/_matrix/client/v3/rooms/{scope_path}/send/m.room.encrypted/{}",
            encode_segment(&transaction_id("pre-join"))
        ),
        Some(&library.token),
        Some(&content.to_string()),
    );
    let pre_join_event_id = sent["event_id"]
        .as_str()
        .expect("a sent event has an id")
        .to_string();

    let collected = nio1.call(json!({
        "op": "collect",
        "room_id": scope,
        "event_ids": [pre_join_event_id],
        "require_decrypted": [pre_join_event_id],
        "timeout_s": 120,
    }));
    let pre_join_outcome = &collected["events"][&pre_join_event_id];
    assert_eq!(
        pre_join_outcome["decrypted"],
        json!(true),
        "matrix-nio must decrypt the pre-join message. It reported: {pre_join_outcome}"
    );
    assert_eq!(
        pre_join_outcome["body"],
        json!(LIBRARY_PAYLOAD_BODY),
        "matrix-nio must recover the pre-join payload exactly"
    );

    let nio1_sent = nio1.call(json!({
        "op": "send",
        "room_id": scope,
        "body": NIO1_PAYLOAD_BODY,
    }));
    let nio1_event_id = nio1_sent["event_id"]
        .as_str()
        .expect("the counterparty reports the id it sent")
        .to_string();

    // The bounded incremental-sync loop from `level_two_interop.rs`
    // direction 2: every payload through receiveSyncChanges, counting what
    // it processed, until the event and a new inbound session both exist.
    let mut since = sync["next_batch"]
        .as_str()
        .expect("a /sync response carries a next_batch")
        .to_string();
    let mut new_sessions = 0u32;
    let mut to_device_events = 0u32;
    let mut nio1_raw_event: Option<Value> = None;
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline && (nio1_raw_event.is_none() || new_sessions == 0) {
        let payload = homeserver.ok(
            "GET",
            &format!(
                "/_matrix/client/v3/sync?timeout=8000&since={}",
                encode_segment(&since)
            ),
            Some(&library.token),
            None,
        );
        since = payload["next_batch"]
            .as_str()
            .expect("a /sync response carries a next_batch")
            .to_string();
        let outcome = run(receive_sync_changes(
            &encryption_slice(&payload).to_string(),
        ))
        .expect("a real /sync payload must be accepted");
        new_sessions += outcome.new_session_count;
        to_device_events += outcome.to_device_event_count;

        if let Some(events) = payload["rooms"]["join"][&scope]["timeline"]["events"].as_array() {
            for event in events {
                if event["event_id"].as_str() == Some(nio1_event_id.as_str()) {
                    nio1_raw_event = Some(event.clone());
                }
            }
        }
    }
    assert!(
        to_device_events > 0,
        "the homeserver must have delivered the counterparty's to-device messages \
         through /sync, and receiveSyncChanges must have processed them"
    );
    assert!(
        new_sessions > 0,
        "receiveSyncChanges must have recovered the counterparty's inbound group \
         session; it reported {new_sessions} across {to_device_events} processed \
         to-device events"
    );
    let nio1_raw_event =
        nio1_raw_event.expect("the counterparty's own encrypted event must arrive in /sync");
    let recovered = run(decrypt_event(
        &scope,
        &nio1_raw_event.to_string(),
        SenderTrustRequirement::Any,
    ))
    .expect("the library must decrypt what matrix-nio encrypted");
    let plaintext: Value = serde_json::from_slice(&recovered.ciphertext)
        .expect("a decrypted content is well-formed JSON");
    assert_eq!(
        plaintext["body"],
        json!(NIO1_PAYLOAD_BODY),
        "the library must recover the first counterparty's payload exactly"
    );

    // ---- 7. The late joiner: nio #2 as a different user on server B -----
    // Started with its own homeserver/user/store overrides; the password is
    // the same shared secret and still arrives by inheritance only.
    let mut nio2 = NioParty::start_as(
        &python,
        &script,
        &[
            (HOMESERVER_ENV, federated_homeserver),
            (USER_ENV, federated_user.clone()),
            (NIO_STORE_ENV, nio2_store.to_string_lossy().into_owned()),
        ],
    );
    let nio2_login = nio2.call(json!({ "op": "login" }));
    let nio2_user_id = nio2_login["user_id"]
        .as_str()
        .expect("the federated counterparty reports its user id")
        .to_string();
    let nio2_device_id = nio2_login["device_id"]
        .as_str()
        .expect("the federated counterparty reports its device id")
        .to_string();
    assert_eq!(
        nio2_user_id, federated_user,
        "the second counterparty must be the federated account the environment names, \
         not a third device of the library's account"
    );

    // The login op's settle already published nio2's device and one-time
    // keys on server B. Invite from the library's account; server A must
    // resolve the invitee over federation before the invite even lands.
    homeserver.ok(
        "POST",
        &format!("/_matrix/client/v3/rooms/{scope_path}/invite"),
        Some(&library.token),
        Some(&json!({ "user_id": federated_user }).to_string()),
    );
    // nio's join completes only after the make_join/send_join federation
    // round trip, so a successful reply means both servers already agree
    // the late joiner is a member.
    nio2.call(json!({ "op": "join", "room_id": scope }));
    // Give nio2's own pump turns to learn the room's other devices; it
    // needs them to encrypt for them in phase 9.
    nio2.call(json!({ "op": "settle", "rounds": 5 }));

    // ---- 8. The key exchange crosses federation --------------------------
    // Two facts to establish, in this order, and the order is load-bearing:
    //
    // 1. Server A's own /sync must show the late joiner as a member: the
    //    m.room.member event for {federated_user} arriving in this room's
    //    timeline. That is the server-side fact the join propagated, and it
    //    is the impl-neutral one. What the two implementations do beyond
    //    that differs, pinned from live runs of this very test and stated
    //    here rather than assumed by either leg: Synapse ALSO reports the
    //    invitee/joiner in `device_lists.changed` (its sync computes device
    //    refetches from membership deltas), which is the report
    //    `level_two_interop.rs` step 5 relies on for a new local device.
    //    Continuwuity v26.7.2 reports NEITHER the remote invite nor the
    //    remote join in `device_lists` at all -- the membership event is
    //    there, `device_lists` stays absent -- so a client of it learns a
    //    new member's devices client-side. That is not a gap this test can
    //    fix, and it is not one the library needs fixed: this library is
    //    the client, and fact 2 is exactly its client-side path.
    //
    // 2. The machine's /keys/query for that user, and A's answer. Here a
    //    federated fact about matrix-sdk-crypto does the sequencing: a
    //    /sync `device_lists` entry for a user the machine is NOT already
    //    tracking is ignored (upstream store/mod.rs's own doc comment:
    //    "Users whose devices we are not tracking are ignored"), and this
    //    library starts tracking a user exactly when `share_scope_key` is
    //    asked to share with them (`update_tracked_users` at the end of
    //    `session.rs`'s `share_scope_key`). So the share below is not just
    //    what sends the key -- it is what makes the machine ask who the
    //    recipient is, and the /keys/query that follows is the first
    //    cross-server step: A answers it by fetching the keys from B over
    //    federation, so its response content -- not merely its 2xx -- is
    //    what proves the fetch happened.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut late_joiner_member = false;
    // Diagnostic, quoted if the loop expires: every device_lists entry this
    // phase saw, which pins which of the two reporting behaviours above
    // this server has.
    let mut device_lists_seen: Vec<String> = Vec::new();
    while Instant::now() < deadline && !late_joiner_member {
        let payload = homeserver.ok(
            "GET",
            &format!(
                "/_matrix/client/v3/sync?timeout=3000&since={}",
                encode_segment(&since)
            ),
            Some(&library.token),
            None,
        );
        since = payload["next_batch"]
            .as_str()
            .expect("a /sync response carries a next_batch")
            .to_string();
        run(receive_sync_changes(
            &encryption_slice(&payload).to_string(),
        ))
        .expect("a real /sync payload must be accepted");
        if let Some(changed) = payload["device_lists"]["changed"].as_array() {
            device_lists_seen.extend(changed.iter().filter_map(Value::as_str).map(str::to_owned));
        }
        if let Some(events) = payload["rooms"]["join"][&scope]["timeline"]["events"].as_array() {
            late_joiner_member = events.iter().any(|event| {
                event["type"].as_str() == Some("m.room.member")
                    && event["state_key"].as_str() == Some(federated_user.as_str())
                    && event["content"]["membership"].as_str() == Some("join")
            });
        }
    }
    assert!(
        late_joiner_member,
        "server A's own /sync must eventually carry {federated_user}'s \
         m.room.member join event for this room -- that event is the \
         server-side fact the join propagated, and no key exchange below can \
         be read as federated if the far side never became a member. \
         device_lists.changed carried, across the whole window (Synapse \
         reports the joiner there, Continuwuity reports nothing): \
         {device_lists_seen:?}"
    );

    // The three-share dance, now across federation -- one share longer than
    // `level_two_interop.rs`'s two, and the extra step is itself a finding
    // worth pinning. Sharing to BOTH users on purpose: when membership
    // changes, the next share may rotate the outbound session, and the
    // existing counterparty then needs the new session's key as much as the
    // late joiner does.
    //
    // Share 1 -- LEARN. At this point the machine does not know the late
    // joiner's device exists (the /keys/query below is what teaches it, and
    // only now is the user tracked at all), so the share can produce nothing
    // for them but a withheld notice.
    run(share_scope_key(
        &scope,
        &[library.user_id.clone(), federated_user.clone()],
    ))
    .expect("sharing a scope key must not fail");
    let (first_share, query_responses, _claim) = pump_capturing_keys(&homeserver, &library.token);
    let queried_federated = query_responses.iter().any(|response| {
        response["device_keys"][&federated_user]
            .as_object()
            .is_some_and(|devices| devices.contains_key(&nio2_device_id))
    });
    assert!(
        queried_federated,
        "the share must make the machine ask who {federated_user}'s devices \
         are, and one of server A's /keys/query answers must carry the \
         federated device {nio2_device_id} -- A can only know it by fetching \
         it from server B. The pump emitted {} /keys/query request(s), and \
         none ever carried the device; the query responses were: \
         {query_responses:?}",
        query_responses.len()
    );
    assert!(
        !first_share.iter().any(|request| {
            request.kind == "to_device"
                && declared_event_type(&request.body) == "m.room.encrypted"
                && addresses(&request.body, &federated_user, &nio2_device_id)
        }),
        "before the one-time key is claimed there is no Olm session to the \
         federated device, so nothing can carry the key to it yet; if this \
         ever fires, the first share is already delivering and the dance \
         below is no longer the load-bearing one"
    );

    // Share 2 -- CLAIM. The query response above taught the machine the
    // device, so this share's session check can now see that it has no Olm
    // session and queue the /keys/claim that fixes that. This is the step
    // `level_two_interop.rs` gets from its first share directly, because its
    // counterparty's device was already known before any share was called;
    // here the device is only learned from share 1's own query, one pump
    // later, so the claim lands one share later too.
    run(share_scope_key(
        &scope,
        &[library.user_id.clone(), federated_user.clone()],
    ))
    .expect("sharing a scope key must not fail");
    let (second_share, _queries, claim_response) = pump_capturing_keys(&homeserver, &library.token);
    assert!(
        second_share
            .iter()
            .any(|request| request.kind == "keys_claim"),
        "now that the machine knows the federated device, sharing must queue a \
         /keys/claim -- without it every to-device request this produces for the \
         late joiner is an m.room_key.withheld notice, and that failure looks \
         exactly like success from inside the process"
    );
    assert!(
        !second_share.iter().any(|request| {
            request.kind == "to_device"
                && declared_event_type(&request.body) == "m.room.encrypted"
                && addresses(&request.body, &federated_user, &nio2_device_id)
        }),
        "the claim has been queued but its response has not reached the machine \
         yet, so there is still no Olm session to carry the key; a delivery \
         here would mean the claim went somewhere else"
    );
    let claimed = claim_response
        .as_ref()
        .and_then(|response| response["one_time_keys"][&federated_user].as_object())
        .and_then(|devices| devices.get(&nio2_device_id))
        .and_then(Value::as_object)
        .is_some_and(|keys| !keys.is_empty());
    assert!(
        claimed,
        "the /keys/claim must resolve a one-time key for the federated device \
         {nio2_device_id} from server B across federation -- the claim response \
         was: {claim_response:?}. An empty answer here is the federation step \
         failing, not the cryptography"
    );

    // Share 3 -- DELIVER. The claimed key is processed; the session exists;
    // this is the share that can actually carry the room key to the late
    // joiner.
    run(share_scope_key(
        &scope,
        &[library.user_id.clone(), federated_user.clone()],
    ))
    .expect("sharing a scope key must not fail");
    let third_share = pump_and_send(&homeserver, &library.token);
    assert!(
        third_share.iter().any(|request| {
            request.kind == "to_device"
                && declared_event_type(&request.body) == "m.room.encrypted"
                && addresses(&request.body, &federated_user, &nio2_device_id)
        }),
        "after the claim, a to-device request must carry the session key to the \
         federated device {nio2_device_id} -- posted to server A, which must \
         forward it to server B. Without it every decryption on the far side fails \
         for a reason that has nothing to do with the wire format"
    );

    // ---- 9. Post-join message: the late joiner decrypts, the first
    //         counterparty still decrypts the same session ----------------
    let envelope = run(encrypt_event(
        &scope,
        "m.room.message",
        &json!({ "msgtype": "m.text", "body": POST_JOIN_PAYLOAD_BODY }).to_string(),
    ))
    .expect("encryption must succeed once a session exists");
    let content: Value = serde_json::from_slice(&envelope.ciphertext)
        .expect("an encrypted content is well-formed JSON");
    let sent = homeserver.ok(
        "PUT",
        &format!(
            "/_matrix/client/v3/rooms/{scope_path}/send/m.room.encrypted/{}",
            encode_segment(&transaction_id("post-join"))
        ),
        Some(&library.token),
        Some(&content.to_string()),
    );
    let post_join_event_id = sent["event_id"]
        .as_str()
        .expect("a sent event has an id")
        .to_string();

    // nio2 watches the post-join message arrive and decrypt.
    let collected = nio2.call(json!({
        "op": "collect",
        "room_id": scope,
        "event_ids": [post_join_event_id],
        "require_decrypted": [post_join_event_id],
        "timeout_s": 120,
    }));
    let post_join_outcome = &collected["events"][&post_join_event_id];
    assert_eq!(
        post_join_outcome["decrypted"],
        json!(true),
        "the late joiner must decrypt a message sent after it joined. It reported: \
         {post_join_outcome}"
    );
    assert_eq!(
        post_join_outcome["body"],
        json!(POST_JOIN_PAYLOAD_BODY),
        "the late joiner must recover the post-join payload exactly -- the room key \
         reached it across federation"
    );

    // The pre-join message cannot ride the same call: it predates the join,
    // so it was handed to nio2 in the first syncs after joining -- which
    // `settle` already consumed -- and /sync never offers it again. The
    // history op is what a real late-joining client does on opening the
    // room: paginate backwards from its sync cursor (across federation, to
    // the room's origin server) and try to decrypt what it fetches. That
    // is the honest shape of the question "what can the late joiner read
    // of the history".
    let history = nio2.call(json!({
        "op": "history",
        "room_id": scope,
        "limit": 20,
        "until_found": [pre_join_event_id],
        "max_rounds": 10,
    }));
    let history_outcome = history["events"]
        .get(&pre_join_event_id)
        .unwrap_or_else(|| {
            panic!(
                "the late joiner's history backfill never surfaced the pre-join event \
             {pre_join_event_id}; the backfilled events were: {}",
                history["events"]
            )
        });
    assert_eq!(
        history_outcome["decrypted"],
        json!(false),
        "the late joiner must NOT decrypt pre-join history: megolm keys are not \
         backfilled and this library does not re-share proactively, so an event \
         that predates the join staying sealed is the spec-compliant answer. It \
         reported: {history_outcome}"
    );
    let history_reason = history_outcome["reason"].as_str().unwrap_or_else(|| {
        panic!("the late joiner must say WHY it refused the pre-join history: {history_outcome}")
    });
    assert!(
        history_reason.contains(NIO_RATCHET_REFUSAL)
            && history_reason.contains(NIO_UNKNOWN_INDEX_REFUSAL),
        "the pre-join history refusal must be vodozemac's own 'unknown message \
         index' ({NIO_UNKNOWN_INDEX_REFUSAL:?}) raised from inside the decrypt \
         ({NIO_RATCHET_REFUSAL:?}) -- that is the pinned, spec-compliant answer: \
         the key DID cross federation (the same session decrypts the post-join \
         messages) but megolm cannot ratchet backwards to the pre-join index. \
         Any other wording means something else broke. It said: {history_reason}"
    );

    // The first counterparty, in the same window: joining a third device
    // must not have disturbed the session it already held.
    let collected = nio1.call(json!({
        "op": "collect",
        "room_id": scope,
        "event_ids": [post_join_event_id],
        "require_decrypted": [post_join_event_id],
        "timeout_s": 120,
    }));
    let nio1_post_join_outcome = &collected["events"][&post_join_event_id];
    assert_eq!(
        nio1_post_join_outcome["decrypted"],
        json!(true),
        "the first counterparty must still decrypt after the third device joined. \
         It reported: {nio1_post_join_outcome}"
    );
    assert_eq!(
        nio1_post_join_outcome["body"],
        json!(POST_JOIN_PAYLOAD_BODY),
        "the first counterparty must recover the post-join payload exactly"
    );

    // ---- 10. The federated control: one corrupted ciphertext ------------
    // The same control `level_two_interop.rs` carries, kept for the
    // federated direction: a SECOND, DISTINCT event from the post-join
    // session, one character of its ciphertext flipped. A corrupted copy
    // of an already-collected event would be refused as a replayed megolm
    // index regardless of the ciphertext, which is the false pass this
    // shape exists to escape (that file's send-site comment has the whole
    // of it). Here the control additionally proves the key that crossed
    // federation authenticates what it unlocks.
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

    let collected = nio2.call(json!({
        "op": "collect",
        "room_id": scope,
        "event_ids": [corrupted_event_id],
        "require_decrypted": [],
        "timeout_s": 120,
    }));
    let corrupted_outcome = &collected["events"][&corrupted_event_id];
    assert_eq!(
        corrupted_outcome["decrypted"],
        json!(false),
        "the corrupted-ciphertext control must NOT decrypt. It did, which means \
         this test would pass whether or not the cryptography is correct: \
         {corrupted_outcome}"
    );
    let refusal = corrupted_outcome["reason"].as_str().unwrap_or_else(|| {
        panic!("the late joiner must say why it refused the control: {corrupted_outcome}")
    });
    assert!(
        refusal.contains(NIO_RATCHET_REFUSAL),
        "the control must have been refused by the megolm ratchet itself, not by \
         bookkeeping around it -- only the colon variant is a MAC failure, and it \
         is the only answer that means the key crossed federation intact. It said: \
         {refusal}"
    );

    // ---- 11. Reverse direction: the late joiner sends ---------------------
    // Its room key now leaves through server B's federation sender and must
    // arrive at BOTH pre-existing devices.
    nio2.call(json!({ "op": "settle", "rounds": 3 }));
    let nio2_sent = nio2.call(json!({
        "op": "send",
        "room_id": scope,
        "body": FEDERATED_PAYLOAD_BODY,
    }));
    let nio2_event_id = nio2_sent["event_id"]
        .as_str()
        .expect("the federated counterparty reports the id it sent")
        .to_string();

    let mut new_sessions = 0u32;
    let mut to_device_events = 0u32;
    let mut nio2_raw_event: Option<Value> = None;
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline && (nio2_raw_event.is_none() || new_sessions == 0) {
        let payload = homeserver.ok(
            "GET",
            &format!(
                "/_matrix/client/v3/sync?timeout=8000&since={}",
                encode_segment(&since)
            ),
            Some(&library.token),
            None,
        );
        since = payload["next_batch"]
            .as_str()
            .expect("a /sync response carries a next_batch")
            .to_string();
        let outcome = run(receive_sync_changes(
            &encryption_slice(&payload).to_string(),
        ))
        .expect("a real /sync payload must be accepted");
        new_sessions += outcome.new_session_count;
        to_device_events += outcome.to_device_event_count;

        if let Some(events) = payload["rooms"]["join"][&scope]["timeline"]["events"].as_array() {
            for event in events {
                if event["event_id"].as_str() == Some(nio2_event_id.as_str()) {
                    nio2_raw_event = Some(event.clone());
                }
            }
        }
    }
    assert!(
        to_device_events > 0,
        "server A must have delivered the late joiner's to-device messages through \
         /sync -- they left server B through its federation sender -- and \
         receiveSyncChanges must have processed them"
    );
    assert!(
        new_sessions > 0,
        "receiveSyncChanges must have recovered the late joiner's inbound group \
         session from a key that crossed federation; it reported {new_sessions} \
         across {to_device_events} processed to-device events"
    );
    let nio2_raw_event = nio2_raw_event
        .expect("the late joiner's own encrypted event must arrive in the library's /sync");
    let recovered = run(decrypt_event(
        &scope,
        &nio2_raw_event.to_string(),
        SenderTrustRequirement::Any,
    ))
    .expect("the library must decrypt what the federated device encrypted");
    let plaintext: Value = serde_json::from_slice(&recovered.ciphertext)
        .expect("a decrypted content is well-formed JSON");
    assert_eq!(
        plaintext["body"],
        json!(FEDERATED_PAYLOAD_BODY),
        "the library must recover the late joiner's payload exactly"
    );
    assert_eq!(
        recovered.sender, federated_user,
        "the decrypted event's sender must be the federated user itself -- this is \
         the assertion that distinguishes 'a third device of the library's account' \
         from 'a genuinely different user on a different server'"
    );

    // And the first counterparty decrypts the same federated message: the
    // late joiner shared with every device it knew about, not only the
    // library's.
    let collected = nio1.call(json!({
        "op": "collect",
        "room_id": scope,
        "event_ids": [nio2_event_id],
        "require_decrypted": [nio2_event_id],
        "timeout_s": 120,
    }));
    let nio1_federated_outcome = &collected["events"][&nio2_event_id];
    assert_eq!(
        nio1_federated_outcome["decrypted"],
        json!(true),
        "the first counterparty must decrypt the late joiner's message too. It \
         reported: {nio1_federated_outcome}"
    );
    assert_eq!(
        nio1_federated_outcome["body"],
        json!(FEDERATED_PAYLOAD_BODY),
        "the first counterparty must recover the late joiner's payload exactly -- \
         the late joiner's key reached server A's devices across federation"
    );

    // ---- Tidy up ----------------------------------------------------------
    // nio1's device is on the library's account and is removed by the
    // guard's `/delete_devices` fallback if its own logout does not get
    // there first; nio2's device is a different user on server B and is
    // removed by its own logout alone (the guard cannot reach it -- see
    // the declaration above). The room and the library's device go with
    // the guard's `Drop`.
    nio2.call(json!({ "op": "quit" }));
    nio1.call(json!({ "op": "quit" }));
    teardown.counterparty_logged_itself_out();
}
