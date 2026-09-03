//! Level 1 interoperability: two parties in one process (design doc section 8).
//!
//! # Which side is the library, and which is not
//!
//! This library holds **one** crypto machine per process, behind the
//! process-wide registry in `machine.rs`. Two parties therefore cannot both
//! be created through `create_machine`, and this test does not pretend
//! otherwise:
//!
//! * **Alice is the library.** Every operation attributed to her goes
//!   through this crate's public surface and nothing else --
//!   `create_machine`, `receive_sync_changes`, `share_scope_key`,
//!   `take_outgoing_requests`, `mark_request_sent`, `encrypt_event`,
//!   `decrypt_event` -- against the one registered machine, with a real
//!   SQLite store on disk.
//! * **Bob is a bare `matrix_sdk_crypto::OlmMachine`**, constructed and
//!   driven directly, exactly the way `matrix-sdk-crypto`'s own tests
//!   construct a second party. No crypto state, no store and no function of
//!   this crate is involved on his side; the single exception is that his
//!   calls, like everything else in this test, run inside
//!   `matrix_crypto_core::in_runtime`, which is a tokio runtime context and
//!   nothing more -- it is there because upstream's `share_room_key`
//!   reaches `tokio::task::spawn` on his side too, and this crate happens to
//!   own the only runtime in the process. He stands in for the third-party
//!   client that level 2 will use for real.
//!
//! Read every assertion with that asymmetry in mind: what this test proves
//! is that *the library* can deliver a key to, and read an event from, a
//! machine it does not control -- not that two copies of the library agree
//! with each other, which would be the weaker claim a symmetric setup makes.
//!
//! # The key travels through the pump, not through this test's own hands
//!
//! Spec section 10 requires the group key to reach the other party through
//! `take_outgoing_requests`/`mark_request_sent` rather than being handed
//! over directly, because a test that shortcuts the pump proves the
//! cryptography while hiding whether the delivery mechanism works -- the
//! exact gap design doc section 3bis was written about. So every request
//! leaving Alice is drained from the pump, and the one carrying the session
//! key is delivered to Bob as the to-device event a homeserver would have
//! relayed, and then marked sent.
//!
//! # Ordering (design doc section 3ter)
//!
//! A group key travels wrapped in an Olm session, and an Olm session does
//! not exist until a one-time key has been claimed. So: `/keys/query`, then
//! `/keys/claim`, then the key-carrying `/sendToDevice`. Skipping the claim
//! does not fail loudly -- it produces an `m.room_key.withheld` notice with
//! code `m.no_olm`, a successful-looking to-device request whose content
//! says the key could not be sent. This test therefore asserts on the
//! **decoded event type** of every to-device body it cares about, never on
//! `kind == "to_device"` alone: a review already found that exact assertion
//! passing on a withheld notice while nothing was being delivered at all.

use std::collections::BTreeMap;

use matrix_crypto_core::{
    create_machine, decrypt_event, device_statuses, encrypt_event, in_runtime, mark_request_sent,
    receive_sync_changes, share_scope_key, take_outgoing_requests, with_machine, MachineConfig,
    OutgoingRequest, SenderTrustRequirement, SenderVerification, TrustState,
};
use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::Response as KeysClaimResponse;
use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
use matrix_sdk_common::ruma::api::client::sync::sync_events::DeviceLists;
use matrix_sdk_common::ruma::api::IncomingResponse;
use matrix_sdk_common::ruma::events::{AnyMessageLikeEventContent, AnyToDeviceEvent};
// `exports::http`, not a direct `http` dependency: the exact version ruma's
// own `IncomingResponse::try_from_http_response` requires, reached through
// ruma's re-export -- the same reasoning `session.rs` documents for itself.
use matrix_sdk_common::ruma::exports::http;
use matrix_sdk_common::ruma::serde::Raw;
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId, TransactionId};
use matrix_sdk_crypto::types::requests::AnyOutgoingRequest;
use matrix_sdk_crypto::{
    DecryptionSettings, EncryptionSettings, EncryptionSyncChanges, LocalTrust, OlmMachine,
    TrustRequirement,
};

const SCOPE: &str = "!interop:example.org";
const ALICE_USER: &str = "@alice:example.org";
const ALICE_DEVICE: &str = "ALICEDEVICE";
const BOB_USER: &str = "@bob:example.org";
const BOB_DEVICE: &str = "BOBDEVICE";
/// A user id nobody in this test has any device under.
///
/// Used to re-address an event the other party genuinely encrypted, which
/// is the whole of what an impersonating homeserver has to do: the
/// ciphertext, the session and the sender key are untouched and still
/// decrypt, and only the envelope's claim about who sent it is a lie.
const CLAIMED_OTHER_SENDER: &str = "@carol:example.org";

/// Distinct per direction, deliberately: a test using one payload for both
/// directions could pass while only ever proving one machine's own
/// self-round-trip, which `session.rs` already covers and which is not what
/// this file is for. Keys in ascending byte order so the byte-for-byte
/// comparison does not additionally depend on serde's map ordering.
const ALICE_PAYLOAD: &str = r#"{"body":"sent by the library machine","msgtype":"m.text"}"#;
const BOB_PAYLOAD: &str = r#"{"body":"sent by the bare machine","msgtype":"m.text"}"#;

/// The fields this test reads out of a decrypted event. `content` is a
/// `RawValue`, not a `serde_json::Value`, so the comparison against the
/// original payload is byte-for-byte rather than "equal after a round trip
/// through a value tree that may reorder keys".
#[derive(serde::Deserialize)]
struct DecryptedFields {
    content: Box<serde_json::value::RawValue>,
}

/// A fixed-shape 200 response, the form ruma's own
/// `IncomingResponse::try_from_http_response` expects.
fn http_ok(body: &str) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(200)
        .body(body.as_bytes().to_vec())
        .expect("a fixed-shape http::Response with no custom headers cannot fail to build")
}

fn keys_upload_response(body: &str) -> KeysUploadResponse {
    KeysUploadResponse::try_from_http_response(http_ok(body))
        .expect("this test builds its own well-formed keys-upload response")
}

fn keys_query_response(body: &str) -> KeysQueryResponse {
    KeysQueryResponse::try_from_http_response(http_ok(body))
        .expect("this test builds its own well-formed keys-query response")
}

fn keys_claim_response(body: &str) -> KeysClaimResponse {
    KeysClaimResponse::try_from_http_response(http_ok(body))
        .expect("this test builds its own well-formed keys-claim response")
}

/// The top-level `event_type` a to-device request's JSON body declares.
///
/// The whole point of this helper: `kind == "to_device"` is true of an
/// `m.room_key.withheld` notice and of the key itself alike, so no assertion
/// in this file is allowed to stop at `kind`. Design doc section 3ter.
fn declared_event_type(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<no event_type in body>".to_string())
}

/// Turns one to-device request body into the to-device event the addressed
/// device would have received from its homeserver.
///
/// This is the only place this test "relays" anything, and it does no more
/// than a homeserver does: it reads the per-recipient content out of the
/// request the pump produced, and wraps it with the sender and type the
/// request itself declares. It does not reach into either machine.
fn relay_to(body: &str, sender: &str, user_id: &str, device_id: &str) -> Option<String> {
    let request: serde_json::Value = serde_json::from_str(body).ok()?;
    let event_type = request.get("event_type")?.as_str()?;
    let content = request.get("messages")?.get(user_id)?.get(device_id)?;
    Some(
        serde_json::json!({
            "sender": sender,
            "type": event_type,
            "content": content,
        })
        .to_string(),
    )
}

/// Wraps an encrypted content in the surrounding `m.room.encrypted` event a
/// homeserver would have delivered. `event_id` and `origin_server_ts` are
/// required by upstream's own `EncryptedEvent` shape; neither is read by
/// anything this test asserts on.
fn room_event(sender: &str, event_id: &str, content: &str) -> String {
    let content: serde_json::Value =
        serde_json::from_str(content).expect("an encrypted content is well-formed JSON");
    serde_json::json!({
        "sender": sender,
        "event_id": event_id,
        "origin_server_ts": 1_700_000_000_000u64,
        "content": content,
    })
    .to_string()
}

/// The device keys and one one-time key a fresh bare machine wants published.
///
/// Read from the machine's own outgoing key upload, not fabricated: the
/// one-time key must carry a real signature by that account, or the claiming
/// side rejects it and no Olm session is ever established.
fn published_keys(
    requests: &[matrix_sdk_crypto::types::requests::OutgoingRequest],
) -> (serde_json::Value, String, serde_json::Value) {
    let device_keys = requests
        .iter()
        .find_map(|r| match r.request() {
            AnyOutgoingRequest::KeysUpload(u) => u.device_keys.clone(),
            _ => None,
        })
        .expect("a fresh machine always has device keys to upload");
    let (key_id, key) = requests
        .iter()
        .find_map(|r| match r.request() {
            AnyOutgoingRequest::KeysUpload(u) => u
                .one_time_keys
                .iter()
                .next()
                .map(|(id, k)| (id.clone(), k.clone())),
            _ => None,
        })
        .expect("a fresh machine always has one-time keys to upload");

    (
        serde_json::to_value(&device_keys).expect("upstream device keys serialise"),
        key_id.to_string(),
        serde_json::to_value(&key).expect("an upstream one-time key serialises"),
    )
}

/// `{"one_time_keys": {user: {device: {key_id: key}}}}`, the `/keys/claim`
/// response shape.
fn claim_body(user_id: &str, device_id: &str, key_id: &str, key: &serde_json::Value) -> String {
    serde_json::json!({
        "one_time_keys": { user_id: { device_id: { key_id: key } } }
    })
    .to_string()
}

/// `{"device_keys": {user: {device: keys}}}`, the `/keys/query` response shape.
fn query_body(user_id: &str, device_id: &str, device_keys: &serde_json::Value) -> String {
    serde_json::json!({ "device_keys": { user_id: { device_id: device_keys } } }).to_string()
}

/// M2 verifies no device, so both machines decrypt with upstream's most
/// permissive trust requirement -- the same deliberate placeholder
/// `session.rs`'s own `decryption_settings()` documents, mirrored here so
/// Bob is held to the same standard the library holds itself to.
fn decryption_settings() -> DecryptionSettings {
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

/// Hands `events` to the bare machine as a sync would.
async fn deliver_to_bare(bob: &OlmMachine, events: Vec<String>) -> usize {
    let to_device_events: Vec<Raw<AnyToDeviceEvent>> = events
        .into_iter()
        .map(|event| {
            Raw::from_json_string(event).expect("this test builds its own well-formed event")
        })
        .collect();
    let changed_devices = DeviceLists::default();
    let counts = BTreeMap::new();

    let (_processed, room_keys) = bob
        .receive_sync_changes(
            EncryptionSyncChanges {
                to_device_events,
                changed_devices: &changed_devices,
                one_time_keys_counts: &counts,
                unused_fallback_keys: None,
                next_batch_token: None,
            },
            &decryption_settings(),
        )
        .await
        .expect("the bare machine must accept a sync it is the addressee of");

    room_keys.len()
}

/// The whole milestone in one test: a group key crosses from the library to
/// a machine it does not control and back, through the pump, and each side
/// recovers exactly what the other encrypted.
///
/// One `#[test]` fn, not several: the machine registry and the pump's
/// request bookkeeping are both process-wide, and an integration test has no
/// access to the `#[cfg(test)]` reset helpers `machine.rs` and `session.rs`
/// keep for their own unit tests. Cargo gives each file under `tests/` its
/// own process, so this file owns one machine for its whole lifetime and
/// cannot race a sibling test for it.
///
/// Driven by `futures::executor::block_on`, not `#[tokio::test]`: no test
/// harness supplies a runtime here, so what runtime there is comes from this
/// crate.
///
/// That is a weaker property than "no ambient runtime", and the difference
/// is worth being exact about. The whole body is wrapped in `in_runtime`,
/// because the *bare* machine needs a tokio context that this crate does not
/// supply for it -- upstream's `share_room_key` reaches
/// `tokio::task::spawn`. So every library call inside this test does see a
/// runtime context, and this test would therefore **not** catch a library
/// function that forgot its own `in_runtime`. Two other tests do:
/// `machine.rs`'s `with_machine_supplies_a_runtime_for_store_touching_calls`
/// and `tests/pump_eviction.rs`, which drives only library calls and so can
/// enter with genuinely nothing.
#[test]
fn two_parties_exchange_a_group_key_and_each_decrypts_what_the_other_encrypted() {
    // Bound here, dropped when this function returns: the store must not
    // outlive the test. `TempDir::keep` -- which `session.rs`'s own
    // `test_config` helper calls, deliberately, for a reason that does not
    // apply here -- would leave it on disk.
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
        // ---- The two parties -------------------------------------------
        create_machine(MachineConfig {
            user_id: ALICE_USER.to_string(),
            device_id: ALICE_DEVICE.to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        let alice_user: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
        let bob_user: OwnedUserId = BOB_USER.parse().expect("a literal user id parses");
        let bob_device: OwnedDeviceId = BOB_DEVICE.into();
        let bob = OlmMachine::new(&bob_user, &bob_device).await;
        let room_id: OwnedRoomId = SCOPE.parse().expect("a literal room id parses");

        // ---- Both parties publish their keys ---------------------------
        // Alice's go out through the library's pump, which is the half of
        // it design doc section 3bis is named for: without this, the
        // device is invisible and nobody can ever claim a key from it.
        let alice_batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let alice_upload = alice_batch
            .iter()
            .find(|r| r.kind == "keys_upload")
            .expect("a fresh machine must have keys to publish");
        let alice_upload_body: serde_json::Value = serde_json::from_str(&alice_upload.body)
            .expect("the pump's own body is well-formed JSON");
        let alice_device_keys = alice_upload_body
            .get("device_keys")
            .cloned()
            .expect("a fresh machine's upload carries its device keys");
        let (alice_key_id, alice_key) = alice_upload_body
            .get("one_time_keys")
            .and_then(serde_json::Value::as_object)
            .and_then(|keys| keys.iter().next())
            .map(|(id, key)| (id.clone(), key.clone()))
            .expect("a fresh machine's upload carries one-time keys");
        mark_request_sent(&alice_upload.id, r#"{"one_time_key_counts":{}}"#)
            .await
            .expect("a keys-upload response must be accepted");

        // Bob's go out through his own machine's requests, which is not
        // this crate's pump and is not what this test is proving -- it is
        // only how a homeserver would have obtained the keys Alice claims
        // below. They must be his real, self-signed ones: a fabricated
        // one-time key is rejected on claim and no Olm session is formed.
        let bob_batch = bob
            .outgoing_requests()
            .await
            .expect("a fresh bare machine has keys to publish");
        let (bob_device_keys, bob_key_id, bob_key) = published_keys(&bob_batch);
        let bob_upload_id = bob_batch
            .iter()
            .find(|r| matches!(r.request(), AnyOutgoingRequest::KeysUpload(_)))
            .expect("a fresh bare machine has a key upload")
            .request_id()
            .to_owned();
        bob.mark_request_as_sent(
            &bob_upload_id,
            &keys_upload_response(r#"{"one_time_key_counts":{}}"#),
        )
        .await
        .expect("the bare machine must accept its own upload response");

        // ---- Step 1 of 3ter: /keys/query -------------------------------
        // Alice learns Bob's device exists.
        //
        // This first `share_scope_key` cannot deliver anything -- no device
        // of Bob's is known yet -- and that is the point: it is what makes
        // the machine ask about him at all. `share_scope_key` tracks the
        // users it is given, because upstream's own
        // `mark_tracked_users_as_changed` (store/mod.rs:291) **skips every
        // user it has never seen**, and a sync's `changed_devices` list
        // routes nowhere else. Without the tracking, no call on the shipped
        // surface could ever get a `/keys/query` issued for a user this
        // device has not already encrypted to.
        share_scope_key(SCOPE, &[BOB_USER.to_string()])
            .await
            .expect("sharing a scope key must not fail");

        // Kept, and now honest about what it does: Bob is already tracked
        // by the call above, so this only re-flags him -- which is the only
        // thing a `changed_devices` list can ever do. It is here because a
        // real product receives these constantly and the library must
        // accept them, not because this step depends on it.
        receive_sync_changes(&format!(
            r#"{{"changed_devices":{{"changed":["{BOB_USER}"],"left":[]}}}}"#
        ))
        .await
        .expect("a device-list change must be accepted");

        let query = take_outgoing_requests()
            .await
            .expect("the pump must be drainable")
            .into_iter()
            .find(|r| r.kind == "keys_query")
            .expect("the machine must ask who exists before it can encrypt to anyone");
        // Parsed, not substring-matched: the users a `/keys/query` asks
        // about are the keys of its `device_keys` object, and asserting on
        // that structure survives a body-shape change upstream that a
        // `contains` would silently keep passing. This batch's query
        // legitimately names this machine's own user as well (upstream
        // flagged it on the first pump call above, and that request was
        // never marked sent), so membership is what is checked, not
        // equality: what matters is that the other party is in there at
        // all. Without it, the response below would be teaching the machine
        // about a device it never asked for, and this step would prove
        // nothing.
        let queried: Vec<String> = serde_json::from_str::<serde_json::Value>(&query.body)
            .ok()
            .and_then(|body| {
                Some(
                    body.get("device_keys")?
                        .as_object()?
                        .keys()
                        .cloned()
                        .collect(),
                )
            })
            .expect("a keys-query body always carries a device_keys object");
        assert!(
            queried.iter().any(|user| user == BOB_USER),
            "the query the pump hands out must ask about the other party"
        );
        mark_request_sent(
            &query.id,
            &query_body(BOB_USER, BOB_DEVICE, &bob_device_keys),
        )
        .await
        .expect("a keys-query response must be accepted");

        // The mirror image, on the bare side: Bob learns Alice's device.
        // Driven directly, since Bob is not the library.
        bob.mark_request_as_sent(
            &TransactionId::new(),
            &keys_query_response(&query_body(ALICE_USER, ALICE_DEVICE, &alice_device_keys)),
        )
        .await
        .expect("the bare machine must accept a keys-query response");

        // ---- Step 2 of 3ter: /keys/claim -------------------------------
        // Sharing now, before any Olm session exists, is the trap: it
        // succeeds, and produces to-device requests that carry a refusal
        // rather than the key. Asserted on the decoded event type, which is
        // the only thing that tells the two apart.
        share_scope_key(SCOPE, &[BOB_USER.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let before_claim = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let refusals: Vec<String> = before_claim
            .iter()
            .filter(|r| r.kind == "to_device")
            .map(|r| declared_event_type(&r.body))
            .collect();
        assert_eq!(
            refusals,
            vec!["m.room_key.withheld".to_string()],
            "before a one-time key is claimed there is no Olm session, so the only \
             thing a share can produce is a notice that the key was not sent -- if \
             this is ever the key itself, section 3ter's ordering has changed"
        );

        let claim_id = before_claim
            .into_iter()
            .find(|r| r.kind == "keys_claim")
            .expect("sharing to a device with no Olm session must queue a keys claim")
            .id;
        mark_request_sent(
            &claim_id,
            &claim_body(BOB_USER, BOB_DEVICE, &bob_key_id, &bob_key),
        )
        .await
        .expect("a keys-claim response must be accepted");

        // The mirror image again, on the bare side: Bob claims one of the
        // library's one-time keys, so he has a session of his own to send
        // his own group key over in direction 2 below. Claimed here rather
        // than there because by then he would already have an inbound Olm
        // session, created for him by the very message direction 1 sends --
        // upstream would report nothing missing, and the claim this
        // milestone is about would silently not happen.
        let (bob_claim_id, _bob_claim_request) = bob
            .get_missing_sessions(std::iter::once(alice_user.as_ref()))
            .await
            .expect("the bare machine must be able to report missing sessions")
            .expect("the bare machine has no Olm session to the library's device yet");
        bob.mark_request_as_sent(
            &bob_claim_id,
            &keys_claim_response(&claim_body(
                ALICE_USER,
                ALICE_DEVICE,
                &alice_key_id,
                &alice_key,
            )),
        )
        .await
        .expect("the bare machine must accept a keys-claim response");

        // ---- Step 3 of 3ter: the key itself ----------------------------
        share_scope_key(SCOPE, &[BOB_USER.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let after_claim = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let carrying_the_key: Vec<&OutgoingRequest> = after_claim
            .iter()
            .filter(|r| r.kind == "to_device" && declared_event_type(&r.body) == "m.room.encrypted")
            .collect();
        assert_eq!(
            carrying_the_key.len(),
            1,
            "after the claim exactly one to-device request must carry the session \
             key; a count of zero means the claim did not take effect, and the \
             earlier withheld notice is still in the batch as well because it was \
             never marked sent"
        );

        // Relayed to Bob exactly as a homeserver would, then marked sent --
        // this is the pump requirement of spec section 10, and the reason
        // this test is not allowed to hand Bob the key directly.
        let key_request = carrying_the_key[0];
        let relayed = relay_to(&key_request.body, ALICE_USER, BOB_USER, BOB_DEVICE)
            .expect("the key-carrying request must address the device it was shared with");
        let new_sessions = deliver_to_bare(&bob, vec![relayed]).await;
        assert_eq!(
            new_sessions, 1,
            "the relayed to-device message must give the bare machine exactly one \
             new inbound group session"
        );
        mark_request_sent(&key_request.id, "{}")
            .await
            .expect("a to-device response must be accepted");

        // ---- Direction 1: the library encrypts, the bare machine reads --
        let alice_envelope = encrypt_event(SCOPE, "m.room.message", ALICE_PAYLOAD)
            .await
            .expect("encryption must succeed once a session exists");
        let alice_content = String::from_utf8(alice_envelope.ciphertext)
            .expect("an encrypted content is well-formed UTF-8 JSON");
        let alice_event = room_event(ALICE_USER, "$from-library:example.org", &alice_content);
        let raw: Raw<matrix_sdk_crypto::types::events::room::encrypted::EncryptedEvent> =
            Raw::from_json_string(alice_event).expect("this test builds its own well-formed event");
        let decrypted = bob
            .decrypt_room_event(&raw, &room_id, &decryption_settings())
            .await
            .expect("the bare machine must decrypt what the library encrypted");
        let recovered: DecryptedFields = serde_json::from_str(decrypted.event.json().get())
            .expect("a decrypted event carries a content");
        assert!(
            recovered.content.get().as_bytes() == ALICE_PAYLOAD.as_bytes(),
            "the bare machine must recover the library's payload byte for byte \
             (recovered {} bytes, sent {} bytes)",
            recovered.content.get().len(),
            ALICE_PAYLOAD.len()
        );

        // ---- Direction 2: the bare machine encrypts, the library reads --
        let bob_shares = bob
            .share_room_key(
                &room_id,
                std::iter::once(alice_user.as_ref()),
                EncryptionSettings::default(),
            )
            .await
            .expect("the bare machine must be able to share its own group key");
        let bob_key_events: Vec<String> = bob_shares
            .iter()
            .map(|request| {
                serde_json::to_string(request.as_ref())
                    .expect("an upstream to-device request serialises")
            })
            .filter(|body| declared_event_type(body) == "m.room.encrypted")
            .filter_map(|body| relay_to(&body, BOB_USER, ALICE_USER, ALICE_DEVICE))
            .collect();
        assert_eq!(
            bob_key_events.len(),
            1,
            "the bare machine must produce exactly one to-device message carrying \
             its session key to the library's device; zero means it produced a \
             withheld notice instead, the same 3ter failure in the other direction"
        );

        let outcome = receive_sync_changes(
            &serde_json::json!({
                "to_device_events": bob_key_events
                    .iter()
                    .map(|e| serde_json::from_str::<serde_json::Value>(e)
                        .expect("this test builds its own well-formed event"))
                    .collect::<Vec<_>>()
            })
            .to_string(),
        )
        .await
        .expect("the library must accept a sync carrying a room key");
        assert_eq!(
            outcome.new_session_count, 1,
            "the relayed to-device message must give the library exactly one new \
             inbound group session"
        );

        let content = Raw::<AnyMessageLikeEventContent>::from_json_string(BOB_PAYLOAD.to_owned())
            .expect("a literal payload is well-formed JSON");
        let bob_encrypted = bob
            .encrypt_room_event_raw(&room_id, "m.room.message", &content)
            .await
            .expect("the bare machine must be able to encrypt for its own session");
        let bob_event = room_event(
            BOB_USER,
            "$from-bare-machine:example.org",
            bob_encrypted.content.json().get(),
        );
        let library_envelope = decrypt_event(SCOPE, &bob_event, SenderTrustRequirement::Any)
            .await
            .expect("the library must decrypt what the bare machine encrypted");

        assert!(
            library_envelope.ciphertext == BOB_PAYLOAD.as_bytes(),
            "the library must recover the bare machine's payload byte for byte \
             (recovered {} bytes, sent {} bytes)",
            library_envelope.ciphertext.len(),
            BOB_PAYLOAD.len()
        );
        assert_eq!(library_envelope.event_type, "m.room.message");
        assert!(
            library_envelope.scope == SCOPE,
            "the decrypted envelope must carry back the scope it was decrypted for"
        );
        assert!(
            library_envelope.sender == BOB_USER,
            "the decrypted envelope's sender must be the other party, not this one \
             -- unauthenticated transport metadata, per spec section 7.1, but it \
             must at least be the value the event carried"
        );
        assert!(
            !library_envelope.algorithm.is_empty(),
            "the algorithm tag must be populated"
        );

        // ---- What upstream knew about each sender ----------------------
        //
        // Three decryptions, then -- separately, and deliberately in that
        // order -- what each one says about who sent it.
        //
        // The separation is the point. Every assertion above and in the
        // next two paragraphs is about decryption: plaintext recovered,
        // type carried, scope carried. Every assertion in the block after
        // them is about authenticity, and reads a value upstream computed
        // rather than anything this test can infer from decryption having
        // worked. Severing the wiring between the two must turn the second
        // block red and leave the first untouched; keeping them apart is
        // what makes that observable in one run instead of three.
        //
        // Nothing in *this file* cross-signs anything, so the only levels
        // available here are the ones needing no cross-signing identity on
        // either side. Read that as a fact about these fixtures and not
        // about the library: `tests/cross_signed_peer.rs` gives the
        // counterparty an identity and reaches `UnverifiedIdentity`, which
        // this build does produce. Until 0.1.0 the absence of that file was
        // read as evidence that it did not, which is how the type
        // documentation came to say so.
        //
        // This used to add that `Verified` "cannot be reached", full stop.
        // It can, since M4: `tests/verified_sender.rs` reaches it by
        // driving the whole chain, bootstrap through decryption. What is
        // true here is narrower and is the reason this file still matters.
        // Nothing in *these* fixtures bootstraps an identity, so `Verified`
        // is out of reach in this file, and this file's job is to prove
        // that the values it can reach are told apart from each other and
        // from that one. It fakes nothing to do it, which is the rule that
        // replaced the old one: nothing except the real chain produces
        // `Verified`, and holding the rungs below it is how the rest of the
        // suite says so. See `SenderVerification`'s own doc comment.

        // (2) The same ciphertext, re-addressed.
        //
        // Byte-identical content, same session, same sender key. The only
        // thing changed is the envelope's claim about who sent it, which is
        // the part a homeserver controls and cryptography does not cover.
        let readdressed_event = room_event(
            CLAIMED_OTHER_SENDER,
            "$re-addressed:example.org",
            bob_encrypted.content.json().get(),
        );
        let readdressed_envelope =
            decrypt_event(SCOPE, &readdressed_event, SenderTrustRequirement::Any)
                .await
                .expect(
                    "re-addressing an event does not stop it decrypting -- Megolm \
                 authenticates the session, not the envelope's sender claim",
                );
        assert!(
            readdressed_envelope.ciphertext == BOB_PAYLOAD.as_bytes(),
            "a re-addressed event still decrypts to the same plaintext \
             (recovered {} bytes, sent {} bytes)",
            readdressed_envelope.ciphertext.len(),
            BOB_PAYLOAD.len()
        );
        assert_eq!(readdressed_envelope.event_type, "m.room.message");
        assert!(
            readdressed_envelope.sender == CLAIMED_OTHER_SENDER,
            "the envelope carries back the sender the event claimed -- the \
             unauthenticated value the authenticity field exists to qualify"
        );

        // (3) The same event again, after the sending device is locally
        // trusted.
        //
        // `LocalTrust::Verified` is the exact state a completed short-string
        // comparison sets: upstream's own `mark_device_as_verified` calls
        // `set_trust_state(LocalTrust::Verified)` and does nothing else with
        // trust. It is set here directly, through upstream, rather than by
        // running a comparison -- `tests/sas_two_party.rs` already proves a
        // comparison reaches this state, and what is under test here is what
        // the *event* path reads once it has been reached.
        let trusted_user: OwnedUserId = BOB_USER.parse().expect("a literal user id parses");
        let trusted_device: OwnedDeviceId = BOB_DEVICE.into();
        with_machine(move |machine| {
            Box::pin(async move {
                machine
                    .get_device(&trusted_user, &trusted_device, None)
                    .await
                    .expect("the store must be readable")
                    .expect("the other party's device is known by now")
                    .set_local_trust(LocalTrust::Verified)
                    .await
                    .expect("setting local trust must not fail");
            })
        })
        .await
        .expect("the machine must be reachable");

        // The control on the last authenticity assertion below. Without
        // this, "the event still reads unsigned" would pass just as well on
        // a machine where the trust change silently did nothing.
        let statuses = device_statuses(BOB_USER)
            .await
            .expect("the other party's devices must be readable");
        assert!(
            statuses.iter().any(|status| {
                status.device_id == BOB_DEVICE && status.trust == TrustState::Verified
            }),
            "local trust must actually have taken effect, or the assertion \
             it is the control for passes for the wrong reason"
        );

        let after_trust = decrypt_event(SCOPE, &bob_event, SenderTrustRequirement::Any)
            .await
            .expect("the library must still decrypt what the bare machine encrypted");
        assert!(
            after_trust.ciphertext == BOB_PAYLOAD.as_bytes(),
            "verifying a device does not change what its events decrypt to \
             (recovered {} bytes, sent {} bytes)",
            after_trust.ciphertext.len(),
            BOB_PAYLOAD.len()
        );

        // ---- Authenticity, and nothing else, from here down ------------

        // (1) An event genuinely sent by the other party's device.
        //
        // Alice queried Bob's keys above, so his device is in her store and
        // owns the session that decrypted this. It carries no
        // cross-signature, because nothing here publishes one. That is
        // `UnsignedDevice`, and it is the ordinary case for every peer.
        assert_eq!(
            library_envelope.sender_verification,
            Some(SenderVerification::UnsignedDevice),
            "a device this machine knows, that owns the session, and that \
             carries no cross-signature is an unsigned device -- a `NoDevice*` \
             value here would mean the keys-query step above never took effect \
             and the session's sender was never identified at all"
        );

        // (2) The impersonation signal.
        assert_eq!(
            readdressed_envelope.sender_verification,
            Some(SenderVerification::MismatchedSender),
            "an event whose claimed sender is not the owner of the session \
             that encrypted it is an impersonation signal, and must not be \
             folded into its neighbours -- a product has to be able to react \
             to this case specifically"
        );
        assert_ne!(
            readdressed_envelope.sender_verification, library_envelope.sender_verification,
            "two decryptions whose upstream verification state genuinely \
             differs must surface as two different public values; equal here \
             means the public surface lost a distinction upstream made"
        );

        // (3) The one that keeps `Verified` honest without faking it.
        assert_eq!(
            after_trust.sender_verification,
            Some(SenderVerification::UnsignedDevice),
            "a device that now reports verified still sends events reading \
             `UnsignedDevice`: the event path consults cross-signing, and a \
             short-string comparison sets local trust. This message used to \
             end \"which is why `Verified` is documented as unreachable in \
             this build\", and M4 made that false while leaving this \
             assertion green, which is the failure it was warning about \
             happening to itself. `Verified` is reachable now, through the \
             whole chain in `tests/verified_sender.rs`, and a comparison \
             alone is still one step of seven, which is what this line \
             holds. It says nothing about `UnverifiedIdentity`, which this \
             build does produce and `tests/cross_signed_peer.rs` proves"
        );
    }));
}
