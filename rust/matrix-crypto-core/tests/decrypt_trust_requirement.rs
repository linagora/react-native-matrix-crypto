//! The trust decision `decrypt_event` hands the caller, held against the
//! sender that every tightened tier exists to refuse: a device no identity
//! vouches for.
//!
//! # Why this file exists separately from `two_parties.rs`
//!
//! This library holds **one** crypto machine per process (design doc
//! section 8), and an integration test binary is one process. `two_parties.rs`
//! already creates the machine for its own fixture, so the test here cannot
//! live in the same file -- a second `create_machine` in the same process is
//! refused as `AlreadyInitialised`, and no test may reach for the
//! `#[cfg(test)]` reset helpers from outside the crate. One machine per
//! test binary is the discipline every multi-party file in `tests/` keeps.
//!
//! The fixture itself is the same shape `two_parties.rs` walks in full:
//! Alice is the library, Bob is a bare `matrix_sdk_crypto::OlmMachine`
//! standing in for a third-party client, and neither side carries a
//! cross-signing identity -- which is exactly the condition under which the
//! two tightened [`matrix_crypto_core::SenderTrustRequirement`] tiers must
//! refuse, and the one under which the default must keep decrypting.
//!
//! What this file deliberately does **not** cover is a tightened tier
//! accepting anything: that needs a sender with a published identity, which
//! is `verified_sender.rs`'s fixture and not this file's.
//!
//! # The key travels through the pump, not through this test's own hands
//!
//! The same rule `two_parties.rs` states for itself applies here: Bob's
//! group key reaches Alice through a claim of her published one-time key
//! and a to-device message relayed the way a homeserver relays it, never by
//! any shortcut.

use matrix_crypto_core::{
    create_machine, decrypt_event, in_runtime, mark_request_sent, receive_sync_changes,
    share_scope_key, take_outgoing_requests, MachineConfig, SenderTrustRequirement, SessionError,
};
use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::Response as KeysClaimResponse;
use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
use matrix_sdk_common::ruma::api::IncomingResponse;
use matrix_sdk_common::ruma::events::AnyMessageLikeEventContent;
use matrix_sdk_common::ruma::exports::http;
use matrix_sdk_common::ruma::serde::Raw;
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId, TransactionId};
use matrix_sdk_crypto::types::requests::AnyOutgoingRequest;
use matrix_sdk_crypto::{EncryptionSettings, OlmMachine};

const SCOPE: &str = "!trust-requirement:example.org";
const ALICE_USER: &str = "@alice:example.org";
const ALICE_DEVICE: &str = "ALICEDEVICE";
const BOB_USER: &str = "@bob:example.org";
const BOB_DEVICE: &str = "BOBDEVICE";
const BOB_PAYLOAD: &str = r#"{"body":"sent by the bare machine","msgtype":"m.text"}"#;

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

/// The top-level `event_type` a to-device request's JSON body declares,
/// copied from `two_parties.rs` for the reason stated there: `kind ==
/// "to_device"` is true of a withheld notice and of the key itself alike.
fn declared_event_type(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<no event_type in body>".to_string())
}

/// Turns one to-device request body into the to-device event the addressed
/// device would have received from its homeserver -- the same relay
/// `two_parties.rs` uses, doing no more than a homeserver does.
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
/// homeserver would have delivered, as in `two_parties.rs`.
fn room_event(sender: &str, event_id: &str, content: &str) -> String {
    let content: serde_json::Value =
        serde_json::from_str(content).expect("an encrypted content is well-formed JSON");
    serde_json::json!({
        "sender": sender,
        "type": "m.room.encrypted",
        "event_id": event_id,
        "origin_server_ts": 1_700_000_000_000u64,
        "content": content,
    })
    .to_string()
}

/// Bob's device keys and one one-time key, out of his own upload batch.
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

#[test]
fn a_tightened_sender_trust_requirement_refuses_an_unsigned_sender() {
    // Bound here, dropped when this function returns: the store must not
    // outlive the test, for the reason `two_parties.rs` states.
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    futures::executor::block_on(in_runtime(async move {
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
        // it design doc section 3bis is named for. Bob's go out through his
        // own machine's requests, and are his real, self-signed ones.
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

        let bob_batch = bob
            .outgoing_requests()
            .await
            .expect("a fresh bare machine has keys to publish");
        let (bob_device_keys, _, _) = published_keys(&bob_batch);
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

        // ---- Alice learns Bob's device exists --------------------------
        // The first `share_scope_key` delivers nothing -- no device of
        // Bob's is known yet -- and is what makes the machine ask about him
        // at all, for the reason `two_parties.rs` records. With no identity
        // on either side the collect strategy is `AllDevices` either way,
        // so this share behaves exactly as it always has.
        share_scope_key(SCOPE, &[BOB_USER.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let query = take_outgoing_requests()
            .await
            .expect("the pump must be drainable")
            .into_iter()
            .find(|r| r.kind == "keys_query")
            .expect("the machine must ask who exists before it can decrypt from anyone");
        mark_request_sent(
            &query.id,
            &query_body(BOB_USER, BOB_DEVICE, &bob_device_keys),
        )
        .await
        .expect("a keys-query response must be accepted");

        // The mirror image, on the bare side: Bob learns Alice's device, so
        // he has something to claim a one-time key from below. Driven
        // directly, since Bob is not the library.
        bob.mark_request_as_sent(
            &TransactionId::new(),
            &keys_query_response(&query_body(ALICE_USER, ALICE_DEVICE, &alice_device_keys)),
        )
        .await
        .expect("the bare machine must accept a keys-query response");

        // ---- Bob opens his session and sends his group key -------------
        // Claimed before any inbound session exists for him, for the reason
        // `two_parties.rs` states; then the key itself, relayed as the
        // to-device event a homeserver would deliver.
        let (bob_claim_id, _) = bob
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
             its session key to the library's device"
        );
        receive_sync_changes(
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

        let content = Raw::<AnyMessageLikeEventContent>::from_json_string(BOB_PAYLOAD.to_owned())
            .expect("a literal payload is well-formed JSON");
        let bob_encrypted = bob
            .encrypt_room_event_raw(&room_id, "m.room.message", &content)
            .await
            .expect("the bare machine must be able to encrypt for its own session");
        let bob_event = room_event(
            BOB_USER,
            "$trust-requirement:example.org",
            bob_encrypted.content.json().get(),
        );

        // ---- The same ciphertext, three requirements -------------------

        // The control: the permissive default keeps decrypting, which is
        // the behaviour every caller before the requirement existed has.
        let permissive = decrypt_event(SCOPE, &bob_event, SenderTrustRequirement::Any)
            .await
            .expect("the default requirement must keep decrypting an unsigned sender");
        assert!(
            permissive.ciphertext == BOB_PAYLOAD.as_bytes(),
            "the control must recover the plaintext before the refusals below \
             mean anything"
        );

        // The tightened tiers refuse it, and refuse it as its own kind: a
        // policy gap, not a broken event -- the split `SessionError`'s doc
        // comment describes as B8, dispatched now that the requirement is
        // the caller's to choose.
        let strict = decrypt_event(SCOPE, &bob_event, SenderTrustRequirement::IdentitySigned)
            .await
            .expect_err("the strictest requirement must refuse an unsigned sender");
        assert_eq!(
            strict,
            SessionError::SenderNotTrusted,
            "a sender that does not clear the requirement is a policy gap, \
             reported as `SenderNotTrusted` -- `UnknownDevice` would tell a \
             product its event's provenance is broken, which is the opposite \
             of the truth here"
        );

        let legacy_tier = decrypt_event(
            SCOPE,
            &bob_event,
            SenderTrustRequirement::IdentitySignedOrLegacy,
        )
        .await
        .expect_err("the legacy-tolerant requirement must refuse an unsigned sender too");
        assert_eq!(
            legacy_tier,
            SessionError::SenderNotTrusted,
            "a session created with trust information collected is not a legacy \
             session, so the legacy escape does not apply and the refusal is the \
             same kind as the strict tier's"
        );

        // Decryption failure under a tightened requirement is repeatable,
        // not consuming: the same event still decrypts under the default,
        // after the two refusals, on a machine nothing has changed about.
        let still_there = decrypt_event(SCOPE, &bob_event, SenderTrustRequirement::Any)
            .await
            .expect("a refused decryption must not consume the session");
        assert!(
            still_there.ciphertext == BOB_PAYLOAD.as_bytes(),
            "the refusals above must leave the event decryptable, or a product \
             retrying under a relaxed requirement would fail for a reason of \
             this library's making"
        );
    }));
}
