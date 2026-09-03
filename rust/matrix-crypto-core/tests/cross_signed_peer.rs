//! What a cross-signed counterparty makes this build report about an event.
//!
//! # The gap this file exists to close
//!
//! Every fixture in `tests/two_parties.rs` and `tests/sas_two_party.rs` is a
//! bare `OlmMachine` that never bootstrapped cross-signing, so no test in
//! this repository ever decrypted an event from a device that carried its
//! owner's signature. On that evidence the type documentation claimed three
//! of `SenderVerification`'s six values could not occur in this build. One
//! of them can, and no test could see it, because the counterparty that
//! produces it was never constructed.
//!
//! [`SenderVerification::UnverifiedIdentity`] does not depend on this
//! library holding a cross-signing identity. Upstream's gate is
//! `Device::is_cross_signed_by_owner`, and for another user's device that
//! is `device_identity.is_device_signed(self)` and nothing else: the
//! **sender's** self-signing key over the **sender's** device. This machine
//! is not consulted. The second gate,
//! `Device::is_cross_signing_trusted`, is where our own identity is read,
//! and with none it returns `false` -- which is what makes the answer
//! `SenderUnverified` rather than `SenderVerified`. So a peer who has set
//! cross-signing up, which is every Element user, already produces this
//! value against a machine that has no identity of its own.
//!
//! **This file's machine is such a machine, and that is now a property of
//! this fixture rather than of the build.** M4 gave the library
//! `bootstrap_identity`, so a machine that calls it does hold an identity,
//! and `tests/verified_sender.rs` drives one all the way to `Verified`.
//! Nothing here calls it, deliberately: what this file measures is the
//! value a peer produces against a machine that has not bootstrapped,
//! which is every product before its first bootstrap and every product
//! that never bootstraps at all. The premise is asserted against the
//! machine below rather than left to the reader.
//!
//! # Two counterparties, and why one would not do
//!
//! Bob bootstraps cross-signing and signs his own device. Carol does not.
//! Both are otherwise identical: same construction, same key publication,
//! same Olm session, same relayed group key, same payload shape. The only
//! difference between them is the self-signature on the device, so the only
//! thing that can explain two different values here is that signature.
//!
//! With Bob alone this file would pass just as well against a library that
//! answered `UnverifiedIdentity` for every peer -- which is the same class
//! of defect as the one it was written to catch, one value over. Carol is
//! the control, and her assertion is the one that fails if the mapping ever
//! collapses.
//!
//! # Which side is the library
//!
//! The asymmetry `tests/two_parties.rs` documents at length holds here too:
//! **Alice is the library**, driven only through this crate's public
//! surface against the one process-wide machine, and Bob and Carol are bare
//! upstream machines standing in for third-party clients. Nothing in this
//! file makes the library publish a cross-signing key, and one assertion
//! below states that as a fact read from the machine rather than as an
//! assumption: the value under test arrives at a machine that has never
//! bootstrapped.

use matrix_crypto_core::{
    create_machine, decrypt_event, device_statuses, in_runtime, mark_request_sent,
    receive_sync_changes, share_scope_key, take_outgoing_requests, with_machine, MachineConfig,
    SenderTrustRequirement, SenderVerification, SessionError, TrustState,
};
use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::Response as KeysClaimResponse;
use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
use matrix_sdk_common::ruma::api::IncomingResponse;
use matrix_sdk_common::ruma::events::AnyMessageLikeEventContent;
// `exports::http`, not a direct `http` dependency: the exact version ruma's
// own `IncomingResponse::try_from_http_response` requires, reached through
// ruma's re-export -- the same reasoning `session.rs` documents for itself.
use matrix_sdk_common::ruma::exports::http;
use matrix_sdk_common::ruma::serde::Raw;
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId, TransactionId};
use matrix_sdk_crypto::types::requests::AnyOutgoingRequest;
use matrix_sdk_crypto::types::DeviceKeys;
use matrix_sdk_crypto::{EncryptionSettings, OlmMachine};

const SCOPE: &str = "!cross-signed:example.org";
const ALICE_USER: &str = "@alice:example.org";
const ALICE_DEVICE: &str = "ALICEDEVICE";
/// The cross-signed peer. Bootstraps, signs his own device, publishes both.
const BOB_USER: &str = "@bob:example.org";
const BOB_DEVICE: &str = "BOBDEVICE";
/// The control. Identical in every respect except that she never bootstraps,
/// so her device carries no signature from an identity she owns.
const CAROL_USER: &str = "@carol:example.org";
const CAROL_DEVICE: &str = "CAROLDEVICE";

const BOB_PAYLOAD: &str = r#"{"body":"sent by the cross-signed peer","msgtype":"m.text"}"#;
const CAROL_PAYLOAD: &str = r#"{"body":"sent by the unsigned peer","msgtype":"m.text"}"#;

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
/// `kind == "to_device"` is true of an `m.room_key.withheld` notice as well
/// as of the key itself, so no assertion here stops at `kind`. Design doc
/// section 3ter, and the same helper `tests/two_parties.rs` keeps.
fn declared_event_type(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<no event_type in body>".to_string())
}

/// Turns one to-device request body into the to-device event the addressed
/// device would have received from its homeserver. Reads the per-recipient
/// content out of the request and wraps it with the sender and type the
/// request itself declares; it reaches into neither machine.
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
/// homeserver would have delivered.
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

/// The device keys a bare machine holds for its own device.
///
/// Read from the store rather than from the key upload request, because the
/// upload was built before the bootstrap below and a bootstrap does not
/// retroactively change what an already-built request carried.
async fn device_keys_of(
    machine: &OlmMachine,
    user_id: &OwnedUserId,
    device_id: &OwnedDeviceId,
) -> DeviceKeys {
    machine
        .get_device(user_id, device_id, None)
        .await
        .expect("a machine's own store must be readable")
        .expect("a machine always knows its own device")
        .as_device_keys()
        .to_owned()
}

/// The self-signing signature a bootstrap produced over the peer's own
/// device, put back onto that device's keys.
///
/// # Why this is not cheating
///
/// A bootstrap does **not** write this signature into the signing machine's
/// own store copy of its device. It emits it in an
/// `upload_signatures_req`, for `/keys/signatures/upload`, and the
/// homeserver is what stores it and hands it back on the next
/// `/keys/query`. Upstream even leaves a `// TODO: store the signature
/// upload request as well.` where the local copy would go. So this function
/// is the homeserver's half and nothing more: it moves a signature the peer
/// genuinely computed, over its own genuine device keys, from the request
/// the peer emitted into the response the library is about to be handed.
/// Nothing is fabricated -- both the signature and the keys it covers come
/// out of upstream.
///
/// Written as a helper with this comment rather than inline because doing
/// it wrong is invisible: `/keys/query` bodies are just JSON, and one
/// describing an unsigned device reads exactly like one describing a signed
/// device. The assertion in `verification_of_event_from` counts the
/// signatures for that reason.
fn with_owner_signature(
    mut device_keys: DeviceKeys,
    bootstrap: &matrix_sdk_crypto::CrossSigningBootstrapRequests,
    user_id: &OwnedUserId,
    device_id: &OwnedDeviceId,
) -> DeviceKeys {
    let self_signing_key_id = bootstrap
        .upload_signing_keys_req
        .self_signing_key
        .as_ref()
        .expect("a bootstrap always produces a self-signing key")
        .get_first_key_and_id()
        .expect("a self-signing key always carries exactly one key")
        .0
        .to_owned();
    // Looked up by device id, not taken as the first entry: this map is
    // keyed by device id *and* by cross-signing key id, because a bootstrap
    // also signs its own master key with the device. Taking whichever came
    // first would deserialise a cross-signing key as device keys and fail
    // somewhere unrelated.
    let signed: DeviceKeys = bootstrap
        .upload_signatures_req
        .signed_keys
        .get(user_id)
        .expect("a bootstrap signs the device of the user that ran it")
        .iter()
        .find(|(id, _)| *id == device_id.as_str())
        .map(|(_, raw)| {
            serde_json::from_str(raw.get())
                .expect("upstream's own signed device keys deserialise as device keys")
        })
        .expect("a bootstrap signs the running device, keyed by its device id");
    device_keys.signatures.add_signature(
        user_id.clone(),
        self_signing_key_id.clone(),
        signed
            .signatures
            .get_signature(user_id, &self_signing_key_id)
            .expect("the signed copy carries the signature the bootstrap just made"),
    );
    device_keys
}

/// Drains the pump and returns the one request of `kind` in it.
async fn drain_for(kind: &str, why: &str) -> matrix_crypto_core::OutgoingRequest {
    take_outgoing_requests()
        .await
        .expect("the pump must be drainable")
        .into_iter()
        .find(|r| r.kind == kind)
        .unwrap_or_else(|| panic!("{why}"))
}

/// One peer's whole side of the exchange, from key publication to a
/// decrypted event, driven entirely through the library's public surface on
/// Alice's half.
///
/// Returns the `sender_verification` the library reported for an event that
/// peer genuinely encrypted.
///
/// `bootstrap` is the single axis the two peers differ on.
/// Alice's published keys, as the peer machine has to be told them: the
/// device keys a `/keys/query` answers with, and the one one-time key a
/// `/keys/claim` hands over.
///
/// Grouped rather than passed as three parameters, which is not a style
/// preference: as three they put this helper at eight arguments, one over
/// `clippy::too_many_arguments`, and `cargo clippy -- -D warnings` is a
/// step of the gates job. They travel together at both call sites and are
/// read together in the two responses below, so the group is the shape
/// they already had.
struct AliceKeys<'a> {
    device_keys: &'a serde_json::Value,
    key_id: &'a str,
    key: &'a serde_json::Value,
}

async fn verification_of_event_from(
    user_id: &str,
    device_id: &str,
    payload: &str,
    bootstrap: bool,
    requirements: &[SenderTrustRequirement],
    alice: AliceKeys<'_>,
) -> Vec<(
    SenderTrustRequirement,
    Result<Option<SenderVerification>, SessionError>,
)> {
    // Destructured back into the three names the body already used, so
    // grouping them cost the reader nothing below this line.
    let AliceKeys {
        device_keys: alice_device_keys,
        key_id: alice_key_id,
        key: alice_key,
    } = alice;

    let peer_user: OwnedUserId = user_id.parse().expect("a literal user id parses");
    let peer_device: OwnedDeviceId = device_id.into();
    let alice_user: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
    let room_id: OwnedRoomId = SCOPE.parse().expect("a literal room id parses");

    let peer = OlmMachine::new(&peer_user, &peer_device).await;

    // ---- The peer publishes its device keys ----------------------------
    let batch = peer
        .outgoing_requests()
        .await
        .expect("a fresh bare machine has keys to publish");
    let upload_id = batch
        .iter()
        .find(|r| matches!(r.request(), AnyOutgoingRequest::KeysUpload(_)))
        .expect("a fresh bare machine has a key upload")
        .request_id()
        .to_owned();
    peer.mark_request_as_sent(
        &upload_id,
        &keys_upload_response(r#"{"one_time_key_counts":{}}"#),
    )
    .await
    .expect("the bare machine must accept its own upload response");

    // ---- The one axis: does this peer have a cross-signing identity? ---
    //
    // `false`, not `true`: the device keys were published above, and what
    // this bootstrap is wanted for is the identity and the signature it
    // puts on that device, not a second upload of it.
    let mut peer_device_keys = device_keys_of(&peer, &peer_user, &peer_device).await;
    let cross_signing_keys = if bootstrap {
        let requests = peer
            .bootstrap_cross_signing(false)
            .await
            .expect("a bare machine must be able to bootstrap its own identity");
        peer_device_keys =
            with_owner_signature(peer_device_keys, &requests, &peer_user, &peer_device);
        Some((
            serde_json::to_value(&requests.upload_signing_keys_req.master_key)
                .expect("an upstream master key serialises"),
            serde_json::to_value(&requests.upload_signing_keys_req.self_signing_key)
                .expect("an upstream self-signing key serialises"),
        ))
    } else {
        None
    };
    let peer_device_keys =
        serde_json::to_value(&peer_device_keys).expect("upstream device keys serialise");

    // The fixture must actually be the fixture. A `/keys/query` body is
    // just JSON, and one that claims a cross-signed device while carrying
    // an unsigned one would make the assertion at the end of this test
    // pass or fail for a reason that has nothing to do with the library.
    let signature_count = peer_device_keys
        .get("signatures")
        .and_then(|s| s.get(user_id))
        .and_then(serde_json::Value::as_object)
        .map(|s| s.len())
        .unwrap_or(0);
    if bootstrap {
        assert_eq!(
            signature_count, 2,
            "a bootstrapped peer's device must carry two signatures -- its own \
             device key and its owner's self-signing key. One means the \
             bootstrap did not sign the device, and this peer is not the \
             fixture this test says it is"
        );
    } else {
        assert_eq!(
            signature_count, 1,
            "an unbootstrapped peer's device must carry exactly its own \
             signature; a second one means the control is not a control"
        );
    }

    // ---- Alice learns about the peer -----------------------------------
    //
    // `share_scope_key` first, because it is what makes the library track
    // the user at all: upstream's `mark_tracked_users_as_changed` skips
    // every user it has never seen, so without this no call on the shipped
    // surface could get a `/keys/query` issued for him.
    share_scope_key(SCOPE, &[user_id.to_string()])
        .await
        .expect("sharing a scope key must not fail");
    let query = drain_for(
        "keys_query",
        "the machine must ask who exists before it can encrypt to anyone",
    )
    .await;

    // The response carries the peer's cross-signing keys when he has them.
    // This is the whole of what a homeserver adds for a cross-signed user,
    // and the whole of what M3's fixtures never carried.
    let mut body = serde_json::json!({
        "device_keys": { user_id: { device_id: peer_device_keys } },
    });
    if let Some((master_key, self_signing_key)) = cross_signing_keys {
        body["master_keys"] = serde_json::json!({ user_id: master_key });
        body["self_signing_keys"] = serde_json::json!({ user_id: self_signing_key });
    }
    mark_request_sent(&query.id, &body.to_string())
        .await
        .expect("a keys-query response must be accepted");

    // The mirror image on the bare side: the peer learns Alice's device, so
    // he can claim a one-time key from it and open an Olm session to carry
    // his group key.
    peer.mark_request_as_sent(
        &TransactionId::new(),
        &keys_query_response(
            &serde_json::json!({
                "device_keys": { ALICE_USER: { ALICE_DEVICE: alice_device_keys } }
            })
            .to_string(),
        ),
    )
    .await
    .expect("the bare machine must accept a keys-query response");

    let (claim_id, _request) = peer
        .get_missing_sessions(std::iter::once(alice_user.as_ref()))
        .await
        .expect("the bare machine must be able to report missing sessions")
        .expect("the bare machine has no Olm session to the library's device yet");
    peer.mark_request_as_sent(
        &claim_id,
        &keys_claim_response(
            &serde_json::json!({
                "one_time_keys": { ALICE_USER: { ALICE_DEVICE: { alice_key_id: alice_key } } }
            })
            .to_string(),
        ),
    )
    .await
    .expect("the bare machine must accept a keys-claim response");

    // ---- The peer's group key reaches the library ----------------------
    let shares = peer
        .share_room_key(
            &room_id,
            std::iter::once(alice_user.as_ref()),
            EncryptionSettings::default(),
        )
        .await
        .expect("the bare machine must be able to share its own group key");
    let key_events: Vec<String> = shares
        .iter()
        .map(|request| {
            serde_json::to_string(request.as_ref())
                .expect("an upstream to-device request serialises")
        })
        .filter(|body| declared_event_type(body) == "m.room.encrypted")
        .filter_map(|body| relay_to(&body, user_id, ALICE_USER, ALICE_DEVICE))
        .collect();
    assert_eq!(
        key_events.len(),
        1,
        "the bare machine must produce exactly one to-device message carrying \
         its session key to the library's device; zero means it produced a \
         withheld notice instead, which is section 3ter's ordering failure and \
         not anything this test is about"
    );

    let outcome = receive_sync_changes(
        &serde_json::json!({
            "to_device_events": key_events
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

    // ---- The peer encrypts, the library decrypts -----------------------
    let content = Raw::<AnyMessageLikeEventContent>::from_json_string(payload.to_owned())
        .expect("a literal payload is well-formed JSON");
    let encrypted = peer
        .encrypt_room_event_raw(&room_id, "m.room.message", &content)
        .await
        .expect("the bare machine must be able to encrypt for its own session");
    let event = room_event(
        user_id,
        &format!("$from-{device_id}:example.org"),
        encrypted.content.json().get(),
    );

    // ---- The same ciphertext, once per requirement --------------------
    //
    // The decryption matrix: what each requirement does with this exact
    // sender, on a machine where nothing else changes. One event,
    // decrypted several times, because the requirement is a parameter of
    // the call and not a property of the machine -- and because a refused
    // decryption must not consume the session, which the repeated
    // successes here also hold.
    let mut matrix = Vec::new();
    for requirement in requirements {
        let decrypted = decrypt_event(SCOPE, &event, *requirement).await;
        // Only the success arm has anything to check, which is why this is
        // an `if let` and not a `match`. A refusal under a tightened
        // requirement is the finding this matrix exists to make: it says
        // nothing about the ciphertext, so there is no payload to check --
        // the caller is expected to assert on the error kind instead.
        if let Ok(envelope) = &decrypted {
            // The control on every authenticity assertion below. If
            // decryption itself broke, the value under test would be
            // meaningless rather than wrong, and this says which of the
            // two happened.
            assert!(
                envelope.ciphertext == payload.as_bytes(),
                "the library must recover the peer's payload byte for byte \
                 (recovered {} bytes, sent {} bytes)",
                envelope.ciphertext.len(),
                payload.len()
            );
        }
        matrix.push((
            *requirement,
            decrypted.map(|envelope| envelope.sender_verification),
        ));
    }
    matrix
}

/// One `#[test]` fn, for the reason `tests/two_parties.rs` gives: the
/// machine registry and the pump's bookkeeping are process-wide, and an
/// integration test has no access to the `#[cfg(test)]` reset helpers. Cargo
/// gives each file under `tests/` its own process, so this file owns one
/// machine for its whole lifetime.
///
/// Driven by `futures::executor::block_on` inside `in_runtime`, because the
/// bare machines need a tokio context this crate does not supply for them --
/// upstream's `share_room_key` reaches `tokio::task::spawn`.
#[test]
fn a_cross_signed_peer_produces_unverified_identity_against_a_library_with_no_identity() {
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

        // ---- The library publishes its own keys ------------------------
        let upload = drain_for("keys_upload", "a fresh machine must have keys to publish").await;
        let upload_body: serde_json::Value =
            serde_json::from_str(&upload.body).expect("the pump's own body is well-formed JSON");
        let alice_device_keys = upload_body
            .get("device_keys")
            .cloned()
            .expect("a fresh machine's upload carries its device keys");
        // One per peer. A single one-time key would be consumed by the
        // first claim and the second peer would silently fall back, or fail
        // to open a session at all.
        let alice_keys: Vec<(String, serde_json::Value)> = upload_body
            .get("one_time_keys")
            .and_then(serde_json::Value::as_object)
            .map(|keys| {
                keys.iter()
                    .take(2)
                    .map(|(id, key)| (id.clone(), key.clone()))
                    .collect()
            })
            .expect("a fresh machine's upload carries one-time keys");
        assert!(
            alice_keys.len() >= 2,
            "this test claims two one-time keys, one per peer; with fewer, the \
             second peer's session would be established by some other means and \
             the two halves would not be comparable"
        );
        mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
            .await
            .expect("a keys-upload response must be accepted");

        // ---- The premise, read rather than assumed ---------------------
        //
        // The claim under test is that this value arrives at a library that
        // has no cross-signing identity of its own. This said "nothing in
        // this crate calls `bootstrap_cross_signing`, but 'nothing calls
        // it' is a property of the source and this is the machine", and M4
        // is exactly the milestone that sentence was hedging against: the
        // crate does call it now, from `bootstrap_identity`. Reading the
        // machine instead of trusting the source is what kept this premise
        // honest through that change, and it is why the assertion below
        // exists rather than a comment. It stays green because nothing in
        // *this* file bootstraps, and it turns red the moment something
        // does, rather than quietly changing what the assertion at the
        // bottom means.
        let status =
            with_machine(|machine| Box::pin(async move { machine.cross_signing_status().await }))
                .await
                .expect("the machine must be reachable");
        assert!(
            !status.has_master && !status.has_self_signing && !status.has_user_signing,
            "this machine has published no cross-signing identity, and the \
             value this test is about is reachable precisely because it does \
             not depend on one. Red here means something in this file \
             bootstrapped, and every assertion below it is now measuring a \
             different question: {status:?}"
        );

        // ---- The cross-signed peer -------------------------------------
        //
        // Decrypted under all three requirements: the default because the
        // value under test must arrive through the surface a product
        // actually calls, the two tightened tiers because the point of
        // them is to refuse *unsigned* senders and they must not refuse
        // this one -- a device vouched for by its owner's identity, on a
        // machine with no identity of its own. The machine's own state
        // matters for the outbound share strategy, not for decryption.
        let (bob_key_id, bob_key) = alice_keys[0].clone();
        let bob_matrix = verification_of_event_from(
            BOB_USER,
            BOB_DEVICE,
            BOB_PAYLOAD,
            true,
            &[
                SenderTrustRequirement::Any,
                SenderTrustRequirement::IdentitySignedOrLegacy,
                SenderTrustRequirement::IdentitySigned,
            ],
            AliceKeys {
                device_keys: &alice_device_keys,
                key_id: &bob_key_id,
                key: &bob_key,
            },
        )
        .await;

        // ---- The control -----------------------------------------------
        // Same matrix, one difference: no self-signature on the device.
        // The tightened tiers must refuse it, and refuse it as its own
        // kind: a policy gap, not a broken event.
        let (carol_key_id, carol_key) = alice_keys[1].clone();
        let carol_matrix = verification_of_event_from(
            CAROL_USER,
            CAROL_DEVICE,
            CAROL_PAYLOAD,
            false,
            &[
                SenderTrustRequirement::Any,
                SenderTrustRequirement::IdentitySignedOrLegacy,
                SenderTrustRequirement::IdentitySigned,
            ],
            AliceKeys {
                device_keys: &alice_device_keys,
                key_id: &carol_key_id,
                key: &carol_key,
            },
        )
        .await;

        // ---- Authenticity, and nothing else, from here down ------------

        // (1) The finding. A peer who has set cross-signing up produces
        //     this against a library that has none, because upstream's
        //     first gate reads the sender's identity and not ours.
        for (requirement, outcome) in &bob_matrix {
            assert_eq!(
                outcome,
                &Ok(Some(SenderVerification::UnverifiedIdentity)),
                "an event from a device its owner cross-signed reads \
                 `UnverifiedIdentity` under {requirement:?} in this build. \
                 `UnsignedDevice` here would mean the cross-signature was not \
                 seen; a refusal would mean the tightened tier refuses the \
                 senders it exists to admit"
            );
        }

        // (2) The control. Same code path, same relay, same payload shape,
        //     one difference: no self-signature on the device.
        for (requirement, outcome) in &carol_matrix {
            match requirement {
                SenderTrustRequirement::Any => assert_eq!(
                    outcome,
                    &Ok(Some(SenderVerification::UnsignedDevice)),
                    "a peer with no cross-signing identity reads `UnsignedDevice` \
                     under the default requirement; if this has become \
                     `UnverifiedIdentity`, the library is not reading the \
                     signature, it is answering the same thing for everyone"
                ),
                _ => assert_eq!(
                    outcome,
                    &Err(SessionError::SenderNotTrusted),
                    "a peer with no cross-signing identity must be refused under \
                     {requirement:?}, and refused as `SenderNotTrusted` -- a \
                     policy gap, not a broken event. `UnknownDevice` would tell \
                     a product its event's provenance is broken, which is the \
                     opposite of the truth here"
                ),
            }
        }

        // (3) The two are different, stated on its own. Assertions (1) and
        //     (2) could both be rewritten to one constant by a defect that
        //     also rewrote the expected values; this one cannot.
        assert_ne!(
            bob_matrix[0].1, carol_matrix[0].1,
            "the only difference between these two peers is a signature on a \
             device, and it must be the difference between two reported values"
        );

        // (4) Cross-signed is not verified. The distinction the corrected
        //     documentation now turns on: the sender's identity is what
        //     makes the value reachable, ours is what would make it
        //     `Verified`, and we have none -- so the device is not verified
        //     and the event is not authenticated.
        let statuses = device_statuses(BOB_USER)
            .await
            .expect("the cross-signed peer's devices must be readable");
        assert!(
            statuses
                .iter()
                .any(|status| status.device_id == BOB_DEVICE
                    && status.trust == TrustState::Unverified),
            "a device cross-signed by its own owner is not thereby verified \
             by us: that needs our user-signing key over their master key, \
             and this machine has not bootstrapped one. This said \"which \
             this build has no way to produce\", which M4 made false; the \
             assertion is unchanged because what it rests on was always \
             this fixture, not the build"
        );
    }));
}
