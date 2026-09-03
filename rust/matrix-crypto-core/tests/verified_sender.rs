//! The seven-step chain that makes a decrypted event read `Verified`, and
//! the one step of it that is silent when it is left out.
//!
//! # What this file is
//!
//! Two real machines, no homeserver, and the whole chain driven through
//! this crate's shipped surface on the library's half:
//!
//! 1. **We hold a private signing identity.** [`bootstrap_identity`], and
//!    the account key query that unlocks it.
//! 2. **Our own public identity is marked verified.** A side effect of (1)
//!    upstream, read back here rather than assumed.
//! 3. **The sender published their identity and signed their own device.**
//!    Theirs to do, not ours: without it every value below is
//!    `UnsignedDevice` whatever we do.
//! 4. **We fetched the sender's keys.** The `keys_query` the pump hands
//!    out, answered with what a homeserver would have returned.
//! 5. **We signed the sender's master key with our user-signing key.** A
//!    completed comparison does this inside upstream's `mark_as_done`, and
//!    the resulting signature upload reaches this crate's pump as an
//!    ordinary outgoing request.
//! 6. **We uploaded that signature.** The `signature_upload` the pump hands
//!    out, resolved through [`mark_request_sent`].
//! 7. **We fetched the sender's keys again**, so that our own signature is
//!    on the master key in our own store.
//!
//! # Step seven is the trap, and it is why the second test exists
//!
//! Nothing caches the outgoing signature. Upstream carries a
//! `// TODO: store the signature upload request as well.` at exactly the
//! point where the local copy would go
//! (`matrix-sdk-crypto-0.18.0/src/verification/mod.rs`), so a signature we
//! computed, uploaded and never fetched back is a signature our own store
//! has never seen. Upstream's second gate,
//! `Device::is_cross_signing_trusted`, reads the store and nothing else.
//!
//! So a chain that stops at step six looks complete from the outside --
//! every call returned `Ok`, the comparison finished, the device reads
//! verified, the signature really was uploaded -- and events from that
//! sender sit one rung below where a product would expect them, with
//! nothing anywhere reporting a problem. That is a defect a comment cannot
//! defend against, because a refactor deletes comments and keeps behaviour.
//! [`omitting_the_second_key_fetch_leaves_the_sender_below_verified`] is
//! the guard, and it is deliberately the mirror image of the chain test:
//! one `bool`, one difference, both halves of the pair asserted.
//!
//! # The third test, and why it is not about the chain at all
//!
//! [`history_does_not_improve_when_the_sender_is_verified_later`] runs the
//! same steps in a different order, which is its whole subject. A message
//! sent *before* the chain keeps the value it was decrypted with, forever,
//! and completing the chain afterwards does not revisit it: upstream fixes
//! an inbound session's sender data when the session key arrives and
//! recalculates it later only from `UnknownDevice`, `DeviceInfo` or
//! `VerificationViolation`, never from `SenderUnverified`. The two tests
//! above send after the chain for exactly that reason, and until M4 that
//! reason lived in a comment with nothing asserting it. It is a promise a
//! product's user interface has to keep ("from here on", not "your history
//! improves"), so it is a test now.
//!
//! # Which side is the library
//!
//! The asymmetry `tests/two_parties.rs` and `tests/cross_signed_peer.rs`
//! both document holds here too. **Alice is the library**, driven only
//! through this crate's public surface against the one process-wide
//! machine. The counterparties are bare upstream `OlmMachine`s standing in
//! for third-party clients, and this file relays between them exactly what
//! a homeserver would relay and nothing else.
//!
//! # The rule this file discharges
//!
//! M3 forbade any test that *appears* to produce `Verified`, because a
//! fixture faking it would teach precisely the false belief the rule
//! existed to prevent. Reaching the value through the real chain is what
//! discharges that rule rather than breaking it, and the complement keeps
//! its value under a new name: what must stay true is not "nothing
//! produces `Verified`" but **"nothing except the real chain does"**. The
//! second test here is the first instance of that replacement -- a chain
//! missing one step produces a value below it -- and
//! `tests/cross_signed_peer.rs` and `tests/two_parties.rs` hold the other
//! two rungs. The third test holds a fourth: a real chain, completed in
//! full, still does not reach back and produce `Verified` for what was
//! decrypted before it.

use matrix_crypto_core::{
    begin_comparison, confirm_flow, create_identity, create_machine, decrypt_event,
    device_statuses, flow_stage, identity_status, in_runtime, mark_request_sent, read_material,
    receive_sync_changes, request_flow, share_scope_key, take_outgoing_requests, with_machine,
    FlowId, FlowStage, MachineConfig, OutgoingRequest, SenderTrustRequirement, SenderVerification,
    TrustState,
};
use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::Response as KeysClaimResponse;
use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
use matrix_sdk_common::ruma::api::client::sync::sync_events::DeviceLists;
use matrix_sdk_common::ruma::api::client::to_device::send_event_to_device::v3::Response as ToDeviceResponse;
use matrix_sdk_common::ruma::api::IncomingResponse;
use matrix_sdk_common::ruma::events::key::verification::VerificationMethod;
use matrix_sdk_common::ruma::events::{AnyMessageLikeEventContent, AnyToDeviceEvent};
// `exports::http`, not a direct `http` dependency: the exact version ruma's
// own `IncomingResponse::try_from_http_response` requires, reached through
// ruma's re-export -- the same reasoning `session.rs` documents for itself.
use matrix_sdk_common::ruma::exports::http;
use matrix_sdk_common::ruma::serde::Raw;
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId, TransactionId};
use matrix_sdk_crypto::types::requests::{AnyOutgoingRequest, OutgoingVerificationRequest};
use matrix_sdk_crypto::types::DeviceKeys;
use matrix_sdk_crypto::{
    CrossSigningBootstrapRequests, DecryptionSettings, EncryptionSettings, EncryptionSyncChanges,
    OlmMachine, TrustRequirement,
};
use std::collections::BTreeMap;
use std::sync::Mutex as StdMutex;

const ALICE_USER: &str = "@alice:example.org";
const ALICE_DEVICE: &str = "ALICEDEVICE";
/// A scope only ever used to make the library ask who a user's devices are
/// and to carry one event. Nothing about it is read back.
const SCOPE: &str = "!verified-sender:example.org";

/// The counterparty of the complete chain.
const REFETCHED_USER: &str = "@refetched:example.org";
const REFETCHED_DEVICE: &str = "PEERREFETCHED";
const REFETCHED_PAYLOAD: &str = r#"{"body":"sent after the whole chain ran","msgtype":"m.text"}"#;

/// The counterparty whose chain stops one step short.
const UNFETCHED_USER: &str = "@unfetched:example.org";
const UNFETCHED_DEVICE: &str = "PEERUNFETCHED";
const UNFETCHED_PAYLOAD: &str =
    r#"{"body":"sent after a chain missing its last step","msgtype":"m.text"}"#;

/// A `/keys/query` answer naming no identity for this account: the server
/// has been asked, it has answered **about this account**, and what it holds
/// for it is nothing.
///
/// Continuwuity v26.7.2's real answer for such an account, measured directly
/// over HTTP; Synapse 1.159.0 and Dendrite 0.15.2 answer the same thing with
/// `"failures":{}` and the three empty cross-signing maps beside it. The
/// account is **named**, which the `{"device_keys":{}}` this constant used to
/// hold was not, and which no measured homeserver omits. A body that names
/// nobody is silent about this account, and `session::answer_about_this_account`
/// has why silence does not lift the gate.
const NO_IDENTITY: &str = r#"{"device_keys":{"@alice:example.org":{}}}"#;

/// Serialises this file's tests over the one machine and the one pump this
/// process has. `into_inner` on a poisoned lock deliberately: a test that
/// panicked has already failed, and the other should report its own
/// outcome rather than a poisoning inherited from it.
static SERIAL: StdMutex<()> = StdMutex::new(());

/// What the library published about itself, captured once.
///
/// The one-time keys are handed out one per counterparty: a single key
/// would be consumed by the first claim and the second counterparty would
/// silently fall back to some other means of establishing a session, so the
/// two halves of this file would no longer be comparable.
struct Library {
    device_keys: String,
    one_time_keys: Vec<(String, String)>,
}

static LIBRARY: StdMutex<Option<Library>> = StdMutex::new(None);

// ------------------------------------------------------------- wire shapes

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
/// Every assertion here about what crossed the wire goes through this
/// rather than stopping at `kind == "to_device"`: all six messages a
/// comparison exchanges are to-device requests, and so is a withheld
/// notice, so the kind alone distinguishes nothing.
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
fn relay_to(body: &str, sender: &str, user_id: &str, device_id: &str) -> Option<serde_json::Value> {
    let request: serde_json::Value = serde_json::from_str(body).ok()?;
    let event_type = request.get("event_type")?.as_str()?;
    let content = request.get("messages")?.get(user_id)?.get(device_id)?;
    Some(serde_json::json!({
        "sender": sender,
        "type": event_type,
        "content": content,
    }))
}

/// Whether a to-device request's body addresses the given device, by
/// reading its `messages` map the way a homeserver would.
fn addresses(body: &str, user_id: &str, device_id: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|request| {
            request
                .get("messages")?
                .get(user_id)?
                .get(device_id)
                .cloned()
        })
        .is_some()
}

/// The withheld code a to-device request carries for the given device,
/// read from the per-device message's own `code` field -- the one thing
/// that tells an identity-based withholding (`m.unverified`) apart from
/// the section 3ter ordering failure (`m.no_olm`).
fn withheld_code_for(body: &str, user_id: &str, device_id: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("messages")?
        .get(user_id)?
        .get(device_id)?
        .get("code")?
        .as_str()
        .map(str::to_owned)
}

/// The wire body of one request upstream handed back to its caller rather
/// than queueing.
fn verification_body(request: &OutgoingVerificationRequest) -> String {
    match request {
        OutgoingVerificationRequest::ToDevice(to_device) => {
            serde_json::to_string(to_device).expect("an upstream to-device request serialises")
        }
        // Unreachable: an in-room flow only exists if an in-room
        // verification event was fed to the machine, and this library has
        // no entry point that does that.
        OutgoingVerificationRequest::InRoom(_) => {
            panic!("this library runs to-device verification flows only")
        }
    }
}

/// Wraps an encrypted content in the surrounding event a homeserver would
/// have delivered.
fn scoped_event(sender: &str, event_id: &str, content: &str) -> String {
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

/// The most permissive requirement, the same one `session.rs`'s own
/// `decryption_settings()` uses, mirrored here so the counterparty is held
/// to the standard the library holds itself to and no difference between
/// the two can explain a result.
fn decryption_settings() -> DecryptionSettings {
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

// ------------------------------------------------------------ the two pumps

/// Drains the library's pump and returns the one request of `kind` in it,
/// leaving everything else pending.
async fn drain_for(kind: &str, why: &str) -> OutgoingRequest {
    take_outgoing_requests()
        .await
        .expect("the pump must be drainable")
        .into_iter()
        .find(|request| request.kind == kind)
        .unwrap_or_else(|| panic!("{why}"))
}

/// The users a `/keys/query` body asks about.
fn queried_users(body: &str) -> Vec<String> {
    serde_json::from_str::<serde_json::Value>(body)
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
        .expect("a keys-query body always carries a device_keys object")
}

/// Drains the library's pump and returns the key query that asks about
/// `user_id`.
///
/// **Not `drain_for("keys_query", ..)`**, and the difference is not
/// defensive. `PendingKind::tag` is deliberately not injective: a query for
/// this account and a query for anyone else are one endpoint with one wire
/// tag, distinguished only inside `session.rs`. Taking whichever came first
/// would let a run in which the pump happened to owe an own-account query
/// answer *that* one with this counterparty's keys, and the counterparty's
/// real query would go unanswered while every assertion below still read
/// plausibly.
async fn drain_for_query_about(user_id: &str, why: &str) -> OutgoingRequest {
    take_outgoing_requests()
        .await
        .expect("the pump must be drainable")
        .into_iter()
        .find(|request| {
            request.kind == "keys_query"
                && queried_users(&request.body).iter().any(|u| u == user_id)
        })
        .unwrap_or_else(|| panic!("{why}"))
}

/// Hands events to a bare machine as a sync would.
async fn deliver_to_bare(peer: &OlmMachine, events: Vec<serde_json::Value>) {
    let to_device_events: Vec<Raw<AnyToDeviceEvent>> = events
        .into_iter()
        .map(|event| {
            Raw::from_json_string(event.to_string())
                .expect("this test builds its own well-formed event")
        })
        .collect();
    let changed_devices = DeviceLists::default();
    let counts = BTreeMap::new();

    peer.receive_sync_changes(
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
}

/// Hands events to the library as a sync would, through its own public
/// entry point and its own wire shape.
async fn deliver_to_library(events: Vec<serde_json::Value>) {
    let payload = serde_json::json!({ "to_device_events": events }).to_string();
    receive_sync_changes(&payload)
        .await
        .expect("the library must accept a sync it is the addressee of");
}

/// Drains the library's pump, relays every to-device request in it to the
/// counterparty, **marks each one sent**, and reports what crossed.
///
/// The mark is what this turns on: upstream advances a comparison only when
/// the key message is reported sent.
async fn pump_to_bare(peer: &OlmMachine, user_id: &str, device_id: &str) -> Vec<String> {
    let batch = take_outgoing_requests()
        .await
        .expect("the pump must be drainable");

    let mut crossed = Vec::new();
    let mut events = Vec::new();
    for request in batch.iter().filter(|request| request.kind == "to_device") {
        if let Some(event) = relay_to(&request.body, ALICE_USER, user_id, device_id) {
            crossed.push(declared_event_type(&request.body));
            events.push(event);
        }
        mark_request_sent(&request.id, "{}")
            .await
            .expect("a to-device response must be accepted");
    }

    if !events.is_empty() {
        deliver_to_bare(peer, events).await;
    }
    crossed
}

/// The mirror image: drains the bare machine's own outbound requests,
/// relays its to-device ones to the library, and marks them sent on its
/// side.
async fn pump_bare_to_library(peer: &OlmMachine, user_id: &str) -> Vec<String> {
    let batch = peer
        .outgoing_requests()
        .await
        .expect("the bare machine's requests must be readable");

    let mut crossed = Vec::new();
    let mut events = Vec::new();
    for request in &batch {
        if let AnyOutgoingRequest::ToDeviceRequest(to_device) = request.request() {
            let body =
                serde_json::to_string(to_device).expect("an upstream to-device request serialises");
            if let Some(event) = relay_to(&body, user_id, ALICE_USER, ALICE_DEVICE) {
                crossed.push(declared_event_type(&body));
                events.push(event);
            }
            peer.mark_request_as_sent(request.request_id(), &ToDeviceResponse::new())
                .await
                .expect("the bare machine must accept its own to-device response");
        }
    }

    if !events.is_empty() {
        deliver_to_library(events).await;
    }
    crossed
}

/// Relays one request the bare machine handed back to its caller.
async fn deliver_verification_request(request: &OutgoingVerificationRequest, sender: &str) {
    let body = verification_body(request);
    let event = relay_to(&body, sender, ALICE_USER, ALICE_DEVICE)
        .expect("the counterparty addresses the library's own device");
    deliver_to_library(vec![event]).await;
}

// ------------------------------------------------------------- the fixtures

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
/// own store copy of its device. It emits it in an `upload_signatures_req`,
/// and the homeserver is what stores it and hands it back on the next
/// `/keys/query`. So this function is the homeserver's half and nothing
/// more: it moves a signature the peer genuinely computed, over its own
/// genuine device keys, from the request the peer emitted into the response
/// the library is about to be handed. Nothing is fabricated.
///
/// The same helper, and the same reasoning, as `tests/cross_signed_peer.rs`.
fn with_owner_signature(
    mut device_keys: DeviceKeys,
    bootstrap: &CrossSigningBootstrapRequests,
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
    // also signs its own master key with the device.
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

/// The signatures the library's own signature upload carries over the
/// counterparty's master key.
///
/// The wire body of a `signature_upload` **is** the `signed_keys` map, so
/// this reads `{ user: { master key: signed key } }` and returns the
/// `signatures` object of the one entry inside.
///
/// Only the signatures are taken, never the key object around them.
/// Upstream's `sign_user` *replaces* the master key's signature map with
/// its own single signature rather than adding to it
/// (`olm/signing/pk_signing.rs`: `master_key.signatures = signatures`), so
/// posting that object verbatim as the master key would silently drop the
/// signature the counterparty's own device made over it. [`with_our_signature`]
/// merges instead, which is what a homeserver does with this endpoint's body.
fn uploaded_signatures(body: &str, user_id: &str) -> serde_json::Value {
    let parsed: serde_json::Value =
        serde_json::from_str(body).expect("the pump's own body is well-formed JSON");
    let per_user = parsed
        .get(user_id)
        .and_then(serde_json::Value::as_object)
        .unwrap_or_else(|| {
            panic!("the signature upload must name the counterparty it signed: {body}")
        });
    assert_eq!(
        per_user.len(),
        1,
        "a user signature covers exactly the master key, so exactly one entry \
         is expected here; more means this upload is not the one this test \
         thinks it is: {body}"
    );
    per_user
        .values()
        .next()
        .and_then(|signed| signed.get("signatures"))
        .cloned()
        .expect("a signed master key always carries the signature that signed it")
}

/// How many signatures, across every signing user, a cross-signing key
/// carries.
fn signature_count(key: &serde_json::Value) -> usize {
    key.get("signatures")
        .and_then(serde_json::Value::as_object)
        .map(|users| {
            users
                .values()
                .filter_map(serde_json::Value::as_object)
                .map(serde_json::Map::len)
                .sum()
        })
        .unwrap_or(0)
}

/// Merges the signatures the library uploaded into the counterparty's
/// master key, as a homeserver would.
///
/// Asserts the merge actually added one. A `/keys/query` body is just JSON,
/// and one describing an unsigned master key reads exactly like one
/// describing a signed master key, so the fixture that makes step seven
/// meaningful has to be checked rather than trusted -- the same reasoning
/// `tests/cross_signed_peer.rs` gives for counting device signatures.
fn with_our_signature(
    mut master_key: serde_json::Value,
    signatures: &serde_json::Value,
) -> serde_json::Value {
    let before = signature_count(&master_key);

    let target = master_key
        .get_mut("signatures")
        .and_then(serde_json::Value::as_object_mut)
        .expect("a published master key always carries its own device's signature");
    for (user, keys) in signatures
        .as_object()
        .expect("an uploaded signature map is an object")
    {
        let slot = target
            .entry(user.clone())
            .or_insert_with(|| serde_json::json!({}));
        let slot = slot
            .as_object_mut()
            .expect("a per-user signature map is an object");
        for (key_id, signature) in keys
            .as_object()
            .expect("a per-user signature map is an object")
        {
            slot.insert(key_id.clone(), signature.clone());
        }
    }

    let after = signature_count(&master_key);
    assert!(
        after > before,
        "merging the uploaded signature must add one: the master key carried \
         {before} signatures before and {after} after. Equal means this \
         response is indistinguishable from the one step seven was skipped \
         with, and the chain test would be asserting nothing"
    );
    master_key
}

/// Creates the one library machine this process has, performs steps 1 and 2
/// of the chain on it, and returns its published device keys.
///
/// Called by every test in this file; each gets the machine the one before
/// it left behind, which is the only shape available -- the machine registry
/// and the pump are process-wide and an integration test cannot reset them.
async fn library() -> serde_json::Value {
    if let Some(library) = LIBRARY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
    {
        return serde_json::from_str(&library.device_keys)
            .expect("this test stored well-formed JSON");
    }

    // `keep()`: the store outlives the test that created it, because the
    // second test in this file shares the machine it belongs to.
    let dir = tempfile::tempdir().expect("temp dir").keep();
    create_machine(MachineConfig {
        user_id: ALICE_USER.to_string(),
        device_id: ALICE_DEVICE.to_string(),
        store_path: dir.join("store").to_string_lossy().into_owned(),
        store_passphrase: Some("test-passphrase".to_string()),
    })
    .await
    .expect("the library's machine must be creatable");

    // ---- The library publishes its own keys -----------------------------
    let batch = take_outgoing_requests()
        .await
        .expect("the pump must be drainable");
    let upload = batch
        .iter()
        .find(|request| request.kind == "keys_upload")
        .expect("a fresh machine must have keys to publish");
    let body: serde_json::Value =
        serde_json::from_str(&upload.body).expect("the pump's own body is well-formed JSON");
    let device_keys = body
        .get("device_keys")
        .cloned()
        .expect("a fresh machine's upload carries its device keys");
    let one_time_keys: Vec<(String, String)> = body
        .get("one_time_keys")
        .and_then(serde_json::Value::as_object)
        .map(|keys| {
            keys.iter()
                .take(3)
                .map(|(id, key)| (id.clone(), key.to_string()))
                .collect()
        })
        .expect("a fresh machine's upload carries one-time keys");
    assert!(
        one_time_keys.len() >= 3,
        "this file stands up three counterparties and claims one key each; \
         with fewer, a counterparty's session would be established by some \
         other means and the halves of this file would not be comparable"
    );
    mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
        .await
        .expect("a keys-upload response must be accepted");

    // ---- Step 1: we hold a private signing identity ---------------------
    //
    // The account key query first: `bootstrap_identity` refuses until this
    // process has asked the server about this account and been answered,
    // which is the gate `tests/identity_bootstrap_ordering.rs` drives.
    // Matched on the user it asks about, not on its kind: `keys_query` is
    // one wire tag for the account's own query and everyone else's, so a
    // kind-only match would answer whichever came first and could lift this
    // gate with somebody else's answer.
    let account_query = batch
        .iter()
        .find(|request| {
            request.kind == "keys_query"
                && queried_users(&request.body).iter().any(|u| u == ALICE_USER)
        })
        .expect("a fresh machine must owe a key query for its own account");
    mark_request_sent(&account_query.id, NO_IDENTITY)
        .await
        .expect("answering the account key query must not fail");

    create_identity().await.expect(
        "creating this account's identity after the keys have been fetched must be \
                 served",
    );

    let status = identity_status()
        .await
        .expect("reading the identity status must not fail");
    assert!(
        status.private_keys_held,
        "step 1 of the chain is this device holding the private signing keys, \
         and every step after it is blocked without them: {status:?}"
    );

    // The requests the bootstrap queued are drained and answered, so the
    // pump each test drives afterwards carries only that test's own
    // traffic. Answering them is also what a product does; leaving an
    // identity unpublished would be a different fixture.
    let published = take_outgoing_requests()
        .await
        .expect("the pump must be drainable");
    for request in &published {
        mark_request_sent(&request.id, "{}")
            .await
            .expect("a bootstrap publication response must be accepted");
    }

    // ---- Step 2: our own public identity is marked verified -------------
    //
    // Automatic upstream: `to_public_identity()` marks it at bootstrap.
    // Read back rather than assumed, because it is the first half of
    // upstream's second gate -- `is_identity_verified` is
    // `self.is_verified() && user_signing_key.verify_master_key(theirs)` --
    // and if it were ever false, every `Verified` below would be
    // unreachable for a reason that has nothing to do with step seven.
    let own_identity_verified = with_machine(|machine| {
        Box::pin(async move {
            machine
                .get_identity(machine.user_id(), None)
                .await
                .expect("the store must be readable")
                .expect("a bootstrapped machine knows its own identity")
                .own()
                .expect("this machine's own identity is an own identity")
                .is_verified()
        })
    })
    .await
    .expect("the library's machine must be live");
    assert!(
        own_identity_verified,
        "step 2 of the chain is our own public identity being marked verified, \
         which a bootstrap does by itself"
    );

    *LIBRARY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Library {
        device_keys: device_keys.to_string(),
        one_time_keys,
    });
    device_keys
}

/// Takes one of the library's published one-time keys, so each counterparty
/// opens its session with a key no other counterparty used.
fn claim_one_time_key() -> (String, serde_json::Value) {
    let mut held = LIBRARY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let library = held
        .as_mut()
        .expect("the library fixture is built before any counterparty");
    let (id, key) = library
        .one_time_keys
        .pop()
        .expect("this file claims one key per counterparty and publishes enough for all");
    (
        id,
        serde_json::from_str(&key).expect("this test stored well-formed JSON"),
    )
}

/// What one run of the chain produced.
struct Outcome {
    /// What the library reported about the sender of the event it decrypted.
    verification: Option<SenderVerification>,
    /// The plaintext the library recovered. The control on every
    /// authenticity assertion: if decryption itself broke, the value above
    /// is meaningless rather than wrong, and this says which of the two
    /// happened.
    recovered: Vec<u8>,
    /// Whether the library's own view of the counterparty's *identity* is
    /// verified. Upstream's second gate is
    /// `own_identity.is_identity_verified(theirs) && theirs.is_device_signed(device)`,
    /// and this is its first half -- the half step seven is what moves.
    identity_verified: bool,
    /// What the shipped `device_statuses` call reports for the
    /// counterparty's device.
    device_trust: TrustState,
}

/// The counterparty of the ordering test, whose message is sent before the
/// chain rather than after it.
const HISTORY_USER: &str = "@history:example.org";
const HISTORY_DEVICE: &str = "PEERHISTORY";
const HISTORY_PAYLOAD: &str = r#"{"body":"sent before the chain ran","msgtype":"m.text"}"#;
const HISTORY_SAME_SESSION_PAYLOAD: &str =
    r#"{"body":"sent after the chain, on the session that predates it","msgtype":"m.text"}"#;
const HISTORY_ROTATED_PAYLOAD: &str =
    r#"{"body":"sent after the chain, on a session created after it","msgtype":"m.text"}"#;

/// A counterparty that holds a cross-signing identity of its own and has
/// signed its own device with it. Step three of the chain, plus the key
/// publication that has to precede it.
struct Counterparty {
    peer: OlmMachine,
    signed_device_keys: serde_json::Value,
    master_key: serde_json::Value,
    self_signing_key: serde_json::Value,
}

/// Stands up one counterparty and performs step three against it.
///
/// Extracted from `chain` so that the ordering test can perform the steps
/// in a different order rather than reproducing them. The order is the
/// subject of that test, so it has to be able to vary it without varying
/// anything else.
async fn counterparty_with_identity(user_id: &str, device_id: &str) -> Counterparty {
    let peer_user: OwnedUserId = user_id.parse().expect("a literal user id parses");
    let peer_device: OwnedDeviceId = device_id.into();

    let peer = OlmMachine::new(&peer_user, &peer_device).await;

    // ---- The counterparty publishes its device keys ---------------------
    let batch = peer
        .outgoing_requests()
        .await
        .expect("a fresh bare machine has keys to publish");
    let upload_id = batch
        .iter()
        .find(|request| matches!(request.request(), AnyOutgoingRequest::KeysUpload(_)))
        .expect("a fresh bare machine has a key upload")
        .request_id()
        .to_owned();
    peer.mark_request_as_sent(
        &upload_id,
        &keys_upload_response(r#"{"one_time_key_counts":{}}"#),
    )
    .await
    .expect("the bare machine must accept its own upload response");

    // ---- Step 3: the sender publishes an identity and signs its device --
    //
    // `false`, not `true`: the device keys were published above, and what
    // this bootstrap is wanted for is the identity and the signature it
    // puts on that device.
    let bootstrap = peer
        .bootstrap_cross_signing(false)
        .await
        .expect("a bare machine must be able to bootstrap its own identity");
    let signed_device_keys = with_owner_signature(
        device_keys_of(&peer, &peer_user, &peer_device).await,
        &bootstrap,
        &peer_user,
        &peer_device,
    );
    let signed_device_keys =
        serde_json::to_value(&signed_device_keys).expect("upstream device keys serialise");
    let master_key = serde_json::to_value(&bootstrap.upload_signing_keys_req.master_key)
        .expect("an upstream master key serialises");
    let self_signing_key =
        serde_json::to_value(&bootstrap.upload_signing_keys_req.self_signing_key)
            .expect("an upstream self-signing key serialises");

    // The fixture must actually be the fixture: two signatures on the
    // device, its own and its owner's self-signing key. One means the
    // bootstrap did not sign the device, and gate one would fail for a
    // reason that has nothing to do with anything below.
    assert_eq!(
        signature_count(&signed_device_keys),
        2,
        "a bootstrapped counterparty's device carries two signatures, its own \
         and its owner's self-signing key"
    );

    Counterparty {
        peer,
        signed_device_keys,
        master_key,
        self_signing_key,
    }
}

/// Step four: the library asks who this user is, and is answered.
///
/// Returns the answer, because step seven has to repeat it with one
/// signature merged in and nothing else changed.
async fn fetch_counterparty_keys(
    counterparty: &Counterparty,
    user_id: &str,
    device_id: &str,
    alice_device_keys: &serde_json::Value,
) -> serde_json::Value {
    let peer = &counterparty.peer;
    let signed_device_keys = counterparty.signed_device_keys.clone();
    let master_key = counterparty.master_key.clone();
    let self_signing_key = counterparty.self_signing_key.clone();

    // ---- Step 4: we fetch the sender's keys -----------------------------
    //
    // `share_scope_key` first, because it is what makes the library track
    // the user at all: upstream's `mark_tracked_users_as_changed` skips
    // every user it has never seen, so without this no call on the shipped
    // surface could get a `/keys/query` issued for them.
    share_scope_key(SCOPE, &[user_id.to_string()])
        .await
        .expect("sharing a scope key must not fail");
    let query = drain_for_query_about(
        user_id,
        "the machine must ask who exists before it can verify anyone",
    )
    .await;
    let first_answer = serde_json::json!({
        "device_keys": { user_id: { device_id: signed_device_keys } },
        "master_keys": { user_id: master_key },
        "self_signing_keys": { user_id: self_signing_key },
    });
    mark_request_sent(&query.id, &first_answer.to_string())
        .await
        .expect("a keys-query response must be accepted");

    // The mirror image on the bare side: the counterparty learns the
    // library's device, so it can claim a one-time key and open a session
    // to carry its own group key later.
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

    // Anything the tracking above queued is drained so the assertions
    // below describe only this chain's own traffic.
    take_outgoing_requests()
        .await
        .expect("the pump must be drainable");

    first_answer
}

/// Steps five and six: a completed comparison signs the sender's master
/// key, and the signature it produces is uploaded.
///
/// Returns the signatures the upload carried, which step seven needs.
async fn compare_and_sign(peer: &OlmMachine, user_id: &str, device_id: &str) -> serde_json::Value {
    let alice_user: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");

    // ---- Step 5: a completed comparison signs the sender's master key ---
    //
    // Nothing else on this crate's surface signs another user's identity,
    // and nothing here reaches past that surface to do it: upstream's
    // `mark_as_done` calls `sign_user` for the other party as part of
    // finishing the comparison, and the signature upload it produces is
    // what the pump hands out below.
    let flow = request_flow(user_id, device_id)
        .await
        .expect("a known device can be asked to verify itself");
    let crossed = pump_to_bare(peer, user_id, device_id).await;
    assert!(
        crossed.contains(&"m.key.verification.request".to_string()),
        "the request must reach the counterparty through the pump: {crossed:?}"
    );

    let peer_request = peer
        .get_verification_request(&alice_user, &flow.0)
        .expect("the counterparty must have received the request");
    let ready = peer_request
        .accept_with_methods(vec![VerificationMethod::SasV1])
        .expect("a fresh request can be accepted");
    deliver_verification_request(&ready, user_id).await;

    begin_comparison(&flow)
        .await
        .expect("a ready flow can start a comparison");
    let crossed = pump_to_bare(peer, user_id, device_id).await;
    assert!(
        crossed.contains(&"m.key.verification.start".to_string()),
        "the start must reach the counterparty through the pump: {crossed:?}"
    );

    let peer_sas = bare_comparison(peer, &flow);
    let accept = peer_sas
        .accept()
        .expect("a comparison the other side started can be accepted");
    deliver_verification_request(&accept, user_id).await;

    pump_to_bare(peer, user_id, device_id).await;
    pump_bare_to_library(peer, user_id).await;

    assert_eq!(
        flow_stage(&flow).await.expect("the flow exists"),
        FlowStage::KeysExchanged
    );
    let material = read_material(&flow)
        .await
        .expect("the string is available once the keys are exchanged");
    assert_eq!(
        material.decimals,
        peer_sas
            .decimals()
            .expect("the counterparty has a string too"),
        "the two sides must have computed the same digits; a comparison whose \
         sides disagree is not a comparison, and everything below it would be \
         resting on nothing"
    );

    let (contents, _signatures) = peer_sas
        .confirm()
        .await
        .expect("the counterparty can confirm");
    for content in &contents {
        deliver_verification_request(content, user_id).await;
    }
    confirm_flow(&flow)
        .await
        .expect("a flow showing a string can be confirmed");

    let crossed = pump_to_bare(peer, user_id, device_id).await;
    assert!(
        crossed.contains(&"m.key.verification.mac".to_string()),
        "the library's confirmation must reach the counterparty: {crossed:?}"
    );
    let crossed = pump_bare_to_library(peer, user_id).await;
    assert!(
        crossed.contains(&"m.key.verification.done".to_string()),
        "the counterparty's acknowledgement must reach the library: {crossed:?}"
    );
    assert_eq!(
        flow_stage(&flow).await.expect("the flow exists"),
        FlowStage::Done,
        "the comparison must have finished; nothing signs an identity until it \
         does"
    );

    // ---- Step 6: we upload that signature -------------------------------
    //
    // The completion above was driven by the counterparty's own
    // acknowledgement arriving in a sync, so upstream queued the signature
    // upload for itself and it reaches this crate's pump as an ordinary
    // outgoing request. Asserted by name: a comparison that finished
    // without producing one would mean the identity was never signed, and
    // every step after this would be moot for a reason no assertion below
    // would name.
    let signature_upload = drain_for(
        "signature_upload",
        "a completed comparison with a cross-signed counterparty must produce \
         a signature over their master key",
    )
    .await;
    let signatures = uploaded_signatures(&signature_upload.body, user_id);
    mark_request_sent(&signature_upload.id, "{}")
        .await
        .expect("a signature-upload response must be accepted");

    signatures
}

/// Step seven: the library fetches the sender's keys again, so that the
/// signature it made in step five is in its own store.
async fn refetch_counterparty_keys(
    user_id: &str,
    device_id: &str,
    first_answer: &serde_json::Value,
    signatures: &serde_json::Value,
) {
    receive_sync_changes(
        &serde_json::json!({ "changed_devices": { "changed": [user_id] } }).to_string(),
    )
    .await
    .expect("the library must accept a sync naming a changed device list");

    let requery = drain_for_query_about(
        user_id,
        "a sync naming the counterparty as changed must get a second key \
         query issued",
    )
    .await;
    let second_answer = serde_json::json!({
        "device_keys": { user_id: { device_id: first_answer["device_keys"][user_id][device_id] } },
        "master_keys": {
            user_id: with_our_signature(
                first_answer["master_keys"][user_id].clone(),
                signatures,
            )
        },
        "self_signing_keys": { user_id: first_answer["self_signing_keys"][user_id] },
    });
    mark_request_sent(&requery.id, &second_answer.to_string())
        .await
        .expect("a keys-query response must be accepted");
}

/// Opens the counterparty's Olm session to the library's device.
///
/// Once per counterparty: it consumes one of the library's published
/// one-time keys, and a second call would find no missing session to
/// report.
async fn open_session_to_library(peer: &OlmMachine) {
    let alice_user: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");

    let (claim_id, _request) = peer
        .get_missing_sessions(std::iter::once(alice_user.as_ref()))
        .await
        .expect("the bare machine must be able to report missing sessions")
        .expect("the bare machine has no session to the library's device yet");
    let (key_id, key) = claim_one_time_key();
    peer.mark_request_as_sent(
        &claim_id,
        &keys_claim_response(
            &serde_json::json!({
                "one_time_keys": { ALICE_USER: { ALICE_DEVICE: { key_id: key } } }
            })
            .to_string(),
        ),
    )
    .await
    .expect("the bare machine must accept a keys-claim response");
}

/// Shares the counterparty's current group session key with the library.
///
/// Called again after a rotation, which is what makes the ordering test's
/// last reading possible: upstream fixes an inbound session's sender data
/// when its key arrives, so a new key arriving later is the only way a
/// sender's authenticity is ever re-evaluated.
async fn share_group_key(peer: &OlmMachine, user_id: &str) {
    let alice_user: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
    let scope_id: OwnedRoomId = SCOPE.parse().expect("a literal scope id parses");

    let shares = peer
        .share_room_key(
            &scope_id,
            std::iter::once(alice_user.as_ref()),
            EncryptionSettings::default(),
        )
        .await
        .expect("the bare machine must be able to share its own group key");
    let key_events: Vec<serde_json::Value> = shares
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
         withheld notice instead, which is an ordering failure and not \
         anything this test is about"
    );
    deliver_to_library(key_events).await;
}

/// One encrypted event from the counterparty, ready to hand to the library.
///
/// The event id is a parameter rather than derived, because the ordering
/// test decrypts the *same* event twice and has to hand back the same
/// identifier both times: a different one over the same message index is a
/// replay to upstream, and would fail for a reason unrelated to anything
/// under test.
async fn encrypted_event_from(
    peer: &OlmMachine,
    user_id: &str,
    event_id: &str,
    payload: &str,
) -> String {
    let scope_id: OwnedRoomId = SCOPE.parse().expect("a literal scope id parses");

    let content = Raw::<AnyMessageLikeEventContent>::from_json_string(payload.to_owned())
        .expect("a literal payload is well-formed JSON");
    let encrypted = peer
        .encrypt_room_event_raw(&scope_id, "m.room.message", &content)
        .await
        .expect("the bare machine must be able to encrypt for its own session");
    scoped_event(user_id, event_id, encrypted.content.json().get())
}

/// What the library's own surfaces say about the counterparty right now:
/// whether its identity is verified, and what its device's trust reads.
async fn observed(user_id: &str, device_id: &str) -> (bool, TrustState) {
    let peer_user: OwnedUserId = user_id.parse().expect("a literal user id parses");

    let identity_verified = with_machine({
        let peer_user = peer_user.clone();
        move |machine| {
            Box::pin(async move {
                machine
                    .get_identity(&peer_user, None)
                    .await
                    .expect("the store must be readable")
                    .expect("the counterparty's identity was fetched in step four")
                    .other()
                    .expect("another user's identity is an other identity")
                    .is_verified()
            })
        }
    })
    .await
    .expect("the library's machine must be live");

    let device_trust = device_statuses(user_id)
        .await
        .expect("the counterparty's devices must be readable")
        .into_iter()
        .find(|status| status.device_id == device_id)
        .expect("the library must know the device it just verified")
        .trust;

    (identity_verified, device_trust)
}

/// Drives the whole chain against one counterparty and decrypts one event
/// from it.
///
/// `refetch` is the single axis the two tests differ on: with it, step
/// seven happens; without it, everything up to and including step six
/// happens and the chain stops there.
async fn chain(
    user_id: &str,
    device_id: &str,
    payload: &str,
    refetch: bool,
    alice_device_keys: &serde_json::Value,
) -> Outcome {
    let counterparty = counterparty_with_identity(user_id, device_id).await;
    let first_answer =
        fetch_counterparty_keys(&counterparty, user_id, device_id, alice_device_keys).await;
    let signatures = compare_and_sign(&counterparty.peer, user_id, device_id).await;
    if refetch {
        refetch_counterparty_keys(user_id, device_id, &first_answer, &signatures).await;
    }

    // ---- The counterparty sends, and the library decrypts ---------------
    //
    // After the chain, not before it. Upstream fixes an inbound session's
    // sender data when the key arrives and recalculates it later only from
    // `UnknownDevice`, `DeviceInfo` or `VerificationViolation`
    // (`SenderData::should_recalculate`) -- never from `SenderUnverified`.
    // So a session received *before* its sender was verified keeps reading
    // `UnverifiedIdentity` for its whole life, and these two tests would be
    // measuring that instead of what they say they measure.
    //
    // That behaviour used to be documented here and asserted nowhere.
    // [`history_does_not_improve_when_the_sender_is_verified_later`] is now
    // the test for it, and this comment records why these two tests order
    // themselves the way they do rather than standing in for the property.
    open_session_to_library(&counterparty.peer).await;
    share_group_key(&counterparty.peer, user_id).await;
    let event = encrypted_event_from(
        &counterparty.peer,
        user_id,
        &format!("$from-{device_id}:example.org"),
        payload,
    )
    .await;
    let envelope = decrypt_event(SCOPE, &event, SenderTrustRequirement::Any)
        .await
        .expect("the library must decrypt what the bare machine encrypted");

    let (identity_verified, device_trust) = observed(user_id, device_id).await;

    Outcome {
        verification: envelope.sender_verification,
        recovered: envelope.ciphertext,
        identity_verified,
        device_trust,
    }
}

/// The counterparty's view of a flow the library started.
fn bare_comparison(peer: &OlmMachine, flow: &FlowId) -> matrix_sdk_crypto::Sas {
    let alice: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
    *peer
        .get_verification(&alice, &flow.0)
        .expect("the counterparty must have been told a comparison started")
        .sas_v1()
        .expect("a flow this test started through begin_comparison is a comparison, not a code. It said this library only ever starts short-string comparisons, which was a claim about the library and stopped being true when it learned to scan")
}

// ------------------------------------------------------------------ tests

/// All seven steps, and an event that reads `Verified` at the end.
///
/// This is the first test in this repository to reach that value, and it
/// reaches it the only way the milestone permits: by performing every step
/// of the chain against a counterparty this process does not control, with
/// no fixture anywhere asserting or fabricating the value on the way.
#[test]
fn the_whole_chain_makes_an_event_read_verified() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let alice_device_keys = library().await;
        let outcome = chain(
            REFETCHED_USER,
            REFETCHED_DEVICE,
            REFETCHED_PAYLOAD,
            true,
            &alice_device_keys,
        )
        .await;

        // The control on every authenticity assertion below, stated first.
        // If decryption itself broke, the value under test would be
        // meaningless rather than wrong, and this is what says which of the
        // two happened.
        assert_eq!(
            outcome.recovered,
            REFETCHED_PAYLOAD.as_bytes(),
            "the library must recover the counterparty's payload byte for byte"
        );

        // Upstream's second gate, read at its own level rather than only
        // through the value it produces: our user-signing key over their
        // master key, present in our store because step seven fetched it
        // back.
        assert!(
            outcome.identity_verified,
            "after the chain, the library's own view of the counterparty's \
             identity is verified -- this is the half of upstream's second \
             gate that step seven moves"
        );

        // The claim.
        assert_eq!(
            outcome.verification,
            Some(SenderVerification::Verified),
            "an event from a device whose owner we have signed, uploaded and \
             fetched back reads `Verified`. `UnverifiedIdentity` here means \
             the second key fetch did not take effect; `UnsignedDevice` means \
             the counterparty's own signature was never seen"
        );

        // And the device-level surface agrees. Not a restatement: this
        // reads `Device::is_verified()`, which is local trust *or*
        // cross-signing trust, while the value above reads only the second
        // of those. They are two answers from two upstream predicates, and
        // asserting both is what stops one of them carrying the whole
        // proof.
        assert_eq!(
            outcome.device_trust,
            TrustState::Verified,
            "the shipped device surface must agree that this device is trusted"
        );
    }));
}

/// The same chain, missing only its last step, produces a value below
/// `Verified`.
///
/// **The most valuable test in this file.** Everything up to and including
/// the signature upload happens exactly as in the test above: the
/// comparison completes, the device reads verified, the signature is
/// genuinely produced and genuinely uploaded. The only difference is that
/// the library never fetches the counterparty's keys again, so its own
/// store never sees the signature it just made -- and nothing anywhere
/// reports a problem.
///
/// Asserted as a value and not merely as "not `Verified`": the rung it
/// falls to is `UnverifiedIdentity`, one step down, which is what makes
/// this a silent defect rather than a loud one. A product reading it would
/// see the ordinary state of an unverified peer, with no indication that a
/// verification it performed had failed to take effect.
#[test]
fn omitting_the_second_key_fetch_leaves_the_sender_below_verified() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let alice_device_keys = library().await;
        let outcome = chain(
            UNFETCHED_USER,
            UNFETCHED_DEVICE,
            UNFETCHED_PAYLOAD,
            false,
            &alice_device_keys,
        )
        .await;

        // Green here, and green in the test above. Whatever the chain does
        // to authenticity, it does nothing to decryption, and this pair is
        // what says so.
        assert_eq!(
            outcome.recovered,
            UNFETCHED_PAYLOAD.as_bytes(),
            "omitting the second key fetch must not stop the library decrypting"
        );

        // The trap, at the level it happens: the signature exists and was
        // uploaded, and our own store has never seen it, so upstream's
        // second gate is still shut.
        assert!(
            !outcome.identity_verified,
            "a signature we made and uploaded but never fetched back is a \
             signature our own store has never seen: nothing caches it, and \
             upstream reads the store"
        );

        // The value, named exactly. `assert_ne!(.., Verified)` would also
        // pass if the chain had collapsed to `NoDeviceMissing` or
        // `UnsignedDevice`, which would mean this test was measuring some
        // other breakage entirely.
        assert_eq!(
            outcome.verification,
            Some(SenderVerification::UnverifiedIdentity),
            "a chain missing only its last step lands one rung below \
             `Verified`, silently. `Verified` here means the value is not \
             derived from what the store holds; `UnsignedDevice` means this \
             run failed somewhere earlier and is not testing step seven"
        );

        // The half of the surface that does *not* fall back, and the reason
        // this defect is invisible: the comparison really did verify the
        // device, so a product watching device trust sees success while
        // every event from that device still reads unverified.
        assert_eq!(
            outcome.device_trust,
            TrustState::Verified,
            "the comparison verified the device locally whatever happened to \
             the identity, which is exactly why omitting step seven looks \
             like success"
        );
    }));
}

/// Verifying a sender does not improve the events already decrypted from
/// them. It changes what arrives next, on the next session.
///
/// # The property, and why a product has to know it
///
/// A product's user interface has to decide what a badge does when someone
/// verifies a contact halfway down a conversation. The honest answer is
/// "from here on", not "your history improves", and this test is what makes
/// that answer a fact about the library rather than a note in a design
/// document.
///
/// The mechanism is upstream's and it is not configurable. An inbound group
/// session's `SenderData` is computed once, when the session key arrives,
/// and recomputed later only when `SenderData::should_recalculate` says so.
/// That predicate is true for `UnknownDevice`, `DeviceInfo` and
/// `VerificationViolation`, and false for `SenderUnverified`
/// (`matrix-sdk-crypto-0.18.0/src/olm/group_sessions/sender_data.rs`). A
/// session whose key arrived while its sender was merely cross-signed is
/// `SenderUnverified`, so it is never revisited, and the `/keys/query`
/// sweep that does revisit sessions only looks at the two device-level
/// states. Doing better would mean enumerating and rewriting stored
/// sessions ourselves, and `Store::save_inbound_group_sessions` is
/// `pub(crate)`.
///
/// # Four readings, in one run, on one counterparty
///
/// The order is the whole subject, so the readings are taken around the
/// chain rather than after it:
///
/// 1. **Before any verification**, on a session created before it:
///    `UnverifiedIdentity`. The premise. If this were `UnsignedDevice` the
///    counterparty never bootstrapped and every reading below would be
///    measuring something else.
/// 2. **The same event, decrypted again after the whole chain has run**:
///    still `UnverifiedIdentity`. This is the claim, in its literal form.
///    The same bytes, the same event id, a library that now holds our
///    signature over this sender's master key, and the same answer.
/// 3. **A new message on that same session**: still `UnverifiedIdentity`.
///    The value belongs to the session, not to the message, so a
///    conversation that keeps flowing on an established session does not
///    start improving either.
/// 4. **A message on a session created after the chain**: `Verified`. The
///    contrast, and the reason readings 2 and 3 mean anything. Without it
///    this test would pass just as well against a chain that silently did
///    nothing at all, which is precisely the failure
///    [`omitting_the_second_key_fetch_leaves_the_sender_below_verified`]
///    exists to catch one rung higher.
///
/// Between 1 and 2 the library's own view of the sender really does change:
/// `identity_verified` and the device's `TrustState` are both asserted
/// after the chain, so nothing here can pass by the chain having failed.
/// That is the shape of this test's own guard against vacuity, and it is
/// worth being explicit about it: three of the four readings are assertions
/// that a value did **not** move, and such a test is worthless unless
/// something in the same run proves the machinery underneath it did.
#[test]
fn history_does_not_improve_when_the_sender_is_verified_later() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        let scope_id: OwnedRoomId = SCOPE.parse().expect("a literal scope id parses");
        let alice_device_keys = library().await;
        let counterparty = counterparty_with_identity(HISTORY_USER, HISTORY_DEVICE).await;
        let first_answer = fetch_counterparty_keys(
            &counterparty,
            HISTORY_USER,
            HISTORY_DEVICE,
            &alice_device_keys,
        )
        .await;

        // ---- (1) One message, sent and decrypted before any comparison --
        open_session_to_library(&counterparty.peer).await;
        share_group_key(&counterparty.peer, HISTORY_USER).await;
        let event_id = format!("$before-the-chain-{HISTORY_DEVICE}:example.org");
        let event =
            encrypted_event_from(&counterparty.peer, HISTORY_USER, &event_id, HISTORY_PAYLOAD)
                .await;

        let before = decrypt_event(SCOPE, &event, SenderTrustRequirement::Any)
            .await
            .expect("the library must decrypt what the counterparty encrypted");
        assert_eq!(
            before.ciphertext,
            HISTORY_PAYLOAD.as_bytes(),
            "the control on every authenticity assertion below: if decryption \
             broke, the values under test are meaningless rather than wrong"
        );
        assert_eq!(
            before.sender_verification,
            Some(SenderVerification::UnverifiedIdentity),
            "the premise. A cross-signed sender we have not verified reads \
             `UnverifiedIdentity`; `UnsignedDevice` here would mean the \
             counterparty's own signature was never seen and this run is not \
             testing what it says it tests"
        );

        // ---- The whole chain, after the message rather than before it ---
        let signatures = compare_and_sign(&counterparty.peer, HISTORY_USER, HISTORY_DEVICE).await;
        refetch_counterparty_keys(HISTORY_USER, HISTORY_DEVICE, &first_answer, &signatures).await;

        let (identity_verified, device_trust) = observed(HISTORY_USER, HISTORY_DEVICE).await;
        assert!(
            identity_verified,
            "the chain must actually have completed: our user-signing key over \
             their master key, in our own store. Red here and every assertion \
             below is asserting that nothing changed while nothing changed"
        );
        assert_eq!(
            device_trust,
            TrustState::Verified,
            "the device-level surface must report the verification a product \
             just performed, which is the half that does move"
        );

        // ---- (2) The same event again. The claim. --------------------
        let again = decrypt_event(SCOPE, &event, SenderTrustRequirement::Any)
            .await
            .expect("the same event decrypts the same way, chain or no chain");
        assert_eq!(
            again.ciphertext,
            HISTORY_PAYLOAD.as_bytes(),
            "decrypting the same event twice recovers the same plaintext"
        );
        assert_eq!(
            again.sender_verification,
            Some(SenderVerification::UnverifiedIdentity),
            "an event decrypted before its sender was verified reads the same \
             afterwards. `Verified` here would mean this library had started \
             rewriting the authenticity of stored sessions, which upstream \
             does not do and this repository does not add"
        );

        // ---- (3) A new message on the session that predates the chain ---
        let same_session_event = encrypted_event_from(
            &counterparty.peer,
            HISTORY_USER,
            &format!("$same-session-{HISTORY_DEVICE}:example.org"),
            HISTORY_SAME_SESSION_PAYLOAD,
        )
        .await;
        let same_session = decrypt_event(SCOPE, &same_session_event, SenderTrustRequirement::Any)
            .await
            .expect("the library must decrypt a later message on the same session");
        assert_eq!(
            same_session.ciphertext,
            HISTORY_SAME_SESSION_PAYLOAD.as_bytes(),
            "a later message on the same session still decrypts"
        );
        assert_eq!(
            same_session.sender_verification,
            Some(SenderVerification::UnverifiedIdentity),
            "the value belongs to the session and not to the message, so a \
             conversation already flowing does not start improving in the \
             middle either"
        );

        // ---- (4) A session created after the chain. The contrast. -------
        //
        // Rotation is the only thing that moves this value, and it is the
        // counterparty's to perform: a new key arriving is a new
        // `SenderData` computed, this time against a store that holds our
        // signature.
        assert!(
            counterparty
                .peer
                .discard_room_key(&scope_id)
                .await
                .expect("the counterparty's own store must be writable"),
            "there must have been a session to discard; false here means the \
             three readings above ran against no shared session at all"
        );
        share_group_key(&counterparty.peer, HISTORY_USER).await;
        let rotated_event = encrypted_event_from(
            &counterparty.peer,
            HISTORY_USER,
            &format!("$rotated-{HISTORY_DEVICE}:example.org"),
            HISTORY_ROTATED_PAYLOAD,
        )
        .await;
        let rotated = decrypt_event(SCOPE, &rotated_event, SenderTrustRequirement::Any)
            .await
            .expect("the library must decrypt what the rotated session encrypted");
        assert_eq!(
            rotated.ciphertext,
            HISTORY_ROTATED_PAYLOAD.as_bytes(),
            "a rotated session still decrypts"
        );
        assert_eq!(
            rotated.sender_verification,
            Some(SenderVerification::Verified),
            "a session created after the chain reads `Verified`, and that is \
             what makes the three readings above a statement about history \
             rather than about a chain that failed. `UnverifiedIdentity` here \
             means the chain did not take effect and nothing above was \
             measured against a working verification"
        );
    }));
}

/// The counterparty with no cross-signing identity at all, for the test
/// below: a plain bare machine, like `two_parties.rs`'s Bob.
const IDENTITYLESS_USER: &str = "@identityless:example.org";
const IDENTITYLESS_DEVICE: &str = "PEERIDENTITYLESS";

/// The outbound half of the trust decision `decrypt_event` hands the
/// caller: what a bootstrapped machine shares with a user whose device no
/// identity vouches for.
///
/// `share_scope_key` on a machine that holds a verified identity of its own
/// collects recipients identity-based -- the strategy MSC4153 recommends,
/// and the one upstream refuses to run for a machine without an identity of
/// its own, which is why the choice is a consequence of the machine's state
/// rather than a parameter. The condition that can occur in either
/// direction is the load-bearing one here: by the second share below the
/// Olm session *exists* -- the claim has succeeded -- and the key is still
/// withheld, because the refusal is about the device's identity, not about
/// the absence of a session. Under `AllDevices`, the strategy this machine
/// used before it bootstrapped, the second share is exactly the call that
/// carries the key; `tests/two_parties.rs` and
/// `tests/decrypt_trust_requirement.rs` hold that half.
#[test]
fn a_bootstrapped_machine_withholds_the_scope_key_from_an_identityless_user() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    futures::executor::block_on(in_runtime(async move {
        // `library()` bootstraps an identity and asserts it is marked
        // verified -- the state that arms the identity-based strategy.
        // Nothing else from its fixture is used: the counterparty here
        // must be a user with no identity, which the file's other
        // fixtures deliberately are not.
        let _ = library().await;

        let peer_user: OwnedUserId = IDENTITYLESS_USER.parse().expect("a literal user id parses");
        let peer_device: OwnedDeviceId = IDENTITYLESS_DEVICE.into();
        let peer = OlmMachine::new(&peer_user, &peer_device).await;

        // ---- The peer publishes its device keys, with no identity ------
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
        let peer_device_keys =
            serde_json::to_value(&device_keys_of(&peer, &peer_user, &peer_device).await)
                .expect("upstream device keys serialise");
        let (peer_key_id, peer_key) = batch
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

        // ---- The library learns the peer's device ----------------------
        //
        // The query answer names a device and no master or self-signing
        // key, exactly as a server answers for a user whose client has no
        // cross-signing set up.
        share_scope_key(SCOPE, &[IDENTITYLESS_USER.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let query = take_outgoing_requests()
            .await
            .expect("the pump must be drainable")
            .into_iter()
            .find(|r| r.kind == "keys_query")
            .expect("the machine must ask who exists before it can share with anyone");
        mark_request_sent(
            &query.id,
            &serde_json::json!({
                "device_keys": { IDENTITYLESS_USER: { IDENTITYLESS_DEVICE: peer_device_keys } }
            })
            .to_string(),
        )
        .await
        .expect("a keys-query response must be accepted");

        // ---- First share: the claim, and the identity withholding ------
        //
        // The withheld code asserted here is the point: `m.unverified` is
        // the *identity* refusal, produced by the collect strategy before
        // anything is encrypted. The missing-session failure would read
        // `m.no_olm`, and it is not what this fixture is about.
        share_scope_key(SCOPE, &[IDENTITYLESS_USER.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let first = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let claim = first
            .iter()
            .find(|r| r.kind == "keys_claim")
            .expect("sharing to a device with no Olm session must queue a keys claim");
        let first_codes: Vec<String> = first
            .iter()
            .filter(|r| r.kind == "to_device")
            .filter_map(|r| withheld_code_for(&r.body, IDENTITYLESS_USER, IDENTITYLESS_DEVICE))
            .collect();
        assert!(
            first_codes.contains(&"m.unverified".to_string()),
            "an identity-based share must withhold the key from a user with no \
             published identity, as m.unverified -- the codes were {first_codes:?}"
        );

        // The claim is answered, so an Olm session now exists. Under
        // `AllDevices` -- the strategy this machine used before it
        // bootstrapped -- the next share is the call that carries the key.
        mark_request_sent(
            &claim.id,
            &serde_json::json!({
                "one_time_keys": {
                    IDENTITYLESS_USER: { IDENTITYLESS_DEVICE: { peer_key_id: peer_key } }
                }
            })
            .to_string(),
        )
        .await
        .expect("a keys-claim response must be accepted");

        // ---- Second share: the session exists, the key must not travel --
        share_scope_key(SCOPE, &[IDENTITYLESS_USER.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let second = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let key_carrying: Vec<&OutgoingRequest> = second
            .iter()
            .filter(|r| {
                r.kind == "to_device"
                    && declared_event_type(&r.body) == "m.room.encrypted"
                    && addresses(&r.body, IDENTITYLESS_USER, IDENTITYLESS_DEVICE)
            })
            .collect();
        assert!(
            key_carrying.is_empty(),
            "an identity-based share must never carry the key to a device whose \
             owner has no published identity, even once the Olm session exists \
             -- under AllDevices this is exactly the call that delivers it"
        );
    }));
}
