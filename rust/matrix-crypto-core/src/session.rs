//! Ingesting sync changes into the crypto machine.
//!
//! The product already performs the `/sync` request; this module only
//! consumes the encryption-relevant slice of the response it hands back --
//! to-device events, one-time and fallback key counts, and changed or left
//! devices -- so the machine can decrypt, track key counts, and learn about
//! other devices. This is the prerequisite every later crypto operation
//! (sharing a key, encrypting, decrypting) depends on.

use std::collections::BTreeMap;
use std::sync::Mutex as StdMutex;

// Already a direct dependency of this crate (see the Cargo.toml comment on
// the `matrix-sdk-common` entry, written for reaching `ruma` the same way):
// this is the type `MegolmError::MissingRoomKey`'s own `Option<_>` carries,
// reached through the crate that defines it rather than through
// `matrix-sdk-crypto`, which does not re-export it.
use matrix_sdk_common::deserialized_responses::{
    DeviceLinkProblem, VerificationLevel, VerificationState, WithheldCode,
};
// Response types for the six kinds `OlmMachine::outgoing_requests` and
// `share_room_key` can ever hand out (matched exhaustively against
// `AnyOutgoingRequest` below, with no wildcard -- see `describe_outgoing`).
// Each is renamed on import: their upstream names collide with either one
// another (every endpoint module calls its own type `Response`) or with this
// module's own public `OutgoingRequest`.
use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::{
    Request as KeysClaimRequest, Response as KeysClaimResponse,
};
use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
use matrix_sdk_common::ruma::api::client::keys::upload_signatures::v3::Response as SignatureUploadResponse;
// The seventh response type, reached through `ruma` directly: unlike the six
// above it is not re-exported by `matrix_sdk_crypto::types::requests`, which
// imports it privately for `AnyIncomingResponse`'s own declaration and stops
// there.
use matrix_sdk_common::ruma::api::client::keys::upload_signing_keys::v3::Response as SigningKeysUploadResponse;
use matrix_sdk_common::ruma::api::client::message::send_message_event::v3::Response as RoomMessageResponse;
use matrix_sdk_common::ruma::api::client::sync::sync_events::DeviceLists;
use matrix_sdk_common::ruma::api::client::to_device::send_event_to_device::v3::Response as ToDeviceHttpResponse;
use matrix_sdk_common::ruma::api::IncomingResponse;
use matrix_sdk_common::ruma::events::{
    AnyMessageLikeEventContent, AnyToDeviceEvent, MessageLikeEventContent,
};
// `exports::http`, not a direct `http` dependency of this crate: it is the
// exact `http` version `ruma`'s own `IncomingResponse::try_from_http_response`
// requires, reached through `ruma`'s own re-export rather than a second,
// independently-versioned copy this crate would have to keep in step by hand.
use matrix_sdk_common::ruma::exports::http;
use matrix_sdk_common::ruma::serde::Raw;
use matrix_sdk_common::ruma::{
    OneTimeKeyAlgorithm, OwnedRoomId, OwnedTransactionId, OwnedUserId, TransactionId, UInt, UserId,
};
use matrix_sdk_crypto::types::events::room::encrypted::EncryptedEvent;
// `OutgoingRequest` is renamed on import: this module publishes a public
// type of the same name, and the upstream one is only ever held, never
// exposed.
use matrix_sdk_crypto::types::requests::{
    AnyIncomingResponse, AnyOutgoingRequest, KeysQueryRequest,
    OutgoingRequest as UpstreamOutgoingRequest, ToDeviceRequest, UploadSigningKeysRequest,
};
// Upstream's own wrapper for a cross-signing key marked as a master key.
// Imported rather than re-derived so that `answer_about_this_account` reads
// the answer's master key with the exact call upstream reads it with --
// `deserialize_as_unchecked::<MasterPubkey>`, whose `try_from` validates the
// `usage` and the inner `user_id` -- and compares it with upstream's own
// `PartialEq`.
use matrix_sdk_crypto::types::MasterPubkey;
use matrix_sdk_crypto::UserIdentity;
// Reached through `matrix_sdk_crypto`'s own `pub use vodozemac;` re-export
// rather than a direct `vodozemac` dependency this crate would then have to
// keep version-matched by hand -- the same reasoning `machine.rs` documents
// for reaching `ruma` through `matrix-sdk-common` rather than depending on
// it directly.
use matrix_sdk_crypto::vodozemac::megolm::DecryptionError;
use matrix_sdk_crypto::{
    CollectStrategy, DecryptionSettings, EncryptionSettings, EncryptionSyncChanges, MegolmError,
    OlmMachine, TrustRequirement,
};
use serde::Deserialize;

use crate::machine::{with_machine, MachineError};

/// What [`decrypt_event`] requires of a sender's device before it hands an
/// event to the product.
///
/// The closed, library-shaped mirror of upstream's own three tiers
/// (`matrix-sdk-crypto-0.18.0/src/lib.rs`: `Untrusted`,
/// `CrossSignedOrLegacy`, `CrossSigned`), named in this crate's own
/// vocabulary rather than upstream's, on the same terms
/// [`SenderVerification`] already carries: the sender's *device* is signed
/// by its owner's cross-signing identity, and that fact is what each
/// tightened tier checks, whether or not this machine has verified the
/// owner. Local trust is deliberately absent from the set, exactly as it is
/// upstream: a comparison or a scan sets local trust in a device, and no
/// tier takes it, so a carefully compared peer whose device carries no
/// cross-signature is refused by every tightened tier alike.
///
/// This crate's own default is [`Any`](Self::Any), the tier that preserves
/// this library's behaviour since 0.1.0. It is upstream's most permissive
/// option, the one upstream documents as "not recommended, per the guidance
/// of MSC4153", and it is the default because a library cannot know whether
/// the product's users carry cross-signing identities -- refusing events
/// from unsigned senders is the product's decision, and this type exists so
/// the product can make it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderTrustRequirement {
    /// Decrypt events from every sender's device, signed or not.
    ///
    /// The historical behaviour, and what a caller passes to keep it. The
    /// returned [`Envelope`]'s `sender_verification` still carries what
    /// this machine knows about the sender, so a product that reads it can
    /// apply the same gate itself -- what this tier buys is not having to.
    Any,
    /// Decrypt events from a device signed by its owner's cross-signing
    /// identity, and from legacy sessions whose sender this machine could
    /// not record when the session was created.
    ///
    /// The tightening a product reaching for "refuse unauthenticated
    /// senders" wants when it has pre-existing sessions around: events from
    /// unsigned devices are refused, but history that predates trust
    /// information keeps decrypting, reading
    /// [`SenderVerification::NoDeviceInsecureSource`] or
    /// [`SenderVerification::UnsignedDevice`] on the events that pass on
    /// legacy grounds alone.
    IdentitySignedOrLegacy,
    /// Decrypt events from a device signed by its owner's cross-signing
    /// identity, and nothing else.
    ///
    /// The strictest tier upstream offers. Events from legacy sessions are
    /// refused along with events from unsigned devices, so a product that
    /// has never imported history can take this tier directly.
    IdentitySigned,
}

/// Settings for `OlmMachine::receive_sync_changes`.
///
/// A fresh value built per call, not a cached constant: the decision this
/// encodes is meant to be revisited, not optimised into something a later
/// reader has to track down through an extra indirection.
fn decryption_settings() -> DecryptionSettings {
    // This said "verification lands in M3; revisit this with it." M3 landed
    // verification, this was revisited, and the answer was that it must not
    // move yet -- recorded here rather than left as an invitation to make
    // exactly the wrong change next. That answer has since split in two,
    // and only one half of it is still this line's to give.
    //
    // The half that moved is [`decrypt_event`], which now takes a
    // [`SenderTrustRequirement`] from the caller: the product decides what
    // a room event's sender must satisfy, and the product is the only layer
    // that can, because it knows whether its users carry cross-signing
    // identities. See that type's own doc comment for the three tiers and
    // why local trust is absent from all of them.
    //
    // The half that stays is this line. These settings also gate what
    // [`receive_sync_changes`] accepts, and what crosses that path is not
    // events the product renders but the to-device traffic the machine
    // ingests -- room keys, verification messages, key requests. A trust
    // requirement tightened there would refuse a room key from the user's
    // own unverified device, and every event that key ever protected would
    // stop decrypting; there is no tier above `Untrusted` whose refusal
    // there a library may take on the product's behalf. So this one stays
    // `Untrusted`, upstream's own most permissive option, explicitly
    // documented as "not recommended", as a deliberate, named choice about
    // the ingest path rather than a placeholder.
    DecryptionSettings {
        sender_device_trust_requirement: TrustRequirement::Untrusted,
    }
}

/// Errors from operating on the crypto machine: ingesting sync changes,
/// encrypting, decrypting, and pumping outbound requests.
///
/// Carries no payload content, ciphertext, device id or user id -- see spec
/// section 7: upstream `Display` output can embed event content, so no
/// upstream error is ever forwarded, only mapped to one of these fixed
/// shapes. `MalformedPayload` and `Failed` are kept distinct because they
/// call for different product responses: nonsense the product sent itself
/// is not the same problem as a crypto operation failing on well-formed
/// input.
///
/// The five decryption kinds below (`MissingKey` through `Undecryptable`)
/// exist for the same reason, one level more specific: decryption failure
/// is normal Matrix operation, not a single exceptional condition, and
/// collapsing all five into `Failed` would tell a product nothing about
/// which of "retry", "request the key again", "warn about an untrusted
/// device" or "show a placeholder" applies. See [`classify_megolm_error`]
/// for exactly which upstream condition maps to which.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// `raw_json` did not parse into the shape this function accepts.
    ///
    /// Also what [`mark_request_sent`] returns for a `response_json` that
    /// is not a success response at all -- a standard Matrix error body, or
    /// a user-interactive authentication challenge. Those parse into a
    /// valid empty success for every shape this module handles, which is
    /// why they are refused explicitly rather than left to serde; see
    /// [`refuse_a_non_response`]. Reported as this kind rather than a new
    /// one because it is the same answer to the caller: what you handed
    /// back is not this endpoint's response.
    #[error("the payload could not be parsed")]
    MalformedPayload,
    /// A `scope` or user id handed to this call is not a parseable
    /// identifier.
    ///
    /// Split out of [`MalformedPayload`](Self::MalformedPayload), which it
    /// used to share. Two kinds exist to be told apart, and a caller who
    /// passed a scope that is not a well-formed identifier was being told
    /// their *payload* was malformed while their payload was fine. The
    /// public `asCryptoScopeId` performs no validation at all, so an
    /// unparseable scope is an ordinary mistake rather than an exotic one,
    /// and pointing at the wrong argument costs the caller the whole
    /// diagnosis.
    ///
    /// Fieldless like every other kind here, and for the usual reason: what
    /// the identifier contained is caller-supplied content this crate does
    /// not carry across the boundary. Nothing is lost by that here in
    /// particular, since the identifier is the caller's own argument and
    /// the caller still has it.
    ///
    /// Declared next to `MalformedPayload`, where it reads, rather than
    /// appended: this enum has no wire representation, so its order is free.
    /// Its FFI mirror does have one, and is appended last there for the
    /// reason that mirror's own doc comment gives.
    #[error("an identifier could not be parsed")]
    MalformedIdentifier,
    /// No crypto machine has been created yet.
    #[error("no crypto machine has been created")]
    NotInitialised,
    /// The crypto machine rejected or failed to process the sync changes.
    #[error("the crypto operation failed")]
    Failed,
    /// `mark_request_sent` was called with an `id` this machine never
    /// handed out through `take_outgoing_requests`, or already resolved.
    ///
    /// Kept distinct from `MalformedPayload`: the caller's `id` is
    /// syntactically fine (any string parses as a `TransactionId`, which is
    /// an opaque identifier with no format of its own) -- what is wrong is
    /// that it does not match anything this process is waiting to hear
    /// about, which calls for a different product response than "you sent
    /// nonsense".
    #[error("the request id does not match a pending request")]
    UnknownRequest,
    /// [`mark_request_failed`] was given a `status` that is not one a
    /// refused request can carry.
    ///
    /// Accepted are `0`, meaning no response reached the caller at all, and
    /// `300` through `599`. Everything else is rejected, and the case worth
    /// naming is a **2xx**: a caller passing one has confused this call with
    /// [`mark_request_sent`], and since a refusal changes no state, being
    /// told nothing would let that confusion stand.
    ///
    /// It is the confusion this call can see **in its own arguments**, which
    /// is not the same as the only one the library catches: reporting a
    /// refused response through [`mark_request_sent`] is caught too whenever
    /// the body is not shaped like that endpoint's answer, by
    /// [`refuse_a_non_response`]. What neither can see is a refusal whose
    /// body *is* shaped like an answer. See [`mark_request_failed`].
    ///
    /// Declared next to [`UnknownRequest`](Self::UnknownRequest), which it
    /// reads beside, rather than appended: this enum has no wire
    /// representation, so its order is free. Its FFI mirror does have one,
    /// and is appended last there.
    #[error("the status is not one a refused request can carry")]
    NotAFailureStatus,
    /// [`decrypt_event`] either found no record at all of the group
    /// session that encrypted this event, or found the session but could
    /// not use it because its ratchet has already advanced past this
    /// message's index (the ordinary "you joined the room after this was
    /// sent" case). Worth a retry either way: the key may simply not have
    /// arrived yet, or an earlier ratchet state may still arrive, e.g. a
    /// later sync or a key request may bring in what is missing.
    #[error("no key is available to decrypt this event")]
    MissingKey,
    /// [`decrypt_event`] found a record that the group session was
    /// explicitly withheld, or never shared with this device, for a
    /// *circumstantial* reason: `m.unavailable` (the sender did not have
    /// the key yet) or `m.no_olm` (the sender could not reach this
    /// device), or any withheld code this crate does not specifically
    /// classify. Distinct from `MissingKey`: this is a known fact about
    /// the session rather than the mere absence of one. Worth requesting
    /// again -- the circumstance that produced it can change on a later
    /// attempt.
    ///
    /// The two withheld codes that are a deliberate *policy* refusal
    /// instead of a circumstance -- `m.blacklisted`, `m.unauthorised` --
    /// are [`SessionRefused`](Self::SessionRefused), not this kind; see
    /// its own doc comment for why retrying those is never productive.
    /// This kind does not distinguish which of its own remaining reasons
    /// applies -- the reason itself is sender-supplied wire content this
    /// crate deliberately does not carry into any error, per the
    /// no-payload-content rule.
    #[error("the session that encrypted this event was not shared with this device")]
    UnsharedSession,
    /// [`decrypt_event`] found a record that the group session's sender
    /// deliberately refused to share it with this device: `m.blacklisted`
    /// (the sender has blocked this device) or `m.unauthorised` (this
    /// device was not entitled to the key -- for example, it asked for a
    /// key to a message sent before it joined the room). Split out from
    /// [`UnsharedSession`](Self::UnsharedSession) rather than folded into
    /// it, and rather than adding a field to either: G26 in the
    /// milestone's own ledger ruled that a product treating every
    /// `UnsharedSession` occurrence as retriable would retry one of these
    /// two forever, for no possible gain, at real cost in battery and
    /// network, since both are the sender's own decision and nothing this
    /// device does changes it.
    ///
    /// Fieldless like every other kind here, and not by discipline but by
    /// construction: the split happens by matching upstream's `WithheldCode`
    /// *variant* to choose between two already-existing, already-fixed
    /// kinds, never by reading it into a field, so which of the two codes
    /// produced this is still sender-supplied wire content this crate does
    /// not carry across the boundary. This kind never distinguishes which
    /// of the two applies.
    #[error("the session that encrypted this event was refused by its sender's policy")]
    SessionRefused,
    /// [`decrypt_event`] could not trust the device that supposedly
    /// encrypted this event because its identity does not match what this
    /// machine has on record.
    ///
    /// Unfixable, and distinct from [`SenderNotTrusted`](Self::SenderNotTrusted)
    /// for that exact reason: nothing the user does changes a room key
    /// whose own embedded identity disagrees with itself, so a product
    /// must read this as "this event's provenance is broken, never trust
    /// it" -- the opposite of that variant's "verify this person to read
    /// this". This kind used to fold the two together, and the fold was
    /// documented as one to split "when the arm becomes reachable", which
    /// the day the trust requirement became configurable made happen. B8
    /// in the M3 design's own deferred list; dispatched now.
    ///
    /// Note that the fieldless shape this kind keeps is the one half of
    /// the old fold that is about the *machine's records*, not about any
    /// caller-supplied content: nothing of the mismatch crosses the
    /// boundary, per the no-payload-content rule.
    #[error("the device that encrypted this event is not trusted")]
    UnknownDevice,
    /// [`decrypt_event`] was asked for a [`SenderTrustRequirement`] the
    /// device that encrypted this event does not meet.
    ///
    /// A policy gap, not a defect in the event: the device is fine, it
    /// simply does not clear the trust bar the call required. Fixable by
    /// the user verifying the device -- or by the product relaxing the
    /// requirement it asked for -- and distinct from
    /// [`UnknownDevice`](Self::UnknownDevice) for that exact reason: the
    /// two want opposite things done about them, and one shared kind
    /// could not say which. This said "unreachable until the day
    /// `decryption_settings()` stops passing `Untrusted`", which is the
    /// day [`decrypt_event`]'s requirement became the caller's to choose.
    ///
    /// Not retriable on its own: the same call with the same requirement
    /// fails the same way every time. What resolves it is a verification,
    /// or a different requirement.
    #[error("the sender's device does not meet the trust requirement for decryption")]
    SenderNotTrusted,
    /// [`decrypt_event`] ran the cryptographic operation and it did not
    /// produce a usable plaintext: a corrupted or tampered ciphertext, a
    /// malformed event, or a decrypted payload that is not a well-formed
    /// Matrix event. Not worth retrying: the same input fails the same way
    /// every time.
    #[error("this event could not be decrypted")]
    Undecryptable,
}

impl From<MachineError> for SessionError {
    fn from(error: MachineError) -> Self {
        match error {
            MachineError::NotInitialised => SessionError::NotInitialised,
            // `with_machine` can only ever produce `NotInitialised` today --
            // see its own doc comment in `machine.rs`. Every other
            // `MachineError` variant belongs to `create_machine`/
            // `open_store`, not to a call that already requires a live
            // machine. Matched explicitly anyway, with no wildcard, so a
            // future `MachineError` variant fails this build instead of
            // silently landing on `Failed`.
            // Carried across by name rather than collapsed into `Failed`,
            // now that this enum has the matching kind. Unreachable today
            // for the reason above, and mapping it truthfully costs
            // nothing if it ever stops being.
            MachineError::MalformedIdentifier { .. } => SessionError::MalformedIdentifier,
            // The three verification-flow kinds belong to `verification.rs`,
            // which returns `MachineError` directly and never routes through
            // this conversion. Listed by name for the same no-wildcard reason
            // as everything above: they are unreachable here today, and a
            // future variant must still fail this build rather than land on
            // `Failed` unnoticed.
            // Carried across by name, like `MalformedIdentifier` above and
            // for the same reason: this enum has the matching kind, so
            // mapping it truthfully costs nothing. Still unreachable here --
            // `with_machine` only ever produces `NotInitialised`.
            MachineError::UnknownDevice => SessionError::UnknownDevice,
            // The two identity-bootstrap kinds belong to `signing.rs`, which
            // returns `MachineError` directly and never routes through this
            // conversion either. Listed by name for the same no-wildcard
            // reason as everything above.
            MachineError::AlreadyInitialised
            | MachineError::Store { .. }
            | MachineError::MismatchedAccount
            | MachineError::UnknownFlow
            | MachineError::WrongStage
            | MachineError::MaterialNotReady
            | MachineError::AccountKeysNotFetched
            | MachineError::IdentityAlreadyExists
            // `verification.rs`'s third refusal, and it belongs to that
            // module for the same reason as the three flow kinds above:
            // unreachable through this conversion, listed by name so a
            // future variant still has to be ruled on here.
            | MachineError::IdentityNotKnown
            // `recovery.rs`'s four, on the same rule again. That module
            // returns `MachineError` directly and never routes through this
            // conversion, so all four are unreachable here; they are listed
            // by name rather than caught by a wildcard so the next variant
            // added anywhere still has to be ruled on in this match.
            | MachineError::PrivateKeysNotHeld
            | MachineError::RecoveryNotSetUp
            | MachineError::RecoveryKeyIncorrect
            | MachineError::RecoveryDataMalformed
            // `recovery.rs`'s fifth, added when `create_recovery` stopped
            // writing over a recovery the account already had. Same rule,
            // same unreachability, listed by name for the same reason.
            | MachineError::RecoveryAlreadyExists
            // `verification.rs`'s three refusals for a flow driven by
            // scanning a code, on the same rule again: that module returns
            // `MachineError` directly and never routes through this
            // conversion, so all three are unreachable here and are listed
            // by name so the next variant added anywhere still has to be
            // ruled on in this match. This match is what caught all three
            // of them the moment they were declared, which is what a
            // wildcard here would have cost.
            | MachineError::PeerIdentityNotKnown
            | MachineError::CodeNotOffered
            | MachineError::ScannedCodeRefused
            // The three that split `ScannedCodeRefused` apart when the
            // payload gained a surface to cross to. Same rule, same
            // unreachability, listed by name for the same reason, and this
            // match caught all three of them the moment they were declared.
            | MachineError::ScannedCodeUnrecognised
            | MachineError::ScannedCodeMalformed
            | MachineError::ScannedCodeForAnotherFlow
            // The half that left `CodeNotOffered` when the code switch
            // became two facts rather than one boolean. Same rule, same
            // unreachability, listed by name for the same reason, and this
            // match caught it the moment it was declared.
            | MachineError::PeerCannotScan => SessionError::Failed,
        }
    }
}

/// What a call to [`receive_sync_changes`] did to the machine's state.
///
/// Both counts describe the call's own two returned collections --
/// processed to-device events, then new or updated room keys, per
/// `matrix-sdk-crypto-0.18.0/src/machine/mod.rs:1728` -- not an echo of what
/// the caller sent. The machine can fold in its own bookkeeping (e.g.
/// garbage-collected verification objects) and can also drop an encrypted
/// event entirely (e.g. one from a dehydrated device), so the input length
/// and `to_device_event_count` are not guaranteed to match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// How many to-device events this call reported having processed.
    pub to_device_event_count: u32,
    /// How many new or updated end-to-end sessions this call produced.
    pub new_session_count: u32,
}

/// The wire shape `receive_sync_changes` accepts, mirroring
/// `EncryptionSyncChanges`'s own field names exactly (confirmed against
/// `matrix-sdk-crypto-0.18.0/src/machine/mod.rs:3150`) so there is no
/// separate translation layer to keep in sync with upstream as it evolves.
///
/// Every field defaults when its key is absent, not only when its value is
/// empty: an empty sync is the shape a product sends constantly, and it
/// must be accepted and report nothing, not rejected as malformed because
/// one key was left out. `#[serde(default)]` is required even on the two
/// `Option` fields -- serde does not treat a missing key as `None` for an
/// `Option` field on its own, only when told to.
///
/// No `#[derive(Debug)]`: `to_device_events` can carry ciphertext, and
/// nothing here needs printing. Never format this struct or its fields.
#[derive(Deserialize)]
struct SyncChangesPayload {
    #[serde(default)]
    to_device_events: Vec<Raw<AnyToDeviceEvent>>,
    #[serde(default)]
    changed_devices: DeviceLists,
    #[serde(default)]
    one_time_keys_counts: BTreeMap<OneTimeKeyAlgorithm, UInt>,
    #[serde(default)]
    unused_fallback_keys: Option<Vec<OneTimeKeyAlgorithm>>,
    #[serde(default)]
    next_batch_token: Option<String>,
}

/// Feeds the encryption-relevant slice of a `/sync` response into the crypto
/// machine, so it can decrypt to-device events, track one-time and fallback
/// key counts, and learn about changed or left devices.
///
/// The bridge takes the JSON the product already fetched; it never performs
/// the sync request itself. See [`SyncChangesPayload`] for the accepted
/// shape.
pub async fn receive_sync_changes(raw_json: &str) -> Result<SyncOutcome, SessionError> {
    let payload: SyncChangesPayload =
        serde_json::from_str(raw_json).map_err(|_| SessionError::MalformedPayload)?;

    let SyncChangesPayload {
        to_device_events,
        changed_devices,
        one_time_keys_counts,
        unused_fallback_keys,
        next_batch_token,
    } = payload;

    // Owned locals moved into the closure, not borrowed from this stack
    // frame: `with_machine` requires its closure `Send + 'static` (see its
    // doc comment in `machine.rs`). `EncryptionSyncChanges` itself borrows
    // (`changed_devices`, `one_time_keys_counts`), but only from these
    // locals, and only for the duration of the `receive_sync_changes` call
    // below, all inside the one async block -- so the borrow never needs to
    // outlive anything the closure does not already own.
    //
    // `with_machine` already runs inside the library's runtime and holds the
    // machine lock for this closure's duration; wrapping this call in
    // `in_runtime` again, or emitting a signal from inside it, is exactly
    // what its doc comment warns against.
    let processed = with_machine(move |machine| {
        Box::pin(async move {
            let changes = EncryptionSyncChanges {
                to_device_events,
                changed_devices: &changed_devices,
                one_time_keys_counts: &one_time_keys_counts,
                unused_fallback_keys: unused_fallback_keys.as_deref(),
                next_batch_token,
            };

            machine
                .receive_sync_changes(changes, &decryption_settings())
                .await
        })
    })
    .await?;

    match processed {
        Ok((events, room_keys)) => {
            // After the machine lock is released, never inside the closure
            // above -- which is exactly what that closure's own comment
            // warns against. This is the moment every verification
            // transition this library observes actually happens: an
            // invitation arriving, a peer's confirmation completing a
            // comparison, a reciprocation saying the far side scanned this
            // device's code, a flow timing out. It returns without touching
            // the store when nobody has subscribed to the signal channel.
            //
            // The processed events are handed over rather than the payload
            // this function was given, and upstream's own doc comment on
            // `receive_sync_changes` is the reason: what it returns is
            // "decrypted where needed and where possible", so a
            // verification event that arrived Olm-encrypted appears here in
            // the clear. The one flow shape that cannot be enumerated out
            // of the machine has to be recognised from these, and
            // recognising it from the raw input instead would miss every
            // encrypted one. See `verification::bare_start_candidates`.
            // Before the announcement, and outside the closure above for the
            // same reason it is. A cross-user code verification that just
            // finished owes a `/keys/query` about the person it verified, and
            // nothing else in this library will ever ask it. Queued first so
            // that it is already in the pump when a listener is told the flow
            // completed: `emit_crypto` detaches delivery, so a listener that
            // reacts by draining can be running before this call returns.
            // Ungated by the observer, unlike the announcement, because a
            // product that never subscribes still reads
            // `device_statuses` and still deserves the right answer.
            crate::verification::queue_peer_key_queries().await;
            crate::verification::announce_state_changes(&events).await;
            Ok(SyncOutcome {
                to_device_event_count: events.len() as u32,
                new_session_count: room_keys.len() as u32,
            })
        }
        // Upstream `Display` output can embed event content, a device id or
        // a user id (e.g. `OlmError::SessionWedged(OwnedUserId, Curve25519PublicKey)`,
        // matrix-sdk-crypto-0.18.0/src/error.rs:61) -- never forwarded, per
        // spec section 7. Mapped to a fixed-shape variant instead, with no
        // `detail` field to carry it in.
        Err(_upstream) => Err(SessionError::Failed),
    }
}

/// Parses the opaque scope string into the identifier it addresses today.
///
/// This is the one place that name appears in this module: a scope maps to
/// a room id 1:1 for now, but that mapping is this function's own
/// implementation detail, never a public identifier -- see spec section 6
/// and the design doc's section 3bis. A later scope kind (e.g. an MLS group)
/// would branch here without moving anything public.
/// `MalformedIdentifier`, not `MalformedPayload`: what failed is the
/// caller's scope argument, not the event or response body they also
/// passed. See [`SessionError::MalformedIdentifier`].
fn parse_scope(scope: &str) -> Result<OwnedRoomId, SessionError> {
    scope.parse().map_err(|_| SessionError::MalformedIdentifier)
}

/// Same reasoning as [`parse_scope`]: a user id that does not parse is a
/// malformed identifier, and the caller supplied it directly.
fn parse_user(user_id: &str) -> Result<OwnedUserId, SessionError> {
    user_id
        .parse()
        .map_err(|_| SessionError::MalformedIdentifier)
}

/// What upstream knew about the sender of one event, at the moment it
/// decrypted that event.
///
/// **This is not [`crate::TrustState`], and the difference is the whole
/// reason there are two of them.** `TrustState` describes a *device*, and a
/// completed short-string comparison changes it. This describes *one
/// event's sender at one moment*, and a completed comparison does not
/// change it: upstream's decryption path asks whether the sending device
/// carries a cross-signature its owner published, and a comparison sets
/// local trust instead. Two subjects, two vocabularies. Folding them would
/// lose the distinction between an unverified identity, an unsigned device
/// and a sender mismatch, which are three different things for a product to
/// do about one event.
///
/// # What each of these costs to reach, and whose identity pays
///
/// The distinction is **whose** cross-signing identity a value depends on.
/// Upstream's decision function is `SenderData::from_device`, and it has
/// two gates. The first, `Device::is_cross_signed_by_owner`, asks only
/// whether the sending device carries a signature from a self-signing key
/// its own owner published. This machine is not consulted. The second,
/// `Device::is_cross_signing_trusted`, is where our own identity is read:
/// for another user's device it is
/// `own_identity.is_identity_verified(theirs) && theirs.is_device_signed(device)`,
/// so it needs our user-signing key over their master key, **present in our
/// own store**.
///
/// So [`SenderVerification::UnverifiedIdentity`] arrives on the ordinary
/// path, with no work on our side at all. It is what the first gate
/// passing and the second failing means. Any peer who has set cross-signing
/// up already produces it here, which is every Element user, and
/// `tests/cross_signed_peer.rs` decrypts an event from one and asserts it.
/// Nothing about that value is a claim of authenticity: it says the sending
/// device is one its owner vouches for, and that we have no opinion about
/// the owner.
///
/// [`SenderVerification::Verified`] is what the second gate passing means,
/// and reaching it is a chain of seven steps rather than a call. We hold a
/// private signing identity ([`crate::bootstrap_identity`]); our own public
/// identity is marked verified, which the bootstrap does by itself; the
/// sender published their identity and signed their own device; we fetched
/// their keys; a completed comparison signed their master key with our
/// user-signing key; we uploaded that signature; and **we fetched their
/// keys again**. `tests/verified_sender.rs` performs all seven against a
/// counterparty this process does not control.
///
/// The last step is the one to know about, because omitting it is silent.
/// Nothing caches the outgoing signature -- upstream carries a
/// `// TODO: store the signature upload request as well.` at exactly that
/// point -- so a signature we made and uploaded but never fetched back is
/// one our own store has never seen, and the second gate reads the store.
/// A chain stopped at step six leaves every event from that sender reading
/// `UnverifiedIdentity` while the comparison, the device trust and every
/// return value say success. `tests/verified_sender.rs`'s second test
/// drives exactly that and asserts where the value lands.
///
/// [`SenderVerification::VerificationViolation`] sits one step past
/// `Verified` rather than beside it: upstream reaches it only when the
/// sender's identity was previously marked verified, and the only thing
/// that marks it is our own user-signing key verifying their master key,
/// which is step seven above. So it becomes reachable once, and only once,
/// the chain has completed for that sender and their identity has since
/// changed. No test in this repository constructs one.
///
/// # The rule that governs `Verified` in this repository's tests
///
/// It used to be that **nothing** in this repository's tests produced
/// `Verified`. That rule was written against a real failure: a fixture
/// faking the value would teach exactly the belief this doc comment exists
/// to prevent, and a mapping test with `Verified` as a literal says the
/// library produces a value when the wiring might not.
///
/// The rule is now the narrower one it always meant, and it is stricter,
/// not looser: **nothing except the real chain produces `Verified`.**
/// Reaching it through bootstrap, publish, sign, upload and re-query is
/// what discharges the old rule rather than breaking it. Reaching it any
/// other way is still forbidden, and the complement is what the other
/// tests hold: `tests/two_parties.rs` marks a device locally trusted,
/// confirms `device_statuses` now calls it verified, and asserts that
/// events from it still read [`SenderVerification::UnsignedDevice`];
/// `tests/cross_signed_peer.rs` holds the rung above it; and
/// `tests/verified_sender.rs`'s second test holds the rung immediately
/// below `Verified`, which is the one a defect would cross.
///
/// Every one of those four is a test rather than a comment, and each was
/// watched failing against a mapping that answered `Verified` regardless
/// of what upstream said.
///
/// Every variant is declared whatever its cost, because the set is closed
/// on both sides of the boundary: widening it later is a breaking change
/// for every consumer that matched on it exhaustively, and the alternative
/// to a full type is not a smaller true type but a different false one. A
/// four-value type would say that four values is all this vocabulary has,
/// which is not true of what it models.
///
/// # How this went wrong once, which is why the paragraphs above are long
///
/// Until 0.1.0 this comment said all three were unreachable, and every
/// mirror of it in the tree repeated that. It was never true.
/// `UnverifiedIdentity` was reachable from the first release; what was
/// missing was a test with a cross-signed counterparty, because every
/// fixture in this repository was a bare machine that never bootstrapped.
/// The sentence sounded like the neighbouring ones about `Verified`, which
/// were true when they were written and are not any more, and stood in for
/// them for a whole milestone. `tests/cross_signed_peer.rs` exists so that
/// it cannot again, and the lesson generalises: a claim about what a build
/// cannot produce is a claim about every peer it might meet, not only about
/// the peers its own tests construct.
///
/// # Order
///
/// Upstream's, not this crate's: `VerificationState::Verified` first, then
/// `VerificationLevel`'s own declaration order, with its `None` sub-enum
/// expanded in `DeviceLinkProblem`'s declaration order
/// (`matrix-sdk-common-0.18.0/src/deserialized_responses.rs`). Borrowing
/// upstream's order rather than inventing one keeps the mapping below
/// checkable by reading the two lists side by side, and makes every later
/// change an append -- which the FFI mirror needs, since UniFFI assigns
/// wire ordinals by declaration position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SenderVerification {
    /// **Produced by this build, and only at the end of the whole chain.**
    /// The event came from a device belonging to a user this machine has
    /// verified. Upstream's own words for it: the only state in which
    /// authenticity is guaranteed.
    ///
    /// "A comparison makes it reachable" is the wrong summary of what it
    /// takes. The path that produces this reads
    /// `SenderData::SenderVerified`, which needs **our own** user-signing
    /// key over the sender's master key, **read back out of our own
    /// store**; local trust, which is all a comparison sets by itself, is
    /// never consulted there. So a completed comparison is one step of
    /// seven, and the signature it produces has to be uploaded and then
    /// fetched back before this value can arrive. See this type's own doc
    /// comment for the full chain and for the step that is silent when it
    /// is skipped.
    ///
    /// A device can therefore read [`crate::TrustState::Verified`] while
    /// every event from it reads [`SenderVerification::UnverifiedIdentity`],
    /// and that combination is not a defect: it is a comparison whose
    /// signature has not come back yet.
    Verified,
    /// **Produced by this build.** The device is signed by its owner's
    /// cross-signing identity, and that identity is one this machine has
    /// not verified.
    ///
    /// It needs a published master key from **the sender**, and nothing
    /// from us: upstream's gate for it reads only whether the sender signed
    /// their own device. So it arrives from any peer whose client has set
    /// cross-signing up, whatever this machine holds, and it is the
    /// ordinary case for a peer running a mainstream Matrix client rather
    /// than a state a product can defer handling.
    ///
    /// It is not a weaker `Verified` and not a stronger `UnsignedDevice`.
    /// It says the owner of the sending device vouches for that device, and
    /// that we have no opinion about the owner. **It is also where an
    /// incomplete chain lands**: verifying this sender and then not
    /// fetching their keys back leaves events reading exactly this, which
    /// is indistinguishable from never having verified them at all. See
    /// [`SenderVerification::Verified`] for the chain and its last step.
    UnverifiedIdentity,
    /// The device is signed by its owner's cross-signing identity, that
    /// identity was verified once, and it is not the same identity any
    /// more.
    ///
    /// **Reachable only past `Verified`, never instead of it.** Upstream
    /// reaches this only when the sender's identity was previously marked
    /// verified, and the only thing that marks it is our own user-signing
    /// key verifying their master key, which is the last step of the chain
    /// [`SenderVerification::Verified`] describes. So a sender has to have
    /// been fully verified once, and then have changed identity, before any
    /// event of theirs can read this. No test in this repository constructs
    /// one, and a product that has never completed a chain will never see
    /// it.
    VerificationViolation,
    /// The sending device is known to this machine and carries no signature
    /// from its owner's cross-signing identity.
    ///
    /// **The ordinary case for every peer in this build**, before and after
    /// a short-string comparison alike. It says this event came from a
    /// device this machine has heard of, and nothing beyond that.
    UnsignedDevice,
    /// The event could not be linked back to any device, because no such
    /// device is in this machine's store -- deleted, never fetched, or
    /// omitted by a server.
    NoDeviceMissing,
    /// The event could not be linked back to any device, because the key
    /// that decrypted it came from somewhere unauthenticated: an imported
    /// session, a legacy backup, an unsafe forward -- or a device that
    /// turned out not to own the session it was offered for.
    NoDeviceInsecureSource,
    /// **The sender this event claims is not the owner of the session that
    /// encrypted it.**
    ///
    /// The one value here reporting an act rather than an absence of
    /// evidence. Decryption succeeds -- the ciphertext really was encrypted
    /// with a session this machine holds -- and the envelope's claim about
    /// who sent it is still false. A product has to be able to react to
    /// this case on its own, which is why it is not folded into its
    /// neighbours.
    MismatchedSender,
}

/// Upstream's verification state for one decrypted event, in this crate's
/// own vocabulary.
///
/// Exhaustive on both enums, with no wildcard arm: neither upstream type is
/// `#[non_exhaustive]`, so a variant added to either in a later version
/// fails this build rather than being silently folded into a neighbour --
/// the same discipline every `From` impl across the boundary already keeps.
fn sender_verification(state: &VerificationState) -> SenderVerification {
    match state {
        VerificationState::Verified => SenderVerification::Verified,
        VerificationState::Unverified(level) => match level {
            VerificationLevel::UnverifiedIdentity => SenderVerification::UnverifiedIdentity,
            VerificationLevel::VerificationViolation => SenderVerification::VerificationViolation,
            VerificationLevel::UnsignedDevice => SenderVerification::UnsignedDevice,
            VerificationLevel::None(DeviceLinkProblem::MissingDevice) => {
                SenderVerification::NoDeviceMissing
            }
            VerificationLevel::None(DeviceLinkProblem::InsecureSource) => {
                SenderVerification::NoDeviceInsecureSource
            }
            VerificationLevel::MismatchedSender => SenderVerification::MismatchedSender,
        },
    }
}

/// An event encrypted for a scope, or the plaintext recovered by decrypting
/// one -- see spec section 6/7. `algorithm` and the scope inside `scope` are
/// both open: neither this struct nor anything that produces it may name a
/// specific group-session algorithm.
///
/// No `#[derive(Debug)]`: `ciphertext` is, depending on which function
/// produced this, either the wire ciphertext or the plaintext this call
/// just recovered, and `sender` is a user id -- both are exactly what the
/// global "no ciphertext, no plaintext, no user id in any Debug output"
/// rule names. `Debug` is hand-written below instead, redacting both, the
/// same pattern `machine.rs`'s `MachineConfig` already uses and for the
/// same reason: a future `{:?}`, a panic message that formats this struct,
/// or a `#[derive(Debug)]` on something that embeds it would otherwise
/// print either verbatim.
#[derive(Clone, PartialEq, Eq)]
pub struct Envelope {
    pub scope: String,
    /// Open tag, e.g. the wire algorithm id upstream attached to the
    /// encrypted content. From [`encrypt_event`], read back from the
    /// content that call itself just produced, so a future algorithm
    /// upstream adds needs no change here.
    ///
    /// From [`decrypt_event`], read from the *input* event's own content
    /// before decryption runs -- unauthenticated, the same caveat as
    /// `sender` below: this is what the event claims about itself on the
    /// wire, not a value independently confirmed by upstream's own
    /// `EncryptionInfo::algorithm_info`. A mismatch between the two is
    /// exactly what makes `decrypt_room_event` fail in the first place,
    /// so they necessarily agree whenever this field is populated by a
    /// successful decrypt -- but the *source* of this value is still the
    /// untrusted side of that check, not the authenticated one.
    pub algorithm: String,
    pub event_type: String,
    /// The wire ciphertext from [`encrypt_event`], or the plaintext
    /// [`decrypt_event`] recovered -- see this struct's own doc comment
    /// above for why `Debug` is hand-written to redact this regardless of
    /// which one it is. Do not assume the field name on the decrypt path:
    /// code that logs, persists, or otherwise handles this value needs
    /// the same care any other plaintext gets.
    pub ciphertext: Vec<u8>,
    /// `@user:server`, verbatim. From [`encrypt_event`], the current
    /// machine's own user id, since that call is always this device's own
    /// outbound encryption -- authenticated by definition, it is this
    /// process's own identity.
    ///
    /// From [`decrypt_event`], this is the *outer, server-supplied*
    /// sender of the `m.room.encrypted` event, copied verbatim into the
    /// reconstructed decrypted event by upstream itself
    /// (`matrix-sdk-crypto-0.18.0/src/olm/group_sessions/inbound.rs`) --
    /// the Megolm plaintext carries no independent sender claim of its
    /// own to cross-check it against. This is not a corner this function
    /// cut: upstream's own `DecryptedRoomEvent::encryption_info` carries
    /// the identical value in its own `sender` field (confirmed by
    /// reading `OlmMachine::get_encryption_info`, which literally echoes
    /// back the `&UserId` it was called with -- `sender:
    /// sender.to_owned()`), so there is no more-authenticated alternative
    /// available to substitute here. What *does* say how much to trust
    /// this value is `sender_verification` below, which reads upstream's
    /// `EncryptionInfo::verification_state` for the same event. Read the
    /// two together or neither: this field alone is unauthenticated
    /// transport metadata on the decrypt path, and the whole point of the
    /// field below is to say how much of a claim it is.
    ///
    /// Note that `sender_verification` is not a stamp of approval on this
    /// string. `MismatchedSender` is precisely the case where this value
    /// is a lie that decryption did not catch.
    pub sender: String,
    /// What upstream knew about the sender **at the moment it decrypted
    /// this event** -- `None` from [`encrypt_event`], `Some` from every
    /// successful [`decrypt_event`].
    ///
    /// # Only one direction has one
    ///
    /// The same shared-return-type caveat `algorithm` and `sender` above
    /// each carry, in its strongest form: those two hold a real, if
    /// differently-sourced, value on both paths, and this one is
    /// **discarded** on the encrypt path rather than absent from it.
    ///
    /// Being exact about that, because this whole field is about which
    /// values exist and where. `OlmMachine::encrypt_room_event_raw` -- the
    /// call [`encrypt_event`] makes -- returns a `RawEncryptionResult`
    /// carrying an `EncryptionInfo`, and `own_encryption_info` fills its
    /// `verification_state` with `VerificationState::Verified`
    /// (`matrix-sdk-crypto-0.18.0/src/machine/mod.rs:1111-1142`). So a
    /// value does exist there, this crate holds it for the length of one
    /// closure, and drops it.
    ///
    /// Dropping it is the point. It is upstream reporting `Verified` about
    /// *this device's own keys*, which is a statement about a device and is
    /// true of a machine that has never verified anything and never
    /// published an identity. On the decrypt path the same word is the end
    /// of a seven-step chain against another user
    /// (see [`SenderVerification::Verified`]), so forwarding this one would
    /// put a value that cost nothing onto the field where a product reads a
    /// value that cost all seven. `None` says "this question was not asked
    /// of this event", which is the honest answer for something this device
    /// just encrypted for itself.
    ///
    /// # It is a snapshot, and upstream says so
    ///
    /// Upstream documents this as the state of the sending device at the
    /// time of decryption, which "may change in the future if a device gets
    /// verified or deleted", and tells callers who persist it to mark it
    /// dirty when a device change is received down the sync
    /// (`matrix-sdk-common-0.18.0/src/deserialized_responses.rs:345-351`).
    /// That obligation passes straight through to whoever holds this
    /// value. The trigger is already visible from outside: a
    /// `changed_devices` list arrives through [`receive_sync_changes`].
    /// Nothing in this crate re-derives a stored value for you.
    pub sender_verification: Option<SenderVerification>,
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Destructured, not field-accessed: a field added later must fail
        // this to compile rather than be silently printed unredacted, the
        // same discipline `MachineConfig::fmt` documents for itself.
        let Envelope {
            scope,
            algorithm,
            event_type,
            ciphertext,
            sender: _,
            sender_verification,
        } = self;
        f.debug_struct("Envelope")
            .field("scope", scope)
            .field("algorithm", algorithm)
            .field("event_type", event_type)
            .field("ciphertext_len", &ciphertext.len())
            .field("sender", &"[redacted]")
            // Printed, not redacted: a fixed set of tags naming no device,
            // no user and no key. It is also the field most worth seeing in
            // a `{:?}` when something is wrong with an event.
            .field("sender_verification", sender_verification)
            .finish()
    }
}

/// Encrypts `payload_json` (a JSON event content, opaque to this function)
/// for `scope`, returning the [`Envelope`] to hand back across the
/// boundary.
///
/// Order matters and is enforced by upstream, not by a check here: a scope
/// must have a group session before this can succeed --
/// [`share_scope_key`] establishes one. Calling this first is a caller
/// error upstream reports as a panic (`encrypt_room_event_raw`'s own
/// documented behaviour), which is deliberate -- see the design doc section
/// 7 and section 4's note on why `panic = "unwind"` stays: UniFFI's
/// `catch_unwind` turns it into a catchable error at the boundary rather
/// than a runtime check this layer cannot correctly make (it cannot tell "no
/// session yet" from "session legitimately empty" without reaching into
/// upstream's own state).
pub async fn encrypt_event(
    scope: &str,
    event_type: &str,
    payload_json: &str,
) -> Result<Envelope, SessionError> {
    let room_id = parse_scope(scope)?;
    let content = Raw::<AnyMessageLikeEventContent>::from_json_string(payload_json.to_owned())
        .map_err(|_| SessionError::MalformedPayload)?;

    let scope = scope.to_owned();
    let event_type = event_type.to_owned();

    // `with_machine` already runs inside the library's runtime and holds
    // the machine lock for this closure's duration; see its own doc comment
    // in `machine.rs`.
    let result = with_machine(move |machine| {
        Box::pin(async move {
            machine
                .encrypt_room_event_raw(&room_id, &event_type, &content)
                .await
                .map(|encrypted| {
                    // `encrypted`'s type is never named: it lives in a
                    // private module of `matrix-sdk-crypto` and is only
                    // reachable here, unnamed, through inference on this
                    // closure parameter (confirmed by trying to name it
                    // and reading rustc's own "private module" error).
                    //
                    // Read back from the encrypted content itself, not
                    // matched against upstream's `AlgorithmInfo` enum: this
                    // needs no arm for a future algorithm upstream adds,
                    // and it is what actually went over the wire in
                    // `ciphertext`, not a second, possibly-diverging
                    // description of it.
                    let algorithm = encrypted
                        .content
                        .get_field::<String>("algorithm")
                        .ok()
                        .flatten()
                        .unwrap_or_default();
                    let ciphertext = encrypted.content.json().get().as_bytes().to_vec();

                    Envelope {
                        scope,
                        algorithm,
                        event_type,
                        ciphertext,
                        sender: machine.user_id().as_str().to_string(),
                        // Dropped, not defaulted and not absent upstream:
                        // `encrypt_room_event_raw` does return an
                        // `EncryptionInfo` here and its `verification_state`
                        // is `Verified`, about this device's own keys. That
                        // is a statement about a device, so it is not
                        // forwarded onto a field a decrypted event reads.
                        // See the field's own doc comment.
                        sender_verification: None,
                    }
                })
        })
    })
    .await?;

    // Upstream `Display` output on a Megolm error can embed a session id or
    // device id -- never forwarded, per spec section 7, same as
    // `receive_sync_changes` above.
    result.map_err(|_upstream| SessionError::Failed)
}

/// The fields [`decrypt_event`] reads out of a successfully decrypted
/// event's raw JSON. Private: this shape is this function's own
/// implementation detail, never part of this crate's public declarations.
/// `content` is captured as a `RawValue`, not a `serde_json::Value`, so it
/// survives into the returned [`Envelope`] exactly as it came off the wire
/// rather than round-tripping through a value tree that could reorder its
/// keys.
#[derive(Deserialize)]
struct DecryptedEventFields {
    #[serde(rename = "type")]
    event_type: String,
    sender: String,
    content: Box<serde_json::value::RawValue>,
}

/// Maps an upstream Megolm decryption failure onto one of [`SessionError`]'s
/// five dedicated kinds, by matching on the variant -- never on its
/// rendered text, which can embed a session id or key material (e.g.
/// `MismatchedIdentityKeys`'s own `Display` impl serialises the keys
/// involved). Exhaustive, no wildcard, for the same reason
/// `From<MachineError>` above is: a future `MegolmError` variant must fail
/// this build instead of silently landing on one of these five.
fn classify_megolm_error(error: MegolmError) -> SessionError {
    match error {
        // No record of the room key that encrypted this event. `None` --
        // no explanation offered -- is the "just don't have it yet" case a
        // product can retry or wait out.
        MegolmError::MissingRoomKey(None) => SessionError::MissingKey,

        // `Some(code)` means the sending device explicitly told us, via an
        // `m.room_key.withheld` to-device message, that this session was
        // withheld or never shared -- a distinct fact worth a distinct
        // kind, split further by `code` itself (G26 in the milestone's own
        // ledger, ruled but never dispatched until now): `m.blacklisted`
        // and `m.unauthorised` are the sender's own deliberate policy
        // decision to refuse this device, which no retry from this device
        // can ever change, so they get `SessionRefused`, never
        // `UnsharedSession`. Every other code, named here or not
        // (`m.unavailable`, `m.no_olm`, and anything this crate does not
        // specifically classify) is circumstantial, so it stays
        // `UnsharedSession`.
        //
        // Matching on `code` still never *reads* it into an error: this
        // only chooses between two kinds that already exist regardless of
        // which specific code arrived, and neither carries a field for it.
        // The sender-supplied wire content a withheld code is has nowhere
        // to flow into -- structurally, per the no-payload-content rule,
        // not by the discipline of an arm that declines to look.
        MegolmError::MissingRoomKey(Some(
            WithheldCode::Blacklisted | WithheldCode::Unauthorised,
        )) => SessionError::SessionRefused,
        MegolmError::MissingRoomKey(Some(_)) => SessionError::UnsharedSession,

        // The session is present -- this is not `MissingRoomKey` -- but its
        // ratchet has already advanced past this message's index. The
        // ordinary shape of that is joining a room after this message was
        // sent, or a key shared from a later index than this message needs:
        // the same input succeeds the moment an earlier ratchet state
        // arrives (e.g. from a device that still holds it, via a key
        // request), so this is exactly the "not yet, ask again" case
        // `MissingKey` exists for, not a permanent failure. Fix for a
        // review finding: this used to fall through to the general
        // `Decryption(_)` arm below and land on `Undecryptable`, which
        // upstream's own behaviour contradicts -- the only place upstream
        // acts on this classification, it pairs this exact case with
        // `MissingRoomKey` and issues a key re-request for both
        // (`matrix-sdk-crypto-0.18.0/src/machine/mod.rs`'s
        // `MegolmError::MissingRoomKey(_) | MegolmError::Decryption(DecryptionError::UnknownMessageIndex(_, _))`
        // arm). Carved out here, ahead of the general `Decryption(_)` arm,
        // so the remaining match keeps working: a `match` picks the first
        // pattern that fits, so this specific pattern intercepts exactly
        // this one case and leaves every other `Decryption` variant to
        // fall through unchanged.
        MegolmError::Decryption(DecryptionError::UnknownMessageIndex(_, _)) => {
            SessionError::MissingKey
        }

        // The device that sent this session's room key does not match the
        // identity keys recorded in the room key's own to-device message --
        // a spoofing-shaped condition about *who* encrypted this, not
        // about the ciphertext itself. Unfixable: nothing the user does,
        // including verifying the device, changes the fact that the room
        // key's own embedded identity disagrees with itself. This is one
        // half of the old fold, and the half that keeps `UnknownDevice`;
        // the other half moved to `SenderNotTrusted` the day the trust
        // requirement became the caller's to choose.
        MegolmError::MismatchedIdentityKeys(_) => SessionError::UnknownDevice,

        // The device that sent this session's room key is fine, and does
        // not clear the trust bar this call required: upstream's
        // `check_sender_trust_requirement` refused it under the tightened
        // requirement `decrypt_event` was handed
        // (`matrix-sdk-crypto-0.18.0/src/machine/mod.rs` -- the
        // `Untrusted` arm returns `Ok` unconditionally, so this is
        // unreachable under the default `SenderTrustRequirement::Any` and
        // reachable under the two tightened tiers). This said the arm was
        // unreachable "until `decryption_settings()` stops passing
        // `Untrusted`", and was grouped with `MismatchedIdentityKeys`
        // above under the same kind, documented as a merge to revisit the
        // day it became reachable -- a product then needs to tell "verify
        // this person to read this" apart from "this event's provenance is
        // broken, never trust it", and one shared kind cannot say which.
        // That day is now, and the split is `SenderNotTrusted`; see its
        // own doc comment. B8 in the M3 design's own deferred list,
        // dispatched.
        MegolmError::SenderIdentityNotTrusted(_) => SessionError::SenderNotTrusted,

        // The event or its decrypted content was malformed, or the
        // ciphertext itself could not be decoded or decrypted -- every
        // remaining case where this crate ran the operation and did not
        // produce a usable plaintext, as opposed to knowing exactly which
        // key is absent. `Decryption`'s own `UnknownMessageIndex` case is
        // carved out above, ahead of this arm; what is left of it here --
        // `Signature`, `InvalidMAC`, `InvalidMACLength`, `InvalidPadding`
        // -- is a genuine tampering or corruption failure with no "just
        // wait" exception.
        MegolmError::EventError(_)
        | MegolmError::JsonError(_)
        | MegolmError::Decode(_)
        | MegolmError::Decryption(_) => SessionError::Undecryptable,

        // A storage failure, not a fact about this event's decryptability --
        // the same bucket `machine.rs`'s own `Store` variant already falls
        // into via `From<MachineError>` above.
        MegolmError::Store(_) => SessionError::Failed,
    }
}

/// Decrypts an event received for `scope`, returning the [`Envelope`]
/// carrying the plaintext recovered from it.
///
/// `raw_json` is the `m.room.encrypted` event as received, verbatim.
/// Decryption failure is normal Matrix operation -- a key that has not
/// arrived yet, a session withheld, a device this machine does not
/// recognise -- not an exceptional condition, which is why this can return
/// several distinct [`SessionError`] kinds instead of one opaque failure;
/// see [`classify_megolm_error`].
///
/// `requirement` is the one decision this call cannot make for the caller:
/// what a sender's device must satisfy before the plaintext is handed over.
/// [`SenderTrustRequirement::Any`] is the historical default and what every
/// caller before this parameter existed gets; the two tightened tiers make
/// [`SessionError::SenderNotTrusted`] reachable for the first time, which
/// is its own kind rather than a fold into [`SessionError::UnknownDevice`]
/// for the reason that variant's doc comment gives. Read
/// [`SenderTrustRequirement`]'s own doc comment before choosing: local
/// trust is absent from every tier, so a product whose users verify
/// devices without cross-signing identities should stay on `Any` and gate
/// on the returned envelope's `sender_verification` instead.
pub async fn decrypt_event(
    scope: &str,
    raw_json: &str,
    requirement: SenderTrustRequirement,
) -> Result<Envelope, SessionError> {
    let room_id = parse_scope(scope)?;
    let raw = Raw::<EncryptedEvent>::from_json_string(raw_json.to_owned())
        .map_err(|_| SessionError::MalformedPayload)?;

    // Read back from the event's own content, not hard-coded -- the same
    // reasoning `encrypt_event` documents for its own `algorithm` field
    // above. Falls back to empty, like that field, rather than failing the
    // whole call over a display tag: an absent or non-string `algorithm`
    // here does not stop `decrypt_room_event` below succeeding or failing
    // on its own terms.
    let algorithm = raw
        .get_field::<serde_json::Value>("content")
        .ok()
        .flatten()
        .and_then(|content| content.get("algorithm")?.as_str().map(str::to_owned))
        .unwrap_or_default();

    let scope = scope.to_owned();

    // Fresh per call, from the caller's requirement, not a cached
    // constant: the decision this encodes is the caller's, and this is the
    // only line that carries it to upstream. See `decryption_settings`
    // for the half of the settings this call deliberately does *not* take
    // -- the ingest path's requirement stays `Untrusted` there.
    let settings = DecryptionSettings {
        sender_device_trust_requirement: match requirement {
            SenderTrustRequirement::Any => TrustRequirement::Untrusted,
            SenderTrustRequirement::IdentitySignedOrLegacy => TrustRequirement::CrossSignedOrLegacy,
            SenderTrustRequirement::IdentitySigned => TrustRequirement::CrossSigned,
        },
    };

    // `with_machine` already runs inside the library's runtime and holds
    // the machine lock for this closure's duration; see its own doc
    // comment in `machine.rs`.
    let result = with_machine(move |machine| {
        Box::pin(async move { machine.decrypt_room_event(&raw, &room_id, &settings).await })
    })
    .await?;

    let decrypted = result.map_err(classify_megolm_error)?;

    // Pulled out with a small `Deserialize` helper, not the full
    // `AnyTimelineEvent` enum: this crate needs exactly these three fields
    // and nothing about which of Matrix's many event types this is. Every
    // field required, not defaulted: a successfully decrypted event
    // missing any of them is not a display-tag gap the way a missing
    // `algorithm` above is -- it means the Megolm layer authenticated a
    // plaintext that is not a well-formed Matrix event, which this
    // function reports as `Undecryptable` rather than handing the product
    // a half-populated `Envelope`.
    let DecryptedEventFields {
        event_type,
        sender,
        content,
    } = decrypted
        .event
        .deserialize_as_unchecked::<DecryptedEventFields>()
        .map_err(|_upstream| SessionError::Undecryptable)?;

    Ok(Envelope {
        scope,
        algorithm,
        event_type,
        ciphertext: content.get().as_bytes().to_vec(),
        sender,
        // Derived from upstream's own `EncryptionInfo`, not inferred from
        // the fact that decryption succeeded. Those are different
        // questions, and `MismatchedSender` is the case that proves it:
        // the ciphertext decrypts perfectly and the sender is still not
        // who the event says. `tests/two_parties.rs` decrypts one event
        // twice, re-addressed the second time, to hold the two apart.
        sender_verification: Some(sender_verification(
            &decrypted.encryption_info.verification_state,
        )),
    })
}

/// Ensures `scope` has a group session and shares it with the given users'
/// known devices, and makes those users' device lists tracked so they can
/// become known in the first place.
///
/// The tracking is not a convenience. Upstream only learns that a user's
/// devices exist by issuing a `/keys/query` for them, and it only issues one
/// for a user it is *tracking*: `mark_tracked_users_as_changed`
/// (matrix-sdk-crypto-0.18.0/src/store/mod.rs:291) opens with
/// `if tracked_users.contains(user_id)` and silently skips everyone else,
/// and a sync's `changed_devices` list routes nowhere but there
/// (`receive_sync_changes` -> `receive_device_changes`). Without this call,
/// no function on this crate's shipped surface could get a `/keys/query`
/// issued for a user this device has not already encrypted to, and
/// [`take_outgoing_requests`] would keep handing out upstream's own-user
/// fallback query instead -- a silent failure whose only symptom is
/// encrypting to nobody.
///
/// It is implicit rather than a separate `track_users` call because "share
/// this scope's key with these users" already means "these users' devices
/// matter to me". A separate call would add public surface and add a way to
/// hold the API wrong: forgetting it fails silently, exactly like the
/// mistake design doc section 3bis is named for.
///
/// Repeated calls are cheap: upstream's `update_tracked_users` flags only
/// users it has not seen before (`if tracked_users.insert(...)`), so calling
/// this every time a product sends is not a per-send key query.
///
/// **A first call for a never-seen user necessarily delivers nothing.** It
/// has no device of theirs to encrypt to yet; what it does is cause the
/// `/keys/query` that makes a *later* call able to. The full loop is
/// therefore share, pump, share, pump, share -- see the ordering note below
/// and `tests/two_parties.rs`, which walks it.
///
/// This is the call that reaches `tokio::task::spawn` through
/// `matrix-sdk-common` during group key sharing, and the reason Task 1's
/// runtime exists -- see the design doc section 4.
///
/// Two upstream calls, not one, per the design doc's section 3ter.
/// `share_room_key` alone is not enough: encrypting a room key *to* a
/// device requires an Olm session with it, and an Olm session cannot exist
/// until this device has claimed one of the other device's one-time keys
/// (a `/keys/claim` round trip). Skip that and `share_room_key` still
/// "succeeds" -- but every to-device request it produces is an
/// `m.room_key.withheld` notice with code `m.no_olm`, a message whose
/// content is "I could not send you the key", not the key itself. That
/// failure is silent and looks exactly like success from inside this
/// process, which is exactly the class of mistake section 3bis's own
/// discarded-requests story is about, one layer deeper.
///
/// So `get_missing_sessions` is called first and, if it reports a missing
/// session, queues the `/keys/claim` request [`take_outgoing_requests`]
/// must hand out before a *subsequent* `share_scope_key` call can actually
/// deliver the key to that device -- this call still attempts
/// `share_room_key` regardless, so any device that already has a session
/// (or belongs to a different, already-established user) is not held back
/// waiting on one that does not.
///
/// The to-device requests `share_room_key` returns carry the session key
/// itself, on its way to the recipients' devices. They are queued here for
/// [`take_outgoing_requests`] to hand out, never discarded -- discarding
/// them is the mistake the design doc's section 3bis exists to prevent: the
/// group session would exist locally, `encrypt_event` would happily
/// produce ciphertext, and no other device would ever be able to read it.
pub async fn share_scope_key(scope: &str, users: &[String]) -> Result<(), SessionError> {
    let room_id = parse_scope(scope)?;
    let user_ids: Vec<OwnedUserId> = users
        .iter()
        .map(|user| parse_user(user))
        .collect::<Result<_, _>>()?;

    let (tracked, missing, shared) = with_machine(move |machine| {
        Box::pin(async move {
            let missing = machine
                .get_missing_sessions(user_ids.iter().map(AsRef::as_ref))
                .await;

            // The outbound half of the trust decision `decrypt_event`
            // hands the caller: who gets this scope's key. This said
            // "verification lands in M3; revisit this with it", then that
            // the strategy could not move before cross-signing (M4), then
            // that M4 had landed and left a *condition* to rule on rather
            // than an absence. The condition is ruled on now, here rather
            // than by a parameter, and the rule is the one that condition
            // dictates:
            //
            // `EncryptionSettings::default()` carries
            // `CollectStrategy::AllDevices`, which upstream marks "not
            // recommended, per the guidance of MSC4153" because it shares
            // with every unblacklisted device rather than only devices
            // signed by their owner. The recommended strategy is
            // identity-based, and it refuses outright when *this* machine
            // has no verified cross-signing identity of its own
            // (`SessionRecipientCollectionError::CrossSigningNotSetup`, or
            // `SendingFromUnverifiedDevice`, before it looks at a single
            // recipient -- `session_manager/group_sessions/
            // share_strategy.rs`). So the strategy can only be a
            // *consequence* of the machine's state, and the consequence
            // takes both halves: a machine that holds a verified identity
            // of its own shares identity-based, which is what MSC4153
            // recommends for it; a machine that never bootstrapped still
            // has none, keeps `AllDevices`, and keeps working exactly as
            // it did.
            //
            // The check is the same one upstream's own strategy performs
            // before deciding anything, read through the public
            // `get_identity` rather than through the store, so the two
            // cannot drift into disagreeing about what "has an identity"
            // means. `None` as the timeout: waiting on a pending query
            // here would depend on the caller draining the pump from
            // another task while this call holds the machine lock, which
            // it cannot do -- the same discipline `device_statuses`
            // documents.
            //
            // A store failure falls back to `AllDevices` rather than
            // propagating, and that is not a silent demotion:
            // `get_missing_sessions` above and `share_room_key` below run
            // against the same store and report its failure on their own
            // terms, so a broken store surfaces through them; the
            // strategy choice is not the place it does.
            let sharing_strategy = match machine.get_identity(machine.user_id(), None).await {
                Ok(Some(UserIdentity::Own(identity))) if identity.is_verified() => {
                    CollectStrategy::IdentityBasedStrategy
                }
                // Every other state falls back to `AllDevices`: no own
                // identity at all (never bootstrapped), an own identity
                // this machine cannot vouch for, or a store answer shaped
                // as someone else's identity. `IdentityBasedStrategy`
                // would refuse the first two outright, and the third
                // cannot occur for this machine's own user id, so the
                // fallback is exactly the set of states where the
                // identity-based strategy would fail before looking at a
                // recipient.
                _ => CollectStrategy::AllDevices,
            };
            let shared = machine
                .share_room_key(
                    &room_id,
                    user_ids.iter().map(AsRef::as_ref),
                    EncryptionSettings {
                        sharing_strategy,
                        ..Default::default()
                    },
                )
                .await;
            // Tracked *after* `share_room_key`, not before, and the
            // order is load-bearing rather than incidental. Upstream's
            // `get_user_devices_for_encryption`
            // (identities/manager.rs:924) waits up to a hard-coded
            // `KEYS_QUERY_WAIT_TIME` of 5 seconds for an outstanding
            // `/keys/query` to complete, for any user it is asked to
            // encrypt to that has no known device and is flagged for a
            // query. Flagging first would arm exactly that wait, on this
            // call, for a request the product has not been handed yet --
            // `take_outgoing_requests` is a *separate* call the caller
            // makes after this one returns, so the query cannot possibly
            // complete while this wait runs. Worse, `with_machine` holds
            // the machine lock for this closure's whole duration, so no
            // concurrent library call could satisfy the wait either: it
            // would block every other caller for the full five seconds
            // before timing out and proceeding to do exactly what it does
            // now. Measured on this crate's own two-party test: 7.47s
            // flagging first, 2.47s flagging last, for an identical
            // outcome. Flagging last arms nothing -- the flag is set for
            // the *pump*, which runs after this returns, which is the only
            // thing that can act on it.
            let tracked = machine
                .update_tracked_users(user_ids.iter().map(AsRef::as_ref))
                .await;
            (tracked, missing, shared)
        })
    })
    .await?;

    // Checked, and queued, before `shared`'s own result is even inspected:
    // this is progress worth keeping regardless of whether the share
    // attempt below succeeds, since it is the only way a *later*
    // `share_scope_key` call can do better.
    //
    // Both queues below are written under one `STATE.lock()` acquisition,
    // not two: `pending_claim` and `queued_to_device` are two of the three
    // fields `RequestState`'s own doc comment says share a lock precisely
    // so a caller can never observe one updated without the others (N1 in
    // the milestone's own ledger -- parked, not fixed, until now). Neither
    // write here is preceded or followed by an `.await`: `missing` and
    // `shared` are already-resolved `Result`s by this point, taken from the
    // tuple `with_machine` handed back above, not futures still to be
    // polled -- so holding the guard across both is exactly as cheap as the
    // two separate acquisitions it replaces, and cannot deadlock the
    // executor the way holding a lock across an `.await` already has once
    // in this crate (see `machine.rs`).
    let mut state = STATE.lock().expect("request registry poisoned");

    if let Some(claim) = missing.map_err(|_upstream| SessionError::Failed)? {
        state.pending_claim = Some(claim);
    }

    let to_device_requests = shared.map_err(|_upstream| SessionError::Failed)?;

    if !to_device_requests.is_empty() {
        // Keyed by `txn_id`, not appended to a growing `Vec`:
        // `share_room_key` returns the *entire* persisted
        // `to_share_with_set` on every call
        // (matrix-sdk-crypto-0.18.0/src/session_manager/group_sessions/mod.rs:785,
        // upstream's own comment: "The to-device requests get added to the
        // outbound group session, this way we're making sure that they are
        // persisted and scoped to the session"), so a second
        // `share_scope_key` call before the first is marked sent would
        // otherwise queue an identical request under a second `Vec` slot --
        // the same message sent to the product twice, and the second
        // `mark_request_sent` failing with `UnknownRequest` once the first
        // consumes its id. Keying by `txn_id` makes the second call
        // idempotent instead: same key, equivalent value, one entry.
        for request in to_device_requests {
            state
                .queued_to_device
                .insert(request.txn_id.to_string(), request);
        }
    }

    // Dropped explicitly, rather than left to fall out of scope at the
    // function's end: nothing below needs it, and the whole point of this
    // block is to hold it no longer than the two writes actually require.
    drop(state);

    // Reported last, after both queues above have kept whatever progress
    // this call made: a tracking failure is a store failure, and a store
    // this broken will have failed the other two as well -- but it is not
    // swallowed, because the users this call named would then never be
    // queried and encryption to them would silently reach nobody.
    tracked.map_err(|_upstream| SessionError::Failed)?;

    Ok(())
}

/// Which upstream response shape a request id crossing back in through
/// [`mark_request_sent`] must be parsed as.
///
/// Recorded in [`STATE`] when the request crosses out through
/// [`take_outgoing_requests`], consulted and removed when the matching
/// response crosses back in. Private: never part of this crate's public
/// declarations, so its variants carry whatever names describe upstream's
/// own request kinds best, including ones the facade agility rule (design
/// doc section 6 / M1 spec section 6) would reject as a *public* name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    KeysUpload,
    KeysQuery,
    /// A `/keys/query` whose user list names **this machine's own account**.
    ///
    /// The same endpoint and the same wire `kind` tag as [`KeysQuery`]: a
    /// caller cannot tell the two apart and has nothing to do differently
    /// with them. The distinction is this module's own bookkeeping, and it
    /// exists for exactly one reader -- `signing.rs`'s ordering gate, which
    /// must know whether this process has *asked the server about its own
    /// account and received an answer*, not merely whether its local
    /// identity happens to be empty.
    ///
    /// **This variant is half of that fact and not the whole of it.** It
    /// records which question was asked; [`answer_about_this_account`] records
    /// whether the body that came back said anything about the account the
    /// question was about. An earlier version stopped here, on the reading
    /// that "a response naming no identity for this account and a response
    /// about somebody else are indistinguishable once the question is gone".
    /// The question is not gone -- this entry is the question -- and the two
    /// are told apart in [`mark_request_sent`], where both are in hand.
    ///
    /// [`KeysQuery`]: PendingKind::KeysQuery
    AccountKeysQuery,
    /// The same question as [`AccountKeysQuery`], asked out-of-band.
    ///
    /// Built by `OlmMachine::query_keys_for_users` rather than volunteered
    /// by `users_for_key_query`, which `signing.rs` reaches for when it
    /// refuses a bootstrap and upstream would otherwise never ask. Same
    /// endpoint, same wire tag, same response handling, and it sets the
    /// same flag when answered.
    ///
    /// **It is a separate variant for exactly one reason: it must not share
    /// an eviction group with the other two.** Upstream's own
    /// `build_key_query_for_users` says so outright -- it "does not store
    /// the details" and there can be several such queries in flight at once
    /// (`identities/manager.rs:804-816`) -- so the "forget about any
    /// previous key queries in flight" rule that makes the other two
    /// supersede each other does not reach it. Folded in with them, a
    /// fresh ordinary `/keys/query` for some unrelated user would evict
    /// this one while it was still in flight, and the recovery path it
    /// exists for would be broken by the very case it exists for: a process
    /// whose account is already tracked, where every batch carries ordinary
    /// key queries and none of them asks about this account.
    ///
    /// [`AccountKeysQuery`]: PendingKind::AccountKeysQuery
    AccountKeysQueryOutOfBand,
    /// An out-of-band `/keys/query` naming **another person**, queued by a
    /// verification that finished by scanning a code.
    ///
    /// [`AccountKeysQueryOutOfBand`]'s sibling, built the same way by
    /// `OlmMachine::query_keys_for_users` and for the same class of reason:
    /// upstream will not volunteer this question either, and the answer to
    /// it is the whole product of the verification that queued it. See
    /// `verification::queue_peer_key_queries` for what that verification is
    /// and why the query belongs to it.
    ///
    /// **A separate variant rather than [`KeysQuery`], for
    /// [`AccountKeysQueryOutOfBand`]'s reason exactly.** Upstream's
    /// `build_key_query_for_users` "does not store the details" and several
    /// such queries can be in flight at once
    /// (`identities/manager.rs:804-816`), so the "forget about any previous
    /// key queries in flight" rule that makes ordinary key queries supersede
    /// each other does not reach it. Folded in with them, an ordinary
    /// `/keys/query` handed out for some unrelated user would evict this one
    /// while it was still in flight, and the signature the verification just
    /// posted would never be read back.
    ///
    /// **And a separate variant rather than
    /// [`AccountKeysQueryOutOfBand`]**, which asks about *this* account and
    /// whose answer sets [`RequestState::account_keys_answered`]. This one
    /// names somebody else, so it must set nothing: `signing.rs`'s ordering
    /// gate would otherwise be lifted by an answer about a stranger, which
    /// is the exact failure [`answer_about_this_account`] exists to prevent.
    ///
    /// [`KeysQuery`]: PendingKind::KeysQuery
    /// [`AccountKeysQueryOutOfBand`]: PendingKind::AccountKeysQueryOutOfBand
    PeerKeysQueryOutOfBand,
    KeysClaim,
    ToDevice,
    SignatureUpload,
    RoomMessage,
    /// `POST /_matrix/client/v3/keys/device_signing/upload`, the third
    /// request class.
    ///
    /// M3 established two: *reaction* requests upstream queues for itself
    /// and the pump drains, and *action* requests upstream hands back to its
    /// caller for [`queue_action_request`]. This is neither.
    /// `AnyOutgoingRequest` has six variants and none for this endpoint, so
    /// `outgoing_requests()` can never produce it and
    /// [`queue_action_request`] can never accept it -- upstream returns it
    /// to its caller in a crate-local struct of three key fields. Hence its
    /// own queue slot, its own hand-serialised body
    /// ([`describe_signing_keys`]), and its own arm in [`mark_sent`].
    SigningKeysUpload,
}

impl PendingKind {
    /// The public, open-tag `kind` string -- spec section 3bis's own
    /// examples for the first three, extended the same way for the rest.
    ///
    /// Not injective, and deliberately so: `KeysQuery` and
    /// `AccountKeysQuery` are one endpoint with one wire tag, distinguished
    /// only inside this module. Everything downstream of this string treats
    /// them as one request kind, which is what the eviction rule below
    /// relies on.
    fn tag(self) -> &'static str {
        match self {
            PendingKind::KeysUpload => "keys_upload",
            PendingKind::KeysQuery
            | PendingKind::AccountKeysQuery
            | PendingKind::AccountKeysQueryOutOfBand
            | PendingKind::PeerKeysQueryOutOfBand => "keys_query",
            PendingKind::KeysClaim => "keys_claim",
            PendingKind::ToDevice => "to_device",
            PendingKind::SignatureUpload => "signature_upload",
            PendingKind::RoomMessage => "room_message",
            PendingKind::SigningKeysUpload => "signing_keys_upload",
        }
    }

    /// The top-level field names this kind's response type actually
    /// declares, read off the vendored `ruma-client-api-0.24.0` rather than
    /// off the specification, because it is that crate's `Response` that
    /// `mark_sent` deserialises into.
    ///
    /// Used by [`refuse_a_non_response`] for the one rule that is *positive*
    /// rather than negative. `ruma-client-api` sets `deny_unknown_fields`
    /// nowhere, and every `/keys/query` field is `#[serde(default)]`, so
    /// serde reads any object at all as a fully defaulted success. Listing
    /// what a response may contain is the only way to reject what no
    /// response contains, because the set of things a proxy might send is
    /// unbounded and cannot be enumerated the other way round.
    ///
    /// **Two kinds declare nothing, and that is not an omission.**
    /// `to_device` and `signing_keys_upload` are `Response {}`. The empty
    /// slice is the correct answer for them and gives exactly the right
    /// rule: no key can match, so the only object they accept is an empty
    /// one, which is the only object their success can be. Those two get no
    /// body parse from ruma at all, so this is the single check standing
    /// between a proxy's error page and an identity marked published.
    fn declared_response_fields(self) -> &'static [&'static str] {
        match self {
            PendingKind::KeysUpload => &["one_time_key_counts"],
            PendingKind::KeysQuery
            | PendingKind::AccountKeysQuery
            | PendingKind::AccountKeysQueryOutOfBand
            | PendingKind::PeerKeysQueryOutOfBand => &[
                "failures",
                "device_keys",
                "master_keys",
                "self_signing_keys",
                "user_signing_keys",
            ],
            PendingKind::KeysClaim => &["failures", "one_time_keys"],
            PendingKind::SignatureUpload => &["failures"],
            PendingKind::RoomMessage => &["event_id"],
            PendingKind::ToDevice | PendingKind::SigningKeysUpload => &[],
        }
    }

    /// Which set of previously handed-out, still-unresolved ids a fresh
    /// request of this kind makes obsolete, or `None` for a kind that makes
    /// none obsolete at all.
    ///
    /// Two entries are in the same group when a fresh request of one makes a
    /// stale entry of the other pointless to keep, and eviction happens
    /// per group rather than per variant. Every group name here happens to
    /// be the endpoint's [`tag`](PendingKind::tag) except one, and that
    /// exception is the whole reason this returns a name instead of a bool.
    ///
    /// # Superseded because upstream forgot the id
    ///
    /// `keys_upload`, `keys_query` and `keys_claim` are the three kinds
    /// where upstream re-derives "is this still needed" from scratch on
    /// every call, minting a new, uncorrelated id each time and forgetting
    /// whatever id it handed out last: `keys_for_upload` recomputes from the
    /// account's current state (`machine/mod.rs:825`);
    /// `users_for_key_query`'s own comment says "Forget about any previous
    /// key queries in flight" (`identities/manager.rs:832`); and
    /// `get_missing_sessions` documents the identical single-slot behaviour
    /// on its own `current_key_claim_request` ("there should only be one
    /// such request active at a time", `session_manager/sessions.rs`). A
    /// stale id of one of these names nothing upstream is tracking any more,
    /// so it is evicted from [`RequestState::pending`] the moment a fresh one
    /// of the same group is handed out rather than accumulating for the life
    /// of the process.
    ///
    /// `AccountKeysQuery` shares `keys_query`'s group because it *is* one of
    /// those queries -- same call, same forgetting -- and grouping is why:
    /// evicting per variant would leave a stale `AccountKeysQuery` behind a
    /// fresh `KeysQuery` and the reverse, an id `mark_request_sent` still
    /// accepts, whose response upstream then has no request to correlate,
    /// and which here would additionally record "we asked about our own
    /// account" for a question the server was never asked.
    ///
    /// # Superseded because *this crate* re-derives it
    ///
    /// `signing_keys_upload` and `account_keys_query_out_of_band` are not
    /// forgotten by upstream -- it never held an id for either -- so a stale
    /// one of these stays technically resolvable. They are evicted anyway,
    /// for a different and weaker reason that is worth keeping distinct:
    /// each is re-derived *here* from state that has not changed, so a
    /// second one asks the identical question or publishes the identical
    /// three keys. Keeping both would hand a caller two ids for one
    /// question, and (for the signing-keys upload) two rounds of
    /// user-interactive authentication to publish one identity. Without
    /// this, `pending` grows by one entry per bootstrap-and-drain cycle for
    /// the life of the process, which is the bound M2 and M3 both had to
    /// prove for their own kinds.
    ///
    /// **The caller-visible cost is that a held `signing_keys_upload` id
    /// does not survive a second `bootstrap_identity` followed by a drain**,
    /// which matters because that is the id a product holds across a
    /// user-interactive authentication loop. It survives any number of
    /// refused attempts, since only success consumes an entry; it does not
    /// survive being superseded. `signing::bootstrap_identity` says so at
    /// the call, and the recovery is to drain again and use the newer id
    /// for the identical body. Reusing one stable id for the life of the
    /// publication was the alternative and was rejected: it would put a
    /// second, differently-shaped bounding rule beside this one for a
    /// single kind, where this rule already covers every kind that needs
    /// one.
    ///
    /// `account_keys_query_out_of_band` is the group name that is **not** a
    /// `tag()`, and it must not be: see
    /// [`AccountKeysQueryOutOfBand`](PendingKind::AccountKeysQueryOutOfBand)
    /// for why sharing `keys_query`'s group would break the one path it
    /// exists to keep open.
    ///
    /// # Not superseded at all
    ///
    /// `to_device` (each entry is a distinct, independently resolvable
    /// message to a distinct recipient -- see `queued_to_device`'s own
    /// `txn_id`-keyed de-duplication instead) and
    /// `signature_upload`/`room_message` (independent, per-flow
    /// verification requests upstream does not describe as superseding one
    /// another). Both were unreachable while verification was deferred and
    /// both are reachable now: `verification::queue` hands them to
    /// [`queue_action_request`], and `facade.ts`'s `OutgoingRequest` table
    /// documents each endpoint as live. They are still given no blanket
    /// eviction rule -- one would have been wrong then and is wrong now.
    ///
    /// [`PeerKeysQueryOutOfBand`](PendingKind::PeerKeysQueryOutOfBand) joins
    /// them, and is the one member of this group that is a `/keys/query`.
    /// It is per-flow in exactly `signature_upload`'s sense: one is queued by
    /// each completed cross-user code verification, each names the person that
    /// verification was with, and a query about one person supersedes nothing
    /// about another. Bounded the same way `signature_upload` is, by there
    /// being one per verification a caller actually ran rather than by any
    /// rule here.
    fn eviction_group(self) -> Option<&'static str> {
        match self {
            PendingKind::KeysUpload
            | PendingKind::KeysQuery
            | PendingKind::AccountKeysQuery
            | PendingKind::KeysClaim
            | PendingKind::SigningKeysUpload => Some(self.tag()),
            // Deliberately not `self.tag()`, which is `keys_query`.
            PendingKind::AccountKeysQueryOutOfBand => Some("account_keys_query_out_of_band"),
            // The first three each name one independently deliverable
            // message, so nothing supersedes them and only `mark_request_sent`
            // resolves them.
            //
            // `PeerKeysQueryOutOfBand` is here for an unrelated reason, and it
            // is worth saying rather than deriving from the variant's own
            // declaration above. **It is the one member of this arm that is a
            // `/keys/query` on the wire**, and `tag()` returns `keys_query` for
            // it exactly as it does for the three grouped queries. Give it a
            // group and it gets `keys_query`, and then an ordinary
            // `/keys/query` handed out for some unrelated user evicts it while
            // it is still in flight; the signature the verification that queued
            // it has just posted is then never read back, and the verification
            // silently produces nothing. Its own group, as
            // `AccountKeysQueryOutOfBand` has, would be wrong too: several of
            // these can be in flight at once, one per peer, and a second peer's
            // query must not evict the first's.
            //
            // The consequence reaches the public API, so it is documented
            // there too: a product can hold two live `keys_query` ids at once,
            // and a new one is not evidence that an older one is dead. See the
            // request-lifecycle paragraphs in `README.md` and in
            // `take_outgoing_requests`' TypeScript doc comment. Those two said
            // the opposite for one merge after this variant landed, because
            // they were written when every `keys_query` was evictable and
            // nothing re-read them; if this arm changes again, they are the
            // two places that go stale with it.
            PendingKind::ToDevice
            | PendingKind::SignatureUpload
            | PendingKind::RoomMessage
            | PendingKind::PeerKeysQueryOutOfBand => None,
        }
    }
}

/// One request this module has handed out and is waiting to have resolved.
///
/// The `sequence` is this module's answer to a question the two queues it
/// draws from cannot answer between them: **in what order were these
/// produced?** Requests reach the pump from two places -- upstream's own
/// cache, which is a `BTreeMap` keyed by a random transaction id and so has
/// no order at all, and [`RequestState::queued_action`], which upstream
/// hands back to its caller. A verification's closing pair straddles that
/// boundary (see [`queue_action_request`]), so ordering each source
/// separately, or concatenating them in a fixed source order, is not enough:
/// only one number spanning both is.
///
/// Assigned when this module first learns of a request -- at queue time for
/// the requests it is handed, at hand-out time for the ones it reads from
/// upstream -- and kept for as long as the request is unresolved, so a
/// request re-offered by upstream in a later batch keeps the position it
/// had rather than jumping to the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pending {
    kind: PendingKind,
    sequence: u64,
}

/// Process-wide outbound-request bookkeeping this module owns.
///
/// Four distinct jobs share one lock rather than four, so a caller can
/// never observe one updated without the others:
///
/// * `queued_to_device` -- to-device requests [`share_scope_key`] obtained
///   from `share_room_key`, keyed by `txn_id`, that have not yet been
///   handed out by [`take_outgoing_requests`]. Drained (not cloned) when
///   they are; keyed rather than appended to a `Vec` so a second
///   `share_scope_key` call before the first is marked sent cannot queue
///   the same persisted request twice (see `share_scope_key`'s own
///   comment).
/// * `pending_claim` -- at most one outstanding `/keys/claim` request
///   [`share_scope_key`] obtained from `get_missing_sessions`, not yet
///   handed out. A single slot, not a queue, mirroring upstream's own
///   "only one such request active at a time" model for the same request
///   (see `PendingKind::eviction_group`'s doc comment): a
///   second `share_scope_key` call before the first claim is taken
///   overwrites it rather than accumulating a second one describing
///   overlapping or stale missing-session state.
/// * `queued_action` -- requests upstream handed back to *its* caller
///   instead of queueing itself, which is how every verification flow's own
///   messages arrive (see [`queue_action_request`]). A `Vec`, not a map,
///   each entry stamped with the [`Pending::sequence`] it was queued at:
///   a verification's last two messages are a confirmation and the
///   acknowledgement that follows it, the far side drops the
///   acknowledgement if it arrives first, and the two do not always come
///   from the same queue. Valued by upstream's own request, so
///   `describe_outgoing` decides the kind and the wire body here exactly as
///   it does for the requests upstream queued for itself.
/// * `pending` -- every request id this module has ever handed out via
///   [`take_outgoing_requests`] that has not yet been resolved by
///   [`mark_request_sent`], with the [`PendingKind`] needed to parse its
///   response. Removed on successful resolution only (a failed
///   `mark_request_sent` leaves the entry in place, so the same id can be
///   retried with corrected input); also evicted early when a fresh
///   request shares its eviction group (`PendingKind::eviction_group`),
///   since a stale entry of such a group is either unresolvable or
///   redundant -- that function says which for each group.
/// * `next_sequence` -- the counter behind [`Pending::sequence`], read and
///   incremented under the same lock as everything else here, so two
///   requests learned of in either order can always be put back into it.
///
/// A `std::sync::Mutex`, not `tokio::sync::Mutex`: every critical section
/// below is a plain synchronous map/vec operation with no `.await` inside
/// it.
struct RequestState {
    queued_to_device: BTreeMap<String, std::sync::Arc<ToDeviceRequest>>,
    pending_claim: Option<(OwnedTransactionId, KeysClaimRequest)>,
    queued_action: Vec<(u64, UpstreamOutgoingRequest)>,
    /// At most one outstanding publication of this account's signing
    /// identity, not yet handed out. A single slot rather than a queue,
    /// mirroring `pending_claim`'s reasoning for the same shape: an account
    /// has exactly one identity, so a second `bootstrap_identity` before the
    /// first is drained re-derives the *same* three keys, and handing the
    /// caller two of them would cost it two rounds of user-interactive
    /// authentication at the homeserver to publish one identity.
    ///
    /// Replacing keeps the sequence the slot already had, so the
    /// publication does not jump behind the signature upload queued
    /// alongside it -- the one ordering upstream states outright, because a
    /// signature may reference a key that is not published yet.
    ///
    /// **The slot alone only bounds this within one drain.** A bootstrap,
    /// a drain, and another bootstrap put a second publication in the slot
    /// with the first still unresolved, and repeating that grew `pending`
    /// without bound until `PendingKind::eviction_group` was taught that a
    /// fresh publication supersedes a stale one. Both halves are needed and
    /// this comment used to claim the first was enough.
    queued_signing_keys: Option<(u64, OwnedTransactionId, UploadSigningKeysRequest)>,
    /// At most one outstanding out-of-band `/keys/query` for this machine's
    /// own account, not yet handed out. Also a single slot: it asks one
    /// question about one account, and asking it twice tells nobody
    /// anything new. The slot bounds this within one drain; across drains it
    /// is `PendingKind::eviction_group` that keeps `pending` from growing.
    ///
    /// Queued by `signing.rs` when it refuses a bootstrap for want of an
    /// answer, so the refusal is recoverable through the ordinary pump loop
    /// rather than a dead end -- upstream only volunteers an own-account key
    /// query while the account is not yet tracked
    /// (`identities/manager.rs:836-852`), which after the first sync it
    /// always is.
    queued_account_query: Option<(u64, OwnedTransactionId, KeysQueryRequest)>,
    /// Out-of-band `/keys/query` requests naming **other people**, queued by
    /// completed cross-user code verifications and not yet handed out.
    ///
    /// A `Vec` rather than a slot, and that is the one shape difference from
    /// `queued_account_query` above. That slot holds one question about one
    /// account and a second copy of it tells nobody anything; these are one
    /// question per person, and two verifications with two different people
    /// completing in the same sync owe two different queries. Collapsing them
    /// into a slot would silently drop one and leave that person reading
    /// unverified for ever.
    ///
    /// Keyed by nothing and de-duplicated by nothing, because
    /// `verification.rs` de-duplicates at the only place a duplicate could be
    /// produced: `FlowRecord::key_query_queued` marks a flow the moment its
    /// query is queued, and one flow completes once.
    ///
    /// **Carries no sequence, unlike the two slots above, and that is the one
    /// thing about this queue that is load-bearing.** A stamp taken at queue
    /// time would sort these ahead of everything upstream produced during the
    /// same sync, and the request they must not overtake is exactly one of
    /// those: the signature upload the completion made, which is what the
    /// query exists to read back. Sent first, the query returns a master key
    /// that does not carry the signature yet and the person stays
    /// `Unverified`. So they are stamped at hand-out instead, after the block
    /// that carries upstream's own requests, which puts them behind it in the
    /// one order this module hands out. **Measured, not reasoned:** with a
    /// queue-time stamp, `tests/level_two_scanned.rs` reported `Unverified`
    /// against a real homeserver after a verification that had demonstrably
    /// succeeded, and no level 1 test could see it because those answer the
    /// query by hand.
    queued_peer_queries: Vec<(OwnedTransactionId, KeysQueryRequest)>,
    pending: BTreeMap<String, Pending>,
    /// Whether a `/keys/query` naming this machine's own account has been
    /// answered **about that account** in this process.
    ///
    /// Set only by [`mark_request_sent`], and only when three things hold at
    /// once: the request was one of the two account-scoped key query kinds,
    /// upstream accepted the response, and upstream's own store then said
    /// whether this account has a signing identity
    /// ([`answer_about_this_account`]). "We asked" is not the fact the gate
    /// needs; neither is "we asked and something came back", nor "we asked
    /// and the answer named us". "We asked, and upstream now knows" is.
    ///
    /// Never unset in production, and deliberately not persisted -- a process
    /// that reopens a store has not asked anything *yet*, and refusing until
    /// it does costs one round trip and is the safe direction. See
    /// `signing.rs`.
    ///
    /// One boolean, not one per account, and that is safe only because
    /// `machine::HELD` is a single slot: `init` refuses any config that
    /// differs from the held one and nothing in the shipped surface clears
    /// it, so a process holds at most one account for its whole life.
    /// `machine::reset_for_test` is the one place that swaps the held
    /// account, and it clears this through
    /// `forget_account_keys_answered_for_test` for exactly that reason.
    /// A plain code span rather than a doc link: that function is
    /// `#[cfg(test)]`, so a doc build cannot resolve it and a link would be
    /// broken in exactly the way `scripts/assert-doc-links.sh` refuses.
    account_keys_answered: bool,
    /// Whether the last accepted answer to a key query about this account
    /// left upstream **still** not knowing whether the account has a signing
    /// identity.
    ///
    /// The companion to `account_keys_answered` and never true alongside it:
    /// together they say which of the two situations a shut gate is in.
    /// Both false is "nobody has asked", whose remedy is the ordinary drain,
    /// send, report. This one true is "we asked, we were answered, and the
    /// answer settled nothing", whose remedy is not to ask again -- see
    /// [`answer_about_this_account`]'s last section for what a product does
    /// instead, and why leaving this unrecorded made the first remedy a loop
    /// that could not terminate.
    ///
    /// Cleared by the same reset as the flag above, for the same reason.
    account_keys_answer_unsettled: bool,
    next_sequence: u64,
}

impl RequestState {
    /// The next position in this module's single production order.
    ///
    /// A `u64` counter that is never reset in production. At one request
    /// per nanosecond it wraps after roughly six hundred years, so the
    /// overflow this deliberately does not handle is not reachable; a
    /// wrapping counter would be, and would silently sort a new request
    /// ahead of every old one.
    fn next_sequence(&mut self) -> u64 {
        let sequence = self.next_sequence;
        self.next_sequence += 1;
        sequence
    }
}

static STATE: StdMutex<RequestState> = StdMutex::new(RequestState {
    queued_to_device: BTreeMap::new(),
    pending_claim: None,
    queued_action: Vec::new(),
    queued_signing_keys: None,
    queued_account_query: None,
    queued_peer_queries: Vec::new(),
    pending: BTreeMap::new(),
    account_keys_answered: false,
    account_keys_answer_unsettled: false,
    next_sequence: 0,
});

/// Queues one request upstream handed back to its caller instead of
/// queueing itself, so [`take_outgoing_requests`] hands it out like any
/// other.
///
/// Upstream splits the requests a verification flow produces in two, and
/// only one half is automatic. The messages it generates in *reaction* to
/// an incoming event -- the key message, a MAC the far side asked for
/// first, a timeout cancellation -- it queues into its own cache, and
/// `OlmMachine::outgoing_requests` already returns them. The requests
/// produced by an *action* the caller took -- requesting a verification,
/// accepting one, starting a comparison, confirming, cancelling, handing in
/// a scanned code, confirming a scan -- it returns directly and never
/// queues. Nothing sends those unless this
/// module holds on to them, and a verification whose first message is
/// never sent is indistinguishable from one nobody answered.
///
/// Stamped with a [`Pending::sequence`] on the way in, and held in a `Vec`
/// rather than a map keyed by request id the way `queued_to_device` is.
/// These requests are not order-independent, and the keyed form was tried
/// first and is wrong twice over:
///
/// * Upstream's request ids are random, so a map hands the batch out in an
///   arbitrary order. A confirmation is followed immediately by the
///   acknowledgement that closes the flow, and a far side that receives the
///   acknowledgement first discards it and waits forever for one that has
///   already been sent -- so a flow completed or hung depending on how two
///   random identifiers happened to sort.
/// * Ordering this queue alone is not enough either, because the pair does
///   not always come out of this queue. Upstream returns both together only
///   when the *peer* confirmed first; when we confirm first, it hands back
///   the confirmation and later produces the acknowledgement as a reaction
///   to the peer's own, into its own cache. One batch then carries one from
///   each source, which is why the sequence spans both rather than each
///   source being ordered separately.
///
/// De-duplicated by request id on the way in: a caller that repeats an
/// action before the first is taken would otherwise queue the same id
/// twice, and the second `mark_request_sent` for it would fail with
/// `UnknownRequest` once the first consumed the entry. Checked against
/// `pending` as well as against this queue, since an id already handed out
/// and not yet resolved is in neither the queue nor upstream's hands but is
/// just as unrepeatable. Both scans are over collections holding a handful
/// of entries.
pub(crate) fn queue_action_request(request: UpstreamOutgoingRequest) {
    let mut state = STATE.lock().expect("request registry poisoned");
    let id = request.request_id().to_string();
    if state
        .queued_action
        .iter()
        .any(|(_, queued)| queued.request_id() == request.request_id())
        || state.pending.contains_key(&id)
    {
        return;
    }
    let sequence = state.next_sequence();
    state.queued_action.push((sequence, request));
}

/// Queues this account's signing-identity publication, the one request
/// upstream hands back in a type [`queue_action_request`] cannot accept.
///
/// The transaction id is minted here, which is sound for this endpoint and
/// for no other: upstream's `receive_cross_signing_upload_response`
/// (`machine/mod.rs:641-648`) takes no request id at all -- it marks the
/// identity as shared and saves. So there is nothing to correlate, and the
/// id exists only so this module's own `pending` bookkeeping, and the
/// caller's own `mark_request_sent`, have something to name the request by.
/// Upstream mints ids the same way for the two `From<_> for OutgoingRequest`
/// impls it does provide (`types/requests/enums.rs:116-126`).
///
/// See [`RequestState::queued_signing_keys`] for why this is a single slot
/// and why replacing it preserves the sequence.
pub(crate) fn queue_signing_keys_request(request: UploadSigningKeysRequest) {
    let mut state = STATE.lock().expect("request registry poisoned");
    let sequence = match &state.queued_signing_keys {
        Some((sequence, _, _)) => *sequence,
        None => state.next_sequence(),
    };
    state.queued_signing_keys = Some((sequence, TransactionId::new(), request));
}

/// Queues the out-of-band `/keys/query` for this machine's own account that
/// `signing.rs` refuses a bootstrap in favour of.
///
/// The id comes from upstream (`OlmMachine::query_keys_for_users` returns
/// one alongside the request) and must be used verbatim: unlike the signing
/// keys upload above, `mark_request_as_sent` does pass it on to
/// `receive_keys_query_response`, which looks it up among the queries it
/// believes are in flight.
pub(crate) fn queue_account_key_query(id: OwnedTransactionId, request: KeysQueryRequest) {
    let mut state = STATE.lock().expect("request registry poisoned");
    let sequence = match &state.queued_account_query {
        Some((sequence, _, _)) => *sequence,
        None => state.next_sequence(),
    };
    state.queued_account_query = Some((sequence, id, request));
}

/// Queues the out-of-band `/keys/query` for **another person** that a
/// completed cross-user code verification owes.
///
/// [`queue_account_key_query`]'s sibling, with the same rule about the
/// transaction id: it comes from upstream and must be used verbatim, because
/// `mark_request_as_sent` passes it on to `receive_keys_query_response`,
/// which looks it up among the queries it believes are in flight.
///
/// Appends rather than replacing, for the reason
/// [`RequestState::queued_peer_queries`] gives: two verifications with two
/// people can complete in one sync, and they owe two different questions.
///
/// Takes no sequence, which is the other thing that queue says: this request
/// must not overtake the signature upload the same completion produced, so it
/// is stamped when it is handed out rather than when it is queued.
pub(crate) fn queue_peer_key_query(id: OwnedTransactionId, request: KeysQueryRequest) {
    let mut state = STATE.lock().expect("request registry poisoned");
    state.queued_peer_queries.push((id, request));
}

/// Whether a `/keys/query` naming this machine's own account has been asked
/// *and answered* in this process. `signing.rs`'s ordering gate reads this
/// and nothing else for the "have we asked" half of its question.
pub(crate) fn account_keys_answered() -> bool {
    STATE
        .lock()
        .expect("request registry poisoned")
        .account_keys_answered
}

/// Whether the last accepted answer to a key query about this account left
/// upstream still not knowing whether the account has a signing identity.
///
/// Reported by `signing::read_status` and by nothing else. It gates nothing:
/// the gate is [`account_keys_answered`] alone, and this exists so that a
/// caller facing a refusal can tell which of the two shut-gate situations it
/// is in. See [`RequestState::account_keys_answer_unsettled`].
pub(crate) fn account_keys_answer_unsettled() -> bool {
    STATE
        .lock()
        .expect("request registry poisoned")
        .account_keys_answer_unsettled
}

/// Forgets that this process was ever answered about its own account, and
/// forgets nothing else.
///
/// For `machine::reset_for_test`, which is the only place in this codebase
/// where one process holds account A and then account B. Every other field
/// of [`RequestState`] holds request bodies and ids, which that function's
/// own comment explains it deliberately leaves alone;
/// [`RequestState::account_keys_answered`] is not one of those. It is a fact
/// about *which account* has been asked about, so swapping the account
/// without clearing it leaves the next machine's gate standing open on the
/// previous machine's answer -- and any gate test written inside `src/` would
/// then pass or fail for a reason belonging to whichever test ran before it.
/// That is why every proof of this gate lives in its own file under `tests/`
/// today, and clearing it here is what makes a `src/` one possible.
#[cfg(test)]
pub(crate) fn forget_account_keys_answered_for_test() {
    let mut state = STATE.lock().expect("request registry poisoned");
    state.account_keys_answered = false;
    state.account_keys_answer_unsettled = false;
}

#[cfg(test)]
fn reset_request_state_for_test() {
    let mut state = STATE.lock().expect("request registry poisoned");
    state.queued_to_device.clear();
    state.pending_claim = None;
    state.queued_action.clear();
    state.queued_signing_keys = None;
    state.queued_account_query = None;
    state.queued_peer_queries.clear();
    state.pending.clear();
    state.account_keys_answered = false;
    state.account_keys_answer_unsettled = false;
    state.next_sequence = 0;
}

/// Serialises `value`, mapping a failure to [`SessionError::Failed`] rather
/// than swallowing it into an empty or default JSON value. `serde_json`'s
/// own `json!` macro cannot fail this way (it panics internally instead, on
/// the rare types whose `Serialize` impl can fail at all), but the several
/// direct `serde_json::to_value`/`to_string` calls below are not routed
/// through it -- this is their one shared, fallible chokepoint, so none of
/// them is tempted to reach for `.unwrap_or_default()` and quietly hand out
/// a `body` that looks like a valid request but carries none of its data.
fn to_json<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, SessionError> {
    serde_json::to_value(value).map_err(|_| SessionError::Failed)
}

/// The wire body of a `/keys/claim` request: exactly `one_time_keys`, plus
/// `timeout` when upstream set one. Upstream's own `Request` marks
/// `timeout` `#[serde(skip_serializing_if = "Option::is_none")]` and
/// `one_time_keys` with no such attribute (verified against
/// `ruma-client-api-0.24.0/src/keys/claim_keys/v3.rs`); matched here rather
/// than serialising `r.timeout` as an explicit `null` the way an earlier
/// version of this function did for every optional field (finding 9: ruma
/// omits these, so this does too, now that the fix is this cheap alongside
/// the rest of this function's rewrite).
///
/// Shared between [`describe_outgoing`]'s `KeysClaim` arm (reachable only
/// if a future upstream version starts returning one from
/// `outgoing_requests()` itself -- see `PendingKind`'s own doc comment) and
/// [`take_outgoing_requests`]'s draining of `RequestState::pending_claim`,
/// the actual source of every `keys_claim` request this crate hands out
/// today.
fn describe_keys_claim(r: &KeysClaimRequest) -> Result<String, SessionError> {
    let mut body = serde_json::Map::new();
    body.insert("one_time_keys".to_string(), to_json(&r.one_time_keys)?);
    if let Some(ms) = r.timeout.map(|d| d.as_millis() as u64) {
        body.insert("timeout".to_string(), serde_json::json!(ms));
    }
    Ok(serde_json::Value::Object(body).to_string())
}

/// The wire body of a `/keys/query` request: `device_keys` always, plus
/// `timeout` when upstream set one. `device_keys` is present even when
/// empty, because ruma's own `Request` has no `skip_serializing_if` on it.
///
/// Shared between [`describe_outgoing`]'s `KeysQuery` arm and
/// [`take_outgoing_requests`]'s draining of
/// [`RequestState::queued_account_query`], which carries the identical
/// upstream type -- `OlmMachine::query_keys_for_users` returns the same
/// `KeysQueryRequest` `AnyOutgoingRequest::KeysQuery` wraps, just built
/// out-of-band. Factored out for that second caller the same way
/// [`describe_keys_claim`] already was.
fn describe_keys_query(r: &KeysQueryRequest) -> Result<String, SessionError> {
    let mut body = serde_json::Map::new();
    body.insert("device_keys".to_string(), to_json(&r.device_keys)?);
    if let Some(ms) = r.timeout.map(|d| d.as_millis() as u64) {
        body.insert("timeout".to_string(), serde_json::json!(ms));
    }
    Ok(serde_json::Value::Object(body).to_string())
}

/// The wire body of a `/keys/device_signing/upload` request.
///
/// Hand-serialised field by field rather than through `to_json` on the
/// request itself, because upstream's `UploadSigningKeysRequest`
/// (`types/requests/signing_keys.rs:21-32`) derives `Debug` and `Clone` and
/// **not** `Serialize`: it is a crate-local struct of three key fields, not
/// a ruma request, and nothing in `matrix-sdk-crypto` ever turns it into
/// one. Each field is omitted when absent, matching the
/// `skip_serializing_if = "Option::is_none"` ruma's real request carries on
/// all three (`ruma-client-api-0.24.0/src/keys/upload_signing_keys.rs`).
///
/// **`auth` is deliberately absent**, and its absence is the design, not an
/// omission. That endpoint is user-interactive: the server refuses the first
/// attempt with a challenge, and only then can a caller say anything
/// meaningful about authentication. So the product sends this body, reads
/// the challenge out of the 401, asks its user, and sends the same body
/// again with an `auth` object merged in -- a field added to opaque JSON,
/// which is what [`OutgoingRequest::body`] has always been. This library
/// never sees the credential, and [`mark_request_sent`] looks its entry up
/// without removing it, so the id survives any number of refused attempts
/// and the retry is an ordinary second send.
fn describe_signing_keys(r: &UploadSigningKeysRequest) -> Result<String, SessionError> {
    let mut body = serde_json::Map::new();
    // Destructured, not field-accessed: a field upstream adds later must
    // fail this to compile rather than be silently dropped from a request
    // whose whole purpose is to publish exactly these keys.
    let UploadSigningKeysRequest {
        master_key,
        self_signing_key,
        user_signing_key,
    } = r;
    for (field, key) in [
        ("master_key", master_key),
        ("self_signing_key", self_signing_key),
        ("user_signing_key", user_signing_key),
    ] {
        if let Some(key) = key {
            body.insert(field.to_string(), to_json(key)?);
        }
    }
    Ok(serde_json::Value::Object(body).to_string())
}

/// Flattens one upstream outgoing request into the `{ kind, body }` shape
/// that crosses the boundary, alongside the [`PendingKind`] needed to parse
/// its eventual response.
///
/// Matched exhaustively against `AnyOutgoingRequest`, with no wildcard: a
/// variant upstream adds later must fail this build instead of silently
/// falling through unhandled, the same reasoning `SessionError`'s own
/// `From<MachineError>` above documents for itself.
///
/// Each body is built from the request's own public fields, not from
/// `OutgoingRequest::try_into_http_request` -- that method additionally
/// needs an auth scheme and a homeserver's supported-version list neither
/// of which this bridge has any business deciding (the product owns
/// transport, per spec section 6).
///
/// `keys_upload`, `keys_query`, `keys_claim` and `signature_upload` are
/// exactly that endpoint's real wire body: field names, and which fields
/// are omitted when absent or empty, checked field-by-field against the
/// vendored `ruma-client-api-0.24.0` source for that endpoint (`keys_upload`:
/// `keys/upload_keys/v3.rs`; `keys_query`: `keys/get_keys/v3.rs`;
/// `keys_claim`: see [`describe_keys_claim`]; `signature_upload`:
/// `keys/upload_signatures/v3.rs`, whose `Request` marks `signed_keys`
/// `#[ruma_api(body)]` -- the wire body *is* that map at the top level, not
/// a wrapper around it, which an earlier version of this function got
/// wrong).
///
/// `to_device` and `room_message` are the two disclosed exceptions:
/// alongside their real body field(s), each also carries the values ruma
/// marks `#[ruma_api(path)]` for that endpoint (`event_type`/`txn_id` for
/// `to_device`; `room_id`/`event_type`/`txn_id` for `room_message`), which
/// the real endpoint's URL needs and the wire body itself omits. The
/// product has no other way to obtain them from this crate, and an extra
/// top-level JSON field is harmless to a server that ignores unknown keys.
/// `room_message` previously omitted `event_type` here, which left the
/// product no way to build that URL at all; that is fixed below.
fn describe_outgoing(request: &AnyOutgoingRequest) -> Result<(PendingKind, String), SessionError> {
    match request {
        AnyOutgoingRequest::KeysUpload(r) => {
            let mut body = serde_json::Map::new();
            if let Some(device_keys) = &r.device_keys {
                body.insert("device_keys".to_string(), to_json(device_keys)?);
            }
            if !r.one_time_keys.is_empty() {
                body.insert("one_time_keys".to_string(), to_json(&r.one_time_keys)?);
            }
            if !r.fallback_keys.is_empty() {
                body.insert("fallback_keys".to_string(), to_json(&r.fallback_keys)?);
            }
            Ok((
                PendingKind::KeysUpload,
                serde_json::Value::Object(body).to_string(),
            ))
        }
        AnyOutgoingRequest::KeysQuery(r) => Ok((PendingKind::KeysQuery, describe_keys_query(r)?)),
        AnyOutgoingRequest::KeysClaim(r) => Ok((PendingKind::KeysClaim, describe_keys_claim(r)?)),
        AnyOutgoingRequest::ToDeviceRequest(r) => {
            // `ToDeviceRequest` is this crate's own type and derives
            // `Serialize` directly (unlike the `ruma` request types
            // above), so the whole struct serialises as-is -- see this
            // function's own doc comment for why `event_type`/`txn_id`
            // alongside `messages` is deliberate, not a wire-accuracy bug.
            let body = serde_json::to_string(r).map_err(|_| SessionError::Failed)?;
            Ok((PendingKind::ToDevice, body))
        }
        AnyOutgoingRequest::SignatureUpload(r) => Ok((
            PendingKind::SignatureUpload,
            to_json(&r.signed_keys)?.to_string(),
        )),
        AnyOutgoingRequest::RoomMessage(r) => {
            let mut body = serde_json::Map::new();
            body.insert("room_id".to_string(), to_json(&r.room_id)?);
            body.insert("event_type".to_string(), to_json(&r.content.event_type())?);
            body.insert("txn_id".to_string(), to_json(&r.txn_id)?);
            body.insert("content".to_string(), to_json(&*r.content)?);
            Ok((
                PendingKind::RoomMessage,
                serde_json::Value::Object(body).to_string(),
            ))
        }
    }
}

/// Narrows a `/keys/query` to [`PendingKind::AccountKeysQuery`] when its
/// user list names `account`, and leaves every other kind exactly as
/// [`describe_outgoing`] classified it.
///
/// Applied after `describe_outgoing` rather than inside it, so the wire
/// bodies that function produces stay a pure function of the request and
/// nothing about this module's own bookkeeping can perturb them.
///
/// A key query that names this account *among others* counts: the answer
/// covers this account either way, which is the only thing the gate reading
/// this cares about. Upstream splits large user lists across several
/// requests (`identities/manager.rs`'s own "convert the set of users into
/// multiple /keys/query requests"), so at most one sibling in such a batch
/// is narrowed here and the rest stay ordinary key queries -- correct,
/// because only that one asks about this account.
fn account_scoped(
    kind: PendingKind,
    request: &AnyOutgoingRequest,
    account: &UserId,
) -> PendingKind {
    match (kind, request) {
        (PendingKind::KeysQuery, AnyOutgoingRequest::KeysQuery(r))
            if r.device_keys.contains_key(account) =>
        {
            PendingKind::AccountKeysQuery
        }
        (kind, _) => kind,
    }
}

/// What upstream's own store says about this account's signing identity,
/// read the instant after upstream has consumed an answer to a `/keys/query`
/// this process asked about the account.
///
/// Three outcomes rather than a `bool`, because "the gate did not lift"
/// covers two situations whose remedies are opposite and one of which used
/// to be invisible. See each variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnswerAboutAccount {
    /// The response was not an answer to a key query about this account, so
    /// there was no question here for it to settle. Every other request kind
    /// lands here, and so does an ordinary key query about other users.
    NotAsked,
    /// Upstream consumed the answer and **now knows** whether this account
    /// has a signing identity. This is the fact `signing.rs`'s gate needs,
    /// and the only outcome that lifts it.
    Settled,
    /// Upstream consumed the answer and **still does not know**. The answer
    /// asserted a cross-signing key for this account that upstream could not
    /// read, or it did not cover this account at all.
    ///
    /// Recorded rather than merely not-recorded, because it is the one thing
    /// a product cannot otherwise find out: the request was sent, the
    /// homeserver answered, `mark_request_sent` returned `Ok`, and the gate
    /// is still shut. Reported as
    /// [`crate::IdentityStatus::account_keys_answer_unsettled`], which is
    /// what turns the documented drain-send-report-again remedy from a loop
    /// that cannot terminate into a fact the caller can act on.
    Unsettled,
}

/// Whether `response` asserts any cross-signing key at all for `account`,
/// in any of the three maps a key query answer carries them in.
///
/// This is the question that decides *which* half of
/// [`answer_about_this_account`]'s rule applies, and it is deliberately
/// asked of ruma's parse of the response rather than of the raw bytes: it
/// is the same value, produced by the same parser, that upstream itself
/// consumed a moment earlier. There is no second reading of the body for a
/// first reading to disagree with.
fn claims_an_identity(response: &KeysQueryResponse, account: &UserId) -> bool {
    response.master_keys.contains_key(account)
        || response.self_signing_keys.contains_key(account)
        || response.user_signing_keys.contains_key(account)
}

/// Whether an accepted `/keys/query` answer left upstream knowing whether
/// this account has a signing identity, read from **upstream's store** after
/// upstream has consumed the answer.
///
/// # The question this asks, and the four it stopped asking
///
/// The gate `signing.rs` reads exists to answer one thing: *does this
/// process know whether the account already has a signing identity*, because
/// minting a second one over an existing one resets the trust of every
/// device and every person who ever verified the account, silently, and
/// nothing afterwards can detect it.
///
/// Four earlier rules answered a proxy for that question instead, each a
/// reading of the response body, and each was defeated by a body the reading
/// judged differently from upstream:
///
/// 1. *Any accepted body* lifted the gate. Then the empty object did.
/// 2. *Which request was answered* lifted it, so another user's keys did.
/// 3. *The answer names this account* lifted it -- and it tested the map
///    **key** and never the value. Measured against a live Synapse 1.159.0:
///    an account that had uploaded a master key and a self-signing key but
///    no user-signing key answered its own key query with a body carrying
///    its published master key, and `bootstrap_identity` minted a second
///    identity over it. So did an account that had uploaded a master key
///    alone. Sharpest form, from a *correct* answer that refused correctly:
///    flipping one character of one base64 signature turned
///    `IdentityAlreadyExists` into a mint.
///
/// The mechanism behind all of (3) is upstream's, and it is silent.
/// `IdentityManager::handle_cross_signing_keys` iterates `master_keys`
/// alone; `get_minimal_set_of_keys` needs a master key *and* a
/// `self_signing_keys` entry for the same user; `handle_new_identity` needs
/// a `user_signing_keys` entry too when the user is our own. Anything
/// missing or unreadable is dropped with a `warn!` and no identity is
/// stored (`matrix-sdk-crypto-0.18.0/src/identities/manager.rs`). Every
/// value in all four maps is a `Raw<CrossSigningKey>`, so ruma accepts any
/// JSON at all under a valid user id and defers the judgement to upstream.
/// A rule that reads the body cannot see that judgement; it can only guess
/// at it, and every guess so far has been wrong in the direction that mints.
///
/// So this asks upstream instead. **Upstream either parsed an identity into
/// the store or did not**, and that is a fact about the answer no reading of
/// the body can contradict.
///
/// # The rule
///
/// Read `machine.get_identity(account)` after the mark, and split on what
/// the answer asserted -- from ruma's parse of the response, which is the
/// same value upstream itself consumed:
///
/// * **The answer asserts a cross-signing key for this account.** Then the
///   only thing that settles anything is upstream now holding *the identity
///   the answer asserted*: a stored identity whose master key is the master
///   key this answer carries, deserialised with
///   `deserialize_as_unchecked::<MasterPubkey>` -- upstream's own call, so
///   upstream's own validation of `usage` and of the inner `user_id`. A
///   partial identity, an unreadable one, or one whose signatures do not
///   verify leaves upstream with nothing stored, and this returns
///   [`AnswerAboutAccount::Unsettled`]. That is the whole of defeat (3),
///   closed at the place upstream made the decision rather than at a second
///   reading of the same bytes.
/// * **The answer asserts no cross-signing key for this account at all.**
///   Then it is a homeserver saying the account has none, and it settles the
///   question if it covered the account at all -- which is
///   `device_keys.contains_key(account)`. That is not this crate's
///   invention: it is upstream's own criterion for "this response covered
///   this user", used for `mark_tracked_users_as_up_to_date` and for
///   removing a server from the failures cache (`manager.rs:152,205-211`).
///
/// The consequence worth stating in one line, because it is the safety
/// property: **the gate can only be lifted with no identity known when the
/// answer named the account under `device_keys` and asserted no
/// cross-signing key for it.** Anything else either leaves the gate shut or
/// leaves `identity_known` true, and `signing::may_mint` refuses on that.
///
/// # What this no longer needs to be careful about
///
/// `failures` is not consulted, and now cannot be: it is not one of the
/// three maps [`claims_an_identity`] reads, nor is it `device_keys`. The
/// previous rule excluded it by hand, on the stated grounds that it is keyed
/// by server name -- which is false. Upstream types it
/// `BTreeMap<String, JsonValue>` (`ruma-client-api`'s `get_keys`), so a user
/// id sits in it happily, and a body whose whole content is
/// `{"failures":{"@account:…":{}}}` distinguishes the exclusion. It is
/// pinned by `tests/identity_bootstrap_silent_body.rs` rather than argued.
///
/// Neither is there a second JSON parser to disagree with ruma about what a
/// user id is. The old rule compared a raw `serde_json` map key against
/// `account.as_str()` while ruma parsed the same key into an
/// `OwnedUserId`; every reading here goes through ruma's parse.
///
/// # What it costs, and where the product finds out
///
/// The Matrix specification's `/keys/query` `failures` description says, of
/// a server that could be reached: *"If the homeserver could be reached, but
/// the user or device was unknown, no failure is recorded. Instead, the
/// corresponding user or device is missing from the `device_keys` result."*
/// So omission is not merely permitted, it is **prescribed**, and against a
/// server that follows it this returns `Unsettled` and the gate stays shut.
/// Measured, and reachable without a non-conformant server: Synapse compares
/// the server-name half of a user id against its own `server_name`
/// case-sensitively, so a machine created with a mixed-case server name in
/// its own account id federates, fails, and answers with an empty
/// `device_keys` and an entry under `failures`.
///
/// The direction of that trade is right -- refusing beats resetting every
/// verification anyone made -- but "loud" is what the previous round claimed
/// for it and it was not true: `mark_request_sent` returned `Ok(())` at the
/// one moment the library held both the question and the answer, and
/// `bootstrap_identity` then reported `AccountKeysNotFetched`, whose
/// documented remedy is drain, send, report, call again. Against an omitting
/// server that loop does not terminate, and nothing told the caller so.
///
/// [`AnswerAboutAccount::Unsettled`] is now recorded, and surfaced as
/// [`crate::IdentityStatus::account_keys_answer_unsettled`]. The refusal is
/// the same; what changed is that the caller can tell "nobody has asked"
/// from "we asked, we were answered, and the answer settled nothing", and
/// those have different remedies -- the second one's is to check the account
/// id this machine was created with against the one `/login` returned, and
/// to stop looping.
async fn answer_about_this_account(
    machine: &OlmMachine,
    response: &KeysQueryResponse,
) -> AnswerAboutAccount {
    let account = machine.user_id();

    // `None` as the timeout, not a duration, for `signing::read_status`'s
    // reason: with `Some`, upstream waits for an in-flight key query for
    // this account to land, and this read happens inside the call that is
    // resolving one.
    let Ok(stored) = machine.get_identity(account, None).await else {
        // The store could not be read, so upstream's answer to "is there an
        // identity" is unavailable rather than negative. Not a fudge: this
        // variant means exactly "upstream does not now know", and here it
        // does not. The mark itself still succeeds -- the answer reached
        // upstream, and the request is resolved.
        return AnswerAboutAccount::Unsettled;
    };

    if !claims_an_identity(response, account) {
        // An answer that asserts no cross-signing key for this account is a
        // homeserver saying the account has none. Two things have to hold
        // before that settles anything.
        //
        // **It has to have covered the account at all**, which is
        // `device_keys` naming it. That is upstream's own criterion for
        // "this response covered this user", used for
        // `mark_tracked_users_as_up_to_date` and for removing a server from
        // the failures cache (`manager.rs:152,205-211`).
        //
        // **And nothing this machine already holds may contradict it.** A
        // store that holds a public identity the account really has is a
        // store saying "this account has an identity" while the answer says
        // "it has none". Those cannot both be current: the Matrix protocol
        // has no way to unpublish an identity, and that premise was tested
        // rather than assumed -- an empty upload is a no-op, nulled keys are
        // refused, and deleting every device leaves the identity standing.
        // So such an answer is stale, or from a server that omitted the
        // account, and it settles nothing. That is what
        // `tests/identity_bootstrap_contradicted_answer.rs` holds.
        //
        // **The premise is true and one inference from it was false, and
        // this is the correction.** The check used to read `stored.is_none()`
        // -- *does this store hold an identity* -- and treated a held
        // identity as proof the answer was stale. *This store holds one* and
        // *this account has one* are different facts, and `create_identity`
        // is precisely the call that makes them differ: it writes the minted
        // identity to disk and then hands the publication to the caller. A
        // killed process, an offline device or a timed-out request between
        // those two moments leaves a durable store holding an identity the
        // account genuinely does not have.
        //
        // Measured on continuwuity and on Synapse, before this correction:
        // after that interruption the next process was refused permanently
        // on `bootstrap_identity`, `create_identity`, `create_recovery` and
        // `recover_identity`, five rounds of the documented remedy changed
        // nothing, and the only escape was deleting the store, which is the
        // user's message history. On Synapse the answer was not even an
        // omission but three explicit empty key maps, which the old check
        // read as a contradiction. That is a worse outcome than the defect
        // the check was added to prevent, and it arrived through the
        // ordinary sign-up flow rather than through a race.
        //
        // So the question is not whether this store holds an identity but
        // whether it holds one **the homeserver has ever accepted**, and
        // only the store can answer it, because a server cannot be asked
        // about a publication that never arrived.
        // `signing::identity_is_unpublished` is that record and its own
        // documentation is where it is kept. An identity this device minted
        // and has not seen accepted does not contradict an answer saying the
        // account has none: those two agree, and the remedy is to finish
        // publishing, which `bootstrap_identity` then does.
        let contradicted =
            stored.is_some() && !crate::signing::identity_is_unpublished(machine).await;
        return if response.device_keys.contains_key(account) && !contradicted {
            AnswerAboutAccount::Settled
        } else {
            AnswerAboutAccount::Unsettled
        };
    }

    let Some(identity) = stored.and_then(UserIdentity::own) else {
        return AnswerAboutAccount::Unsettled;
    };
    let Some(asserted) = response
        .master_keys
        .get(account)
        .and_then(|key| key.deserialize_as_unchecked::<MasterPubkey>().ok())
    else {
        return AnswerAboutAccount::Unsettled;
    };
    // `MasterPubkey`'s `PartialEq` compares the user id, the key material
    // and the usage, and deliberately ignores signatures -- upstream's own
    // words, "the signatures are provided by other devices and don't alter
    // the identity of the key itself". That is the right comparison here:
    // the question is whether upstream now holds *this* identity, not
    // whether every device that ever signed it is still in the answer.
    if identity.master_key() == &asserted {
        // The homeserver has asserted the very identity this store holds,
        // which is the moment a publication can be recorded as landed.
        //
        // **But only if the answer is one a homeserver with that identity
        // could actually have sent, and that check was missing.** Measured:
        // this site cleared the record for a body carrying the master key
        // with *every signature removed*, no self-signing key and no
        // user-signing key -- a body upstream stores nothing whatever from.
        // For our own account the stored identity was minted locally rather
        // than parsed out of any answer, so the branch's usual safety
        // property, that upstream either parsed an identity into the store
        // or did not, does not hold here: the comparison degenerates to
        // "does this body echo our own master key", which anyone who has
        // seen an upload body can do.
        //
        // A homeserver that holds this identity sends all three maps for
        // our own user, because that is what it was given and what upstream
        // requires to store one (`get_minimal_set_of_keys` needs the
        // self-signing key, and `get_user_signing_key_from_response` the
        // user-signing key, for our own user). Requiring all three is
        // necessary rather than sufficient, and it is stated as such: it
        // does not make the site unforgeable by the homeserver, it makes the
        // forgery cost the whole published identity rather than one echoed
        // key.
        //
        // What stops the forgery mattering is elsewhere and is structural:
        // `queue_republication` means the launch-time call has no
        // cross-signing upload to hand over whatever this record says, so a
        // wrongly cleared record no longer arms anything. Clearing it
        // wrongly now only makes `create_identity` refuse, which fails
        // closed.
        let complete = response.self_signing_keys.contains_key(account)
            && response.user_signing_keys.contains_key(account);
        if complete {
            crate::signing::note_identity_published(machine).await;
        }
        AnswerAboutAccount::Settled
    } else {
        AnswerAboutAccount::Unsettled
    }
}

/// What the product must send to its homeserver, or feed to another
/// device -- see the design doc section 3bis. `body` is JSON this module
/// never interprets, sent as-is; `kind` is an open tag mirroring upstream's
/// own request kinds, not restricted to the ones listed in
/// [`describe_outgoing`]'s match today.
///
/// No `#[derive(Debug)]`: `body` is a to-device request's Olm-encrypted
/// payload, or a key-upload/key-claim body carrying device keys and
/// one-time keys, alongside user ids and device ids throughout -- exactly
/// what the global no-secret rule forbids from any `Debug` output or panic
/// message. `Debug` is hand-written below, printing `body`'s length rather
/// than its content, the same pattern `Envelope` and `MachineConfig` use.
#[derive(Clone, PartialEq, Eq)]
pub struct OutgoingRequest {
    /// Opaque; hand it back verbatim to [`mark_request_sent`].
    pub id: String,
    pub kind: String,
    pub body: String,
}

impl std::fmt::Debug for OutgoingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let OutgoingRequest { id, kind, body } = self;
        f.debug_struct("OutgoingRequest")
            .field("id", id)
            .field("kind", kind)
            .field("body_len", &body.len())
            .finish()
    }
}

/// Drains every outstanding outbound request: device/one-time key uploads
/// and key queries upstream still wants sent (`OlmMachine::outgoing_requests`),
/// any to-device requests [`share_scope_key`] queued, any `/keys/claim`
/// request it queued (design doc section 3ter), and every request a
/// verification flow handed back rather than queueing
/// ([`queue_action_request`]).
///
/// This is the half of the pump the design doc section 3bis is named for.
/// A fresh machine's device keys and one-time keys are otherwise never
/// published, and a shared session key never leaves the process -- both
/// silent failures that pass every test which never calls this.
///
/// # The returned order is significant, and a caller must preserve it
///
/// **Send the requests in the order this returns them.** Not "start them in
/// that order and let them race" -- each one has to reach the homeserver
/// before the next is sent, because the server relays them to the other
/// device in the order it receives them.
///
/// This is a real constraint, not a defensive one, and it has exactly one
/// source: a verification flow's last two messages are a confirmation and
/// the acknowledgement that closes the flow, and the far side **silently
/// discards** an acknowledgement that arrives before the confirmation it
/// acknowledges. It then waits for one that has already been sent. The
/// failure is asymmetric -- this side completes and records the other device
/// as verified, the other side records nothing -- and neither side is told.
///
/// Resolving them through [`mark_request_sent`] is a different matter and
/// stays unordered: it is a map lookup by id, and marking the second before
/// the first is harmless. So a caller may still send request *n+1* as soon
/// as *n*'s response arrives, without waiting for *n* to be marked.
///
/// Requests from *different* batches were never orderable against each
/// other -- a batch is a snapshot -- and nothing here changes that. What
/// this function guarantees is that within one batch, the order it returns
/// is the order the requests were produced in, across both of the places
/// they come from.
pub async fn take_outgoing_requests() -> Result<Vec<OutgoingRequest>, SessionError> {
    // The account is read in the same trip as the requests, not from the
    // config: it is what [`account_scoped`] below compares each key query's
    // user list against, and reading it from the machine that produced those
    // requests is the only way the two cannot disagree.
    let (account, upstream) = with_machine(|machine| {
        Box::pin(async move {
            let requests = machine.outgoing_requests().await;
            (machine.user_id().to_owned(), requests)
        })
    })
    .await?;
    let upstream = upstream.map_err(|_upstream| SessionError::Failed)?;

    // Every entry this call will hand out, built in full before
    // `state.pending` is touched: a serialisation failure partway through
    // must not leave `pending` holding an id this call never actually
    // returned to the caller, which nothing could ever resolve.
    //
    // The leading `Option<u64>` is the position the entry already has in
    // this module's production order, for the one source that knows it:
    // `queued_action` stamps its entries when they are queued. Everything
    // else is learned of here, for the first time or again, and is stamped
    // below.
    let mut fresh: Vec<(Option<u64>, String, PendingKind, String)> =
        Vec::with_capacity(upstream.len() + 2);

    for request in &upstream {
        let id = request.request_id().to_string();
        let (kind, body) = describe_outgoing(request.request())?;
        fresh.push((
            None,
            id,
            account_scoped(kind, request.request(), &account),
            body,
        ));
    }

    let mut state = STATE.lock().expect("request registry poisoned");

    // Read, not drained, until every serialisation below has already
    // succeeded: draining first (`mem::take`/`Option::take`) and only then
    // discovering a serialisation failure would strand those items
    // nowhere -- removed from the queue, but never reaching `pending` or
    // the caller either, the same "no state change on a failure partway
    // through" reasoning this function's own opening comment gives for
    // building `fresh` before touching `state` at all.
    //
    // The to-device `txn_id` doubles as the request id, per
    // `share_room_key`'s own doc comment (verified against
    // `matrix-sdk-crypto-0.18.0/src/session_manager/group_sessions/mod.rs`):
    // "the responses need to be passed back to the state machine ... using
    // the to-device txn_id as request_id" -- already true by construction
    // here, since `queued_to_device` is itself keyed by `txn_id`. Cloned,
    // not iterated by reference and drained afterwards in the same pass:
    // `Arc<ToDeviceRequest>` clones are cheap (a refcount bump, not the
    // request's own content), so this is not the deep copy it might look
    // like.
    let queued_to_device = state.queued_to_device.clone();
    for (id, to_device) in &queued_to_device {
        let body = serde_json::to_string(to_device.as_ref()).map_err(|_| SessionError::Failed)?;
        fresh.push((None, id.clone(), PendingKind::ToDevice, body));
    }

    if let Some((txn_id, claim_request)) = &state.pending_claim {
        let body = describe_keys_claim(claim_request)?;
        fresh.push((None, txn_id.to_string(), PendingKind::KeysClaim, body));
    }

    // The two slots `signing.rs` fills, each carrying the sequence it was
    // stamped with when it was queued rather than one assigned here -- like
    // `queued_action` below and unlike the two queues above, because these
    // are requests this module witnessed the production of. The signing-keys
    // upload in particular *must* keep its stamp: it was queued between the
    // device-key upload and the signature upload of the same bootstrap, and
    // upstream states that order outright.
    if let Some((sequence, txn_id, query)) = &state.queued_account_query {
        let body = describe_keys_query(query)?;
        fresh.push((
            Some(*sequence),
            txn_id.to_string(),
            // Not routed through `account_scoped`: this request exists only
            // because `signing.rs` asked for this account by name, so the
            // narrowing that function performs is already a given here. Its
            // own variant, not `AccountKeysQuery`, because upstream does not
            // forget this one the way it forgets the queries it volunteers.
            PendingKind::AccountKeysQueryOutOfBand,
            body,
        ));
    }

    if let Some((sequence, txn_id, signing_keys)) = &state.queued_signing_keys {
        let body = describe_signing_keys(signing_keys)?;
        fresh.push((
            Some(*sequence),
            txn_id.to_string(),
            PendingKind::SigningKeysUpload,
            body,
        ));
    }

    // The queries a completed cross-user code verification owes about the
    // person it verified. Not routed through `account_scoped` either, and for
    // the opposite half of the same reason: `verification.rs` queues one only
    // for a flow whose other party is *not* this account, so narrowing could
    // only ever misclassify.
    //
    // **Stamped here rather than at queue time, unlike the two slots above,
    // and pushed after the block that carries upstream's own requests.** That
    // ordering is the whole point: the same completion that queued this also
    // made a signature upload, which upstream holds in its own cache and which
    // therefore reaches `fresh` in the loop at the top of this function. This
    // request asks the server to hand back what that upload is about to tell
    // it, so overtaking it returns a master key without the signature on it
    // and leaves the person `Unverified`.
    for (txn_id, query) in &state.queued_peer_queries {
        let body = describe_keys_query(query)?;
        fresh.push((
            None,
            txn_id.to_string(),
            PendingKind::PeerKeysQueryOutOfBand,
            body,
        ));
    }

    // Read by reference rather than cloned: `AnyOutgoingRequest` is not
    // `Clone` (it is `Debug` and nothing else upstream), and the borrow
    // ends before the drain below. Same "read, not drained, until every
    // serialisation has already succeeded" discipline as the two queues
    // above, for the same reason. Each entry keeps the sequence it was
    // stamped with when it was queued -- these are the only requests whose
    // production this module actually witnessed -- and carries upstream's
    // own request id, so `describe_outgoing` decides the kind here exactly
    // as it does for the requests upstream queued itself: a verification
    // action request is not a distinct kind on this crate's surface, it is
    // a `to_device`, a `signature_upload` or a `room_message` like any
    // other.
    for (sequence, request) in &state.queued_action {
        let (kind, body) = describe_outgoing(request.request())?;
        fresh.push((
            Some(*sequence),
            request.request_id().to_string(),
            account_scoped(kind, request.request(), &account),
            body,
        ));
    }

    // Every entry now carries a position in one order spanning both
    // sources, and the batch is put into it.
    //
    // An entry stamped at queue time keeps that stamp. An entry upstream is
    // offering keeps the stamp it was given the first time it was offered,
    // read back out of `pending`, so a request handed out and not yet
    // resolved does not jump ahead of everything queued since. Anything
    // genuinely new is stamped here, in the order the three blocks above
    // built it, which is the order this function has always used and which
    // a stable sort therefore leaves exactly as it was.
    //
    // Which is the narrow claim, and the whole one: a batch of requests all
    // seen for the first time comes out exactly as it did before this
    // ordering existed. A batch containing a re-offered unresolved request
    // does *not*, and that is reachable with no verification in sight -- a
    // second `share_scope_key` before the first is marked sent re-queues
    // the same `txn_id`, which then sorts ahead of the freshly stamped key
    // upload and key query beside it. That reordering is harmless because
    // those kinds carry no ordering requirement between them, which is
    // exactly what the pre-verification contract asserted of them and what
    // the current one still affirms; only the verification pair is
    // order-significant. Written down because "nothing moves" is the easier
    // sentence and is not the true one.
    //
    // This runs after every fallible step above and before any queue is
    // drained: it consumes counter values, which is harmless (the counter
    // is monotonic and gaps in it mean nothing), and it mutates nothing a
    // failed call would have to put back.
    let mut ordered: Vec<(u64, String, PendingKind, String)> = Vec::with_capacity(fresh.len());
    for (queued_at, id, kind, body) in fresh {
        // Copied out of the map before the counter is touched: holding the
        // borrow across `next_sequence` would be a mutable and an immutable
        // borrow of `state` at once.
        let already_handed_out = state.pending.get(&id).map(|entry| entry.sequence);
        let sequence = match queued_at.or(already_handed_out) {
            Some(sequence) => sequence,
            None => state.next_sequence(),
        };
        ordered.push((sequence, id, kind, body));
    }
    // Stable, so entries stamped in this call keep the order they were
    // built in rather than an arbitrary one.
    ordered.sort_by_key(|(sequence, _, _, _)| *sequence);

    // Every fallible step above has now succeeded, so the queues can safely
    // be drained for real.
    state.queued_to_device.clear();
    state.pending_claim = None;
    state.queued_action.clear();
    state.queued_account_query = None;
    state.queued_signing_keys = None;
    state.queued_peer_queries.clear();

    // Evict every existing `pending` entry whose kind this batch is about
    // to refresh, once per call rather than once per item -- per-item
    // eviction would be wrong for `keys_query`, which can legitimately
    // hand out *several* requests in the same batch when upstream splits a
    // large user list across multiple `/keys/query` calls
    // (`identities/manager.rs`'s own "convert the set of users into
    // multiple /keys/query requests" comment): evicting after inserting
    // the first of those siblings would discard the second. See
    // `PendingKind::eviction_group`'s own doc comment for
    // why eviction is correct here at all.
    //
    // Grouped by `PendingKind::eviction_group`, not by variant: several
    // variants can be one thing that supersedes itself, and one variant that
    // shares an endpoint with them can fail to be. See that function's own
    // doc comment for each group and the reason behind it.
    let refreshed: Vec<&'static str> = ordered
        .iter()
        .filter_map(|(_, _, kind, _)| kind.eviction_group())
        .collect();
    if !refreshed.is_empty() {
        state.pending.retain(|_, entry| {
            entry
                .kind
                .eviction_group()
                .is_none_or(|group| !refreshed.contains(&group))
        });
    }

    let mut out = Vec::with_capacity(ordered.len());
    for (sequence, id, kind, body) in ordered {
        state.pending.insert(id.clone(), Pending { kind, sequence });
        out.push(OutgoingRequest {
            id,
            kind: kind.tag().to_string(),
            body,
        });
    }

    Ok(out)
}

/// Refuses a `response_json` that is not a success response at all.
///
/// # Why this has to exist, and why it is not paranoia
///
/// [`http_response`] below hardcodes status 200 and **no HTTP status
/// crosses this boundary** -- the frozen `markRequestSent(id, responseJson)`
/// signature carries a body and nothing else. So a homeserver *error* body
/// arrives looking exactly like an answer, and for `/keys/query` it
/// deserialises into a perfectly valid, perfectly empty one: every field of
/// that endpoint's response is `#[serde(default)]`
/// (`ruma-client-api-0.24.0/src/keys/get_keys.rs`), so an object with none
/// of them is a success naming no devices and no identities. Reported that
/// way, `/keys/query` becomes "the server answered and named no identity
/// for this account", which is exactly the fact `signing.rs`'s ordering gate
/// mints an identity on. A product whose HTTP layer does the obvious
/// `markRequestSent(id, await res.text())` without branching on the status
/// therefore mints a second identity on a rate-limited or 502'd key query,
/// and silently invalidates every verification anyone has ever made of that
/// account. That was reproduced end to end, not imagined.
///
/// Four things are refused, and none of them can be a legitimate answer to
/// any endpoint this module handles. That was checked against the vendored
/// response types rather than assumed: the seven of them declare
/// `one_time_key_counts`, `failures`, `device_keys`, `master_keys`,
/// `self_signing_keys`, `user_signing_keys`, `one_time_keys` and `event_id`
/// between them, two declare no fields at all, and not one declares
/// `errcode`, `error` or `flows`.
///
/// * **A standard error response**, which the specification requires to
///   carry a top-level `errcode`. Covers every 4xx and 5xx a conformant
///   homeserver produces.
/// * **A user-interactive authentication challenge**, whose top-level
///   `flows` is what makes it a challenge. This is the 401 the signing-keys
///   upload always gets on its first attempt. Refusing it matters more than
///   it looks: see the next section for why nothing else would catch it.
/// * **A non-conformant error carrying `error` without `errcode`**, which
///   is what a gateway in front of the homeserver tends to produce:
///   `{"error":"Bad Gateway"}` is not a Matrix error and the first rule
///   above cannot see it. Measured as accepted before this key was added,
///   and it lifted the bootstrap gate.
/// * **Anything that is not a JSON object.** Every response body of every
///   endpoint here is one. An array is the case worth naming, because
///   reasoning gets it wrong: serde reads a struct from a sequence
///   positionally and every `/keys/query` field is defaulted, so `[]`
///   deserialised into a flawless empty success. A bare string, a number,
///   `null`, a proxy's HTML page and a body of nothing but spaces are all
///   refused by the same rule.
/// * **An object carrying no field this endpoint's response declares**, by
///   [`PendingKind::declared_response_fields`]. The three rules above all
///   ask "does this look like an error", and that question cannot be
///   finished: a proxy may answer with any object it likes, and
///   `{"message":"Internal server error"}` (AWS API Gateway's default, and
///   several service meshes') carries no marker of any kind. Measured
///   before this rule existed: it, `{"detail":...}`, `{"status":"error",
///   "code":502}` and Cloudflare's `{"success":false,...}` were all
///   accepted for `/keys/query`, all set the gate, and `bootstrap_identity`
///   then minted. Asking instead "does this look like *this endpoint's*
///   response" is answerable, because that list is finite and vendored.
///
/// Presence is tested, not type. `{"errcode":429}` is not a conformant
/// error response and `{"flows":{...}}` is not a conformant challenge, but
/// refusing them costs nothing -- no success shape declares either key, so
/// there is no legitimate answer to falsely refuse -- and an earlier version
/// that required a JSON string and a JSON array respectively let both
/// through. Nested occurrences are untouched, which is the half that has to
/// be right: `/keys/query`, `/keys/claim` and `/keys/signatures/upload` all
/// carry a `failures` map whose values are real per-server errors with real
/// `errcode`s and `error`s inside them, and those are successes.
///
/// # What this accepts, which is a shape rather than a list
///
/// **This is the one statement of that division.** The other places that
/// need it point here rather than restating it: [`mark_request_sent`],
/// `signing.rs`'s module doc and `signing::bootstrap_identity`, and
/// `markRequestFailed` in the TypeScript facade, which carries the same
/// division in the language a product author reads.
///
/// **It is not a substitute for the status.** What it refuses is what it can
/// show is not a response. What it accepts is everything else, and that is a
/// shape rather than a list of literals: **an object with no keys, or an
/// object carrying at least one field this endpoint's response really
/// declares.**
///
/// **Passing this function is necessary, not sufficient.** It is one of two
/// checks, and the per-kind parse in [`mark_sent`] runs after it and refuses
/// more: `{}` reaches that parse for every kind and is then rejected for
/// `keys_upload`, `keys_claim` and `room_message`, whose responses each have
/// one required field. The rules above also compose rather than partition,
/// so a body carrying a declared field *and* an error marker is refused by
/// the marker rule even though the shape rule would pass it. The statement
/// below is therefore about what this function lets through, not about what
/// `mark_request_sent` ultimately accepts.
///
/// Every genuine success is inside that shape, which is the point of drawing
/// it there. So is any failure whose body happens to fall inside it, and the
/// member that matters is the object with no keys. `{}` is the entire
/// success response of both fieldless kinds. A completely empty body is the
/// same input: ruma substitutes `b"{}"` for it before parsing ("If the body
/// is completely empty, pretend it is an empty JSON object instead",
/// `ruma-macros-0.19.0/src/api/common.rs:365-371`), as does `"  {}  "`. So a
/// 503 that carried no body and a 200 that had nothing to say arrive here as
/// the same bytes.
///
/// **This paragraph used to name `/keys/query` first, and say that `{}` is
/// what it answers for an account the server knows no identity for. It is
/// not.** Measured against Synapse 1.159.0, Dendrite 0.15.2 and continuwuity
/// v26.7.2, all three name the queried local account in `device_keys` even
/// when they hold nothing for it, so no real key query answer is the empty
/// object. That collision is now closed one level down rather than here:
/// this function still accepts `{}` for a key query, because it is a
/// well-formed response and upstream has to see it, and
/// [`answer_about_this_account`] is what keeps it from lifting `signing.rs`'s
/// gate. For the two fieldless kinds the collision remains exactly as
/// described, and [`mark_request_failed`] is still what closes it there.
///
/// For the five kinds whose response type has fields, the shape is wider
/// than that one member: `{"device_keys":{}}` reported for a refused
/// `/keys/query` is accepted, because it is indistinguishable from the
/// answer it is a copy of. For `to_device` and `signing_keys_upload` the
/// shape is only the empty object, since they declare no field that could
/// widen it, and they are also the two that get no body parse from ruma at
/// all (`BodyFields::Empty => None`,
/// `ruma-macros-0.19.0/src/api/common.rs:329-331`). Before this function
/// required a JSON object they took literally any bytes,
/// `not json at all !!!` and an HTML 502 page included.
///
/// Only the HTTP status separates a success from a failure inside that
/// shape, and no status crosses this boundary through [`mark_request_sent`].
/// That is what [`mark_request_failed`] is for.
fn refuse_a_non_response(kind: PendingKind, body: &str) -> Result<(), SessionError> {
    // A *completely* empty body is the same input as `{}` and is accepted on
    // the same terms: ruma substitutes an empty object for it before
    // parsing, so by the time anything downstream sees it, that is what it
    // is. See the doc comment above for what an empty object can be hiding
    // and why nothing here can tell.
    if body.is_empty() {
        return Ok(());
    }
    // Every response body of every endpoint this module handles is a JSON
    // object. Anything else is not one, so refusing it here costs no
    // legitimate answer: an array, a bare string, a number, `null`, a
    // proxy's HTML page, a body of nothing but spaces.
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(body) else {
        return Err(SessionError::MalformedPayload);
    };
    let Some(object) = parsed.as_object() else {
        return Err(SessionError::MalformedPayload);
    };
    // Presence, not type, and only at the top level. `error` joins the two
    // the specification defines because a non-conformant gateway that
    // answers `{"error":"Bad Gateway"}` carries no `errcode`. None of the
    // seven response types declares any of the three, so there is no
    // legitimate body to refuse by mistake. Kept as its own rule rather
    // than folded into the one below, which would not catch a hybrid: an
    // object carrying both a real field and an `errcode` is refused here
    // and would pass there.
    if object.contains_key("errcode")
        || object.contains_key("error")
        || object.contains_key("flows")
    {
        return Err(SessionError::MalformedPayload);
    }
    // The positive rule, and the only one that can bound an unbounded set.
    // Everything above answers "does this look like an error", which cannot
    // be finished: a proxy may send any object it likes, and
    // `{"message":"Internal server error"}` carries no marker at all.
    // Asking instead "does this look like *this endpoint's* response" is
    // answerable, because that list is finite and vendored.
    //
    // An empty object is exempt because it has no keys to judge, and it is
    // the entire success response of both fieldless kinds. This comment used
    // to add that `/keys/query` returns it for an account the server knows
    // nothing about; three measured homeservers do not, and the doc comment
    // above says what replaced that reasoning. The exemption stands anyway:
    // refusing it here would refuse the two fieldless kinds outright.
    //
    // For the five kinds with fields this is deliberately not
    // `deny_unknown_fields`. A response carrying a field a later
    // specification adds, *alongside* one this crate knows, still passes.
    // Only a body made up exclusively of fields none of which this crate's
    // ruma declares is refused.
    //
    // For `to_device` and `signing_keys_upload` it *is* `deny_unknown_fields`
    // in every practical sense, and that is worth saying here rather than
    // only where the empty list is defined: their declared list is empty, so
    // no key can ever match and any key at all is refused. A field added to
    // either endpoint's 200 response by a later specification would break
    // them. Both are `Response {}` today and have been stable, and this is
    // the only check either gets, so the trade is taken knowingly.
    //
    // Either way the residual forward-compatibility cost fails closed, with
    // `MalformedPayload` and a gate that stays shut, rather than open.
    if !object.is_empty()
        && !object
            .keys()
            .any(|key| kind.declared_response_fields().contains(&key.as_str()))
    {
        return Err(SessionError::MalformedPayload);
    }
    Ok(())
}

/// Builds a fixed-shape, status-200 `http::Response` around `body`, the
/// shape `ruma`'s own `IncomingResponse::try_from_http_response` expects.
///
/// No custom headers and a status this module always controls itself
/// (never read from `body`), so building it cannot fail -- the `expect`
/// documents that rather than guarding against a case that cannot occur.
///
/// **The hardcoded status is not a safety property**, and an earlier
/// version of this comment read as though it were. It means the opposite:
/// every body reaching here is treated as a 200 whatever the server
/// actually said, which is why [`refuse_a_non_response`] above has to
/// inspect the body before this is ever called.
fn http_response(body: Vec<u8>) -> http::Response<Vec<u8>> {
    http::Response::builder()
        .status(200)
        .body(body)
        .expect("a fixed-shape http::Response with no custom headers cannot fail to build")
}

/// Parses `body` as the response shape `kind` expects and hands it to
/// `machine.mark_request_as_sent`.
///
/// Going through `IncomingResponse::try_from_http_response` rather than
/// constructing each upstream `Response` type by hand is not a style
/// choice: every one of these types is `#[non_exhaustive]`, and some (e.g.
/// `KeysQuery`) expose no public constructor that accepts real field values
/// at all -- `try_from_http_response` is the only public way to build a
/// populated instance of every one of them from outside `ruma-client-api`.
///
/// For `ToDevice`, `SignatureUpload` and `RoomMessage`, upstream's own
/// `mark_request_as_sent` ignores the response value entirely (it only
/// matches the enum tag) -- confirmed by reading `machine/mod.rs:602`'s
/// match arms, each `AnyIncomingResponse::Variant(_)` for those three. This
/// function still parses `body` into the correctly-typed value rather than
/// fabricating one, because "this module does not interpret the JSON" (spec
/// section 3bis) means it does not act on the JSON's meaning, not that it
/// skips deserialising it.
async fn mark_sent(
    machine: &OlmMachine,
    kind: PendingKind,
    transaction_id: OwnedTransactionId,
    body: Vec<u8>,
) -> Result<AnswerAboutAccount, SessionError> {
    // Held past the match so that the account-scoped kinds can ask
    // `answer_about_this_account` what upstream made of it, once upstream
    // has been given it. Kept as ruma's parse rather than as bytes on
    // purpose: it is the value upstream consumed, so there is no second
    // reading of the body for the first to disagree with.
    let mut answer: Option<KeysQueryResponse> = None;
    let outcome = match kind {
        PendingKind::KeysUpload => {
            let response = KeysUploadResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            machine
                .mark_request_as_sent(&transaction_id, &response)
                .await
        }
        PendingKind::KeysQuery
        | PendingKind::AccountKeysQuery
        | PendingKind::AccountKeysQueryOutOfBand
        | PendingKind::PeerKeysQueryOutOfBand => {
            let response = KeysQueryResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            let outcome = machine
                .mark_request_as_sent(&transaction_id, &response)
                .await;
            answer = Some(response);
            outcome
        }
        PendingKind::KeysClaim => {
            let response = KeysClaimResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            machine
                .mark_request_as_sent(&transaction_id, &response)
                .await
        }
        PendingKind::ToDevice => {
            let response = ToDeviceHttpResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            machine
                .mark_request_as_sent(&transaction_id, &response)
                .await
        }
        PendingKind::SignatureUpload => {
            let response = SignatureUploadResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            machine
                .mark_request_as_sent(&transaction_id, &response)
                .await
        }
        PendingKind::RoomMessage => {
            let response = RoomMessageResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            machine
                .mark_request_as_sent(&transaction_id, &response)
                .await
        }
        // The one arm that names its incoming variant by hand. Every other
        // arm passes `&response` and lets the blanket
        // `impl From<&'a T> for AnyIncomingResponse` pick the variant --
        // upstream provides one for seven of the eight response types and
        // **not** for this one (`types/requests/enums.rs:162-205`). Passing
        // `&response` here does not compile, which is the good outcome: the
        // asymmetry is caught by the type checker rather than by an identity
        // that is silently never marked as published.
        //
        // `transaction_id` is passed for symmetry and is genuinely unused by
        // upstream: `receive_cross_signing_upload_response`
        // (`machine/mod.rs:641-648`) takes no id, marks the identity shared
        // and saves. See `queue_signing_keys_request` for why this module
        // mints one at all.
        PendingKind::SigningKeysUpload => {
            let response = SigningKeysUploadResponse::try_from_http_response(http_response(body))
                .map_err(|_| SessionError::MalformedPayload)?;
            // **Deliberately not a clearing site, and that is the ninth
            // round's second change.**
            //
            // This looks like the moment the homeserver accepted the
            // publication, and it is not. It is the moment the *caller* said
            // so, and `refuse_a_non_response`'s own doc comment states which
            // bodies it cannot tell from a success: the empty body and the
            // empty object. Measured, ten bodies a refused
            // `/keys/device_signing/upload` can carry: eight are refused
            // here, and the two that get through are exactly that pair,
            // which is what a connection reset, a socket timeout and a
            // bodiless gateway error hand a product.
            //
            // Clearing on those bricked the account permanently. The store
            // then held an identity no homeserver had, with nothing saying
            // so, so every later "this account has no identity" answer read
            // as a contradiction and every write on the surface refused for
            // ever, with no escape but deleting the user's message history.
            //
            // `signing::note_identity_published` is now reached only from
            // `answer_about_this_account`, where the *server* asserts the
            // identity in an answer it sent. That costs one round trip on
            // the happy path -- the confirming query `create_identity`
            // queues alongside the publication -- and it makes a misreported
            // upload cost nothing at all, because the record survives it and
            // the publication stays finishable.
            machine
                .mark_request_as_sent(
                    &transaction_id,
                    AnyIncomingResponse::SigningKeysUpload(&response),
                )
                .await
        }
    };

    // Upstream `Display` output here can embed device/session/user
    // identifiers pulled straight from the response body -- never
    // forwarded, per spec section 7.
    outcome.map_err(|_upstream| SessionError::Failed)?;

    // Read only after upstream has accepted the answer, and only for the two
    // kinds whose question was about this account. Everything else has no
    // question here to settle. See `answer_about_this_account` for the rule
    // and for the four it replaces.
    Ok(match answer {
        Some(response)
            if matches!(
                kind,
                PendingKind::AccountKeysQuery | PendingKind::AccountKeysQueryOutOfBand
            ) =>
        {
            answer_about_this_account(machine, &response).await
        }
        _ => AnswerAboutAccount::NotAsked,
    })
}

/// Reports that the request named by `id` was sent, handing back the
/// server's response so upstream can update its own state (device lists,
/// one-time key counts, claimed keys -- depending on what `id` was).
///
/// `id` is converted to a `TransactionId` via `From<&str>`, which is
/// infallible: upstream's own doc comment on the type says as much --
/// "Transaction IDs in Matrix are opaque strings" with no format of their
/// own to validate against. What can fail is `id` not matching anything
/// this module handed out -- [`SessionError::UnknownRequest`] -- and
/// `response_json` not parsing as the shape that request's kind expects --
/// [`SessionError::MalformedPayload`].
///
/// The `pending` entry is looked up, not removed, before the mark is
/// attempted, and removed only once it succeeds: a caller who sent a
/// malformed `response_json` (or hit a transient upstream failure) can
/// retry the same `id` with corrected input instead of being told
/// `UnknownRequest` for a request that is, in fact, still exactly as
/// pending as before this call.
///
/// # Report only what a success returned
///
/// **`response_json` must be the body of a 2xx response.** This call is how
/// a request stops being outstanding and how upstream learns what the
/// server said; reporting anything else tells it a falsehood it has no way
/// to detect. The consequences are not uniform and the worst of them is
/// silent: a failed `/keys/query` reported as a success is what
/// `signing.rs`'s ordering gate reads as "the server answered and this
/// account has no identity", and a 401 challenge reported for a
/// signing-keys upload marks an identity published that never was.
///
/// [`refuse_a_non_response`] enforces as much of this as a body alone can
/// carry, and **its doc comment is the single statement of what that is**:
/// what it refuses, what it accepts, and why the remainder cannot be closed
/// from a body. It is not restated here, so that the two cannot drift.
///
/// What matters at this call is the consequence. Some bodies a refused
/// request carries are indistinguishable from a real answer, the empty
/// object among them, so reporting one here is reporting a success. No HTTP
/// status crosses this boundary on *this* call, which makes the branch the
/// caller's obligation: send a 2xx here, and send everything else to
/// [`mark_request_failed`].
///
/// A refused body leaves the request exactly as pending as before, by the
/// same rule as any other failure here, so the ordinary
/// send-again-with-`auth` retry after a 401 needs nothing special: report
/// nothing for the challenge, and report the eventual success.
pub async fn mark_request_sent(id: &str, response_json: &str) -> Result<(), SessionError> {
    let kind = {
        let state = STATE.lock().expect("request registry poisoned");
        state.pending.get(id).map(|entry| entry.kind)
    }
    .ok_or(SessionError::UnknownRequest)?;

    // Before the machine lock is taken, and before any per-kind parse.
    // Some of those parses would have rejected an error body on their own
    // (`keys_upload`, `keys_claim` and `room_message` each have a required
    // field an error body does not carry); `keys_query` would not, and
    // `to_device`/`signing_keys_upload` have no body parse to reject
    // anything at all. See `refuse_a_non_response` for which is which, and
    // for why it needs the kind: its last rule is stated in terms of the
    // fields this endpoint's own response declares.
    refuse_a_non_response(kind, response_json)?;

    let transaction_id: OwnedTransactionId = <&TransactionId>::from(id).to_owned();
    let body = response_json.as_bytes().to_vec();

    // The mark and the read of what upstream made of it happen in the same
    // trip, not in two, for the reason `take_outgoing_requests` gives for
    // reading the account alongside the requests: this is the machine the
    // response was just applied to, and only one trip can guarantee that.
    let settled = with_machine(move |machine| {
        Box::pin(async move { mark_sent(machine, kind, transaction_id, body).await })
    })
    .await?;

    if let Ok(settled) = settled {
        let mut state = STATE.lock().expect("request registry poisoned");
        state.pending.remove(id);
        // Recorded here and nowhere else, and what is recorded is what
        // **upstream** knows, not what this module made of the bytes.
        //
        // Handing the request out is not enough: a caller can drain the pump
        // and never send anything. The kind alone is not enough either: a
        // body carrying only another user's keys answered somebody else's
        // question, and it used to lift this gate. Nor is "the answer names
        // this account" enough, which is the rule this replaces: it read the
        // map key and never the value, so an answer *carrying this
        // account's published master key* lifted the gate while upstream had
        // stored no identity at all, and the next `bootstrap_identity`
        // minted over it. See `answer_about_this_account` for the whole of
        // that and for the rule that ends it.
        //
        // `Unsettled` is recorded too, and that is the second half of this
        // change. It is the one state a product could not otherwise observe
        // -- the send succeeded, the server answered, and the gate is still
        // shut -- and leaving it unrecorded is what made the documented
        // remedy for `AccountKeysNotFetched` a loop that cannot terminate
        // against a server that omits an unknown user. It is not recorded
        // over an already-lifted gate: once upstream knows, a later answer
        // that settles nothing does not un-know it.
        match settled {
            AnswerAboutAccount::NotAsked => {}
            AnswerAboutAccount::Settled => {
                state.account_keys_answered = true;
                state.account_keys_answer_unsettled = false;
            }
            AnswerAboutAccount::Unsettled if !state.account_keys_answered => {
                state.account_keys_answer_unsettled = true;
            }
            AnswerAboutAccount::Unsettled => {}
        }
    }

    settled.map(|_| ())
}

/// Whether `status` is one a request that was **refused** can carry.
///
/// `0` is accepted and means no response reached the caller at all: a
/// dropped connection, a DNS failure, a timeout. A product that meets one
/// has a request it certainly did not get an answer to and no status to
/// describe it with, and inventing a plausible 5xx to satisfy this argument
/// would be worse than having a value that says exactly what happened.
///
/// `300` through `599` are accepted. A 2xx is not, and that is the whole
/// point of the check rather than an edge of it; see
/// [`SessionError::NotAFailureStatus`]. Above 599, and between 1 and 299,
/// are rejected as the caller-side mistakes they are.
fn is_a_failure_status(status: u16) -> bool {
    status == 0 || (300..=599).contains(&status)
}

/// Reports that the request named by `id` was **refused**: it was sent, and
/// what came back was not a success.
///
/// This is the counterpart to [`mark_request_sent`] and the reason that call
/// is no longer the only thing a product can say. Before it existed, a
/// caller that received a 502 from a proxy, or a 503 with an empty body, had
/// one call available and reporting the failure through it read as a
/// success.
///
/// # What this changes, which is deliberately nothing
///
/// A refused request taught this library nothing, so nothing it knows
/// changes. The `pending` entry is looked up and left exactly where it was,
/// by the same rule that makes a refused `response_json` retriable: the
/// request is still outstanding, and the retry is an ordinary second send.
/// In particular the ordering gate `signing.rs` reads is untouched, which is
/// the property that matters. Only a *successful* mark sets it, so a request
/// that is refused, or never reported at all, leaves the gate shut.
///
/// **A product that never calls this behaves exactly as it did before.**
/// That is safe rather than merely tolerable, and the direction is worth
/// being explicit about: silence leaves a request pending, the gate needs a
/// positive mark to open, and [`crate::bootstrap_identity`] then refuses
/// with `AccountKeysNotFetched` rather than minting. The failure mode of
/// forgetting this call is a bootstrap that will not proceed, which is loud,
/// and never an identity destroyed.
///
/// # What this library cannot tell, and will not pretend to
///
/// The unsafe case is not omission. It is calling [`mark_request_sent`] with
/// the body of a response the server refused, and **the library cannot
/// detect that from the body in every case.**
///
/// [`refuse_a_non_response`] states once what it refuses, what it accepts,
/// and why the remainder cannot be closed from a body. That statement is not
/// duplicated here. The short of it is that what gets through is every body
/// shaped like that endpoint's response, and the empty object is inside that
/// shape because it *is* the answer a fresh account's key query returns and
/// the whole success response of the signing-keys upload.
///
/// So a 503 that carried no body and a 200 that had nothing to say arrive as
/// the same bytes. Only the HTTP status separates them, and no status
/// crosses this boundary on [`mark_request_sent`], which is why this call
/// takes one.
///
/// So the obligation is real and it is the caller's: **branch on the status
/// first.** A 2xx goes to [`mark_request_sent`] with the body; anything else
/// comes here. `mark_request_sent(id, res.text())` without that branch is
/// the first-draft wrapper this whole mechanism exists to survive, and on a
/// refused `/keys/query` it tells the gate the server answered and this
/// account has no identity, which is the one fact that authorises minting a
/// new one over whatever the account already had.
///
/// # Refusals
///
/// [`SessionError::UnknownRequest`] if `id` names nothing outstanding, by
/// the same rule and with the same meaning as in [`mark_request_sent`],
/// including the eviction case that call's doc comment describes.
///
/// [`SessionError::NotAFailureStatus`] if `status` is not one a refused
/// request can carry. A 2xx is the case that matters: it means this call and
/// [`mark_request_sent`] have been swapped, and since a refusal changes no
/// state, accepting it silently would let that confusion stand. It is the
/// single misuse of the pair this library can see for itself, and it sees it
/// in the argument rather than in the body.
///
/// The id is checked before the status, matching [`mark_request_sent`],
/// which also answers `UnknownRequest` before it looks at anything else.
pub async fn mark_request_failed(id: &str, status: u16) -> Result<(), SessionError> {
    {
        let state = STATE.lock().expect("request registry poisoned");
        if !state.pending.contains_key(id) {
            return Err(SessionError::UnknownRequest);
        }
    }

    if !is_a_failure_status(status) {
        return Err(SessionError::NotAFailureStatus);
    }

    // No machine lock, no parse, no write. The entry stays pending on
    // purpose: see this function's own doc comment. Returning `Ok` here
    // means "recorded that you got nothing usable", not "recorded a result".
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine config pointing at a directory that outlives this call.
    /// `TempDir::keep`, not the guard itself: the only thing returned is an
    /// owned `MachineConfig`, so nothing here can hand the caller a guard to
    /// hold alive too. The directory is left on disk after the test process
    /// exits -- the same trade every other `tempfile::tempdir()` use in this
    /// crate's tests accepts, just not deferred to a `Drop` here because
    /// this helper's own scope ends before `create_machine` ever runs.
    fn test_config() -> crate::machine::MachineConfig {
        let dir = tempfile::tempdir().expect("temp dir").keep();
        crate::machine::MachineConfig {
            user_id: "@alice:example.org".to_string(),
            device_id: "DEVICE1".to_string(),
            store_path: dir.join("store").to_string_lossy().into_owned(),
            store_passphrase: Some("test-passphrase".to_string()),
        }
    }

    /// An empty sync is the shape a product sends constantly. It must be
    /// accepted and report nothing, not rejected as malformed.
    ///
    /// Deliberately not `#[tokio::test]`: this crate's tests drive
    /// `with_machine` through `futures::executor::block_on` with no ambient
    /// runtime, the same shape the FFI's real calling context has. See
    /// `machine.rs`'s `with_machine_supplies_a_runtime_for_store_touching_calls`
    /// for why that distinction matters -- an ambient runtime would make
    /// this test pass even if `with_machine` supplied none of its own.
    #[test]
    fn an_empty_sync_is_accepted_and_reports_no_new_sessions() {
        // `HELD` is process-wide and shared with `machine.rs`'s and
        // `identity.rs`'s own tests, all in one test binary; guarded the
        // same way theirs are.
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();

        let outcome = futures::executor::block_on(async {
            crate::machine::create_machine(test_config()).await.unwrap();
            receive_sync_changes(r#"{"to_device_events":[],"changed_devices":{"changed":[],"left":[]},"one_time_keys_counts":{}}"#).await
        })
        .unwrap();

        assert_eq!(outcome.to_device_event_count, 0);
        assert_eq!(outcome.new_session_count, 0);
    }

    /// The stronger form of the same property: every key absent, not merely
    /// empty. Proves `#[serde(default)]` covers every field of
    /// `SyncChangesPayload`, including the two `Option` fields the brief's
    /// own sync payload above never exercises because it never mentions
    /// them either.
    #[test]
    fn a_sync_with_every_field_omitted_is_also_accepted() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();

        let outcome = futures::executor::block_on(async {
            crate::machine::create_machine(test_config()).await.unwrap();
            receive_sync_changes("{}").await
        })
        .unwrap();

        assert_eq!(outcome.to_device_event_count, 0);
        assert_eq!(outcome.new_session_count, 0);
    }

    #[test]
    fn malformed_json_is_reported_as_malformed_not_as_a_store_failure() {
        let err = futures::executor::block_on(receive_sync_changes("{oops")).unwrap_err();
        assert_eq!(err, SessionError::MalformedPayload);
    }

    /// A distinct failure mode from the one above: syntactically valid JSON
    /// that does not match the accepted shape. Both must be reported the
    /// same way, so a caller does not have to guess which kind of "not
    /// parseable" it hit.
    #[test]
    fn well_formed_json_of_the_wrong_shape_is_also_reported_as_malformed() {
        let err = futures::executor::block_on(receive_sync_changes(
            r#"{"one_time_keys_counts":"not-a-map"}"#,
        ))
        .unwrap_err();
        assert_eq!(err, SessionError::MalformedPayload);
    }

    /// This crate's own precondition, not upstream's: `with_machine` reports
    /// `NotInitialised` before ever reaching a machine, and that must
    /// surface as `SessionError::NotInitialised`, not `Failed` -- a product
    /// needs to tell "you haven't set me up yet" apart from "the crypto
    /// operation failed".
    #[test]
    fn calls_before_creation_report_not_initialised() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();

        let err = futures::executor::block_on(receive_sync_changes(
            r#"{"to_device_events":[],"changed_devices":{"changed":[],"left":[]},"one_time_keys_counts":{}}"#,
        ))
        .unwrap_err();

        assert_eq!(err, SessionError::NotInitialised);
    }

    /// Both counts in `an_empty_sync_is_accepted_and_reports_no_new_sessions`
    /// are zero, which a function that always hard-coded zero would also
    /// satisfy. This sends one real, unencrypted to-device event and checks
    /// the count follows it, so a regression to "always report zero" cannot
    /// pass unnoticed.
    #[test]
    fn to_device_event_count_reflects_what_the_machine_actually_processed() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();

        let outcome = futures::executor::block_on(async {
            crate::machine::create_machine(test_config()).await.unwrap();
            receive_sync_changes(
                r#"{"to_device_events":[{"sender":"@bob:example.org","type":"m.dummy","content":{}}],"changed_devices":{"changed":[],"left":[]},"one_time_keys_counts":{}}"#,
            )
            .await
        })
        .unwrap();

        assert_eq!(outcome.to_device_event_count, 1);
        // An `m.dummy` event carries no room key, so this call must not be
        // mistaken for one that established a session.
        assert_eq!(outcome.new_session_count, 0);
    }

    // --- Task 5: encryption and the outbound pump ---------------------

    /// A machine config pointing at `dir`, the non-leaking counterpart to
    /// this file's own `test_config()` above (which calls `TempDir::keep`
    /// deliberately, per Task 4's brief -- a trade a review already graded
    /// low and non-blocking, and not this task's to fix). These tests
    /// create real key material on disk and there are several of them, so
    /// each gets its own `TempDir` bound in the test, dropped normally --
    /// the same pattern `machine.rs`'s own `config_in` uses.
    fn config_in(dir: &std::path::Path) -> crate::machine::MachineConfig {
        crate::machine::MachineConfig {
            user_id: "@alice:example.org".to_string(),
            device_id: "DEVICE1".to_string(),
            store_path: dir.join("store").to_string_lossy().into_owned(),
            store_passphrase: Some("test-passphrase".to_string()),
        }
    }

    #[test]
    fn encrypting_produces_ciphertext_that_is_not_the_plaintext() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let envelope = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            encrypt_event(
                "!s:example.org",
                "m.room.message",
                r#"{"body":"hello","msgtype":"m.text"}"#,
            )
            .await
        })
        .unwrap();

        assert!(!envelope.ciphertext.is_empty());
        assert!(
            !String::from_utf8_lossy(&envelope.ciphertext).contains("hello"),
            "the plaintext must not survive in the ciphertext"
        );
        assert_eq!(envelope.sender, "@alice:example.org");
        assert_eq!(envelope.scope, "!s:example.org");
        assert_eq!(envelope.event_type, "m.room.message");
        assert!(
            !envelope.algorithm.is_empty(),
            "the algorithm tag must be populated"
        );
    }

    /// A scope that is not a valid identifier must be rejected before any
    /// cryptographic work happens, and as `MalformedIdentifier` rather than
    /// `MalformedPayload`: the payload this call is given here is an empty
    /// JSON object, which is perfectly well-formed, so naming the payload
    /// would send the caller to look at the wrong argument. See
    /// `SessionError::MalformedIdentifier`.
    #[test]
    fn a_malformed_scope_is_rejected() {
        let err = futures::executor::block_on(encrypt_event("nonsense", "m.room.message", "{}"))
            .unwrap_err();
        assert_eq!(err, SessionError::MalformedIdentifier);
    }

    /// This crate's own "no secret in any error" rule (spec section 7):
    /// regardless of what triggers `MalformedPayload`, the input that
    /// triggered it must not survive into the rendered error.
    #[test]
    fn an_error_never_echoes_the_input_that_caused_it() {
        let secret_like_payload = "super-secret-plaintext-marker";
        let err = futures::executor::block_on(encrypt_event(
            "not-a-valid-scope",
            "m.room.message",
            secret_like_payload,
        ))
        .unwrap_err();

        let rendered = err.to_string();
        assert!(
            !rendered.contains(secret_like_payload),
            "rendered error must not contain the input: {rendered}"
        );
        assert!(
            !rendered.contains("not-a-valid-scope"),
            "rendered error must not contain the input: {rendered}"
        );
    }

    /// A fresh machine has device keys and one-time keys nobody has seen. If
    /// the pump were decorative, this would return nothing and the device
    /// would be invisible to every other client on the homeserver.
    #[test]
    fn a_fresh_machine_has_keys_waiting_to_be_uploaded() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let requests = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            take_outgoing_requests().await
        })
        .unwrap();

        assert!(
            !requests.is_empty(),
            "a new device must have keys to publish"
        );
        assert!(requests.iter().any(|r| r.kind == "keys_upload"));
        // Every request must carry a non-empty, distinct id a caller can
        // hand back verbatim to `mark_request_sent`.
        assert!(requests.iter().all(|r| !r.id.is_empty()));
    }

    /// Parses `body` as JSON and returns its top-level `event_type` string.
    /// Test-only: lets a test decode what an `OutgoingRequest.body` actually
    /// says, the way a real product's transport code would, rather than
    /// only checking `kind` -- see
    /// `sharing_a_scope_key_delivers_the_key_only_after_a_keys_claim_round_trip`,
    /// where checking `kind` alone is exactly the gap a review found.
    fn decoded_event_type(body: &str) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| "<no event_type in body>".to_string())
    }

    /// Sharing a scope key must actually deliver the session key, not
    /// merely produce *something* to send -- design doc section 3ter. A
    /// review found this test's original form asserted only
    /// `kind == "to_device"`, which passes on an `m.room_key.withheld`
    /// notice with code `m.no_olm`: a message whose content is "I could
    /// not send you the key", not the key itself. That is exactly what
    /// `share_room_key` produces for a device this machine has learned the
    /// *identity* keys for (via `/keys/query`) but has no Olm session with
    /// yet -- which is every device, the first time, since an Olm session
    /// requires its own `/keys/claim` round trip.
    ///
    /// This test reproduces both halves of that finding as one permanent
    /// regression: share *before* any session exists and assert the
    /// withheld notice (proving the failure mode is real, and that this
    /// test would have caught it as originally written), then complete the
    /// `/keys/claim` round trip through this module's own pump and share
    /// *again*, asserting the decoded `event_type` is `m.room.encrypted` --
    /// the session key, not a notice that one could not be sent. Both
    /// round trips (`/keys/query` then `/keys/claim`) are driven through
    /// `take_outgoing_requests`/`mark_request_sent` themselves, not
    /// short-circuited, matching the M2 exit criterion that the key travel
    /// through the pump rather than being handed over directly.
    #[test]
    fn sharing_a_scope_key_delivers_the_key_only_after_a_keys_claim_round_trip() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        // Wrapped in this crate's own runtime, not a bare `block_on`: the
        // second machine constructed below is a raw `matrix-sdk-crypto`
        // `OlmMachine` this test drives directly (outside `with_machine`),
        // and `machine.rs`'s own doc comment on `with_machine` records this
        // exact mistake being made twice already in this milestone -- code
        // that only works because a test harness happened to supply an
        // ambient runtime.
        let (before_claim, after_claim) =
            futures::executor::block_on(crate::in_runtime(async move {
                crate::machine::create_machine(config_in(dir.path()))
                    .await
                    .unwrap();

                let bob_user: matrix_sdk_common::ruma::OwnedUserId =
                    "@bob:example.org".parse().unwrap();
                let bob_device: matrix_sdk_common::ruma::OwnedDeviceId = "BOBDEVICE".into();
                let bob = matrix_sdk_crypto::OlmMachine::new(&bob_user, &bob_device).await;
                let bob_upload = bob.outgoing_requests().await.unwrap();
                let bob_device_keys = bob_upload
                    .iter()
                    .find_map(|r| match r.request() {
                        AnyOutgoingRequest::KeysUpload(u) => u.device_keys.clone(),
                        _ => None,
                    })
                    .expect("a fresh machine always has device keys to upload");
                let bob_one_time_key = bob_upload
                    .iter()
                    .find_map(|r| match r.request() {
                        AnyOutgoingRequest::KeysUpload(u) => u
                            .one_time_keys
                            .iter()
                            .next()
                            .map(|(id, key)| (id.clone(), key.clone())),
                        _ => None,
                    })
                    .expect("a fresh machine always has one-time keys to upload");

                // Step 1, `/keys/query`: tell the local machine bob's device
                // list changed, so its own pump reports a real keys-query
                // request to resolve -- rather than hand-inserting one, which
                // would test response parsing alone and nothing about
                // `take_outgoing_requests` itself noticing the change.
                receive_sync_changes(&format!(
                    r#"{{"changed_devices":{{"changed":["{bob_user}"],"left":[]}}}}"#
                ))
                .await
                .unwrap();

                let query_id = take_outgoing_requests()
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|r| r.kind == "keys_query")
                    .expect("a changed device queues a keys query")
                    .id;

                let mut devices = BTreeMap::new();
                devices.insert(
                    bob_device.to_string(),
                    serde_json::to_value(&bob_device_keys).unwrap(),
                );
                let mut by_user = BTreeMap::new();
                by_user.insert(bob_user.to_string(), devices);
                let query_response = serde_json::json!({ "device_keys": by_user }).to_string();
                mark_request_sent(&query_id, &query_response).await.unwrap();

                // Share now, before any Olm session exists: this is the case
                // the review's finding 1 is about. Both `before_claim` and
                // `claim_id` are read from this one `take_outgoing_requests`
                // call, not two separate ones: `pending_claim` is drained
                // (taken, not cloned) the first time it is asked for, so a
                // second call here would find nothing left to drain and prove
                // nothing.
                share_scope_key("!s:example.org", &[bob_user.to_string()])
                    .await
                    .unwrap();
                let taken = take_outgoing_requests().await.unwrap();
                let before_claim: Vec<String> = taken
                    .iter()
                    .filter(|r| r.kind == "to_device")
                    .map(|r| decoded_event_type(&r.body))
                    .collect();

                // Step 2, `/keys/claim`: `share_scope_key` above queued the
                // request for the session it found missing; resolve it with
                // one of bob's own genuinely self-signed one-time keys.
                let claim_id = taken
                    .into_iter()
                    .find(|r| r.kind == "keys_claim")
                    .expect("sharing to a device with no session queues a keys claim")
                    .id;

                let (otk_id, otk_key) = bob_one_time_key;
                let mut otk_map = BTreeMap::new();
                otk_map.insert(otk_id.to_string(), serde_json::to_value(&otk_key).unwrap());
                let mut claim_devices = BTreeMap::new();
                claim_devices.insert(
                    bob_device.to_string(),
                    serde_json::to_value(&otk_map).unwrap(),
                );
                let mut claim_by_user = BTreeMap::new();
                claim_by_user.insert(
                    bob_user.to_string(),
                    serde_json::to_value(&claim_devices).unwrap(),
                );
                let claim_response =
                    serde_json::json!({ "one_time_keys": claim_by_user }).to_string();
                mark_request_sent(&claim_id, &claim_response).await.unwrap();

                // Step 3, `/sendToDevice`: share again, now that a session
                // exists.
                share_scope_key("!s:example.org", &[bob_user.to_string()])
                    .await
                    .unwrap();
                let after_claim: Vec<String> = take_outgoing_requests()
                    .await
                    .unwrap()
                    .into_iter()
                    .filter(|r| r.kind == "to_device")
                    .map(|r| decoded_event_type(&r.body))
                    .collect();

                (before_claim, after_claim)
            }));

        assert_eq!(
            before_claim,
            vec!["m.room_key.withheld".to_string()],
            "sharing before a session exists must be a withheld notice, not silently nothing and not the key"
        );
        // Not `assert_eq!` against a single-element vec: upstream does not
        // retract the first attempt's withheld notice just because a
        // second attempt can now succeed -- it was never marked sent, so
        // `share_room_key` still considers it pending and this second
        // `share_scope_key` call hands it out again alongside the new,
        // genuinely encrypted request, both under distinct ids (proven by
        // `queued_to_device`'s own `txn_id` keying not collapsing them into
        // one). That stale-notice accumulation is upstream's own choice,
        // not a defect this test is about; what matters here is that the
        // real key is *among* what this call produces, not that it is the
        // only thing.
        assert!(
            after_claim.contains(&"m.room.encrypted".to_string()),
            "sharing after a keys-claim round trip must deliver the session key: {after_claim:?}"
        );
    }

    /// Requests upstream hands back to its caller must leave in the order
    /// they were produced.
    ///
    /// A regression test with a specific defect behind it. `queued_action`
    /// was first a map keyed by request id, mirroring `queued_to_device`.
    /// Upstream's request ids are random, so that handed each batch out in
    /// an arbitrary order -- and unlike a shared key, a verification's
    /// messages are ordered: a confirmation is followed by the
    /// acknowledgement that closes the flow, and a far side that receives
    /// the acknowledgement first drops it and waits for one that has
    /// already been sent. The two-party verification test completed or hung
    /// depending on how two random identifiers happened to sort.
    ///
    /// The two ids below therefore sort the opposite way round from the
    /// order they are queued in: under the map this asserted `["aaaa",
    /// "zzzz"]` and failed.
    #[test]
    fn action_requests_leave_in_the_order_they_were_queued() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        fn action(txn_id: &str) -> UpstreamOutgoingRequest {
            let recipient: OwnedUserId = "@other:example.org".parse().unwrap();
            let mut request = ToDeviceRequest::new(
                &recipient,
                matrix_sdk_common::ruma::to_device::DeviceIdOrAllDevices::AllDevices,
                "m.dummy",
                Raw::from_json_string("{}".to_string()).unwrap(),
            );
            request.txn_id = <&TransactionId>::from(txn_id).to_owned();
            matrix_sdk_crypto::types::requests::OutgoingVerificationRequest::ToDevice(request)
                .into()
        }

        let handed_out = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            queue_action_request(action("zzzz"));
            queue_action_request(action("aaaa"));
            take_outgoing_requests().await.unwrap()
        });

        let ours: Vec<String> = handed_out
            .into_iter()
            .map(|request| request.id)
            .filter(|id| id == "zzzz" || id == "aaaa")
            .collect();
        assert_eq!(
            ours,
            vec!["zzzz".to_string(), "aaaa".to_string()],
            "action requests must be handed out in the order they were queued, \
             not in the order their random identifiers happen to sort"
        );
    }

    /// A request queued before the pump ran must be handed out before the
    /// requests the pump learns of while running.
    ///
    /// The companion to the test above, and the half that matters more.
    /// Ordering `queued_action` internally fixes the pair that comes out of
    /// one upstream call; it does nothing for the pair that straddles the
    /// two sources, which is the shape a verification produces whenever
    /// this side confirms first. The action below is queued first and
    /// appended to the batch last, so it can only come out first if the
    /// whole batch is ordered rather than concatenated.
    ///
    /// A fresh machine always has a key upload waiting, which is what
    /// supplies the other side of the comparison: it is real, it comes from
    /// upstream, and this module learns of it only while the pump is
    /// running -- after the action was queued.
    #[test]
    fn an_action_queued_first_is_handed_out_before_what_upstream_offers_later() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let handed_out = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            let recipient: OwnedUserId = "@other:example.org".parse().unwrap();
            let mut request = ToDeviceRequest::new(
                &recipient,
                matrix_sdk_common::ruma::to_device::DeviceIdOrAllDevices::AllDevices,
                "m.dummy",
                Raw::from_json_string("{}".to_string()).unwrap(),
            );
            request.txn_id = <&TransactionId>::from("queued-first").to_owned();
            queue_action_request(
                matrix_sdk_crypto::types::requests::OutgoingVerificationRequest::ToDevice(request)
                    .into(),
            );
            take_outgoing_requests().await.unwrap()
        });

        assert!(
            handed_out
                .iter()
                .any(|request| request.kind == "keys_upload"),
            "this test needs a request from upstream to order against: {handed_out:?}"
        );
        assert_eq!(
            handed_out.first().map(|request| request.id.as_str()),
            Some("queued-first"),
            "a request queued before the pump ran must be handed out before the \
             ones the pump learned of while running: {handed_out:?}"
        );
    }

    /// Queueing the same action twice before the pump takes it must not
    /// hand the same id out twice: the second `mark_request_sent` for it
    /// would fail with `UnknownRequest` once the first consumed the entry.
    #[test]
    fn queueing_the_same_action_twice_hands_it_out_once() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let handed_out = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            let recipient: OwnedUserId = "@other:example.org".parse().unwrap();
            for _ in 0..2 {
                let mut request = ToDeviceRequest::new(
                    &recipient,
                    matrix_sdk_common::ruma::to_device::DeviceIdOrAllDevices::AllDevices,
                    "m.dummy",
                    Raw::from_json_string("{}".to_string()).unwrap(),
                );
                request.txn_id = <&TransactionId>::from("repeated").to_owned();
                queue_action_request(
                    matrix_sdk_crypto::types::requests::OutgoingVerificationRequest::ToDevice(
                        request,
                    )
                    .into(),
                );
            }
            take_outgoing_requests().await.unwrap()
        });

        let repeats = handed_out
            .iter()
            .filter(|request| request.id == "repeated")
            .count();
        assert_eq!(
            repeats, 1,
            "the same action queued twice must be handed out once, not {repeats} times"
        );
    }

    /// An `id` this module never handed out (or already resolved) must be
    /// rejected rather than silently accepted or mistaken for "not
    /// initialised"/"failed".
    #[test]
    fn marking_an_unknown_request_as_sent_is_rejected() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let err = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            mark_request_sent("not-a-request-this-machine-issued", "{}").await
        })
        .unwrap_err();

        assert_eq!(err, SessionError::UnknownRequest);
    }

    /// Every test above already runs through bare `futures::executor::block_on`
    /// with no `#[tokio::test]` anywhere in this file, so each is already
    /// evidence for this property. This test exists anyway, self-contained
    /// and separately named, so "does Task 5's surface work with no ambient
    /// runtime" has one direct answer instead of an inference over the rest
    /// of the file -- and so it exercises the full new surface in one
    /// sequence (create, share, encrypt, take, mark), not just the one
    /// call `a_fresh_machine_has_keys_waiting_to_be_uploaded` above already
    /// covers.
    ///
    /// `#[tokio::test]` supplies a runtime that would hide a missing
    /// `with_machine`/`in_runtime` wrapping -- see `machine.rs`'s own
    /// `with_machine_supplies_a_runtime_for_store_touching_calls` for the
    /// precedent, and the design doc section 4 for why this exact mistake
    /// has already happened twice in this milestone with a green suite both
    /// times.
    #[test]
    fn the_pump_runs_with_no_ambient_tokio_runtime() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let envelope = encrypt_event("!s:example.org", "m.dummy", r#"{"body":"hi"}"#)
                .await
                .unwrap();
            assert!(!envelope.ciphertext.is_empty());

            let requests = take_outgoing_requests().await.unwrap();
            let upload = requests
                .into_iter()
                .find(|r| r.kind == "keys_upload")
                .expect("a fresh machine has a key upload to send");

            mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
                .await
                .unwrap();
        });
    }

    // --- Fix round 1: keys-claim wiring, body accuracy, dedup, redaction,
    //     bounded pending, retriable marks ---------------------------

    /// `describe_outgoing`'s own doc comment claims every body is that
    /// endpoint's real wire body except the two disclosed exceptions
    /// (`to_device`, `room_message`, both augmented with path-segment
    /// values). Proven directly, one kind at a time, by constructing each
    /// `AnyOutgoingRequest` variant by hand -- every field involved is
    /// public, so no live machine is needed. A review found two kinds did
    /// not match this claim before this fix: `signature_upload`'s body was
    /// wrapped in an extra `{"signed_keys": ...}` layer ruma's own
    /// `#[ruma_api(body)]` attribute says does not exist on the wire, and
    /// `room_message` omitted `event_type` entirely, leaving the product
    /// no way to build that endpoint's URL at all.
    ///
    /// "Every kind" means every `AnyOutgoingRequest` variant, which is what
    /// `describe_outgoing` matches on, and that is still all six. It does
    /// **not** mean every [`PendingKind`]: `signing_keys_upload` has no
    /// `AnyOutgoingRequest` variant to construct here at all, which is the
    /// reason it exists as a separate kind. Its body is asserted against a
    /// real bootstrap instead, in `tests/identity_bootstrap.rs`.
    #[test]
    fn describe_outgoing_produces_the_real_wire_body_for_every_kind() {
        // keys_upload: device_keys/one_time_keys/fallback_keys all
        // omitted, not `null`/`{}`, when absent or empty (finding 9).
        // `Request::new()` is the only public constructor a
        // `#[non_exhaustive]` ruma request type like this one has, and it
        // always gives the all-absent/all-empty case.
        let upload = matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Request::new();
        let (kind, body) = describe_outgoing(&AnyOutgoingRequest::KeysUpload(upload)).unwrap();
        assert_eq!(kind.tag(), "keys_upload");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            value.get("device_keys").is_none(),
            "device_keys must be omitted when absent: {body}"
        );
        assert!(
            value.get("one_time_keys").is_none(),
            "one_time_keys must be omitted when empty: {body}"
        );
        assert!(
            value.get("fallback_keys").is_none(),
            "fallback_keys must be omitted when empty: {body}"
        );

        // keys_query: device_keys always present, even empty (ruma's own
        // `Request` has no `skip_serializing_if` on it); timeout omitted
        // when absent. Not `#[non_exhaustive]` (it is matrix-sdk-crypto's
        // own type, not generated by ruma's request macro), so a struct
        // literal works directly.
        let query = matrix_sdk_crypto::types::requests::KeysQueryRequest {
            timeout: None,
            device_keys: BTreeMap::new(),
        };
        let (kind, body) = describe_outgoing(&AnyOutgoingRequest::KeysQuery(query)).unwrap();
        assert_eq!(kind.tag(), "keys_query");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            value.get("device_keys").is_some(),
            "device_keys must always be present, even empty: {body}"
        );
        assert!(
            value.get("timeout").is_none(),
            "timeout must be omitted when absent: {body}"
        );

        // keys_claim: `describe_keys_claim`'s own doc comment covers this;
        // proven again here through the `AnyOutgoingRequest` match arm
        // specifically, currently unreachable in practice (see
        // `PendingKind::eviction_group`'s doc comment) but
        // matched exhaustively anyway. `KeysClaimRequest::new` is the only
        // public constructor this `#[non_exhaustive]` type has, and it
        // always sets a 10-second timeout -- there is no public way to
        // build one with `timeout: None`, so only the always-present case
        // is checked directly here.
        let claim = KeysClaimRequest::new(BTreeMap::new());
        let (kind, body) = describe_outgoing(&AnyOutgoingRequest::KeysClaim(claim)).unwrap();
        assert_eq!(kind.tag(), "keys_claim");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(value.get("one_time_keys").is_some());
        assert_eq!(
            value.get("timeout").and_then(serde_json::Value::as_u64),
            Some(10_000)
        );

        // signature_upload: the wire body *is* the signed_keys map, not a
        // wrapper around it -- an empty map still proves the shape, since
        // a wrapped body would render as `{"signed_keys":{}}`, not `{}`.
        let signature =
            matrix_sdk_common::ruma::api::client::keys::upload_signatures::v3::Request::new(
                BTreeMap::new(),
            );
        let (kind, body) =
            describe_outgoing(&AnyOutgoingRequest::SignatureUpload(signature)).unwrap();
        assert_eq!(kind.tag(), "signature_upload");
        assert_eq!(
            body, "{}",
            "signed_keys is the whole body, not wrapped: {body}"
        );

        // room_message: room_id, event_type, txn_id and content all
        // present -- `event_type` is the one finding 3 found missing.
        let content: matrix_sdk_common::ruma::events::AnyMessageLikeEventContent =
            matrix_sdk_common::ruma::events::room::message::RoomMessageEventContent::text_plain(
                "hi",
            )
            .into();
        let room_message = matrix_sdk_crypto::types::requests::RoomMessageRequest {
            room_id: "!s:example.org".parse().unwrap(),
            txn_id: matrix_sdk_common::ruma::TransactionId::new(),
            content: Box::new(content),
        };
        let (kind, body) =
            describe_outgoing(&AnyOutgoingRequest::RoomMessage(Box::new(room_message))).unwrap();
        assert_eq!(kind.tag(), "room_message");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(
            value.get("room_id").and_then(|v| v.as_str()),
            Some("!s:example.org")
        );
        assert_eq!(
            value.get("event_type").and_then(|v| v.as_str()),
            Some("m.room.message"),
            "event_type must be present -- the product has no other way to build this endpoint's URL: {body}"
        );
        assert!(value.get("txn_id").is_some());
        assert!(value.get("content").is_some());
    }

    /// Calling `share_scope_key` twice for the same scope before either
    /// to-device request is marked sent must not queue the same persisted
    /// request twice. A review measured the pre-fix behaviour producing
    /// two entries with the same content and only one distinct id, so the
    /// second `mark_request_sent` for it -- there being only one real id
    /// to mark -- failed with `UnknownRequest` for what looks like a
    /// perfectly ordinary double call.
    ///
    /// Uses the same withheld-notice-before-a-session-exists setup as
    /// `sharing_a_scope_key_delivers_the_key_only_after_a_keys_claim_round_trip`
    /// above, not a full keys-claim round trip: any to-device request is
    /// subject to the same `queued_to_device` de-duplication, and a
    /// withheld notice is the cheaper one to produce.
    #[test]
    fn sharing_the_same_scope_key_twice_before_marking_does_not_duplicate_the_request() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let to_device: Vec<OutgoingRequest> =
            futures::executor::block_on(crate::in_runtime(async move {
                crate::machine::create_machine(config_in(dir.path()))
                    .await
                    .unwrap();

                let bob_user: matrix_sdk_common::ruma::OwnedUserId =
                    "@bob:example.org".parse().unwrap();
                let bob_device: matrix_sdk_common::ruma::OwnedDeviceId = "BOBDEVICE".into();
                let bob = matrix_sdk_crypto::OlmMachine::new(&bob_user, &bob_device).await;
                let bob_upload = bob.outgoing_requests().await.unwrap();
                let bob_device_keys = bob_upload
                    .iter()
                    .find_map(|r| match r.request() {
                        AnyOutgoingRequest::KeysUpload(u) => u.device_keys.clone(),
                        _ => None,
                    })
                    .expect("a fresh machine always has device keys to upload");

                receive_sync_changes(&format!(
                    r#"{{"changed_devices":{{"changed":["{bob_user}"],"left":[]}}}}"#
                ))
                .await
                .unwrap();
                let query_id = take_outgoing_requests()
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|r| r.kind == "keys_query")
                    .unwrap()
                    .id;
                let mut devices = BTreeMap::new();
                devices.insert(
                    bob_device.to_string(),
                    serde_json::to_value(&bob_device_keys).unwrap(),
                );
                let mut by_user = BTreeMap::new();
                by_user.insert(bob_user.to_string(), devices);
                mark_request_sent(
                    &query_id,
                    &serde_json::json!({ "device_keys": by_user }).to_string(),
                )
                .await
                .unwrap();

                // Two calls, same scope and users, neither result ever
                // marked sent.
                share_scope_key("!s:example.org", &[bob_user.to_string()])
                    .await
                    .unwrap();
                share_scope_key("!s:example.org", &[bob_user.to_string()])
                    .await
                    .unwrap();

                take_outgoing_requests().await
            }))
            .unwrap()
            .into_iter()
            .filter(|r| r.kind == "to_device")
            .collect();

        assert_eq!(
            to_device.len(),
            1,
            "two share_scope_key calls before marking must not duplicate the queued request: {to_device:?}"
        );
    }

    /// A request upstream re-offers keeps the position it was first given,
    /// rather than being restamped and sent to the back of a later batch.
    ///
    /// This is the arm of the stamping in `take_outgoing_requests` that
    /// reads a sequence back out of `pending`, and a previous round of this
    /// work called it unreachable. It is not: it fires for *any* unresolved
    /// request upstream offers again, and the key-sharing path produces one
    /// on its own, because `share_room_key` returns the whole persisted
    /// `to_share_with_set` on every call and so re-queues an unmarked
    /// to-device request under the same `txn_id`. That is what this drives.
    ///
    /// It also matters for verification, which is what the arm was written
    /// for: `cancel_flow` has no stage gate -- it is the one call that must
    /// work at any moment -- so a cancel queued later can share a batch with
    /// an earlier, still-unmarked key message, and the earlier one has to go
    /// first.
    ///
    /// Both halves are asserted, because the position is only meaningful if
    /// something newer is in the batch to be ahead of.
    #[test]
    fn a_request_upstream_re_offers_keeps_the_position_it_was_given() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let (first_id, second_batch): (String, Vec<OutgoingRequest>) =
            futures::executor::block_on(crate::in_runtime(async move {
                crate::machine::create_machine(config_in(dir.path()))
                    .await
                    .unwrap();

                let bob_user: matrix_sdk_common::ruma::OwnedUserId =
                    "@bob:example.org".parse().unwrap();
                let bob_device: matrix_sdk_common::ruma::OwnedDeviceId = "BOBDEVICE".into();
                let bob = matrix_sdk_crypto::OlmMachine::new(&bob_user, &bob_device).await;
                let bob_device_keys = bob
                    .outgoing_requests()
                    .await
                    .unwrap()
                    .iter()
                    .find_map(|r| match r.request() {
                        AnyOutgoingRequest::KeysUpload(u) => u.device_keys.clone(),
                        _ => None,
                    })
                    .expect("a fresh machine always has device keys to upload");

                receive_sync_changes(&format!(
                    r#"{{"changed_devices":{{"changed":["{bob_user}"],"left":[]}}}}"#
                ))
                .await
                .unwrap();
                let query_id = take_outgoing_requests()
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|r| r.kind == "keys_query")
                    .unwrap()
                    .id;
                let mut devices = BTreeMap::new();
                devices.insert(
                    bob_device.to_string(),
                    serde_json::to_value(&bob_device_keys).unwrap(),
                );
                let mut by_user = BTreeMap::new();
                by_user.insert(bob_user.to_string(), devices);
                mark_request_sent(
                    &query_id,
                    &serde_json::json!({ "device_keys": by_user }).to_string(),
                )
                .await
                .unwrap();

                // Handed out once and deliberately never marked sent, so
                // upstream still holds it and the next share re-queues the
                // same `txn_id`.
                share_scope_key("!s:example.org", &[bob_user.to_string()])
                    .await
                    .unwrap();
                let first_id = take_outgoing_requests()
                    .await
                    .unwrap()
                    .into_iter()
                    .find(|r| r.kind == "to_device")
                    .expect("sharing to a device with no session queues a withheld notice")
                    .id;

                share_scope_key("!s:example.org", &[bob_user.to_string()])
                    .await
                    .unwrap();
                let second_batch = take_outgoing_requests().await.unwrap();

                (first_id, second_batch)
            }));

        assert!(
            second_batch
                .iter()
                .any(|request| request.kind != "to_device"),
            "the second batch must carry something newer for the re-offered request to be \
             ahead of, or this asserts nothing: {second_batch:?}"
        );
        assert_eq!(
            second_batch.first().map(|request| request.id.as_str()),
            Some(first_id.as_str()),
            "a request handed out in an earlier batch and still unresolved must keep its \
             place ahead of everything stamped since: {second_batch:?}"
        );
    }

    /// A stale `keys_upload`/`keys_query`/`keys_claim` id from an earlier
    /// `take_outgoing_requests` call must not linger in `STATE.pending`
    /// forever just because it was never marked sent -- upstream mints a
    /// fresh, uncorrelated id for the same standing need on every call
    /// (see `PendingKind::eviction_group`'s own doc
    /// comment). A review measured three idle calls on a fresh machine
    /// leaving six stale entries behind with no eviction at all; this
    /// asserts the count after three calls is no larger than after one,
    /// rather than a specific number, so it does not depend on exactly
    /// which kinds an idle machine happens to report.
    #[test]
    fn a_stale_keys_upload_id_does_not_accumulate_across_repeated_calls() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let (after_one, after_three) = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();

            take_outgoing_requests().await.unwrap();
            let after_one = STATE
                .lock()
                .expect("request registry poisoned")
                .pending
                .len();

            take_outgoing_requests().await.unwrap();
            take_outgoing_requests().await.unwrap();
            let after_three = STATE
                .lock()
                .expect("request registry poisoned")
                .pending
                .len();

            (after_one, after_three)
        });

        assert_eq!(
            after_one, after_three,
            "repeated idle calls must not grow STATE.pending: {after_one} entries after one call, {after_three} after three"
        );
    }

    /// The key query a completed cross-user verification queues must survive
    /// the ordinary key queries handed out beside it and after it.
    ///
    /// [`PendingKind::PeerKeysQueryOutOfBand`] is a separate variant for
    /// exactly this, and nothing else in this crate measures it: its whole
    /// content is that it shares no eviction group with
    /// [`PendingKind::KeysQuery`], so a fresh ordinary query for an
    /// unrelated user does not throw it away while it is still in flight.
    /// Folded into `keys_query`'s group, the id below is gone by the second
    /// drain and the caller can never report the answer, which means the
    /// signature that verification produced is never read back and the
    /// person stays `Unverified` for the life of the process. That is the
    /// bug this variant exists to prevent, and this is the assertion that
    /// would notice it coming back.
    ///
    /// Driven through the real path rather than by inspecting the match: the
    /// query is queued the way `verification.rs` queues it, handed out by
    /// `take_outgoing_requests`, and then two more idle drains are performed
    /// so that upstream re-offers its own `keys_upload` and `keys_query` and
    /// the eviction really runs.
    #[test]
    fn a_key_query_owed_to_a_verified_person_survives_the_ordinary_ones() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            take_outgoing_requests().await.unwrap();

            let peer: matrix_sdk_common::ruma::OwnedUserId =
                "@somebody:example.org".parse().unwrap();
            let id = TransactionId::new();
            queue_peer_key_query(
                id.clone(),
                KeysQueryRequest {
                    timeout: None,
                    device_keys: BTreeMap::from([(peer, Vec::new())]),
                },
            );

            let handed_out = take_outgoing_requests().await.unwrap();
            assert!(
                handed_out.iter().any(|request| request.id == *id),
                "the queued query must be handed out at all, or the assertion below is \
                 about an id that never existed: {handed_out:?}"
            );
            assert!(
                handed_out
                    .iter()
                    .any(|request| request.id != *id && request.kind == "keys_query"),
                "and an ordinary key query must be handed out beside it, or nothing in \
                 this batch could evict anything: {handed_out:?}"
            );

            // Two more idle drains, each of which re-offers upstream's own
            // standing requests and therefore runs the eviction.
            take_outgoing_requests().await.unwrap();
            take_outgoing_requests().await.unwrap();

            assert!(
                STATE
                    .lock()
                    .expect("request registry poisoned")
                    .pending
                    .contains_key(&id.to_string()),
                "the query owed to the person a verification just signed must still be \
                 resolvable after ordinary key queries have come and gone"
            );
        });
    }

    /// A `mark_request_sent` call that fails (malformed `response_json`)
    /// must not remove the request from `pending` -- the caller should be
    /// able to retry the same id with corrected input. A review found the
    /// pre-fix version removed the entry unconditionally, before even
    /// attempting the mark, so a failed first attempt made every
    /// subsequent retry fail with `UnknownRequest` regardless of how
    /// well-formed the retry's own input was.
    #[test]
    fn a_failed_mark_can_be_retried_with_the_same_id() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            let upload_id = take_outgoing_requests()
                .await
                .unwrap()
                .into_iter()
                .find(|r| r.kind == "keys_upload")
                .expect("a fresh machine has a key upload to send")
                .id;

            let first = mark_request_sent(&upload_id, "not valid json at all").await;
            assert_eq!(first, Err(SessionError::MalformedPayload));

            // Same id, corrected input: must succeed, not `UnknownRequest`.
            mark_request_sent(&upload_id, r#"{"one_time_key_counts":{}}"#)
                .await
                .unwrap();
        });
    }

    /// `Envelope` and `OutgoingRequest`'s hand-written `Debug` impls must
    /// never print ciphertext, plaintext, or a user id -- the global
    /// no-secret rule extends explicitly to `Debug` output and panic
    /// messages, and a review found the derived `Debug` this replaces
    /// printed exactly these fields, including into a panic message in
    /// this file's own decisive pump test.
    #[test]
    fn envelope_and_outgoing_request_debug_output_never_contains_the_secret_fields() {
        let envelope = Envelope {
            scope: "!s:example.org".to_string(),
            algorithm: "m.megolm.v1.aes-sha2".to_string(),
            event_type: "m.room.message".to_string(),
            ciphertext: b"super-secret-ciphertext-marker".to_vec(),
            sender: "@alice:example.org".to_string(),
            // Not `Verified`, here or anywhere else in this repository's
            // tests: the type's own doc comment says why, and a fixture
            // reading `Verified` is exactly what it forbids. This value is
            // also the most useful one to see in a `{:?}`.
            sender_verification: Some(SenderVerification::MismatchedSender),
        };
        let rendered = format!("{envelope:?}");
        assert!(
            !rendered.contains("super-secret-ciphertext-marker"),
            "{rendered}"
        );
        assert!(!rendered.contains("@alice:example.org"), "{rendered}");
        // Non-secret fields still appear, so this is not just an
        // empty/panicking `Debug` impl standing in for a real one.
        assert!(rendered.contains("!s:example.org"));
        assert!(rendered.contains("m.room.message"));
        // Named, not redacted: it identifies no device, no user and no key,
        // and a redacted authenticity field would make `Debug` useless for
        // the one question this struct is hardest to answer by eye.
        assert!(rendered.contains("MismatchedSender"), "{rendered}");

        let request = OutgoingRequest {
            id: "some-transaction-id".to_string(),
            kind: "to_device".to_string(),
            body: r#"{"messages":{"@bob:example.org":{"BOBDEVICE":{"ciphertext":"secret-payload-marker"}}}}"#
                .to_string(),
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("secret-payload-marker"), "{rendered}");
        assert!(!rendered.contains("@bob:example.org"), "{rendered}");
        assert!(rendered.contains("some-transaction-id"));
        assert!(rendered.contains("to_device"));
    }

    // --- Task 6: decryption and error classification ------------------

    /// The test that matters most here: not merely that `decrypt_event`
    /// returns `Ok`, but that what comes back is the *exact* payload
    /// `encrypt_event` started from. A round trip that only checked for
    /// success would pass whether or not the cryptography did anything at
    /// all.
    ///
    /// `share_scope_key`'s own upstream call creates a matching inbound
    /// group session alongside the outbound one it shares
    /// (`matrix-sdk-crypto-0.18.0/src/session_manager/group_sessions/mod.rs`'s
    /// own doc comment on `create_outbound_group_session`: "This also
    /// creates a matching inbound group session"), which is why one
    /// machine can decrypt what it just encrypted for itself without a
    /// second device anywhere in this test.
    #[test]
    fn decrypting_recovers_the_exact_payload_encrypt_event_started_from() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        // Keys in ascending byte order, like every other JSON literal this
        // file's tests hand to `encrypt_event`: not load-bearing for
        // encryption, but it is what makes the byte-for-byte assertion
        // below meaningful without this test also having to reverse
        // whatever key order `serde_json::Value` happens to use internally.
        let payload = r#"{"body":"hello","msgtype":"m.text"}"#;

        let envelope = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", payload)
                .await
                .unwrap();

            let content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event1:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            decrypt_event("!s:example.org", &raw_event, SenderTrustRequirement::Any).await
        })
        .unwrap();

        assert_eq!(
            envelope.ciphertext,
            payload.as_bytes(),
            "the recovered plaintext must round-trip byte for byte"
        );
        assert_eq!(envelope.event_type, "m.room.message");
        assert_eq!(envelope.sender, "@alice:example.org");
        assert_eq!(envelope.scope, "!s:example.org");
        assert!(
            !envelope.algorithm.is_empty(),
            "the algorithm tag must be populated"
        );
    }

    /// The discriminating half of the round-trip test above: a decryptor
    /// that always returned success (or always the same bytes) regardless
    /// of the ciphertext would still pass a test that only checks the
    /// happy path. Flipping one character of the base64 `ciphertext`
    /// string -- same length, same alphabet -- must make decryption fail
    /// rather than silently succeed or return the wrong bytes.
    ///
    /// The flipped character is chosen a quarter of the way into the
    /// string, not the first: a vodozemac Megolm message is
    /// `version(1) || message_index || ciphertext || mac || signature`
    /// (`vodozemac-0.10.0/src/megolm/message.rs`), all base64-encoded
    /// together, so the leading few characters encode the version and
    /// ratchet-index header, not the ciphertext body. A review finding
    /// caught this by mutation: this test used to flip the *first*
    /// character, which corrupts that header and makes the whole message
    /// fail to decode as a well-formed `MegolmMessage` before any
    /// session lookup or cryptography runs at all
    /// (`event.deserialize()?`, the first line of upstream's
    /// `decrypt_room_event_inner`) -- proving only that malformed input is
    /// rejected, not that the MAC check catches tampering. A quarter of
    /// the way in falls inside the ciphertext body for any payload this
    /// test's size or larger, well clear of both the leading header and
    /// the fixed-size MAC-and-signature suffix at the end, so corrupting
    /// it can only be caught by the actual decrypt step.
    #[test]
    fn corrupting_the_ciphertext_makes_decryption_fail_rather_than_succeed_silently() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let err = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", r#"{"body":"hi"}"#)
                .await
                .unwrap();

            let mut content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            let original = content["ciphertext"]
                .as_str()
                .expect("a Megolm content always carries a ciphertext string")
                .to_string();
            // A quarter of the way into the string, not the first
            // character -- see this test's own doc comment for why.
            let mut bytes = original.into_bytes();
            let target = bytes.len() / 4;
            bytes[target] = if bytes[target] == b'A' { b'B' } else { b'A' };
            let flipped =
                String::from_utf8(bytes).expect("flipping one base64 byte stays valid UTF-8");
            content["ciphertext"] = serde_json::Value::String(flipped);

            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event2:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            decrypt_event("!s:example.org", &raw_event, SenderTrustRequirement::Any).await
        })
        .unwrap_err();

        assert_eq!(err, SessionError::Undecryptable);
    }

    /// An event referring to a session this machine has no record of at
    /// all -- the ordinary shape of "the key has not arrived yet" -- must
    /// be reported as `MissingKey`, not folded into a generic failure a
    /// product cannot act on differently from any other error.
    #[test]
    fn decrypting_an_event_for_a_session_never_shared_reports_missing_key() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let err = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", r#"{"body":"hi"}"#)
                .await
                .unwrap();

            let mut content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            assert!(
                content["session_id"].is_string(),
                "a Megolm content always carries a session_id string"
            );
            content["session_id"] =
                serde_json::Value::String("AN_UNKNOWN_SESSION_NOBODY_SHARED".to_string());

            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event3:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            decrypt_event("!s:example.org", &raw_event, SenderTrustRequirement::Any).await
        })
        .unwrap_err();

        assert_eq!(err, SessionError::MissingKey);
    }

    /// The other half of the split `MissingRoomKey` provides, and a
    /// review finding: reachable today, unlike `UnknownDevice`, through
    /// the same public surface a real sync loop uses -- feed a real
    /// `m.room_key.withheld` to-device event through `receive_sync_changes`
    /// (the machine's own `AnyToDeviceEvent` dispatch routes it to
    /// `add_withheld_info`, which records it against its `(room_id,
    /// session_id)`, per `matrix-sdk-crypto-0.18.0/src/machine/mod.rs`),
    /// then decrypt an event for that same room and session id, for which
    /// this machine has no actual inbound session. Distinct from
    /// `decrypting_an_event_for_a_session_never_shared_reports_missing_key`
    /// above only in that a withheld record now exists for the same kind
    /// of absent session, which is exactly the fact `UnsharedSession` is
    /// for.
    #[test]
    fn decrypting_an_event_for_a_withheld_session_reports_unshared_session() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let err = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();

            // A real curve25519 key, not a fabricated string: the withheld
            // content's `sender_key` must deserialize as one, and this
            // machine's own identity key is guaranteed to.
            let keys = crate::device_identity_keys("@alice:example.org", "DEVICE1")
                .await
                .unwrap();

            let withheld_session_id = "WITHHELD_SESSION_NOBODY_GOT";
            let withheld_event = serde_json::json!({
                "sender": "@bob:example.org",
                "type": "m.room_key.withheld",
                "content": {
                    "algorithm": "m.megolm.v1.aes-sha2",
                    "code": "m.unavailable",
                    "reason": "the requested key was not found",
                    "room_id": "!s:example.org",
                    "session_id": withheld_session_id,
                    "sender_key": keys.curve25519,
                },
            });
            receive_sync_changes(
                &serde_json::json!({ "to_device_events": [withheld_event] }).to_string(),
            )
            .await
            .unwrap();

            // A real content shape (borrowed from a real encrypt, then
            // repointed at the withheld session id), the same technique
            // the `MissingKey` test above uses -- so this exercises the
            // withheld-record branch specifically, not a shape rejection.
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", r#"{"body":"hi"}"#)
                .await
                .unwrap();
            let mut content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            content["session_id"] = serde_json::Value::String(withheld_session_id.to_string());

            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event5:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            decrypt_event("!s:example.org", &raw_event, SenderTrustRequirement::Any).await
        })
        .unwrap_err();

        assert_eq!(err, SessionError::UnsharedSession);
    }

    /// The half of the split `MissingRoomKey` handling that G26 in the
    /// milestone's own ledger ruled on and this change dispatches:
    /// `m.blacklisted` is not a circumstance a retry can resolve, it is the
    /// sender's own decision to refuse this device, so it must report
    /// `SessionRefused`, not `UnsharedSession`. Structured identically to
    /// `decrypting_an_event_for_a_withheld_session_reports_unshared_session`
    /// above -- same wire event shape, same real dispatch path through
    /// `receive_sync_changes` and `add_withheld_info` -- and differs only
    /// in the withheld `code`, so the contrast this pair of tests proves is
    /// the split itself, not some other difference between the two tests.
    #[test]
    fn decrypting_an_event_for_a_policy_refused_session_reports_session_refused() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let err = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();

            // A real curve25519 key, not a fabricated string: the withheld
            // content's `sender_key` must deserialize as one, and this
            // machine's own identity key is guaranteed to.
            let keys = crate::device_identity_keys("@alice:example.org", "DEVICE1")
                .await
                .unwrap();

            let withheld_session_id = "REFUSED_SESSION_NOBODY_GOT";
            let withheld_event = serde_json::json!({
                "sender": "@bob:example.org",
                "type": "m.room_key.withheld",
                "content": {
                    "algorithm": "m.megolm.v1.aes-sha2",
                    "code": "m.blacklisted",
                    "reason": "The sender has blocked you.",
                    "room_id": "!s:example.org",
                    "session_id": withheld_session_id,
                    "sender_key": keys.curve25519,
                },
            });
            receive_sync_changes(
                &serde_json::json!({ "to_device_events": [withheld_event] }).to_string(),
            )
            .await
            .unwrap();

            // A real content shape (borrowed from a real encrypt, then
            // repointed at the withheld session id), the same technique
            // the sibling `UnsharedSession` test above uses -- so this
            // exercises the withheld-record branch specifically, not a
            // shape rejection.
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", r#"{"body":"hi"}"#)
                .await
                .unwrap();
            let mut content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            content["session_id"] = serde_json::Value::String(withheld_session_id.to_string());

            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event6:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            decrypt_event("!s:example.org", &raw_event, SenderTrustRequirement::Any).await
        })
        .unwrap_err();

        assert_eq!(err, SessionError::SessionRefused);
    }

    /// The split itself, proven directly against `classify_megolm_error`
    /// rather than through the full machine the pair of tests above uses:
    /// the two policy withheld codes (`m.blacklisted`, `m.unauthorised`)
    /// must classify as the new `SessionRefused`, and the two
    /// circumstantial ones this crate names explicitly in its own doc
    /// comments (`m.unavailable`, `m.no_olm`) must still classify as
    /// `UnsharedSession`, which stays retriable. A swap of either pairing
    /// -- a policy code classified as `UnsharedSession`, or a
    /// circumstantial one moved to `SessionRefused` -- turns this test
    /// red, which is the property a fieldless, same-shaped pair of kinds
    /// cannot get from the compiler and must get from a test instead.
    #[test]
    fn a_policy_withheld_code_is_not_retriable_and_a_circumstantial_one_stays_unshared() {
        assert_eq!(
            classify_megolm_error(MegolmError::MissingRoomKey(Some(WithheldCode::Blacklisted))),
            SessionError::SessionRefused,
        );
        assert_eq!(
            classify_megolm_error(MegolmError::MissingRoomKey(Some(
                WithheldCode::Unauthorised
            ))),
            SessionError::SessionRefused,
        );

        assert_eq!(
            classify_megolm_error(MegolmError::MissingRoomKey(Some(WithheldCode::Unavailable))),
            SessionError::UnsharedSession,
        );
        assert_eq!(
            classify_megolm_error(MegolmError::MissingRoomKey(Some(WithheldCode::NoOlm))),
            SessionError::UnsharedSession,
        );
    }

    /// This crate's own "no secret in any error" rule (spec section 7),
    /// for decryption specifically: regardless of which of the five kinds
    /// a failure is classified as, no fragment of the ciphertext that
    /// caused it may survive into the rendered error. The five decryption
    /// variants of `SessionError` are fieldless with fixed literal
    /// messages precisely so this holds structurally; this test proves it
    /// rather than leaving it to be trusted by inspection, reusing the
    /// same "unknown session" shape as the `MissingKey` test above.
    #[test]
    fn no_decryption_error_carries_a_fragment_of_the_ciphertext() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let (err, ciphertext_fragment) = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();
            share_scope_key("!s:example.org", &["@alice:example.org".to_string()])
                .await
                .unwrap();
            let encrypted = encrypt_event("!s:example.org", "m.room.message", r#"{"body":"hi"}"#)
                .await
                .unwrap();

            let mut content: serde_json::Value = serde_json::from_slice(&encrypted.ciphertext)
                .expect("encrypt_event's own ciphertext is well-formed JSON");
            let ciphertext_fragment = content["ciphertext"]
                .as_str()
                .expect("a Megolm content always carries a ciphertext string")[..16]
                .to_string();
            content["session_id"] =
                serde_json::Value::String("AN_UNKNOWN_SESSION_NOBODY_SHARED".to_string());

            let raw_event = serde_json::json!({
                "sender": encrypted.sender,
                "event_id": "$event4:example.org",
                "origin_server_ts": 1_700_000_000_000u64,
                "content": content,
            })
            .to_string();

            let err = decrypt_event("!s:example.org", &raw_event, SenderTrustRequirement::Any)
                .await
                .unwrap_err();
            (err, ciphertext_fragment)
        });

        assert_eq!(err, SessionError::MissingKey);
        let rendered = err.to_string();
        assert!(
            !rendered.contains(&ciphertext_fragment),
            "rendered error must not contain a fragment of the ciphertext: {rendered}"
        );
        assert!(!rendered.contains("ciphertext"));
        assert!(!rendered.contains("!s:example.org"));
    }

    /// A malformed `raw_json` must be rejected before any cryptographic
    /// work happens, the same precondition `a_malformed_scope_is_rejected`
    /// already asserts for `encrypt_event`.
    #[test]
    fn malformed_raw_json_is_rejected_before_any_decryption_is_attempted() {
        let err = futures::executor::block_on(decrypt_event(
            "!s:example.org",
            "{oops",
            SenderTrustRequirement::Any,
        ))
        .unwrap_err();
        assert_eq!(err, SessionError::MalformedPayload);
    }

    /// Mirrors `a_malformed_scope_is_rejected`: an invalid scope must be
    /// rejected before this function ever reaches the machine, for
    /// `decrypt_event` exactly as for `encrypt_event`, and with the same
    /// kind.
    #[test]
    fn a_malformed_scope_is_rejected_for_decryption_too() {
        let err = futures::executor::block_on(decrypt_event(
            "nonsense",
            "{}",
            SenderTrustRequirement::Any,
        ))
        .unwrap_err();
        assert_eq!(err, SessionError::MalformedIdentifier);
    }

    /// The distinction the two kinds exist for, asserted as one thing so it
    /// cannot be half-reverted: one call, given a bad scope with a good
    /// payload and then a good scope with a bad payload, must report two
    /// different kinds. Collapsing them again fails here rather than being
    /// discovered by a consumer sent to inspect the wrong argument.
    #[test]
    fn a_bad_scope_and_a_bad_payload_are_told_apart() {
        let bad_scope = futures::executor::block_on(decrypt_event(
            "nonsense",
            "{}",
            SenderTrustRequirement::Any,
        ))
        .unwrap_err();
        let bad_payload = futures::executor::block_on(decrypt_event(
            "!s:example.org",
            "{oops",
            SenderTrustRequirement::Any,
        ))
        .unwrap_err();

        assert_eq!(bad_scope, SessionError::MalformedIdentifier);
        assert_eq!(bad_payload, SessionError::MalformedPayload);
        assert_ne!(bad_scope, bad_payload);
    }

    // --- Fix round 1: sharing tracks the users it was given -----------

    /// The property that makes every later step reachable at all, and the
    /// one nothing on this surface could do before: naming a user in
    /// `share_scope_key` must make the pump ask the homeserver who that
    /// user's devices are.
    ///
    /// Upstream only issues a `/keys/query` for a user it is *tracking* --
    /// `mark_tracked_users_as_changed` (store/mod.rs:291) opens with
    /// `if tracked_users.contains(user_id)` and silently skips everyone
    /// else -- and a sync's `changed_devices` list routes nowhere but
    /// there. So before `share_scope_key` tracked its users, a product
    /// could name a brand-new user here forever and the pump would keep
    /// handing out upstream's own-user fallback query instead: encrypting
    /// to nobody, with no error anywhere. A review found this while
    /// checking why `tests/two_parties.rs` needed a back door to set the
    /// precondition; the back door is gone and this asserts the shipped
    /// behaviour that replaced it.
    ///
    /// Asserts on the parsed `device_keys` keys, not on a substring of the
    /// body: those keys *are* the set of users the request asks about, and
    /// a structural check survives a body-shape change upstream that a
    /// substring match would silently keep passing.
    #[test]
    fn sharing_a_scope_key_makes_the_pump_ask_about_the_users_it_was_given() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        reset_request_state_for_test();
        let dir = tempfile::tempdir().unwrap();

        let queried: Vec<String> = futures::executor::block_on(async {
            crate::machine::create_machine(config_in(dir.path()))
                .await
                .unwrap();

            // A user this machine has never seen, named here for the
            // first time.
            share_scope_key("!s:example.org", &["@bob:example.org".to_string()])
                .await
                .unwrap();

            let query = take_outgoing_requests()
                .await
                .unwrap()
                .into_iter()
                .find(|r| r.kind == "keys_query")
                .expect("naming a user must queue a query for that user");

            serde_json::from_str::<serde_json::Value>(&query.body)
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
        });

        assert!(
            queried.iter().any(|user| user == "@bob:example.org"),
            "share_scope_key must make the users it was given queryable -- \
             nothing else on this crate's surface can"
        );
    }
}
