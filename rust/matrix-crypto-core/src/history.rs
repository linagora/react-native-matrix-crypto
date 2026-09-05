//! Handing a room's past to somebody who was not there for it.
//!
//! # The problem this exists for
//!
//! Megolm gives a room's members the keys to messages sent *while they were
//! members*. Someone invited today is cryptographically unable to read
//! yesterday, and that is not a defect: it is the property that makes a
//! room's history worth something. It is also, for a product where people
//! are vouched for and brought in one at a time, the thing that makes an
//! invitation feel like a locked door rather than an introduction.
//!
//! [MSC4268] is the protocol's answer. The inviter assembles the room keys
//! they already hold into a *bundle*, encrypts it, uploads it to the media
//! repository, and tells the invitee where it is over an Olm-encrypted
//! to-device message. The invitee fetches it, decrypts it, and imports the
//! sessions. No server ever holds a key it can use.
//!
//! # What upstream gives, and what this module had to write
//!
//! `matrix-sdk-crypto` 0.18 already implements every cryptographic step:
//! `Store::build_room_key_bundle` assembles it,
//! `OlmMachine::share_room_key_bundle_data` encrypts the announcement to the
//! recipient's devices, the ordinary to-device decryption path records an
//! arriving announcement, and `Store::receive_room_key_bundle` imports it.
//! None of that is exposed to a React Native product, and that exposure is
//! all this module is.
//!
//! # This library still performs no request
//!
//! The bundle has to travel through the media repository, and this crate
//! issues no HTTP -- the same rule `recovery.rs` works under. So the split
//! is: this module produces the bundle's bytes and the product uploads
//! them; this module says where an offered bundle lives and the product
//! downloads it. Encryption of the file itself is the product's, because
//! it is ordinary Matrix attachment encryption rather than anything Megolm
//! knows about.
//!
//! That makes the sending half two calls with the product's own work in
//! between, and the ordering is not negotiable: [`build_history_bundle`],
//! then upload, then [`share_history_bundle`]. Announcing a location
//! nothing has been uploaded to yet gives the invitee a URL that 404s and
//! no second chance, because the announcement is not repeated.
//!
//! # What a caller must understand before using this at all
//!
//! **Sharing history cannot be undone.** A key handed over is a key the
//! other device keeps; there is no revocation, no expiry, and no way to
//! narrow it afterwards. It is also not a room-level act but a
//! person-level one: it names one recipient, and it hands them everything
//! this account can decrypt in that room, from the room's beginning.
//!
//! So the surface is shaped to make an accidental call hard rather than
//! convenient. [`build_history_bundle`] reports *how many* sessions the
//! bundle carries before anything has left the device, so a product can put
//! a number in front of a person instead of a verb. And the two halves are
//! separate calls, so "share the history" is never a thing that happens as
//! a side effect of something else.
//!
//! [MSC4268]: https://github.com/matrix-org/matrix-spec-proposals/pull/4268

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use matrix_sdk_common::ruma::events::room::EncryptedFile;
use matrix_sdk_crypto::olm::SenderData;
use matrix_sdk_crypto::types::events::room_key_bundle::RoomKeyBundleContent;
use matrix_sdk_crypto::types::room_history::RoomKeyBundle;

use crate::machine::{with_machine, MachineError};
use crate::session::{collect_strategy, parse_scope, parse_user, queue_to_device_requests};

/// What went wrong, at the granularity a product can act on.
///
/// Fieldless, like every other error in this crate: what an identifier or
/// a payload contained is caller-supplied content this library does not
/// carry back across the boundary.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HistoryError {
    /// A `scope` or user id handed to this call is not a parseable
    /// identifier.
    #[error("an identifier could not be parsed")]
    MalformedIdentifier,
    /// The encrypted-file description, or the bundle itself, did not parse
    /// into the shape this function accepts.
    #[error("the payload could not be parsed")]
    MalformedPayload,
    /// No crypto machine has been created yet.
    #[error("no crypto machine has been created")]
    NotInitialised,
    /// The crypto store failed, or the machine refused the operation.
    #[error("the crypto operation failed")]
    Failed,
    /// [`receive_history_bundle`] was called for a sender who has offered
    /// this device no bundle for this room.
    ///
    /// Distinct from an empty import: nothing was refused, because there
    /// was nothing to refuse. A product that reaches this has either
    /// mistaken the sender or run ahead of the announcement, which has not
    /// arrived yet or has not been fed through `receive_sync_changes`.
    #[error("no bundle has been offered by that sender for that scope")]
    NoOffer,
    /// The bundle's sender is not trusted enough for its keys to be
    /// imported, and importing it would achieve nothing.
    ///
    /// This exists because upstream's own answer here is `Ok(())`. A bundle
    /// from a device this account cannot attribute is dropped with a log
    /// line and a success return, which from inside this process is
    /// indistinguishable from an import that worked -- the same shape of
    /// silent failure `share_scope_key`'s doc comment calls out for
    /// `m.no_olm`. The condition is therefore checked here, before the
    /// call, so it can be reported as the refusal it is.
    ///
    /// Upstream accepts a sender whose device is TOFU-trusted
    /// (`SenderData::SenderUnverified`) or fully verified
    /// (`SenderData::SenderVerified`); everything weaker, including a
    /// device known only by its keys and one whose owner's identity has
    /// changed, is refused.
    #[error("the sender is not trusted enough for this bundle to be imported")]
    SenderNotTrusted,
}

impl From<MachineError> for HistoryError {
    fn from(_error: MachineError) -> Self {
        HistoryError::NotInitialised
    }
}

impl From<crate::session::SessionError> for HistoryError {
    /// Only the two parsers are borrowed from `session.rs`, and both
    /// produce `MalformedIdentifier`; the catch-all is there so this
    /// conversion is total rather than a `match` that could stop being.
    fn from(error: crate::session::SessionError) -> Self {
        match error {
            crate::session::SessionError::MalformedIdentifier => HistoryError::MalformedIdentifier,
            _ => HistoryError::Failed,
        }
    }
}

/// A room's history, assembled and ready to be encrypted and uploaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryBundle {
    /// The bundle itself, as JSON, to be encrypted and uploaded by the
    /// product exactly as it stands.
    ///
    /// **This is key material in clear.** It must not be written to disk,
    /// logged, or sent anywhere but an encrypted upload.
    pub json: String,
    /// How many Megolm sessions this bundle hands over.
    ///
    /// The number to put in front of a person before they commit to an
    /// irreversible act. Zero is an ordinary answer for a room nothing has
    /// been said in yet, and is not an error.
    pub shared: u32,
    /// How many sessions were deliberately left out.
    ///
    /// Upstream excludes any session not flagged as shareable history --
    /// one created while the room's history visibility meant "members
    /// only from here on". The recipient is told these exist, so their
    /// client can say "this part was not shared" rather than showing an
    /// unexplained gap.
    pub withheld: u32,
}

/// Where a bundle somebody has offered this device can be fetched from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryOffer {
    /// The `EncryptedFile` description, as JSON: the MXC URI to download
    /// and the key to decrypt what comes back.
    pub file_json: String,
}

/// What an import actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryImport {
    /// How many sessions the bundle offered.
    pub offered: u32,
    /// How many were imported.
    ///
    /// Lower than `offered` when the bundle carried keys for a different
    /// room, which upstream discards. Both being zero is an empty bundle,
    /// not a failure -- a refusal is [`HistoryError::SenderNotTrusted`],
    /// which never gets this far.
    pub imported: u32,
}

/// Assembles every room key this account holds for `scope` into a bundle
/// for a single recipient.
///
/// Nothing leaves the device. The result is the plaintext to encrypt and
/// upload; [`share_history_bundle`] is the call that tells anybody about
/// it, and it must not be made until the upload has succeeded.
///
/// Cheap to call and free of side effects, which is deliberate: a product
/// can build the bundle purely to show its size, and abandon it.
pub async fn build_history_bundle(scope: &str) -> Result<HistoryBundle, HistoryError> {
    let room_id = parse_scope(scope)?;

    let bundle = with_machine(move |machine| {
        Box::pin(async move { machine.store().build_room_key_bundle(&room_id).await })
    })
    .await?
    .map_err(|_upstream| HistoryError::Failed)?;

    let shared = bundle.room_keys.len() as u32;
    let withheld = bundle.withheld.len() as u32;
    let json = serde_json::to_string(&bundle).map_err(|_upstream| HistoryError::Failed)?;

    Ok(HistoryBundle {
        json,
        shared,
        withheld,
    })
}

/// Tells `user`'s devices where the uploaded bundle for `scope` is.
///
/// `file_json` is the `EncryptedFile` the upload produced -- the MXC URI,
/// the key, the hashes -- serialised as JSON. It is announced over
/// Olm-encrypted to-device messages, so the location and the decryption key
/// never reach the homeserver in clear.
///
/// The requests are queued for `take_outgoing_requests` like every other
/// outbound message this library produces; this call sends nothing itself,
/// and the announcement has not been made until the product has pumped and
/// acknowledged them.
///
/// The recipient's devices are chosen by the same rule that decides who
/// gets a live room key, [`collect_strategy`] -- see its doc comment for
/// why the two must not answer differently.
///
/// **Announcing twice is not free.** Each call encrypts and queues a fresh
/// message to every one of the recipient's devices. Upstream deduplicates
/// nothing here, and neither does the queue, whose key is the transaction
/// id this call mints.
pub async fn share_history_bundle(
    scope: &str,
    user: &str,
    file_json: &str,
) -> Result<(), HistoryError> {
    let room_id = parse_scope(scope)?;
    let user_id = parse_user(user)?;
    let file: EncryptedFile =
        serde_json::from_str(file_json).map_err(|_upstream| HistoryError::MalformedPayload)?;

    let requests = with_machine(move |machine| {
        Box::pin(async move {
            let strategy = collect_strategy(machine).await;
            let content = RoomKeyBundleContent { room_id, file };
            machine
                .share_room_key_bundle_data(&user_id, &strategy, content)
                .await
        })
    })
    .await?
    .map_err(|_upstream| HistoryError::Failed)?;

    queue_to_device_requests(requests.into_iter().map(Arc::new));

    Ok(())
}

/// Reports whether `sender` has offered this device a bundle for `scope`,
/// and if so where it is.
///
/// The announcement arrives as an ordinary to-device event and is recorded
/// by `receive_sync_changes` like everything else, so this is a read of
/// what has already been ingested rather than anything that waits.
///
/// `None` means no announcement has been recorded. It does not mean none
/// was sent: the sync carrying it may not have been fed in yet.
pub async fn offered_history_bundle(
    scope: &str,
    sender: &str,
) -> Result<Option<HistoryOffer>, HistoryError> {
    let room_id = parse_scope(scope)?;
    let user_id = parse_user(sender)?;

    let stored = with_machine(move |machine| {
        Box::pin(async move {
            machine
                .store()
                .get_received_room_key_bundle_data(&room_id, &user_id)
                .await
        })
    })
    .await?
    .map_err(|_upstream| HistoryError::Failed)?;

    stored
        .map(|data| {
            serde_json::to_string(&data.bundle_data.file)
                .map(|file_json| HistoryOffer { file_json })
                .map_err(|_upstream| HistoryError::Failed)
        })
        .transpose()
}

/// Imports a downloaded and decrypted bundle, and reports what landed.
///
/// `bundle_json` is the plaintext recovered from the file
/// [`offered_history_bundle`] pointed at. The announcement it belongs to
/// must already have been ingested, because that announcement -- not this
/// argument -- is what says who sent the bundle and which device's keys
/// signed it; a bundle handed to this call without one is refused with
/// [`HistoryError::NoOffer`] rather than trusted on its own say-so.
///
/// The sender's trustworthiness is checked before the import rather than
/// left to upstream, which drops an untrusted bundle and returns success.
/// See [`HistoryError::SenderNotTrusted`].
pub async fn receive_history_bundle(
    scope: &str,
    sender: &str,
    bundle_json: &str,
) -> Result<HistoryImport, HistoryError> {
    let room_id = parse_scope(scope)?;
    let user_id = parse_user(sender)?;
    let bundle: RoomKeyBundle =
        serde_json::from_str(bundle_json).map_err(|_upstream| HistoryError::MalformedPayload)?;
    let offered = bundle.room_keys.len() as u32;

    // Counted through upstream's own progress callback rather than by
    // re-deriving which keys it will accept. Upstream discards keys naming
    // a different room than the announcement did, and a copy of that rule
    // here would be a second place for it to be written and a first place
    // for it to go stale.
    let imported = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&imported);

    with_machine(move |machine| {
        Box::pin(async move {
            let store = machine.store();
            let Some(data) = store
                .get_received_room_key_bundle_data(&room_id, &user_id)
                .await
                .map_err(|_upstream| HistoryError::Failed)?
            else {
                return Err(HistoryError::NoOffer);
            };

            if !matches!(
                data.sender_data,
                SenderData::SenderUnverified(_) | SenderData::SenderVerified(_)
            ) {
                return Err(HistoryError::SenderNotTrusted);
            }

            store
                .receive_room_key_bundle(&data, bundle, |_current, _total| {
                    counter.fetch_add(1, Ordering::Relaxed);
                })
                .await
                .map_err(|_upstream| HistoryError::Failed)
        })
    })
    .await??;

    Ok(HistoryImport {
        offered,
        imported: imported.load(Ordering::Relaxed),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every call validates its own arguments before it reaches for the
    /// machine, and these tests depend on that: they assert an answer that
    /// must not vary with whether some other test in this binary has
    /// created a machine. A call that started touching the machine first
    /// would fail here as `NotInitialised` -- or pass and fail elsewhere,
    /// depending on test order, which is the reason to pin it.
    const BAD_SCOPE: &str = "not-a-valid-scope";
    const BAD_USER: &str = "not-a-valid-user";
    const GOOD_SCOPE: &str = "!scope:example.org";
    const GOOD_USER: &str = "@entrant:example.org";

    #[test]
    fn an_unparseable_scope_is_an_identifier_fault_in_every_call() {
        for error in [
            futures::executor::block_on(build_history_bundle(BAD_SCOPE)).unwrap_err(),
            futures::executor::block_on(share_history_bundle(BAD_SCOPE, GOOD_USER, "{}"))
                .unwrap_err(),
            futures::executor::block_on(offered_history_bundle(BAD_SCOPE, GOOD_USER)).unwrap_err(),
            futures::executor::block_on(receive_history_bundle(BAD_SCOPE, GOOD_USER, "{}"))
                .unwrap_err(),
        ] {
            assert_eq!(error, HistoryError::MalformedIdentifier);
        }
    }

    #[test]
    fn an_unparseable_user_is_an_identifier_fault_too() {
        for error in [
            futures::executor::block_on(share_history_bundle(GOOD_SCOPE, BAD_USER, "{}"))
                .unwrap_err(),
            futures::executor::block_on(offered_history_bundle(GOOD_SCOPE, BAD_USER)).unwrap_err(),
            futures::executor::block_on(receive_history_bundle(GOOD_SCOPE, BAD_USER, "{}"))
                .unwrap_err(),
        ] {
            assert_eq!(error, HistoryError::MalformedIdentifier);
        }
    }

    /// The distinction `SessionError::MalformedIdentifier` was split out to
    /// make, kept here: a caller whose file description is malformed is not
    /// sent to inspect a scope that was fine.
    #[test]
    fn a_file_description_that_is_not_one_is_a_payload_fault() {
        let error =
            futures::executor::block_on(share_history_bundle(GOOD_SCOPE, GOOD_USER, "not json"))
                .unwrap_err();
        assert_eq!(error, HistoryError::MalformedPayload);
    }

    #[test]
    fn a_bundle_that_is_not_one_is_a_payload_fault() {
        let error =
            futures::executor::block_on(receive_history_bundle(GOOD_SCOPE, GOOD_USER, "not json"))
                .unwrap_err();
        assert_eq!(error, HistoryError::MalformedPayload);
    }

    /// A well-formed JSON document of the wrong shape is still a payload
    /// fault rather than something exotic. This is the likelier mistake of
    /// the two: a product that hands `receive_history_bundle` the *offer*
    /// it downloaded rather than the plaintext inside it passes valid JSON.
    #[test]
    fn json_of_the_wrong_shape_is_refused_as_a_payload() {
        let error = futures::executor::block_on(share_history_bundle(
            GOOD_SCOPE,
            GOOD_USER,
            r#"{"not":"an encrypted file"}"#,
        ))
        .unwrap_err();
        assert_eq!(error, HistoryError::MalformedPayload);
    }

    /// This crate's "no secret in any error" rule, applied to the one
    /// surface whose payload is key material in clear.
    #[test]
    fn an_error_never_echoes_the_bundle_that_caused_it() {
        let secret_like_bundle = "super-secret-session-key-marker";
        let rendered = futures::executor::block_on(receive_history_bundle(
            GOOD_SCOPE,
            GOOD_USER,
            secret_like_bundle,
        ))
        .unwrap_err()
        .to_string();

        assert!(
            !rendered.contains(secret_like_bundle),
            "rendered error must not contain the bundle: {rendered}"
        );
    }

    /// The two kinds a product acts on differently must not collapse into
    /// each other through the conversion `session.rs`'s parsers arrive by.
    #[test]
    fn the_session_conversion_keeps_an_identifier_fault_an_identifier_fault() {
        assert_eq!(
            HistoryError::from(crate::session::SessionError::MalformedIdentifier),
            HistoryError::MalformedIdentifier
        );
        assert_eq!(
            HistoryError::from(crate::session::SessionError::MalformedPayload),
            HistoryError::Failed
        );
    }
}
