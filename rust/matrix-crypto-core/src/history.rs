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
//! `Store::build_room_key_bundle` assembles it, `AttachmentEncryptor` and
//! `AttachmentDecryptor` encrypt and decrypt the file,
//! `OlmMachine::share_room_key_bundle_data` encrypts the announcement to the
//! recipient's devices, the ordinary to-device decryption path records an
//! arriving announcement, and `Store::receive_room_key_bundle` imports it.
//! None of that is exposed to a React Native product, and that exposure is
//! all this module is.
//!
//! # This library still performs no request, and still holds the keys
//!
//! The bundle has to travel through the media repository, and this crate
//! issues no HTTP -- the same rule `recovery.rs` works under. So the product
//! uploads and downloads.
//!
//! **It does not encrypt.** That split was tried the other way round first,
//! with [`build_history_bundle`] returning the bundle in clear for the
//! product to encrypt itself, and consuming it is what showed the mistake: a
//! React Native product has no AES and no SHA-256 to hand, so the API was
//! an instruction to implement Matrix's attachment encryption in JavaScript,
//! on Hermes, correctly, in order to protect *every room key this account
//! holds*. The one place in this system that already links AES and SHA-256
//! is this crate. So it does it, and what crosses the boundary is
//! ciphertext.
//!
//! What that buys, precisely: on the sending side the product handles an
//! opaque secret it must pass back and never store, and on the receiving
//! side it handles no key material at all -- the key came in the
//! announcement, which this library already holds.
//!
//! The sending half is therefore two calls with the product's upload in
//! between, and the ordering is not negotiable: [`build_history_bundle`],
//! then upload, then [`share_history_bundle`]. Announcing a location nothing
//! has been uploaded to yet gives the invitee a URL that 404s and no second
//! chance, because the announcement is not repeated.
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

use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use matrix_sdk_common::ruma::events::room::EncryptedFile;
use matrix_sdk_common::ruma::OwnedMxcUri;
use matrix_sdk_crypto::olm::SenderData;
use matrix_sdk_crypto::types::events::room_key_bundle::RoomKeyBundleContent;
use matrix_sdk_crypto::types::room_history::RoomKeyBundle;
use matrix_sdk_crypto::{AttachmentDecryptor, AttachmentEncryptor, MediaEncryptionInfo};

use crate::machine::{with_machine, MachineError};
use crate::session::{collect_strategy, parse_scope, parse_user, queue_to_device_requests};

/// What went wrong, at the granularity a product can act on.
///
/// Fieldless, like every other error in this crate: what an identifier or
/// a payload contained is caller-supplied content this library does not
/// carry back across the boundary.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HistoryError {
    /// A `scope`, user id, or upload location handed to this call is not a
    /// parseable identifier.
    #[error("an identifier could not be parsed")]
    MalformedIdentifier,
    /// The opaque secret handed back to [`share_history_bundle`] is not one
    /// this library produced.
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
    /// The downloaded bytes are not the bundle the announcement described.
    ///
    /// Either they will not decrypt under the key the announcement carried,
    /// or they decrypt and their SHA-256 is not the one the announcement
    /// promised, or what comes out is not a bundle. Kept apart from
    /// [`MalformedPayload`](Self::MalformedPayload) because the diagnosis is
    /// somebody else's: the caller's arguments were fine, and what is wrong
    /// is the file that came back -- a download that fetched an error page,
    /// a truncated body, or bytes that were altered in the repository.
    #[error("the downloaded bundle is not the one that was announced")]
    BundleUnreadable,
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

/// A room's history, encrypted and ready to upload.
///
/// No `Debug` derive, for the reason [`RecoverySetup`](crate::RecoverySetup)
/// gives: [`secret`](Self::secret) is the key to every room key this account
/// holds for the scope, and a derived `Debug` leaves it a single `{:?}` away
/// from a log. The field's own comment asks a caller not to log it; this is
/// what stops the type from doing it for them.
///
/// The doctest below is the guard, taking the trait bound directly rather
/// than building a value: a `compile_fail` block passes on any compiler
/// error, so a snippet naming the fields could keep passing after `Debug`
/// returns, on an error nobody intended. Naming only the type leaves the
/// missing impl as the sole possible error.
///
/// ```compile_fail
/// fn requires_debug<T: std::fmt::Debug>() {}
///
/// requires_debug::<matrix_crypto_core::HistoryBundle>();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct HistoryBundle {
    /// The encrypted bundle. Upload these bytes verbatim.
    ///
    /// There is no key in here and nothing to protect beyond the ordinary
    /// care an upload deserves: the key that opens it is in
    /// [`secret`](Self::secret).
    pub ciphertext: Vec<u8>,
    /// Opaque. Hand it back to [`share_history_bundle`] unchanged, once the
    /// upload has succeeded.
    ///
    /// **It contains the key that decrypts the bundle**, which is to say the
    /// key to every room key this account holds for that scope. It is
    /// deliberately opaque rather than structured, because a caller has no
    /// reason to read it and every reason not to keep it: do not log it, do
    /// not write it to disk, and drop it once the announcement is made.
    pub secret: String,
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
    /// The `mxc://` URI to download.
    ///
    /// Only the location. The key that opens what comes back arrived in the
    /// same announcement and stays in this library, which is why
    /// [`receive_history_bundle`] takes the downloaded bytes and not a key.
    pub url: String,
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
/// for a single recipient, and encrypts it.
///
/// Nothing leaves the device. The result is ciphertext to upload and a
/// secret to hand back; [`share_history_bundle`] is the call that tells
/// anybody about it, and it must not be made until the upload has
/// succeeded.
///
/// Cheap to call and free of side effects, which is deliberate: a product
/// can build the bundle purely to show its size, and abandon it. Two calls
/// produce two different keys and two different ciphertexts for the same
/// history, which costs nothing here -- the discarded one was never
/// announced, so nobody can fetch it and nobody holds its key.
pub async fn build_history_bundle(scope: &str) -> Result<HistoryBundle, HistoryError> {
    let room_id = parse_scope(scope)?;

    let bundle = with_machine(move |machine| {
        Box::pin(async move { machine.store().build_room_key_bundle(&room_id).await })
    })
    .await?
    .map_err(|_upstream| HistoryError::Failed)?;

    let shared = bundle.room_keys.len() as u32;
    let withheld = bundle.withheld.len() as u32;

    let plaintext = serde_json::to_vec(&bundle).map_err(|_upstream| HistoryError::Failed)?;
    let mut source = Cursor::new(plaintext);
    let mut encryptor = AttachmentEncryptor::new(&mut source);
    let mut ciphertext = Vec::new();
    encryptor
        .read_to_end(&mut ciphertext)
        .map_err(|_upstream| HistoryError::Failed)?;
    let secret =
        serde_json::to_string(&encryptor.finish()).map_err(|_upstream| HistoryError::Failed)?;

    Ok(HistoryBundle {
        ciphertext,
        secret,
        shared,
        withheld,
    })
}

/// Tells `user`'s devices where the uploaded bundle for `scope` is, and how
/// to open it.
///
/// `url` is the `mxc://` URI the upload returned. `secret` is
/// [`HistoryBundle::secret`], handed back unchanged. The two are joined here
/// into the announcement, which travels over Olm-encrypted to-device
/// messages, so neither the location nor the key reaches the homeserver in
/// clear.
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
    url: &str,
    secret: &str,
) -> Result<(), HistoryError> {
    let room_id = parse_scope(scope)?;
    let user_id = parse_user(user)?;

    let location = OwnedMxcUri::from(url);
    if !location.is_valid() {
        return Err(HistoryError::MalformedIdentifier);
    }

    // Rebuilt through serde rather than a struct literal, because ruma marks
    // `EncryptedFile` `#[non_exhaustive]` and this crate is not ruma. That is
    // not a workaround so much as the shape the type already has: the secret
    // *is* the serialised `MediaEncryptionInfo`, whose two fields flatten
    // into exactly the file description minus its location, so adding `url`
    // to the object it deserialises from is the whole conversion.
    let mut described: serde_json::Value =
        serde_json::from_str(secret).map_err(|_upstream| HistoryError::MalformedPayload)?;
    let Some(fields) = described.as_object_mut() else {
        return Err(HistoryError::MalformedPayload);
    };
    fields.insert("url".to_owned(), serde_json::Value::String(url.to_owned()));
    let file: EncryptedFile =
        serde_json::from_value(described).map_err(|_upstream| HistoryError::MalformedPayload)?;

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
/// and if so where to fetch it.
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

    Ok(stored.map(|data| HistoryOffer {
        url: data.bundle_data.file.url.to_string(),
    }))
}

/// Decrypts and imports a bundle the product has downloaded, and reports
/// what landed.
///
/// `ciphertext` is the file [`offered_history_bundle`] pointed at, exactly
/// as it came back. The key that opens it is not a parameter: it arrived in
/// the announcement, which this library recorded, so a product that
/// downloads bytes has everything it needs and never handles key material.
///
/// The announcement must already have been ingested for the same reason it
/// carries the key -- it is also what says who sent the bundle and which
/// device signed it. A download handed to this call without one is refused
/// with [`HistoryError::NoOffer`] rather than trusted on its own say-so.
///
/// The sender's trustworthiness is checked before the bundle is even
/// decrypted, both because it is cheaper and because upstream's own check
/// drops an untrusted bundle and returns success. See
/// [`HistoryError::SenderNotTrusted`].
pub async fn receive_history_bundle(
    scope: &str,
    sender: &str,
    ciphertext: &[u8],
) -> Result<HistoryImport, HistoryError> {
    let room_id = parse_scope(scope)?;
    let user_id = parse_user(sender)?;
    let downloaded = ciphertext.to_vec();

    // Counted through upstream's own progress callback rather than by
    // re-deriving which keys it will accept. Upstream discards keys naming
    // a different room than the announcement did, and a copy of that rule
    // here would be a second place for it to be written and a first place
    // for it to go stale.
    let imported = Arc::new(AtomicU32::new(0));
    let counter = Arc::clone(&imported);

    let offered = with_machine(move |machine| {
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

            // The key and the expected hash both come from the
            // announcement rather than from the caller, which is what
            // makes a swapped or altered download fail here instead of
            // being imported. `read_to_end` is where the SHA-256 is
            // checked, so the error it can return is not merely an I/O
            // one and must not be treated as such.
            let info: MediaEncryptionInfo = data.bundle_data.file.clone().into();
            let mut source = Cursor::new(downloaded);
            let mut decryptor = AttachmentDecryptor::new(&mut source, info)
                .map_err(|_upstream| HistoryError::BundleUnreadable)?;
            let mut plaintext = Vec::new();
            decryptor
                .read_to_end(&mut plaintext)
                .map_err(|_upstream| HistoryError::BundleUnreadable)?;

            let bundle: RoomKeyBundle = serde_json::from_slice(&plaintext)
                .map_err(|_upstream| HistoryError::BundleUnreadable)?;
            let offered = bundle.room_keys.len() as u32;

            store
                .receive_room_key_bundle(&data, bundle, |_current, _total| {
                    counter.fetch_add(1, Ordering::Relaxed);
                })
                .await
                .map_err(|_upstream| HistoryError::Failed)?;

            Ok(offered)
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
    const GOOD_URL: &str = "mxc://example.org/abcdef";

    #[test]
    fn an_unparseable_scope_is_an_identifier_fault_in_every_call() {
        for error in [
            // Not `unwrap_err()`: that needs `Debug` on the SUCCESS type,
            // and `HistoryBundle` deliberately has none -- it carries the
            // key to the bundle. The refusal is read by pattern instead.
            match futures::executor::block_on(build_history_bundle(BAD_SCOPE)) {
                Err(error) => error,
                Ok(_bundle) => panic!("a malformed scope must be refused, not built"),
            },
            futures::executor::block_on(share_history_bundle(BAD_SCOPE, GOOD_USER, GOOD_URL, "{}"))
                .unwrap_err(),
            futures::executor::block_on(offered_history_bundle(BAD_SCOPE, GOOD_USER)).unwrap_err(),
            futures::executor::block_on(receive_history_bundle(BAD_SCOPE, GOOD_USER, b""))
                .unwrap_err(),
        ] {
            assert_eq!(error, HistoryError::MalformedIdentifier);
        }
    }

    #[test]
    fn an_unparseable_user_is_an_identifier_fault_too() {
        for error in [
            futures::executor::block_on(share_history_bundle(GOOD_SCOPE, BAD_USER, GOOD_URL, "{}"))
                .unwrap_err(),
            futures::executor::block_on(offered_history_bundle(GOOD_SCOPE, BAD_USER)).unwrap_err(),
            futures::executor::block_on(receive_history_bundle(GOOD_SCOPE, BAD_USER, b""))
                .unwrap_err(),
        ] {
            assert_eq!(error, HistoryError::MalformedIdentifier);
        }
    }

    /// The upload location is an identifier too, and a product that passes
    /// the upload's whole response body rather than the URI out of it is the
    /// likely way to get here.
    #[test]
    fn an_upload_location_that_is_not_an_mxc_uri_is_an_identifier_fault() {
        let error = futures::executor::block_on(share_history_bundle(
            GOOD_SCOPE,
            GOOD_USER,
            "https://example.org/not-mxc",
            "{}",
        ))
        .unwrap_err();
        assert_eq!(error, HistoryError::MalformedIdentifier);
    }

    /// The distinction `SessionError::MalformedIdentifier` was split out to
    /// make, kept here: a caller whose secret is malformed is not sent to
    /// inspect a scope that was fine.
    #[test]
    fn a_secret_this_library_did_not_produce_is_a_payload_fault() {
        for secret in [
            "not json",
            r#"{"not":"an encryption info"}"#,
            r#"["array"]"#,
        ] {
            let error = futures::executor::block_on(share_history_bundle(
                GOOD_SCOPE, GOOD_USER, GOOD_URL, secret,
            ))
            .unwrap_err();
            assert_eq!(
                error,
                HistoryError::MalformedPayload,
                "secret {secret:?} should be a payload fault"
            );
        }
    }

    /// The whole point of encrypting inside this crate: what a product
    /// uploads is ciphertext, and the bundle is not recoverable from it
    /// without the secret. Round-tripped rather than asserted structurally,
    /// so this fails if the two halves ever stop agreeing.
    #[test]
    fn what_is_built_is_ciphertext_and_it_round_trips() {
        let plaintext = br#"{"room_keys":[],"withheld":[]}"#.to_vec();
        let mut source = Cursor::new(plaintext.clone());
        let mut encryptor = AttachmentEncryptor::new(&mut source);
        let mut ciphertext = Vec::new();
        encryptor.read_to_end(&mut ciphertext).unwrap();
        let secret = serde_json::to_string(&encryptor.finish()).unwrap();

        assert_ne!(
            ciphertext, plaintext,
            "the uploaded bytes must not be the bundle"
        );

        let info: MediaEncryptionInfo = serde_json::from_str(&secret).unwrap();
        let mut encrypted = Cursor::new(ciphertext);
        let mut decryptor = AttachmentDecryptor::new(&mut encrypted, info).unwrap();
        let mut recovered = Vec::new();
        decryptor.read_to_end(&mut recovered).unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// A download altered in the repository must not import. The hash the
    /// announcement carries is what catches it, and it is checked at the
    /// end of the read rather than at the start, which is exactly why the
    /// error `read_to_end` returns cannot be treated as an ordinary I/O
    /// failure.
    #[test]
    fn a_tampered_download_does_not_decrypt() {
        let mut source = Cursor::new(br#"{"room_keys":[],"withheld":[]}"#.to_vec());
        let mut encryptor = AttachmentEncryptor::new(&mut source);
        let mut ciphertext = Vec::new();
        encryptor.read_to_end(&mut ciphertext).unwrap();
        let info: MediaEncryptionInfo =
            serde_json::from_str(&serde_json::to_string(&encryptor.finish()).unwrap()).unwrap();

        ciphertext[0] ^= 0xff;

        let mut altered = Cursor::new(ciphertext);
        let mut decryptor = AttachmentDecryptor::new(&mut altered, info).unwrap();
        let mut recovered = Vec::new();
        assert!(
            decryptor.read_to_end(&mut recovered).is_err(),
            "a flipped byte must fail the hash rather than decrypt to something"
        );
    }

    /// This crate's "no secret in any error" rule, applied to the one
    /// surface whose payload is key material.
    #[test]
    fn an_error_never_echoes_the_secret_that_caused_it() {
        let secret_like = "super-secret-attachment-key-marker";
        let rendered = futures::executor::block_on(share_history_bundle(
            GOOD_SCOPE,
            GOOD_USER,
            GOOD_URL,
            secret_like,
        ))
        .unwrap_err()
        .to_string();

        assert!(
            !rendered.contains(secret_like),
            "rendered error must not contain the secret: {rendered}"
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
