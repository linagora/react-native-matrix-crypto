//! Keeping this account's scope keys on its homeserver, under a key the
//! homeserver never holds.
//!
//! # The problem this exists for
//!
//! Scope keys live in the crypto store and nowhere else. A device that
//! loses its store loses every message it had already received, for good --
//! not a cache, the only copy. `recovery.rs` brings an *identity* back and
//! says so in its own words; it leaves any backup exactly as it found it,
//! because there was none to find.
//!
//! [Server-side key backup] is the protocol's answer, and it is the one that
//! covers the ordinary case of a telephone falling in a river. The device
//! encrypts each key to a public key, uploads the ciphertext, and the
//! homeserver stores something it cannot read. A device that comes back
//! later hands over the private half and gets the past.
//!
//! # What upstream gives, and what this module had to write
//!
//! `matrix_sdk_crypto::backups` is public and needs no Cargo feature. It
//! provides key generation, the base58 form both ways, the public half, the
//! version description to publish, per-session encryption and decryption,
//! the batching of un-backed-up sessions into one request, and the check of
//! whether a private key opens a given backup.
//!
//! It provides none of the plumbing. Nothing upstream turns the four
//! `/room_keys` endpoints into calls a product can make, nothing carries the
//! request to a pump that does not exist upstream, and nothing joins a
//! downloaded backup to `Store::import_room_keys`. That assembly is this
//! module.
//!
//! # The weakness this surface has, stated here because it cannot be fixed
//!
//! **`m.megolm_backup.v1.curve25519-aes-sha2` does not authenticate its
//! ciphertext.** Whoever can write to a backup can substitute keys in it
//! undetectably, and a device restoring would decrypt what they chose.
//! `vodozemac` says so in the plainest way available to a library: the
//! algorithm is gated behind a feature flag named `insecure-pk-encryption`,
//! which `matrix-sdk-crypto` turns on for itself.
//!
//! It is the only server backup the protocol has, so the choice is this or
//! nothing, and a product that offers it owes its user the sentence rather
//! than the footnote. This module cannot make that sentence appear on a
//! screen. It can refuse to let anybody integrate the surface without
//! reading it, which is what this paragraph is for.
//!
//! # Two secrets in this library are called a recovery key. This is not one
//!
//! [`RecoverySetup::recovery_key`](crate::RecoverySetup::recovery_key) is
//! the **secret storage** key: it opens the account's private signing keys,
//! and `recover_identity` is what consumes it. What [`create_backup`]
//! produces is a **backup decryption key**: it opens this backup's scope
//! keys, and [`restore_backup`] is what consumes it. Both are 32 random
//! bytes shown in base58 and they are otherwise unrelated -- neither opens
//! what the other opens, and pasting one where the other belongs fails.
//!
//! So this one is a *restore key* on this surface and never a recovery key,
//! and the two never appear in the same record. A product with only one of
//! them may call it whatever its own users will understand; a product with
//! both must not call them the same thing, which is the mistake this naming
//! exists to make hard rather than merely to warn about.
//!
//! # What travels, and what stays
//!
//! **This library still performs no request.** The four `/room_keys`
//! endpoints belong to the product, as every other endpoint does. The split
//! is not the one `recovery.rs` made, though, and the difference is worth
//! stating once: creating a version is a read-then-write with a value coming
//! back, so [`create_backup`] hands back a body and takes the answer through
//! [`enable_backup`] -- account data's shape exactly. Uploading keys is
//! fire-and-acknowledge, which is what the pump is, so it goes through the
//! pump as an eighth request kind rather than through a second path with
//! rules of its own.
//!
//! **The private half is never stored.** Upstream offers
//! `BackupMachine::save_decryption_key`, and this module does not call it.
//! What a device needs in order to keep *writing* is the public half, which
//! [`BackupSetup::sealing_key`] hands back for the product to keep; the
//! private half is needed only to restore, which is a thing that happens on
//! a different device or after a reinstall. Storing it would put the key to
//! an entire history inside the store whose loss the backup exists to
//! survive, and within reach of anyone holding an unlocked telephone.
//!
//! That costs one real thing, and it is not a defect to be fixed later: this
//! device cannot gossip the key to another device of the same account,
//! because it does not have it. A second device restores from the restore
//! key like any other, which is the flow this surface has.
//!
//! # The version identifier is an opaque string
//!
//! The specification says so, and it is not a formality. Synapse hands back
//! a counter from `"1"`; Continuwuity 26.7.2 hands back a six-digit integer.
//! A client that assumes a small increasing number works against one and
//! breaks against the other. Nothing here parses it, compares it for order,
//! or generates it.
//!
//! [Server-side key backup]: https://spec.matrix.org/v1.11/client-server-api/#server-side-key-backups

use std::collections::BTreeMap;

use matrix_sdk_common::ruma::api::client::backup::RoomKeyBackup;
use matrix_sdk_common::ruma::OwnedRoomId;
use matrix_sdk_crypto::backups::MegolmV1BackupKey;
use matrix_sdk_crypto::olm::ExportedRoomKey;
use matrix_sdk_crypto::store::types::BackupDecryptionKey;
use matrix_sdk_crypto::types::RoomKeyBackupInfo;

use crate::machine::{with_machine, MachineError};

/// What went wrong, at the granularity a product can act on.
///
/// Fieldless, like every other error in this crate: what an identifier or a
/// payload contained is caller-supplied content this library does not carry
/// back across the boundary. `restore_backup`'s payload is key material,
/// which makes the rule more than a convention here.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BackupError {
    /// A restore key, a sealing key, or a version handed to this call is not
    /// one this surface can use.
    ///
    /// A restore key that is not base58, or is base58 for something else; a
    /// sealing key that is not the base64 public half; an empty version,
    /// which is not an opaque identifier but the absence of one.
    #[error("an identifier could not be parsed")]
    MalformedIdentifier,
    /// The JSON handed to [`restore_backup`] or [`restore_key_matches`] is
    /// not the shape that endpoint answers with.
    #[error("the payload could not be parsed")]
    MalformedPayload,
    /// No crypto machine has been created yet.
    #[error("no crypto machine has been created")]
    NotInitialised,
    /// The crypto store failed, or the machine refused the operation.
    #[error("the crypto operation failed")]
    Failed,
    /// The restore key does not open this backup.
    ///
    /// Not [`MalformedIdentifier`](Self::MalformedIdentifier): the key
    /// parsed, it is a real backup key, and it is the wrong one -- somebody
    /// pasted the key to a backup they replaced, or the secret storage
    /// recovery key this module's own header warns is a different secret.
    /// The remedy is a different key, and a product that folds the two
    /// together tells them to fix a typo that is not there.
    ///
    /// Reported before anything is decrypted, from the version description
    /// alone, so it costs a small request rather than the whole backup.
    #[error("that key does not open this backup")]
    WrongKey,
}

impl From<MachineError> for BackupError {
    fn from(_error: MachineError) -> Self {
        BackupError::NotInitialised
    }
}

/// Everything [`create_backup`] produced: the one secret to show the user,
/// the half the device keeps, and the version to publish.
///
/// No `Debug` derive: `restore_key` opens every scope key this backup will
/// ever hold, and a derived one leaves it a single `{:?}` away from a log.
/// The same absence [`RecoverySetup`](crate::RecoverySetup) and
/// [`HistoryBundle`](crate::HistoryBundle) both carry, guarded the same way
/// -- the doctest below takes the `Debug` bound directly rather than
/// building a value, because a `compile_fail` block passes on *any*
/// compiler error and a snippet naming the fields could keep passing after
/// the derive returns, on a field-rename error nobody intended.
///
/// ```compile_fail
/// fn requires_debug<T: std::fmt::Debug>() {}
///
/// // Compiles only while `BackupSetup` has no `Debug` impl; mentions no
/// // field, so a field changing shape cannot make the block pass.
/// requires_debug::<matrix_crypto_core::BackupSetup>();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct BackupSetup {
    /// The base58 restore key, in groups of four characters.
    ///
    /// **This value is not stored anywhere and cannot be produced again.**
    /// Nothing in this library holds it after this record is dropped, by
    /// design -- see the module header. Show it once, and mean it.
    ///
    /// Whitespace is ignored when it comes back, so the groups are a
    /// courtesy to whoever copies it and not part of the value.
    pub restore_key: String,
    /// The public half, base64. Keep it; it is what backing up needs.
    ///
    /// Hand it to [`enable_backup`] with the version the homeserver
    /// answered with, on this launch and on every launch afterwards: this
    /// library does not persist it, and a device that stops calling
    /// [`enable_backup`] stops backing up silently.
    ///
    /// It is not a secret. It encrypts and cannot decrypt, which is the
    /// whole reason the arrangement is worth anything.
    pub sealing_key: String,
    /// The body to publish, as JSON: `algorithm` and `auth_data`.
    ///
    /// Exactly the body of `POST /_matrix/client/v3/room_keys/version`. This
    /// library never adds an envelope of its own around it, so a product
    /// moves these bytes to the homeserver unchanged.
    pub version_request: String,
}

/// What this device is doing about backup at the moment it was asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupState {
    /// Whether [`enable_backup`] has been called since this process started.
    ///
    /// Not whether a backup exists on the homeserver, which this library
    /// cannot know without a request it will not make.
    pub enabled: bool,
    /// The version being backed up to, if any. Opaque; see the module
    /// header for why nothing may parse it.
    pub version: Option<String>,
    /// How many scope keys this device holds.
    pub total: u32,
    /// How many of them the homeserver has a copy of.
    ///
    /// Counted against the enabled version, so it reads zero after a
    /// version is replaced even though nothing was lost: those keys are
    /// backed up to a version this device no longer writes to, and they
    /// will be written again.
    pub backed_up: u32,
}

/// What a restore actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackupImport {
    /// How many keys the downloaded backup carried.
    pub offered: u32,
    /// How many were imported.
    ///
    /// Lower than `offered` when this device already held a better copy of
    /// a key -- one that reaches further back into the conversation -- which
    /// upstream keeps in preference to the backed-up one. Both being zero is
    /// an empty backup, not a failure.
    pub imported: u32,
}

/// Generates a backup key and describes the version to publish with it.
///
/// Nothing has happened when this returns: no request has been made, no
/// state has changed, and this device is not backing anything up. Calling it
/// twice produces two unrelated keys and two version descriptions, of which
/// at most one will ever be published -- which costs nothing, because the
/// discarded one was never uploaded and nobody holds its key.
///
/// The sequence this begins is: publish
/// [`version_request`](BackupSetup::version_request), take the `version` the
/// homeserver answers with, and hand it to [`enable_backup`] along with
/// [`sealing_key`](BackupSetup::sealing_key). Until that call, nothing is
/// backed up.
///
/// **Not `async`, and needs no crypto machine.** Generating a key is
/// arithmetic on 32 random bytes and touches nothing this library holds.
/// So a product may show the restore key -- and let somebody refuse it --
/// before a store exists.
pub fn create_backup() -> BackupSetup {
    let key = BackupDecryptionKey::new();

    // `to_string` rather than `to_base58`: the `Display` impl is the same
    // value in groups of four, which is the form the specification shows and
    // the form `RecoverySetup::recovery_key` already hands back. Whitespace
    // is stripped on the way back in, so the two forms are interchangeable
    // as input and only one of them is pleasant to copy off a screen.
    let restore_key = key.to_string();
    let sealing_key = key.megolm_v1_public_key().to_base64();

    // `to_backup_info` builds the tagged enum whose serialisation is exactly
    // `{"algorithm": ..., "auth_data": {...}}`. Serialising a value this
    // function just built from a freshly generated key cannot fail, and an
    // `expect` documents that rather than guarding a case that cannot occur
    // -- the same reasoning `session.rs`'s `http_response` gives for its own.
    let version_request = serde_json::to_string(&key.to_backup_info())
        .expect("a backup version description built from a fresh key cannot fail to serialise");

    BackupSetup {
        restore_key,
        sealing_key,
        version_request,
    }
}

/// Starts backing up scope keys to `version`, under `sealing_key`.
///
/// `sealing_key` is [`BackupSetup::sealing_key`] and `version` is what the
/// homeserver answered with when the version was published. Both come back
/// on every launch: this library persists neither, so a process that does
/// not make this call is a process that quietly backs nothing up.
///
/// Nothing is uploaded here. The keys go out through
/// [`take_outgoing_requests`](crate::take_outgoing_requests) as
/// `room_key_backup` requests, in batches, starting with the next drain --
/// which is why enabling a backup on a device with a long history is not an
/// event that blocks anything.
pub async fn enable_backup(sealing_key: &str, version: &str) -> Result<(), BackupError> {
    // Refused here rather than passed on, and this is the guard rather than
    // a formality. Upstream's `enable_backup_v1` treats a key with no
    // version as a no-op: it logs a warning and returns `Ok(())`, so an
    // empty version would leave this call reporting success while nothing
    // was ever enabled -- the silent-failure shape this crate refuses
    // wherever it can see one. An empty string is not an opaque identifier;
    // it is the absence of one.
    if version.is_empty() {
        return Err(BackupError::MalformedIdentifier);
    }

    let key = MegolmV1BackupKey::from_base64(sealing_key)
        .map_err(|_| BackupError::MalformedIdentifier)?;
    key.set_version(version.to_owned());

    let version = version.to_owned();
    with_machine(move |machine| {
        Box::pin(async move {
            let backups = machine.backup_machine();

            // MOVING TO A DIFFERENT VERSION MUST DROP THE BATCH ALREADY IN
            // FLIGHT, and nothing upstream does it.
            //
            // `enable_backup_v1` writes the key and nothing else; it never
            // touches `pending_backup`. `BackupMachine::backup` hands back
            // an existing pending request unconditionally, without comparing
            // its version. So enabling a new version while a batch is
            // unacknowledged makes the pump re-emit a body carrying the
            // *retired* version on every drain -- the homeserver answers
            // `M_WRONG_ROOM_KEYS_VERSION`, `mark_request_failed` leaves the
            // entry pending on purpose, and the pump never moves again.
            //
            // That is precisely the path ADR-0013 requires to exist: *« Elle
            // peut être remplacée. Remplacer fait une nouvelle version de
            // sauvegarde et retire l'ancienne clé. »* Replacing a key that
            // wedged the pump for ever would be a remedy worse than the
            // problem it fixes.
            //
            // `disable_backup` is what clears the slot, and its other effect
            // is not collateral here but correct: it marks every key
            // un-backed-up, and keys backed up to the version being left
            // genuinely are not backed up to the one being joined.
            //
            // **Guarded on the version actually differing, and that guard is
            // load-bearing.** Re-enabling the *same* version is the ordinary
            // path -- this call is made on every launch -- and resetting the
            // backup state there would re-upload every key this device holds
            // on every start.
            match backups.backup_version().await {
                Some(current) if current != version => backups.disable_backup().await?,
                _ => {}
            }

            backups.enable_backup_v1(key).await
        })
    })
    .await?
    .map_err(|_upstream| BackupError::Failed)
}

/// Stops backing up, and forgets which keys were already backed up.
///
/// A local act with no protocol meaning: the backup on the homeserver is
/// untouched and still opens with the same restore key. Deleting it is
/// `DELETE /room_keys/version/{version}`, which is the product's request to
/// make like every other.
///
/// The forgetting is upstream's `reset_backup_state`, and it is why this is
/// not free: every key this device holds is marked un-backed-up, so enabling
/// a backup again uploads all of them rather than the difference.
pub async fn disable_backup() -> Result<(), BackupError> {
    with_machine(|machine| Box::pin(async move { machine.backup_machine().disable_backup().await }))
        .await?
        .map_err(|_upstream| BackupError::Failed)
}

/// What this device is doing about backup, and how far along it is.
///
/// The two counts are the honest progress indicator for a first backup, and
/// they are also how a product notices a backup that has quietly stopped:
/// `backed_up` well below `total` on a device that has been draining its
/// pump means the requests are failing somewhere the pump cannot see.
pub async fn backup_state() -> Result<BackupState, BackupError> {
    let (enabled, version, counts) = with_machine(|machine| {
        Box::pin(async move {
            let backups = machine.backup_machine();
            (
                backups.enabled().await,
                backups.backup_version().await,
                backups.room_key_counts().await,
            )
        })
    })
    .await?;

    let counts = counts.map_err(|_upstream| BackupError::Failed)?;

    Ok(BackupState {
        enabled,
        version,
        total: counts.total as u32,
        backed_up: counts.backed_up as u32,
    })
}

/// Whether `restore_key` opens the backup `version_info` describes.
///
/// `version_info` is the body of `GET /room_keys/version` -- or
/// `/room_keys/version/{version}` -- passed through unchanged. Only its
/// `algorithm` and `auth_data` are read; the `version`, `count` and `etag`
/// beside them are ignored, so a caller need not take the object apart.
///
/// Ask this **before** downloading a backup. The version description is a
/// few hundred bytes and the backup is every key this account ever held, so
/// a wrong key found here costs one small request, and found in
/// [`restore_backup`] costs the download. It is the same comparison
/// [`restore_backup`] makes for itself, which is why a product that skips
/// this is wrong about performance and never about safety.
///
/// **Not `async`, and needs no crypto machine**: it compares two public keys
/// and touches nothing this library holds.
///
/// A backup in an algorithm this library does not implement answers `false`
/// rather than failing. It is a real answer -- that key does not open that
/// backup -- and the caller has nothing different to do about it.
pub fn restore_key_matches(restore_key: &str, version_info: &str) -> Result<bool, BackupError> {
    let key = parse_restore_key(restore_key)?;
    let info = parse_version_info(version_info)?;

    Ok(key.backup_key_matches(&info))
}

/// Decrypts a downloaded backup with `restore_key` and imports what it
/// holds.
///
/// `keys` is the body of `GET /room_keys/keys?version={version}` passed
/// through unchanged, and `version` is the version it was downloaded from.
///
/// **`version` is recorded, not checked.** It is what marks the imported
/// keys as already backed up, so a device that restores and then keeps
/// backing up to the same version does not immediately upload everything it
/// just downloaded. Hand back the version the download actually came from;
/// naming a different one costs a redundant upload and nothing worse.
///
/// Keys that fail to decrypt are skipped rather than failing the restore:
/// one damaged entry in a backup of thousands must not cost somebody the
/// other thousands. The difference shows in the two counts.
///
/// This does not enable anything. A device that restores and then wants to
/// keep the backup up to date still calls [`enable_backup`] -- which is a
/// separate act, because restoring on a device that is about to be wiped
/// again is a perfectly ordinary thing to do.
pub async fn restore_backup(
    restore_key: &str,
    version: &str,
    keys: &str,
) -> Result<BackupImport, BackupError> {
    if version.is_empty() {
        return Err(BackupError::MalformedIdentifier);
    }

    let key = parse_restore_key(restore_key)?;

    let downloaded: BackedUpKeys =
        serde_json::from_str(keys).map_err(|_| BackupError::MalformedPayload)?;

    let mut offered: u32 = 0;
    // Counted apart from `offered`, and the difference is the whole of the
    // `WrongKey` decision below. An entry that will not *parse* was never
    // offered to the key, so it cannot be evidence about the key.
    let mut tried: u32 = 0;
    let mut decrypted: Vec<ExportedRoomKey> = Vec::new();

    for (room_id, backup) in downloaded.rooms {
        for (session_id, entry) in backup.sessions {
            offered = offered.saturating_add(1);

            // Each session is deserialised on its own rather than the map
            // being typed as `BTreeMap<String, KeyBackupData>` directly.
            // `Raw` is what ruma's own response type holds here, and it is
            // the right shape for the same reason the skip below exists: a
            // single entry a future specification version has grown a field
            // for, or that a buggy client wrote badly, must cost that entry
            // and not the whole restore.
            let Ok(data) = entry.deserialize() else {
                continue;
            };

            tried = tried.saturating_add(1);

            let Ok(room_key) = key.decrypt_session_data(data.session_data) else {
                continue;
            };

            decrypted.push(ExportedRoomKey::from_backed_up_room_key(
                room_id.clone(),
                session_id,
                room_key,
            ));
        }
    }

    // Nothing decrypted out of everything the key was actually given: this
    // is the wrong key, not an empty backup. Reported as such rather than as
    // a successful import of nothing, which is what the counts alone would
    // have said.
    //
    // The test is "nothing at all", not "some failed": a backup can
    // genuinely carry an entry this device cannot read, and a run that
    // recovered even one key was opened by the right key by definition.
    //
    // **It is `tried`, not `offered`, and that distinction is a defect this
    // code had.** An entry that will not deserialise never reached the key,
    // so a body whose entries are all malformed would have been reported as
    // `WrongKey` -- telling somebody to find a different secret when the
    // secret was never the problem, which is the exact fold that kind's own
    // doc comment forbids. A download that arrives damaged is
    // `MalformedPayload`, and `tried == 0` with `offered > 0` is precisely
    // that: entries existed and not one of them was a key.
    if tried > 0 && decrypted.is_empty() {
        return Err(BackupError::WrongKey);
    }
    if offered > 0 && tried == 0 {
        return Err(BackupError::MalformedPayload);
    }

    let version = version.to_owned();
    let imported = with_machine(move |machine| {
        Box::pin(async move {
            machine
                .store()
                // The progress listener is upstream's hook for a long
                // import, and this surface has no channel to report
                // progress on: a call that crosses the FFI boundary once
                // cannot call back into JavaScript while it runs. The
                // counts come back at the end instead.
                .import_room_keys(decrypted, Some(&version), |_done, _total| {})
                .await
        })
    })
    .await?
    .map_err(|_upstream| BackupError::Failed)?;

    Ok(BackupImport {
        offered,
        imported: imported.imported_count as u32,
    })
}

/// The one shape `GET /room_keys/keys` answers with, named here because
/// ruma's own response type for it cannot be built from outside
/// `ruma-client-api` -- the same wall `session.rs`'s `mark_sent` documents,
/// where the way round it is `try_from_http_response`. There is no such
/// escape for a *response this library receives as text*, so the one field
/// it needs is declared.
///
/// Unknown fields are ignored, which is serde's default and is right here:
/// a homeserver that grows a field must not break a restore.
#[derive(serde::Deserialize)]
struct BackedUpKeys {
    rooms: BTreeMap<OwnedRoomId, RoomKeyBackup>,
}

/// Reads a restore key in either form: base58 as this library hands it out,
/// in groups of four or without them.
///
/// Upstream strips whitespace itself, so this is one call and a mapped
/// error. It exists as a function because both public entry points that take
/// a restore key must fail the same way on the same input, and two call
/// sites that each map an upstream error are two chances to disagree.
fn parse_restore_key(restore_key: &str) -> Result<BackupDecryptionKey, BackupError> {
    BackupDecryptionKey::from_base58(restore_key).map_err(|_| BackupError::MalformedIdentifier)
}

/// Reads the `algorithm`/`auth_data` pair out of a version description.
///
/// The endpoint's body carries `version`, `count` and `etag` alongside them
/// and `RoomKeyBackupInfo` does not declare those, which serde ignores. So
/// the whole body deserialises, and a caller does not have to take it apart
/// before handing it over.
fn parse_version_info(version_info: &str) -> Result<RoomKeyBackupInfo, BackupError> {
    serde_json::from_str(version_info).map_err(|_| BackupError::MalformedPayload)
}

/// Unused outside tests; declared so the two helpers above are exercised
/// against ruma's own types rather than against a hand-written literal.
#[cfg(test)]
fn one_backed_up_session(room_id: &str, session_id: &str, data: serde_json::Value) -> String {
    let entry = serde_json::json!({
        "first_message_index": 0,
        "forwarded_count": 0,
        "is_verified": true,
        "session_data": data,
    });

    serde_json::json!({
        "rooms": { room_id: { "sessions": { session_id: entry } } }
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two calls must not produce the same secret. A generator that did
    /// would be catastrophic and silent, and the assertion costs nothing.
    #[test]
    fn every_backup_gets_its_own_key() {
        let first = create_backup();
        let second = create_backup();

        assert_ne!(first.restore_key, second.restore_key);
        assert_ne!(first.sealing_key, second.sealing_key);
    }

    /// The version description must be the endpoint's body and not a
    /// wrapper around it, because the product posts it unchanged.
    #[test]
    fn the_version_description_is_the_endpoints_own_body() {
        let setup = create_backup();
        let body: serde_json::Value = serde_json::from_str(&setup.version_request).unwrap();

        assert_eq!(
            body["algorithm"], "m.megolm_backup.v1.curve25519-aes-sha2",
            "the algorithm this surface implements, named on the wire"
        );
        assert_eq!(
            body["auth_data"]["public_key"], setup.sealing_key,
            "the published public key must be the sealing key the caller keeps"
        );
    }

    /// The form shown to a person and the form accepted back must be the
    /// same value, or somebody who copies what they were shown is refused.
    #[test]
    fn the_key_that_was_shown_is_the_key_that_is_accepted() {
        let setup = create_backup();

        assert!(
            setup.restore_key.contains(' '),
            "the displayed form groups the characters, which is what makes it copyable"
        );

        let info = format!(
            r#"{{"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2",
                 "auth_data":{{"public_key":"{}","signatures":{{}}}},
                 "version":"1","count":0,"etag":"0"}}"#,
            setup.sealing_key
        );

        assert_eq!(restore_key_matches(&setup.restore_key, &info), Ok(true));

        let ungrouped: String = setup.restore_key.chars().filter(|c| *c != ' ').collect();
        assert_eq!(
            restore_key_matches(&ungrouped, &info),
            Ok(true),
            "whitespace is a courtesy, not part of the value"
        );
    }

    /// The whole point of asking before downloading.
    #[test]
    fn a_key_for_another_backup_does_not_open_this_one() {
        let mine = create_backup();
        let theirs = create_backup();

        let info = format!(
            r#"{{"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2",
                 "auth_data":{{"public_key":"{}","signatures":{{}}}}}}"#,
            mine.sealing_key
        );

        assert_eq!(restore_key_matches(&theirs.restore_key, &info), Ok(false));
    }

    /// A backup in an algorithm this library does not implement is a real
    /// "no", not a parse failure: the caller has nothing different to do.
    #[test]
    fn an_algorithm_this_library_does_not_implement_answers_no() {
        let setup = create_backup();
        let info = r#"{"algorithm":"m.megolm_backup.v9.something-else","auth_data":{}}"#;

        assert_eq!(restore_key_matches(&setup.restore_key, info), Ok(false));
    }

    /// The two failures a caller acts on differently must not collapse into
    /// each other: a wrong key needs another key, a malformed one needs the
    /// same key typed properly.
    #[test]
    fn a_key_that_is_not_a_key_is_told_apart_from_a_key_for_something_else() {
        let info = r#"{"algorithm":"m.megolm_backup.v1.curve25519-aes-sha2","auth_data":{}}"#;

        assert_eq!(
            restore_key_matches("not a key at all", info),
            Err(BackupError::MalformedIdentifier)
        );
        assert_eq!(
            restore_key_matches("", info),
            Err(BackupError::MalformedIdentifier),
            "an empty string is not a key"
        );
    }

    /// A version description that is not one must be reported as a payload
    /// fault, so a product does not tell somebody their key is wrong.
    #[test]
    fn a_version_description_that_is_not_one_is_a_payload_fault() {
        let setup = create_backup();

        assert_eq!(
            restore_key_matches(&setup.restore_key, "not json"),
            Err(BackupError::MalformedPayload)
        );
    }

    /// This crate's "no secret in any error" rule, applied to the surface
    /// whose arguments are key material.
    #[test]
    fn an_error_never_echoes_the_key_that_caused_it() {
        let setup = create_backup();
        let rendered = restore_key_matches(&setup.restore_key, "not json")
            .unwrap_err()
            .to_string();

        assert!(
            !rendered.contains(&setup.restore_key),
            "rendered error must not contain the restore key: {rendered}"
        );
    }

    /// A downloaded backup is read through ruma's own types, so a body the
    /// endpoint really answers with parses and one that is not shaped like
    /// it does not.
    #[test]
    fn a_downloaded_backup_parses_as_the_endpoint_answers_it() {
        let body = one_backed_up_session(
            "!scope:example.org",
            "session-id",
            serde_json::json!({
                "ciphertext": "AAAA",
                "mac": "AAAA",
                "ephemeral": "AAAA",
            }),
        );

        let parsed: BackedUpKeys = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.rooms.len(), 1);

        let sessions = &parsed.rooms.values().next().unwrap().sessions;
        assert!(sessions.contains_key("session-id"));
    }

    /// A download whose entries are all unreadable is a damaged file, not a
    /// wrong key -- and the two send a person to opposite remedies.
    ///
    /// This is the defect the `tried` counter exists for. Counting `offered`
    /// alone, every one of these bodies reported `WrongKey`, which tells
    /// somebody to go and find a different secret when the secret was never
    /// looked at.
    #[test]
    fn a_download_nothing_could_even_be_read_from_is_not_the_key_s_fault() {
        let setup = create_backup();

        for entry in [
            // Shaped like an entry and missing what one has.
            serde_json::json!({ "not": "a key backup entry" }),
            // The right fields, the wrong types.
            serde_json::json!({
                "first_message_index": "not a number",
                "forwarded_count": 0,
                "is_verified": true,
                "session_data": { "ciphertext": "AAAA", "mac": "AAAA", "ephemeral": "AAAA" },
            }),
        ] {
            let body = serde_json::json!({
                "rooms": { "!scope:example.org": { "sessions": { "s": entry } } }
            })
            .to_string();

            assert_eq!(
                futures::executor::block_on(restore_backup(&setup.restore_key, "947281", &body)),
                Err(BackupError::MalformedPayload),
                "an entry the key was never given cannot be evidence about the key"
            );
        }
    }

    /// The other side of the same line: a body with no entries at all is an
    /// empty backup, which is a success and not a fault of any kind.
    #[test]
    fn an_empty_backup_is_not_a_failure() {
        let setup = create_backup();

        // `NotInitialised` and not a payload or key error: the emptiness got
        // past both checks and the call went on to the store, which is the
        // whole assertion. There is no machine here to import into.
        assert_eq!(
            futures::executor::block_on(restore_backup(
                &setup.restore_key,
                "947281",
                r#"{"rooms":{}}"#
            )),
            Err(BackupError::NotInitialised)
        );
    }

    /// `enable_backup` refuses an empty version before it reaches upstream,
    /// where it would have been a warning and a successful return.
    ///
    /// Checked without a machine on purpose: the refusal must come from the
    /// argument and not from the store's absence, which is what
    /// distinguishing it from `NotInitialised` here proves.
    #[test]
    fn an_empty_version_is_refused_rather_than_silently_doing_nothing() {
        let setup = create_backup();

        assert_eq!(
            futures::executor::block_on(enable_backup(&setup.sealing_key, "")),
            Err(BackupError::MalformedIdentifier)
        );
        assert_eq!(
            futures::executor::block_on(restore_backup(&setup.restore_key, "", "{}")),
            Err(BackupError::MalformedIdentifier)
        );
    }

    /// A sealing key that is not one must be refused for what it is, and
    /// before the store is consulted.
    #[test]
    fn a_sealing_key_that_is_not_one_is_refused() {
        assert_eq!(
            futures::executor::block_on(enable_backup("not base64 at all !!", "1")),
            Err(BackupError::MalformedIdentifier)
        );
    }
}
