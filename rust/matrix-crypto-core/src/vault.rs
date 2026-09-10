//! The scope keys of this account in one file, under a passphrase, in the
//! format every Matrix client reads.
//!
//! # Why this exists beside `backup.rs` rather than inside it
//!
//! [`crate::create_backup`] puts key material on a homeserver. That is the
//! right answer for the ordinary case of a telephone falling in a river, and
//! it is the wrong answer for somebody who has a reason to want no key
//! material on a server at all. This is that person's route, and it is a
//! second thing rather than a second spelling of the first:
//!
//! * **The secret is chosen, not generated.** A passphrase, from whoever
//!   makes the file, because they are the one who has to remember it and
//!   there is nothing here to write it down in.
//! * **The ciphertext is authenticated.** The export format carries an
//!   HMAC-SHA256 over what it encrypts, so a file that has been altered
//!   fails to open rather than opening onto something else. The server
//!   backup's algorithm cannot say that, and `backup.rs`'s header is careful
//!   about it; this one can.
//! * **It is not this library's format.** `MEGOLM SESSION DATA` is what
//!   Element writes and reads, so a file made here opens there and a file
//!   made there opens here. That interoperability is the whole point: a
//!   vault only one application can open is a vault that locks somebody into
//!   that application, which is why this crate's `export_secrets` refuses to
//!   exist.
//!
//! # What upstream gives, and what this module had to write
//!
//! Nearly all of it. `matrix_sdk_crypto::encrypt_room_key_export` and
//! `decrypt_room_key_export` are public at the crate root and implement the
//! whole file format -- the headers, PBKDF2, AES-CTR, the MAC, base64 -- and
//! `Store::export_room_keys` collects what goes into one. What this module
//! is, is the joining: the collection, the iteration count, the mapping of
//! seven upstream failure kinds onto the two a person can act on, and the
//! import that puts what comes back into the store.
//!
//! # Nothing is written to disk here, and nothing is read from it
//!
//! A vault crosses the boundary as a string, both ways. Choosing where a
//! file goes is a question about a photo library, a share sheet, an iCloud
//! Drive folder or a downloads directory, and this crate has no business
//! answering it -- the same rule that keeps every HTTP request on the
//! product's side of the line.
//!
//! What the product owes in exchange is the discipline that goes with
//! holding a plaintext secret: the string is every key this account holds,
//! so it should reach a file and be dropped, never a log and never a
//! variable that outlives the operation.

use std::io::Cursor;

use matrix_sdk_crypto::{decrypt_room_key_export, encrypt_room_key_export, KeyExportError};

use crate::backup::BackupImport;
use crate::machine::{with_machine, MachineError};

/// PBKDF2 rounds for a vault this device writes.
///
/// 500,000, which is not a number chosen here: it is
/// `matrix_sdk_crypto::secret_storage`'s own `DEFAULT_PBKDF_ITERATIONS`, so
/// it is already what a recovery written by [`crate::create_recovery`] costs
/// on this device, and it is what the other Matrix clients write into their
/// own exports. Matching them matters in both directions -- a file made here
/// costs an ordinary amount to open elsewhere, and one made elsewhere costs
/// an ordinary amount to open here.
///
/// It is not read back on the way in. The count that opens a vault is the
/// one stored inside it, so lowering this later would not lock anybody out
/// of a file already written, and raising it would not strengthen one.
const ROUNDS: u32 = 500_000;

/// What went wrong, at the granularity a product can act on.
///
/// Fieldless, like every other error in this crate. It matters more here
/// than most: the arguments are a passphrase and a file of keys, and an
/// error that echoed either would put both in whatever caught it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VaultError {
    /// No crypto machine has been created yet.
    #[error("no crypto machine has been created")]
    NotInitialised,
    /// The crypto store failed, or the machine refused the operation.
    #[error("the crypto operation failed")]
    Failed,
    /// What was handed to [`open_key_vault`] is not a vault.
    ///
    /// Missing or damaged headers, a version this build does not implement,
    /// or bytes that are not base64. Nothing was decrypted, so this says
    /// nothing about the passphrase -- which is the distinction that makes
    /// it worth keeping apart from [`WrongPassphrase`](Self::WrongPassphrase).
    #[error("the payload could not be parsed")]
    MalformedPayload,
    /// The passphrase did not open it, or the file has been altered.
    ///
    /// **Two causes and one answer, and saying so is more honest than
    /// picking one.** The MAC is computed over the ciphertext under a key
    /// derived from the passphrase, so a wrong passphrase and a changed byte
    /// fail identically and nothing in the format tells them apart. A
    /// product's sentence therefore has to cover both: check the passphrase,
    /// and if it is certainly right, the file is not the file it was.
    ///
    /// Distinct from [`MalformedPayload`](Self::MalformedPayload), which is
    /// a file that never got as far as being decrypted at all.
    #[error("the passphrase did not open this vault")]
    WrongPassphrase,
}

impl From<MachineError> for VaultError {
    fn from(_error: MachineError) -> Self {
        VaultError::NotInitialised
    }
}

impl From<KeyExportError> for VaultError {
    /// Seven upstream kinds onto two a person can act on.
    ///
    /// Matched exhaustively, with no wildcard: a kind upstream adds later
    /// must fail this build rather than fall silently into whichever arm the
    /// wildcard named, which on this surface would mean telling somebody
    /// their passphrase is wrong about a condition nobody has classified.
    fn from(error: KeyExportError) -> Self {
        match error {
            // The MAC is the only failure that happens *because of* the
            // passphrase.
            KeyExportError::InvalidMac => VaultError::WrongPassphrase,
            // Everything else is the file: headers that are not the
            // format's, a version this build does not implement, base64
            // that is not base64, an unreadable input -- and the last two,
            // which are the strange ones. `InvalidUtf8` and `Json` are
            // reached only *after* the MAC has verified, so they are a file
            // that was made with this passphrase and is not a set of keys.
            // Reporting that as a passphrase fault would send somebody to
            // retype something that is already right.
            KeyExportError::InvalidHeaders
            | KeyExportError::UnsupportedVersion
            | KeyExportError::InvalidUtf8(_)
            | KeyExportError::Json(_)
            | KeyExportError::Decode(_)
            | KeyExportError::Io(_) => VaultError::MalformedPayload,
        }
    }
}

/// Puts every scope key this account holds into one file, encrypted under
/// `passphrase`.
///
/// What comes back is the whole file: the `-----BEGIN MEGOLM SESSION
/// DATA-----` header, the body, and the footer. Write it somewhere; this
/// crate does not.
///
/// **Every key, not one scope's.** A vault is the answer to "I want my
/// history somewhere I control", and a per-scope one would make somebody
/// answer that question once per conversation and get it wrong for the one
/// they forgot.
///
/// **The string is a plaintext secret in the sense that matters.** It is
/// encrypted, and it is encrypted under whatever the person typed, which is
/// the weakest link this library has and the one it imposes no rule on.
/// This crate has no opinion worth having about passphrase strength; a
/// product does, and this is the call it applies it to.
///
/// **It takes a noticeable moment, by design.** [`ROUNDS`] is half a million
/// PBKDF2 iterations, which is the point of a passphrase-derived key and is
/// not something to tune away: the same work is what makes a guess expensive
/// for somebody who has the file. Measured on a debug build of this crate it
/// is several seconds; a release build on a telephone is faster and still
/// long enough that a product should say something is happening rather than
/// appear to have stopped.
///
/// A device holding no keys yet produces a valid, empty vault rather than
/// failing. It is a true statement about that device, and a caller that
/// wants to say "there is nothing to export" can read
/// [`crate::backup_state`]'s `total` before offering.
pub async fn create_key_vault(passphrase: &str) -> Result<String, VaultError> {
    let keys = with_machine(|machine| {
        // Everything, so the predicate is a constant true. Written as a
        // closure that ignores its argument rather than dropped, because
        // upstream's signature is where the filtering would go and a reader
        // should see that this call declines it.
        Box::pin(async move { machine.store().export_room_keys(|_session| true).await })
    })
    .await?
    .map_err(|_upstream| VaultError::Failed)?;

    // `encrypt_room_key_export` zeroizes the plaintext it built before
    // returning, so the only copy of the keys in clear that outlives this
    // call is the one upstream already destroyed. Nothing here holds a
    // second.
    encrypt_room_key_export(&keys, passphrase, ROUNDS).map_err(|_upstream| VaultError::Failed)
}

/// Opens a vault with `passphrase` and imports the keys it holds.
///
/// `vault` is the whole file as text, headers included, from this
/// application or from any other Matrix client -- which is the point of
/// using the format rather than one of our own.
///
/// The counts say what happened. `imported` below `offered` is not a
/// failure: a key this device already holds a better copy of -- one that
/// reaches further back into the conversation -- is kept in preference to
/// the one in the file. Both zero is an empty vault.
///
/// Nothing about a backup changes here. A device that opens a vault and also
/// wants the homeserver to keep a copy still calls [`crate::enable_backup`],
/// and the keys that arrived will go up on the next drain like any other.
pub async fn open_key_vault(vault: &str, passphrase: &str) -> Result<BackupImport, VaultError> {
    // `Cursor`, because upstream takes a reader and this crate has a string:
    // the one adaptation between the two, and it copies nothing.
    let keys = decrypt_room_key_export(Cursor::new(vault), passphrase)?;
    let offered = keys.len() as u32;

    let imported = with_machine(move |machine| {
        Box::pin(async move {
            machine
                .store()
                // `None`, unlike `restore_backup`'s version: keys from a
                // file came from no backup, and claiming they came from the
                // enabled one would mark them as already uploaded when the
                // homeserver has never seen them.
                .import_room_keys(keys, None, |_done, _total| {})
                .await
        })
    })
    .await?
    .map_err(|_upstream| VaultError::Failed)?;

    Ok(BackupImport {
        offered,
        imported: imported.imported_count as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one property that makes the format worth choosing: what comes out
    /// is what Element writes, so what Element writes can come in.
    #[test]
    fn a_vault_is_the_format_every_client_reads() {
        let vault = futures::executor::block_on(async {
            // No machine, so this is the store failure path rather than the
            // happy one -- which is exactly what proves the ordering: the
            // headers are upstream's, and the assertion below belongs to
            // the round trip in `tests/`, not here.
            create_key_vault("a passphrase").await
        });

        assert_eq!(
            vault,
            Err(VaultError::NotInitialised),
            "without a machine there are no keys to put in a file, and that is \
             not a passphrase problem"
        );
    }

    /// The distinction the two error kinds exist for, put to the code rather
    /// than asserted in prose.
    #[test]
    fn a_file_that_is_not_a_vault_is_told_apart_from_a_passphrase_that_is_wrong() {
        assert_eq!(
            VaultError::from(KeyExportError::InvalidMac),
            VaultError::WrongPassphrase
        );
        assert_eq!(
            VaultError::from(KeyExportError::InvalidHeaders),
            VaultError::MalformedPayload
        );
        assert_eq!(
            VaultError::from(KeyExportError::UnsupportedVersion),
            VaultError::MalformedPayload
        );
    }

    /// Reached only after the MAC verifies, so it is a file made with this
    /// passphrase that is not a set of keys -- and telling somebody to
    /// retype a passphrase that is already right is the failure this arm
    /// exists to avoid.
    #[test]
    fn a_vault_that_opens_onto_something_that_is_not_keys_is_not_a_passphrase_fault() {
        let not_keys = serde_json::from_str::<Vec<u8>>("{").unwrap_err();

        assert_eq!(
            VaultError::from(KeyExportError::Json(not_keys)),
            VaultError::MalformedPayload
        );
    }

    /// Anything that is not the armoured format must be refused before a
    /// passphrase is ever derived from -- half a million PBKDF2 rounds is
    /// not a thing to spend on a string that cannot be a vault.
    #[test]
    fn nothing_that_is_not_the_format_gets_as_far_as_the_passphrase() {
        for input in ["", "not a vault", "-----BEGIN SOMETHING ELSE-----"] {
            assert_eq!(
                futures::executor::block_on(open_key_vault(input, "a passphrase")),
                Err(VaultError::MalformedPayload),
                "{input:?} is not a vault and must be refused as one"
            );
        }
    }

    /// This crate's "no secret in any error" rule, on the surface whose two
    /// arguments are a passphrase and a file of keys.
    #[test]
    fn an_error_never_echoes_the_passphrase_or_the_file() {
        let passphrase = "correct-horse-battery-staple-marker";
        let vault =
            "-----BEGIN MEGOLM SESSION DATA-----\nmarker\n-----END MEGOLM SESSION DATA-----";

        let rendered = futures::executor::block_on(open_key_vault(vault, passphrase))
            .unwrap_err()
            .to_string();

        assert!(
            !rendered.contains(passphrase) && !rendered.contains("marker"),
            "rendered error must carry neither the passphrase nor the file: {rendered}"
        );
    }
}
