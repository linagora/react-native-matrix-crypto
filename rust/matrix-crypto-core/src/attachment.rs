//! Encrypting and decrypting an ordinary attachment.
//!
//! A photograph, a recording, a document: bytes a product wants to put in a
//! conversation, encrypted the way Matrix specifies for attachments, with the
//! product doing the upload and the download itself.
//!
//! # Why this is in the library and not in the product
//!
//! This is the same split `history` documents at length, and it is here for
//! the same reason it is there — because that one was tried the other way
//! round first. The bundle code originally handed the product a plaintext and
//! a key and asked it to encrypt; consuming it is what showed the mistake. A
//! React Native product has no AES and no SHA-256. What reads as a small
//! design choice in a library is an instruction to implement Matrix's
//! attachment encryption in JavaScript, on the platform least equipped to do
//! it and with the most to lose if it is done wrong.
//!
//! So the library encrypts. What crosses the boundary is a ciphertext to
//! upload and an opaque secret to keep, and a caller never touches key
//! material it would have to understand.
//!
//! # What is deliberately not here
//!
//! **No upload, and no download.** The media repository is the product's, not
//! this library's: it has the homeserver's address, the access token and the
//! retry policy, and a crypto library that acquired an HTTP client would have
//! acquired all three. `history` draws the boundary in the same place, which
//! is why sharing a bundle is two calls with the product's upload in between.
//!
//! **No `url`.** A bundle's announcement has to carry one, because the
//! recipient learns where to look from the sender. An attachment's does not:
//! the product uploaded it, so the product already knows, and putting the
//! location inside the secret would be asking a caller to hand back a fact it
//! never needed us to hold.

use std::io::Read;

use matrix_sdk_crypto::{AttachmentDecryptor, AttachmentEncryptor};

/// What went wrong, in the only three ways a caller can act on differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentError {
    /// The secret is not one this library produced, or is from a version of
    /// the attachment specification this build does not know.
    ///
    /// A caller's answer is the same either way and neither is recoverable by
    /// retrying: something upstream of this call is wrong.
    MalformedSecret,
    /// The bytes are not the bytes the secret announced.
    ///
    /// Matrix's attachment encryption carries a SHA-256 of the ciphertext in
    /// the secret, and this is that check failing. It means the download was
    /// truncated, corrupted, or substituted -- and a product must say so
    /// rather than showing what decrypted before the check ran, which is why
    /// this is its own kind and not a general failure.
    NotWhatWasAnnounced,
    /// Anything else.
    Failed,
}

/// An attachment, encrypted and ready to upload.
///
/// No `Debug` derive, for the reason [`HistoryBundle`](crate::HistoryBundle)
/// gives: [`secret`](Self::secret) is the key to the file, and a derived
/// `Debug` leaves it a single `{:?}` away from a log.
///
/// ```compile_fail
/// fn requires_debug<T: std::fmt::Debug>() {}
///
/// requires_debug::<matrix_crypto_core::SealedAttachment>();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SealedAttachment {
    /// The encrypted attachment. Upload these bytes verbatim.
    ///
    /// There is no key in here and nothing to protect beyond the ordinary
    /// care an upload deserves: the key that opens it is in
    /// [`secret`](Self::secret).
    pub ciphertext: Vec<u8>,
    /// Opaque. Keep it, send it to whoever may read the file, and hand it
    /// back to [`decrypt_attachment`] unchanged.
    ///
    /// **It contains the key that decrypts the file.** It is deliberately a
    /// string rather than a structure, because a caller has no reason to read
    /// it: put it where the event that references the attachment goes, which
    /// is inside the conversation's own encryption, and nowhere else.
    pub secret: String,
}

/// Encrypts `plaintext`, and hands back the ciphertext to upload and the
/// secret that opens it.
///
/// A fresh key every call, including for the same bytes. Encrypting one file
/// twice produces two ciphertexts and two secrets, which costs nothing: the
/// discarded one was never uploaded, so nobody can fetch it and nobody holds
/// its key.
///
/// The whole file is held in memory twice over, once as plaintext and once as
/// ciphertext. That is a real limit and it is the caller's to respect: this
/// takes a slice rather than a stream because the boundary it crosses has no
/// streams, and a product putting a video through it should know it is doing
/// that.
pub async fn encrypt_attachment(plaintext: &[u8]) -> Result<SealedAttachment, AttachmentError> {
    let mut source = plaintext;
    let mut encryptor = AttachmentEncryptor::new(&mut source);

    let mut ciphertext = Vec::new();
    encryptor
        .read_to_end(&mut ciphertext)
        .map_err(|_upstream| AttachmentError::Failed)?;

    let secret =
        serde_json::to_string(&encryptor.finish()).map_err(|_upstream| AttachmentError::Failed)?;

    Ok(SealedAttachment { ciphertext, secret })
}

/// Decrypts what [`encrypt_attachment`] produced and a product downloaded.
///
/// `secret` is [`SealedAttachment::secret`], handed back unchanged.
///
/// # The two failures are told apart, and the telling is exact
///
/// Constructing the decryptor is where a secret this library did not produce
/// is refused: bad base64, a missing hash, a version this build does not
/// know. That is [`AttachmentError::MalformedSecret`], and it is a statement
/// about the secret.
///
/// Reading is where the SHA-256 of the ciphertext is checked, at the end of
/// the stream. The source here is a slice already in memory, so a read cannot
/// fail for any of the reasons a file or a socket can -- there is no short
/// read, no interruption, no closed connection. Upstream's hash check is the
/// only thing left that can make it fail, which is what makes
/// [`AttachmentError::NotWhatWasAnnounced`] a fact rather than a guess.
pub async fn decrypt_attachment(
    ciphertext: &[u8],
    secret: &str,
) -> Result<Vec<u8>, AttachmentError> {
    let info =
        serde_json::from_str(secret).map_err(|_upstream| AttachmentError::MalformedSecret)?;

    let mut source = ciphertext;
    let mut decryptor = AttachmentDecryptor::new(&mut source, info)
        .map_err(|_upstream| AttachmentError::MalformedSecret)?;

    let mut plaintext = Vec::new();
    decryptor
        .read_to_end(&mut plaintext)
        .map_err(|_upstream| AttachmentError::NotWhatWasAnnounced)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAINTEXT: &[u8] = b"a photograph, or something shaped like one";

    #[tokio::test]
    async fn what_is_uploaded_is_not_what_was_given() {
        let sealed = encrypt_attachment(PLAINTEXT).await.unwrap();
        assert_ne!(
            sealed.ciphertext, PLAINTEXT,
            "the bytes to upload must not be the plaintext"
        );
        assert!(
            !sealed.secret.is_empty(),
            "a secret is needed to open it again"
        );
    }

    #[tokio::test]
    async fn a_round_trip_gives_back_exactly_what_went_in() {
        let sealed = encrypt_attachment(PLAINTEXT).await.unwrap();
        let opened = decrypt_attachment(&sealed.ciphertext, &sealed.secret)
            .await
            .unwrap();
        assert_eq!(opened, PLAINTEXT);
    }

    #[tokio::test]
    async fn an_empty_attachment_round_trips_rather_than_failing() {
        // Zero bytes is a file, not an error. Worth pinning: the hash check
        // runs at the end of a stream that had no middle.
        let sealed = encrypt_attachment(b"").await.unwrap();
        let opened = decrypt_attachment(&sealed.ciphertext, &sealed.secret)
            .await
            .unwrap();
        assert!(opened.is_empty());
    }

    #[tokio::test]
    async fn every_call_draws_a_new_key() {
        let once = encrypt_attachment(PLAINTEXT).await.unwrap();
        let twice = encrypt_attachment(PLAINTEXT).await.unwrap();
        assert_ne!(
            once.ciphertext, twice.ciphertext,
            "the same bytes encrypted twice must not give the same ciphertext"
        );
        assert_ne!(once.secret, twice.secret);
    }

    #[tokio::test]
    async fn one_changed_byte_is_refused_as_not_what_was_announced() {
        let sealed = encrypt_attachment(PLAINTEXT).await.unwrap();
        let mut tampered = sealed.ciphertext.clone();
        tampered[0] ^= 0x01;

        assert_eq!(
            decrypt_attachment(&tampered, &sealed.secret).await,
            Err(AttachmentError::NotWhatWasAnnounced),
            "a tampered ciphertext must be named as such, not as a generic failure"
        );
    }

    #[tokio::test]
    async fn a_truncated_download_is_refused_too() {
        let sealed = encrypt_attachment(PLAINTEXT).await.unwrap();
        let short = &sealed.ciphertext[..sealed.ciphertext.len() - 1];

        assert_eq!(
            decrypt_attachment(short, &sealed.secret).await,
            Err(AttachmentError::NotWhatWasAnnounced)
        );
    }

    #[tokio::test]
    async fn a_secret_that_is_not_json_is_refused_as_malformed() {
        let sealed = encrypt_attachment(PLAINTEXT).await.unwrap();
        assert_eq!(
            decrypt_attachment(&sealed.ciphertext, "not json").await,
            Err(AttachmentError::MalformedSecret)
        );
    }

    #[tokio::test]
    async fn a_secret_from_another_attachment_is_refused() {
        // Two well-formed secrets, and the wrong one. The hash in the secret
        // is of the *other* ciphertext, so this is the announced-bytes check
        // rather than a malformed secret -- which is exactly the distinction
        // the two kinds exist to draw.
        let mine = encrypt_attachment(PLAINTEXT).await.unwrap();
        let theirs = encrypt_attachment(b"a different file").await.unwrap();

        assert_eq!(
            decrypt_attachment(&mine.ciphertext, &theirs.secret).await,
            Err(AttachmentError::NotWhatWasAnnounced)
        );
    }
}
