//! The key vault, end to end through the shipped surface: write one, open
//! it, and watch it refuse a wrong passphrase and a changed byte.
//!
//! Its own file, for `pump_eviction.rs`'s reason: the machine registry is
//! process-wide and cargo gives each file under `tests/` its own process.
//!
//! # The one property this proves that `backup.rs` cannot claim
//!
//! **A vault that has been altered fails to open.** The export format
//! carries an HMAC-SHA256 over its ciphertext, so a changed byte is caught
//! rather than decrypted into something else. That is exactly what
//! `m.megolm_backup.v1.curve25519-aes-sha2` does not do, and it is why the
//! two surfaces document their weaknesses differently. A test asserting it
//! is what stops that claim from being prose.
//!
//! As in `key_backup_round_trip.rs`, one process holds one machine, so there
//! is no second store here to import into: the count is asserted as zero
//! imported out of one offered, and that is the assertion rather than a
//! shortfall -- this store already holds that session.

use matrix_crypto_core::{
    create_key_vault, create_machine, open_key_vault, share_scope_key, MachineConfig, VaultError,
};

const HEADER: &str = "-----BEGIN MEGOLM SESSION DATA-----";
const FOOTER: &str = "-----END MEGOLM SESSION DATA-----";

const PASSPHRASE: &str = "a passphrase somebody chose";

#[test]
fn a_vault_opens_with_its_passphrase_and_refuses_everything_else() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    // A bare `block_on` with no runtime context of its own, for the reason
    // `pump_eviction.rs` sets out: a library call that forgot its own
    // `in_runtime` must panic here rather than be carried by a context this
    // test supplied.
    futures::executor::block_on(async move {
        create_machine(MachineConfig {
            user_id: "@alice:example.org".to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // A device with nothing in it still writes a valid file, which is a
        // true statement about that device rather than a failure. Asserted
        // before anything is shared, because afterwards it is unreachable.
        let empty = create_key_vault(PASSPHRASE)
            .await
            .expect("a device holding no keys must still produce a vault");
        assert!(empty.starts_with(HEADER) && empty.trim_end().ends_with(FOOTER));

        share_scope_key("!scope:example.org", &["@bob:example.org".to_string()])
            .await
            .expect("sharing a scope key must not fail");

        let vault = create_key_vault(PASSPHRASE)
            .await
            .expect("writing a vault must not fail");

        // The armoured format, not a shape of this library's own: this is
        // what makes a file written here open in Element, and one written
        // there open here.
        assert!(
            vault.starts_with(HEADER),
            "a vault must carry the format's own header"
        );
        assert!(
            vault.trim_end().ends_with(FOOTER),
            "a vault must carry the format's own footer"
        );
        assert!(
            !vault.contains(PASSPHRASE),
            "the passphrase must not survive into the file it protects"
        );

        let opened = open_key_vault(&vault, PASSPHRASE)
            .await
            .expect("the passphrase that wrote a vault must open it");
        assert_eq!(
            opened.offered, 1,
            "the vault held the one session this device had"
        );
        assert_eq!(
            opened.imported, 0,
            "this store already holds that session, so upstream keeps what it has -- \
             see the module comment for why zero here is the assertion"
        );

        assert_eq!(
            open_key_vault(&vault, "some other passphrase").await,
            Err(VaultError::WrongPassphrase),
            "another passphrase must be refused rather than opening onto nothing"
        );

        // THE DECISIVE ONE. Change a single character of the body -- not a
        // header, not the length -- and the file must refuse to open. This
        // is the property the server backup's algorithm does not have, and
        // the reason the two surfaces word their weaknesses differently.
        let altered = alter_one_body_character(&vault);
        assert_ne!(altered, vault, "the fixture must actually change something");
        assert_eq!(
            open_key_vault(&altered, PASSPHRASE).await,
            Err(VaultError::WrongPassphrase),
            "a vault with a changed byte must fail its MAC rather than decrypt to \
             something else"
        );

        // And a file that is not this format at all is a different answer,
        // because a product's sentence for it is different: nothing was
        // decrypted, so there is nothing to say about the passphrase.
        assert_eq!(
            open_key_vault("not a vault at all", PASSPHRASE).await,
            Err(VaultError::MalformedPayload)
        );
    });
}

/// Flips one base64 character in the body, leaving the headers and the
/// length alone.
///
/// Deliberately not "append a character" or "truncate": either could be
/// caught by the base64 decode rather than by the MAC, which would make the
/// assertion above pass for the wrong reason -- the property under test is
/// authentication, not framing.
fn alter_one_body_character(vault: &str) -> String {
    vault
        .lines()
        .map(|line| {
            if line.starts_with("-----") || line.is_empty() {
                return line.to_owned();
            }
            let mut chars: Vec<char> = line.chars().collect();
            // The middle, so the change is nowhere near a boundary the
            // format treats specially.
            let at = chars.len() / 2;
            chars[at] = if chars[at] == 'A' { 'B' } else { 'A' };
            chars.into_iter().collect()
        })
        .collect::<Vec<_>>()
        .join("\n")
}
