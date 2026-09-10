//! Key backup, end to end through the shipped surface: set one up, watch the
//! keys leave through the pump, and open what left with the key that was
//! handed out for it.
//!
//! Its own file, for `pump_eviction.rs`'s reason exactly: the machine
//! registry and the pump's bookkeeping are process-wide, cargo gives each
//! file under `tests/` its own process, and an integration test has no access
//! to the `#[cfg(test)]` reset helpers the unit tests use.
//!
//! # What this file can prove and what it cannot
//!
//! One process holds one machine -- `create_machine` refuses a second
//! configuration and `open_store` is the same call under another name -- so
//! there is no second store here to restore *into*. What the last two steps
//! prove instead is the cryptographic round trip, which is the part that
//! could be wrong: the ciphertext `backup()` produced opens under the key
//! `create_backup` handed out, and does not open under another one. An import
//! that actually lands keys in an empty store is a device proof, not a unit
//! one, and it is the product's own restore path that exercises it.
//!
//! The count is deliberately asserted as **zero imported out of one offered**
//! at that step, and that is not a weaker assertion dressed up: this store
//! already holds that session, from before the backup, so upstream keeps what
//! it has. A run that reported one imported here would mean upstream had
//! replaced a live session with a restored copy of itself.

use matrix_crypto_core::{
    backup_state, create_backup, create_machine, disable_backup, enable_backup, mark_request_sent,
    restore_backup, share_scope_key, take_outgoing_requests, BackupError, MachineConfig,
};

/// Six digits, not `"1"`, and the choice is the point. Continuwuity 26.7.2
/// answers `POST /room_keys/version` with a six-digit integer where Synapse
/// answers with a counter from one, and the specification makes the field an
/// opaque string. A library that quietly assumed the Synapse shape would pass
/// a test written with `"1"` and fail against a real homeserver.
const VERSION: &str = "947281";

const SCOPE: &str = "!scope:example.org";

#[test]
fn keys_reach_the_backup_and_open_again_under_the_key_that_was_handed_out() {
    let dir = tempfile::tempdir().expect("temp dir");
    let store_path = dir.path().join("store").to_string_lossy().into_owned();

    // A bare `block_on` with no runtime context of its own, for the reason
    // `pump_eviction.rs` sets out at length: every call below is a library
    // call, and one that forgot its own `in_runtime` must panic here rather
    // than be carried by a context this test supplied.
    futures::executor::block_on(async move {
        create_machine(MachineConfig {
            user_id: "@alice:example.org".to_string(),
            device_id: "DEVICE1".to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        })
        .await
        .expect("the library's machine must be creatable");

        // Something to back up. Nobody receives it -- no device of that user
        // is known -- but the session is created and stored for this device's
        // own use, which is the key a backup exists to keep.
        share_scope_key(SCOPE, &["@bob:example.org".to_string()])
            .await
            .expect("sharing a scope key must not fail");

        let before = backup_state().await.expect("state must be readable");
        assert!(
            !before.enabled,
            "a machine that has never been told about a backup must not claim one"
        );
        assert_eq!(before.version, None);
        assert!(
            before.total >= 1,
            "sharing a scope key must leave this device holding a key, and it holds {}",
            before.total
        );
        assert_eq!(
            before.backed_up, 0,
            "nothing can be backed up before a backup exists"
        );

        // Nothing has happened yet: two calls here would make two unrelated
        // keys and neither would be published. The second one exists so the
        // last step can offer the wrong key to the right backup.
        let setup = create_backup();
        let someone_elses = create_backup();

        // Before the version is enabled, the pump owes no backup at all. This
        // is the guard `PendingKind::RoomKeyBackup` documents: a device that
        // has never set up a backup must not be paying for one on every sync.
        let quiet = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        assert!(
            !quiet.iter().any(|r| r.kind == "room_key_backup"),
            "no backup request may be produced before one is enabled"
        );

        enable_backup(&setup.sealing_key, VERSION)
            .await
            .expect("enabling a backup with a fresh key must not fail");

        let batch = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let request = batch
            .iter()
            .find(|r| r.kind == "room_key_backup")
            .expect("an enabled backup with an un-backed-up key owes the pump a request");

        let body: serde_json::Value =
            serde_json::from_str(&request.body).expect("the pump's body must be JSON");
        // The disclosed exception: the version belongs in the query string
        // and no field of the wire body carries it, so the pump carries it
        // alongside. A product with no way to read it here cannot build the
        // URL at all.
        assert_eq!(
            body["version"], VERSION,
            "the version a product needs for ?version= must travel with the body"
        );
        let rooms = body["rooms"].clone();
        assert!(
            rooms.get(SCOPE).is_some(),
            "the batch must carry the scope whose key was shared, and carries {rooms}"
        );

        // The real response shape: `etag` and `count`, both required.
        mark_request_sent(&request.id, r#"{"etag":"opaque","count":1}"#)
            .await
            .expect("reporting the upload must resolve the request");

        let after = backup_state().await.expect("state must be readable");
        assert!(after.enabled);
        assert_eq!(after.version, Some(VERSION.to_string()));
        assert_eq!(
            after.backed_up, after.total,
            "every key this device held must be counted as backed up once the upload is reported"
        );

        // The acknowledgement is what makes the next drain quiet. Without it
        // upstream keeps handing back the same batch for ever, which is the
        // silent non-progress the pump exists to prevent.
        let settled = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        assert!(
            !settled.iter().any(|r| r.kind == "room_key_backup"),
            "a backup with nothing left to upload must not keep asking"
        );

        // What the homeserver would answer `GET /room_keys/keys` with is the
        // `rooms` map that went up, under a `rooms` key -- so the bytes the
        // product downloads are the bytes it uploaded, and this is them.
        let downloaded = serde_json::json!({ "rooms": rooms }).to_string();

        let restored = restore_backup(&setup.restore_key, VERSION, &downloaded)
            .await
            .expect("the key that was handed out must open the backup it was handed out for");
        assert_eq!(
            restored.offered, 1,
            "the backup carried one session and the restore must say so"
        );
        assert_eq!(
            restored.imported, 0,
            "this store already holds that session, so upstream keeps what it has -- see the \
             module comment for why zero here is the assertion and not a shortfall"
        );

        assert_eq!(
            restore_backup(&someone_elses.restore_key, VERSION, &downloaded).await,
            Err(BackupError::WrongKey),
            "another backup's key must be refused as the wrong key, not accepted as an empty \
             restore"
        );

        disable_backup()
            .await
            .expect("disabling a backup must not fail");
        let stopped = backup_state().await.expect("state must be readable");
        assert!(!stopped.enabled);
        assert_eq!(stopped.version, None);
        assert_eq!(
            stopped.backed_up, 0,
            "disabling forgets what was backed up, which is what makes re-enabling upload \
             everything again"
        );
    });
}
