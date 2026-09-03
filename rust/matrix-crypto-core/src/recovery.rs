//! Server-side storage of this account's private signing keys, and the
//! recovery that brings them back.
//!
//! # What this is for
//!
//! Delete the application and install it again and the store goes with it.
//! Without this module, what is lost is not a cache: the account's private
//! signing keys were only ever on that device, so the new installation has
//! to be verified against another device, and every person who had verified
//! this account has to verify it again. If no other device exists, the
//! identity is gone and there is nothing to join.
//!
//! Secret storage is the answer the protocol already has. The three private
//! signing keys are encrypted under a key derived from a passphrase, and the
//! result is stored in the account's own global account data, which the
//! homeserver keeps and never reads. A reinstalled device asks for the
//! passphrase, decrypts them, and is the same identity it was before.
//!
//! # What upstream gives, and what this module had to write
//!
//! `matrix_sdk_crypto::secret_storage` is public and needs no Cargo
//! feature. It provides key generation, derivation from a passphrase,
//! reconstruction from either a passphrase or the base58 recovery key
//! **verified against a stored MAC**, encryption and decryption per secret
//! name, the account data content object for the key description, and a
//! `DecodeError` that tells a wrong passphrase from input it could not
//! parse.
//!
//! It provides none of the plumbing. There is no code anywhere upstream
//! that assembles those pieces into the five account data events a
//! recovery is made of, none that reads them back, and none that connects
//! the decrypted bytes to the crypto store: turning them into a working
//! identity is `OlmMachine::import_cross_signing_keys`, and nothing joins
//! the two. That assembly is this module.
//!
//! # This library still performs no request
//!
//! Account data is a read-then-write interaction with the homeserver, and
//! the outbound pump is shaped for fire-and-acknowledge: a pump entry is a
//! body to send and a report that it was sent, with no value coming back.
//! Rather than redefine what a pump entry means for every other kind of
//! request, the two calls here **take and return the account data as JSON**
//! and leave the two HTTP requests, a read and a write, to the product.
//! That is the shape `receive_sync_changes` already uses for the one other
//! place this library needs something from the server, and the M4 design's
//! section 5.2 is where it was settled, along with what would overturn it:
//! if the number of round trips a recovery needs turned out to be unusable
//! from a product's point of view, extending the pump becomes the better
//! trade.
//!
//! # What an empty content object means here, once, for both directions
//!
//! **`{}` is how account data is deleted in Matrix.** The client-server API
//! has no `DELETE` for a global account data event; `PUT {}` is the only
//! spelling of "cleared" it offers, and the event stays in place forever
//! afterwards with an empty content. So an empty object is not damage and
//! is not an absence: it is the tombstone the protocol leaves behind, and
//! every reader in this module has to treat it as one.
//!
//! Both directions read the pointer, and they read it through one function,
//! [`pointed_key_id`], rather than through one shared paragraph. That is
//! deliberate. The rule was written down once before, on the ancestor of
//! `names_a_recovery` (removed in `923e68e`, when [`pointed_key_id`] took
//! its place; a plain code span and not a doc link, because linking to
//! something that no longer exists is the same defect one level down), and
//! [`restore`] four hundred lines away read the same bytes the other way
//! and reported a cleared pointer as `RecoveryDataMalformed`, whose remedy
//! is to set recovery up again. A user whose recovery was intact and
//! reversibly cleared was told to destroy it. A shared paragraph did not
//! prevent that and a third reader would not have read it either.
//!
//! **What stops a third reader is a debug assertion in [`entry`], not the
//! type system, and the difference is worth stating.** `pointed_key_id` is
//! the only function that reads this event type today, but nothing about
//! Rust's visibility rules makes that so: `entry` is module-visible and the
//! event type is a string anyone can write. A reader that went around it
//! used to compile, format, pass `clippy -D warnings`, pass every gate and
//! leave every test in this file green, which was demonstrated rather than
//! supposed. It now panics the first time it runs under `cargo test`.
//!
//! A debug assertion rather than a visibility rule, on purpose. Hiding the
//! event type behind a private module would stop a reader that calls
//! [`default_key_event_type`] and would not stop one that writes
//! `"m.secret_storage.default_key"` by hand, which is the same hole one
//! keystroke further away. The assertion catches both, at the cost of being
//! a test-time check rather than a compile-time one: in a release build it
//! is compiled out and nothing stands there at all. That is the honest
//! shape of it, and it is a barrier where there was none rather than a
//! guarantee.
//!
//! The same reasoning applies one level out and is worth knowing before
//! adding a third reader: `{}` is also the real `/keys/query` answer for an
//! account with no signing identity, which is the residue
//! `session::refuse_a_non_response` could not close. An empty object is a
//! meaningful value in this protocol far more often than it is a mistake.
//!
//! # What is deliberately not here
//!
//! Key backup (`m.megolm_backup.v1`) coordination. Upstream has a separate
//! module for it and it is separate work; nothing in this module reads or
//! writes a backup key, and a recovery restored here leaves any backup
//! exactly as it found it.

use matrix_sdk_common::ruma::events::secret::request::SecretName;
use matrix_sdk_common::ruma::events::secret_storage::default_key::SecretStorageDefaultKeyEventContent;
use matrix_sdk_common::ruma::events::secret_storage::key::SecretStorageKeyEventContent;
use matrix_sdk_common::ruma::events::secret_storage::secret::SecretEventContent;
use matrix_sdk_common::ruma::events::{EventContentFromType, GlobalAccountDataEventContent};
use matrix_sdk_crypto::secret_storage::{DecodeError, SecretStorageKey};
use matrix_sdk_crypto::store::types::CrossSigningKeyExport;
use matrix_sdk_crypto::store::SecretImportError;
use matrix_sdk_crypto::OlmMachine;

use crate::machine::{with_machine, MachineError};

/// One global account data event, as the homeserver stores it.
///
/// `content` is the event's content object as JSON, exactly the body of a
/// `PUT /user/{id}/account_data/{type}` and exactly what the matching `GET`
/// answers with. This library never adds an envelope of its own around it,
/// so a product moves these bytes to and from the homeserver unchanged.
///
/// No `Debug` derive: these entries carry the account's encrypted private
/// signing keys, and a derived one leaves a ciphertext a single `{:?}` away
/// from a log. The FFI mirror has refused it for that reason since it was
/// written; this copy had drifted.
///
/// The sentence above documents the invariant; the compile-fail doctest
/// below enforces it. It exists because the drift this comment describes
/// went unnoticed until it was found by review: a prose rule does not fail
/// CI, a `compile_fail` test does.
///
/// The doctest takes the trait bound directly rather than constructing a
/// value and formatting it, and that choice is the guard's whole point: a
/// `compile_fail` block passes on any compiler error, so a snippet that
/// names the record's fields could keep passing after `Debug` returns, on
/// an error no one intended, the day a field is added or renamed. Naming
/// only the type leaves the missing `Debug` impl as the sole possible
/// error, so the block fails if and only if the derive comes back.
///
/// ```compile_fail
/// fn requires_debug<T: std::fmt::Debug>() {}
///
/// // Compiles only while `AccountDataEntry` has no `Debug` impl; mentions
/// // no field, so a field changing shape cannot make the block pass.
/// requires_debug::<matrix_crypto_core::AccountDataEntry>();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct AccountDataEntry {
    /// The global account data event type, such as
    /// `m.secret_storage.default_key`.
    pub event_type: String,
    /// The event's content object, as JSON.
    pub content: String,
}

/// Everything [`create_recovery`] produced: the one secret to show the user,
/// and the account data to write.
///
/// No `Debug` derive: `recovery_key` opens this account's stored identity
/// and must never reach a log. An absence rather than the redacting `Debug`
/// `MachineConfig` and `Envelope` hand-write -- redact both fields here and
/// nothing worth printing is left, so refusing the derive turns the call
/// site into a compile error instead.
///
/// `a_second_recovery_refuses_rather_than_taking_the_first_one_away` already
/// says this type has no derive. That was untrue when it was written.
///
/// Same guard as [`AccountDataEntry`], and the same shape for the same
/// reason: the compile-fail doctest below takes the `Debug` bound directly
/// instead of constructing a value. A `compile_fail` block passes on any
/// compiler error, and a snippet that fills in the record's fields could
/// keep passing after `Debug` returns, on a field-rename error no one
/// intended. Naming only the type leaves the missing impl as the sole
/// possible error.
///
/// ```compile_fail
/// fn requires_debug<T: std::fmt::Debug>() {}
///
/// // Compiles only while `RecoverySetup` has no `Debug` impl; mentions no
/// // field, so a field changing shape cannot make the block pass.
/// requires_debug::<matrix_crypto_core::RecoverySetup>();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct RecoverySetup {
    /// The base58 recovery key, formatted in groups of four characters as
    /// the specification requires.
    ///
    /// **This value is not stored anywhere and cannot be produced again.**
    /// It is the passphrase's equal, not a backup of it: either one opens
    /// this recovery, and losing both loses the identity. Show it once, and
    /// mean it.
    pub recovery_key: String,
    /// The account data to write, in the order it should be written.
    ///
    /// Five events: the key description, one per private signing key, and
    /// the pointer that makes the new key this account's default.
    ///
    /// **The pointer is last and the order matters.** Everything before it
    /// adds to the account without changing what any client currently
    /// resolves, so a product interrupted partway through has written a key
    /// description and some ciphertexts that nothing points at, and whatever
    /// recovery the account had before still works. Writing the pointer
    /// earlier would repoint the account at a key whose secrets do not exist
    /// yet, which is a window in which neither the old recovery nor the new
    /// one opens the account.
    pub account_data: Vec<AccountDataEntry>,
}

/// Errors must not carry an identifier or key material, so an upstream
/// store failure reports its shape and nothing else. The same rule and the
/// same fixed string as `machine.rs`'s `store_error_detail`, `identity.rs`'s
/// `store_failed`, `signing.rs`'s and `verification.rs`'s.
fn store_failed() -> MachineError {
    MachineError::Store {
        detail: "the crypto store could not be opened".to_string(),
    }
}

/// The three secrets a recovery carries, in the order they are written and
/// read.
///
/// One list, used by both directions, so a name added to one and not the
/// other cannot happen.
const SECRETS: [SecretName; 3] = [
    SecretName::CrossSigningMasterKey,
    SecretName::CrossSigningSelfSigningKey,
    SecretName::CrossSigningUserSigningKey,
];

/// The account data event type that names which key is the account's
/// default.
///
/// Built from ruma's own content type rather than written as a literal, so
/// the string comes from the same place the parse below expects it.
fn default_key_event_type() -> String {
    SecretStorageDefaultKeyEventContent::new(String::new())
        .event_type()
        .to_string()
}

/// The content of the first entry whose type matches, if any.
///
/// The **first**, not the only one: a caller may hand over a list built
/// from more than one source, and duplicates of a global account data type
/// are the same event by definition. Taking the first is a rule rather than
/// an accident, and it is the one a `/sync` response's own ordering
/// produces.
fn entry<'a>(account_data: &'a [AccountDataEntry], event_type: &str) -> Option<&'a str> {
    // The default-key pointer is read through `pointed_key_id` and through
    // nothing else, and this is what makes that a rule rather than a habit.
    // Two functions reading these bytes and disagreeing about `{}` is the
    // defect this module was corrected for; a third reader is one `entry`
    // call away, and before this line it compiled, linted and tested clean.
    //
    // `debug_assert!`, so a release build carries no check and no panic: the
    // audience for this is whoever adds the third reader, and they run the
    // tests. See this module's own documentation for why the alternative,
    // hiding the event type, would close less of the hole than it looks.
    debug_assert!(
        event_type != default_key_event_type(),
        "read the default-key pointer through `pointed_key_id`, which is \
         where the rule about what an empty content object means lives. \
         Reading it here means two functions decide that question, which is \
         the defect this module was corrected for."
    );
    account_data
        .iter()
        .find(|entry| entry.event_type == event_type)
        .map(|entry| entry.content.as_str())
}

/// The key id this account data points at, if it points at one.
///
/// **The one reading of `m.secret_storage.default_key` in this module.**
/// [`create_recovery`] asks it whether there is a recovery to protect and
/// [`restore`] asks it which key to open, and they must not be able to
/// disagree: for one round of this task they did, and the answer a user got
/// was that their intact recovery was destroyed. See this module's own
/// documentation on what an empty content object means.
///
/// **The pointer decides, and nothing else does.** It is what every Matrix
/// client follows to find the key it should ask for, so an account whose
/// pointer names a key has a recovery somebody can open, and taking that
/// pointer away is what takes the recovery away.
///
/// Four inputs and one rule, and only the first is a recovery:
///
/// * naming a key id: that key is the account's default.
/// * absent: no client would look for a key, so there is none to find.
/// * an empty object: cleared, which is the only way the client-server API
///   can express a deletion, so it means the same as absent and must.
/// * anything else, including content that is not JSON or that names no
///   `key`: no client can follow it, so it points at nothing.
///
/// The last three are one answer here and stay one answer at both call
/// sites. `create_recovery` writes; `restore` reports
/// [`MachineError::RecoveryNotSetUp`], whose meaning is "the account data
/// handed over carries no complete recovery" and whose remedy is to supply
/// more of it or to create one. Neither is
/// [`MachineError::RecoveryDataMalformed`], because none of the three says
/// anything is damaged.
fn pointed_key_id(account_data: &[AccountDataEntry]) -> Option<String> {
    // Not through `entry`: that helper refuses this event type, which is
    // what makes this function the only reader. The lookup is three lines
    // and duplicating them here is the price of the guard being real.
    let pointer = default_key_event_type();
    account_data
        .iter()
        .find(|entry| entry.event_type == pointer)
        .map(|entry| entry.content.as_str())
        .and_then(|content| serde_json::from_str::<serde_json::Value>(content).ok())
        .and_then(|content| content.get("key")?.as_str().map(str::to_owned))
        .filter(|key_id| !key_id.is_empty())
}

/// The `encrypted` map already stored for one secret, if the account data
/// carries a readable one.
///
/// Merging into it rather than replacing it is the difference between
/// adding a key to this account's secret storage and quietly evicting every
/// other key from it. The specification's shape is a map from key id to
/// ciphertext precisely so that several keys can open the same secret, and
/// another client's entry under its own key id is none of this library's
/// business to remove.
///
/// An unreadable existing value is replaced rather than merged into, and
/// nothing is lost by that: a secret whose `encrypted` map cannot be parsed
/// carries nothing any client could have used.
fn existing_ciphertexts(
    account_data: &[AccountDataEntry],
    name: &SecretName,
) -> serde_json::Map<String, serde_json::Value> {
    entry(account_data, name.as_str())
        .and_then(|content| serde_json::from_str::<serde_json::Value>(content).ok())
        .and_then(|content| content.get("encrypted").cloned())
        .and_then(|encrypted| match encrypted {
            serde_json::Value::Object(map) => Some(map),
            _other => None,
        })
        .unwrap_or_default()
}

/// Writes this account's private signing keys into server-side storage,
/// under a key derived from `passphrase`.
///
/// `account_data` is the account's existing global account data, read back
/// from the homeserver the same way [`recover_identity`] takes it. It is
/// required rather than optional because this call refuses to write over a
/// recovery the account already has, and an empty list is a caller saying
/// there is none.
///
/// Returns the recovery key to show the user and the account data to write.
/// **Nothing here reaches the network**, and nothing is written until the
/// product writes it: on success, `PUT` each entry of
/// [`RecoverySetup::account_data`] to
/// `/_matrix/client/v3/user/{userId}/account_data/{eventType}` with the
/// entry's content as the body, **in the order they are handed back**.
///
/// The order is load-bearing and the pointer is last. Everything before it
/// adds to the account without changing what any client currently resolves;
/// the pointer is the single step that switches the account over. A product
/// interrupted anywhere before it has written a key description and some
/// ciphertexts nothing points at, and the recovery that was already there,
/// if any, still works.
///
/// # What this costs the user, said once
///
/// The recovery key comes back exactly once and is never stored. Losing it
/// **and** forgetting the passphrase loses the account's identity: nothing
/// on the server can open the stored keys without one of them, and this
/// library has no second copy. A product that shows the key and moves on
/// without making the user record it has built the support burden into its
/// first screen.
///
/// # The passphrase is the weak half, and this library imposes no rule on it
///
/// The encrypted keys live on the homeserver, so the passphrase is what
/// stands between anyone who can read this account's account data and the
/// account's private signing keys. `create_recovery("")` is accepted, and so
/// is any other passphrase: **no minimum length, no strength estimate and no
/// refusal**. That is a decision rather than an omission. Any threshold this
/// library picked would be arbitrary, would be wrong for somebody, and would
/// be enforced in the one place a product cannot adjust it; a product knows
/// its users and its threat model and this call does not. Choose a policy
/// and apply it before calling.
///
/// **A strong recovery key does not offset a weak passphrase, and this
/// paragraph used to imply that it did.** Secret storage opens on either
/// credential, so what an attacker who can read this account data has to
/// beat is the *weaker* of the two: thirty-two random bytes are no help at
/// all while `""` also opens the same ciphertext. What the recovery key
/// protects is the user's own access, not the secret's confidentiality, and
/// that is the reason to make them record it.
///
/// # This is the interoperable format
///
/// The account data written here is Matrix's own secret storage, the
/// `m.secret_storage.v1.aes-hmac-sha2` scheme, produced by upstream's own
/// implementation of it. Another Matrix client signed into the same account
/// reads the same five events with the same passphrase or recovery key, and
/// a recovery another client wrote is one [`recover_identity`] restores.
/// Nothing about the container is this library's invention.
///
/// Interoperability is also why the ciphertexts are **merged** rather than
/// replaced. Each `m.cross_signing.*` event holds a map from key id to
/// ciphertext so that more than one key can open the same secret, and this
/// call adds its own entry to whatever it was handed instead of writing a
/// map of one. Another client's entry under its own key id is not this
/// library's to remove.
///
/// # Refusals
///
/// [`MachineError::RecoveryAlreadyExists`] if `account_data` names a
/// recovery already. **This call will not write over one**, and the reason
/// is that it cannot tell the two callers apart: a user replacing their own
/// passphrase, where the old recovery key is meant to stop working, and a
/// product writing a first recovery for a user who already set one up in
/// another client, where the key that stops working is one somebody wrote
/// down and was told to keep forever. Both arrive here as the same call.
///
/// **To add a recovery deliberately, call this again with the same account
/// data minus the `m.secret_storage.default_key` entry.** Drop that one
/// entry from the list; write nothing to the server to arrange it. The
/// refusal lifts because nothing points at a key any more, everything else
/// is still in the list so the ciphertexts still merge, and the recovery the
/// account has goes on working until the last `PUT` of the new pointer
/// switches it over. There is no window in which the account has no working
/// recovery, and nothing to roll back if the product stops halfway.
///
/// # Adding a key is not revoking one, and this call cannot do the second
///
/// **That route re-points the account. It does not revoke anything.** When
/// it finishes, the old key description is still on the server and the old
/// key's ciphertext is still in every `encrypted` map, because the merge is
/// exactly what the route is recommended for. Anyone holding the old
/// passphrase and able to read this account's account data can still open
/// the account's private signing keys, by reading the old description
/// directly instead of following the pointer. `recover_identity` will not do
/// that, because it follows the pointer; nothing else is stopped, and a
/// homeserver operator or anyone with a live access token is not obliged to
/// follow pointers.
///
/// That is the right default and it is not what every caller wants. The
/// refusal above names two callers it cannot tell apart, and the first of
/// them, a user replacing a passphrase they no longer trust, needs the old
/// key to stop working. **This call cannot decide that for them**, for the
/// same reason it refuses in the first place: the entry it would have to
/// drop is indistinguishable from another client's, and dropping the wrong
/// one takes away a recovery key somebody was told to keep forever.
///
/// So revocation is one further act, performed by the product, on data this
/// call has already handed back:
///
/// 1. take the returned `account_data` and remove the **old** key id from
///    each `m.cross_signing.*` entry's `encrypted` map, leaving the new one;
/// 2. `PUT` the entries in the order they were handed back, pointer last, as
///    always;
/// 3. **afterwards**, and only afterwards, `PUT {}` to
///    `m.secret_storage.key.<old id>`.
///
/// The cost is stated plainly because it is the same destruction this
/// refusal exists to prevent, performed on purpose: after step 1 the old key
/// opens nothing on this account, whoever it belonged to. Do it only for a
/// key this product created.
///
/// **Do not clear the key description before the new pointer is live.** That
/// ordering is what makes the difference between a rotation and a loss: the
/// description is where the salt, the iteration count and the MAC live, so a
/// key whose description is gone can never be reconstructed from any secret,
/// and clearing it while it is still the account's default leaves the
/// account with a pointer at nothing recoverable. Step 3 above is the same
/// write performed after the switchover, when the key it describes is no
/// longer the one the account resolves. The refusal itself reads the pointer
/// and only the pointer, so clearing the description buys nothing at all
/// before step 2.
///
/// Two other routes lift the refusal, and both cost something the route
/// above does not:
///
/// * **Clearing the pointer on the server** (`PUT {}`, which is how the
///   client-server API deletes account data) works, and the ciphertexts
///   still merge because everything else is still in the list. What it costs
///   is a window: between that write and the last one the account resolves
///   no recovery, and a product that stops in the middle leaves it there.
/// * **Passing an empty list** works too, and costs the merge. This call
///   merges into what it is handed, so handed nothing it merges into
///   nothing, and every other key's ciphertext, including another client's,
///   is evicted from the account. It asserts a fact rather than describing
///   one, so use it only for an account that genuinely has no account data.
///
/// **This call believes the account data it is handed**, which is what makes
/// all three possible. A caller that passes an empty list asserts the
/// account has no recovery and the refusal believes it, exactly as
/// `crate::bootstrap_identity`'s gate believes a key query reported as
/// answered. That is unavoidable in a library that performs no request of
/// its own, and it is said rather than left to be discovered: what this
/// refusal buys is not that destruction is impossible, but that a product
/// has to have *looked*, and that the cheapest way past it is also the one
/// that destroys nothing. What it does not buy, and what nothing in this
/// call can buy, is that the key it replaced has stopped working: that is
/// the further act above.
///
/// [`MachineError::AccountKeysNotFetched`] if this process has not yet asked
/// the server about this account. The keys this device holds may belong to
/// an identity the account has already replaced, which is exactly the case
/// `crate::bootstrap_identity`'s gate exists for, and a recovery written for
/// them opens correctly and restores an identity the account no longer has.
/// This call queues that key query as it refuses, so the remedy is the
/// ordinary loop: drain the pump, send, report sent, call this again.
///
/// [`MachineError::PrivateKeysNotHeld`] if this device does not hold all
/// three private signing keys. There is nothing to write, and a partial
/// write would be worse than none: it would leave account data that opens
/// with the right passphrase and restores an incomplete identity.
/// [`crate::identity_status`] says which of the two remedies applies, which
/// are [`crate::create_identity`] for an account with no identity, once the
/// product has decided this account should be getting its first one, and
/// [`crate::request_self_flow`] for one this device has not joined yet.
pub async fn create_recovery(
    passphrase: &str,
    account_data: &[AccountDataEntry],
) -> Result<RecoverySetup, MachineError> {
    let passphrase = passphrase.to_string();
    let account_data = account_data.to_vec();
    with_machine(move |machine| {
        Box::pin(async move { write(machine, &passphrase, &account_data).await })
    })
    .await?
}

/// The whole of [`create_recovery`] once a machine is in hand.
///
/// Separate so that the `with_machine` closure stays a single expression,
/// matching [`restore`] below.
async fn write(
    machine: &OlmMachine,
    passphrase: &str,
    account_data: &[AccountDataEntry],
) -> Result<RecoverySetup, MachineError> {
    // The argument is checked before the machine, unlike `restore` below,
    // and the order is deliberate in both. There, the machine check is a
    // precondition that saves half a million PBKDF2 iterations. Here, the
    // refusal that protects something a user already has comes first: a
    // caller whose account already has a recovery should be told that
    // whatever else is true of its process.
    if pointed_key_id(account_data).is_some() {
        return Err(MachineError::RecoveryAlreadyExists);
    }

    // The same gate `bootstrap_identity` and `recover_identity` carry, and
    // for the reason `signing.rs` states at length: a store restored from a
    // backup, or one whose account had its identity reset from another
    // device, holds a *complete* private identity the server has already
    // replaced, and only a key query dislodges it. Writing a recovery for
    // those keys produces account data that opens perfectly and restores an
    // identity the account no longer has, and the failure surfaces much
    // later, at `recover_identity`, as unreadable data.
    let status = crate::signing::read_status(machine).await?;
    if status.account_keys_fetched && status.identity_publication_pending {
        // **A recovery for an identity no homeserver has ever accepted.**
        //
        // The private keys are real and complete, so every other check here
        // passes, and the account data this call returns opens perfectly
        // with the passphrase. What it restores is an identity that exists
        // on one device and nowhere else. Measured: a user who sets recovery
        // up during an interrupted sign-up is shown a recovery key, writes it
        // down, and months later on a new phone gets `RecoveryDataMalformed`
        // -- and the remedy that error names, running this call again,
        // answers `PrivateKeysNotHeld` on a device that holds nothing. Every
        // door shut but one, and that one needs the device they no longer
        // have.
        //
        // Refusing costs a user one call: `crate::create_identity` finishes
        // the publication, the confirming answer clears the record, and this
        // call is served. That is the whole cost, and it is paid before the
        // recovery key is ever shown rather than months afterwards.
        //
        // `IdentityNotKnown` rather than a new variant: what it says is that
        // the account has no identity this library can point at, which is
        // exactly true here, and its documented remedy is already
        // `create_identity`.
        return Err(MachineError::IdentityNotKnown);
    }
    if !status.account_keys_fetched {
        // Queued by the refusal, exactly as `bootstrap_identity` and
        // `recover_identity` do, so the refusal is recoverable rather than
        // a dead end on any process that shared a key before writing.
        let (id, request) = machine.query_keys_for_users(std::iter::once(machine.user_id()));
        crate::session::queue_account_key_query(id, request);
        return Err(MachineError::AccountKeysNotFetched);
    }

    let export = machine
        .export_cross_signing_keys()
        .await
        .map_err(|_upstream| store_failed())?
        .ok_or(MachineError::PrivateKeysNotHeld)?;

    // Cloned field by field, which is the one place in this crate that does
    // not destructure an upstream struct. It cannot: `CrossSigningKeyExport`
    // is `ZeroizeOnDrop`, so it implements `Drop` and Rust forbids moving
    // its fields out. The rule Global Constraints states, that a field added
    // upstream must fail this build rather than be silently dropped, is kept
    // by the exhaustive `let ... else` immediately below instead: it names
    // all three fields, and a fourth private key upstream added would be
    // visible as an export whose contents this module knowingly ignores
    // rather than as a compile error.
    let master_key = export.master_key.clone();
    let self_signing_key = export.self_signing_key.clone();
    let user_signing_key = export.user_signing_key.clone();

    // `Some` for all three, not merely a non-`None` export. Upstream returns
    // `Some` as soon as any one of them is present, and a store holding one
    // seed of three is exactly the half-recovered state this refusal exists
    // to keep out of account data.
    let (Some(master), Some(self_signing), Some(user_signing)) =
        (master_key, self_signing_key, user_signing_key)
    else {
        return Err(MachineError::PrivateKeysNotHeld);
    };

    let key = SecretStorageKey::new_from_passphrase(passphrase);
    let key_id = key.key_id().to_string();

    let mut entries = Vec::with_capacity(2 + SECRETS.len());
    entries.push(AccountDataEntry {
        event_type: key.event_type().to_string(),
        content: to_json(key.event_content())?,
    });

    for (name, seed) in SECRETS.iter().zip([master, self_signing, user_signing]) {
        // The plaintext is the seed exactly as upstream exports it, an
        // unpadded base64 string, which is what the specification puts in
        // these events and what every other client expects to find there.
        // Encoding it any other way would produce account data only this
        // library could read.
        let encrypted = key.encrypt(seed.into_bytes(), name);
        let mut ciphertexts = existing_ciphertexts(account_data, name);
        ciphertexts.insert(
            key_id.clone(),
            serde_json::to_value(encrypted).map_err(|_| store_failed())?,
        );
        entries.push(AccountDataEntry {
            event_type: name.as_str().to_string(),
            content: to_json(&serde_json::json!({ "encrypted": ciphertexts }))?,
        });
    }

    // Last, and this is the order a product must preserve. Everything above
    // adds to the account without changing what any client resolves today;
    // this is the single step that switches the account over to the key just
    // written, so an interrupted write leaves whatever was there working.
    entries.push(AccountDataEntry {
        event_type: default_key_event_type(),
        content: to_json(&SecretStorageDefaultKeyEventContent::new(key_id.clone()))?,
    });

    Ok(RecoverySetup {
        recovery_key: key.to_base58(),
        account_data: entries,
    })
}

/// Serialises a value that cannot reasonably fail to serialise.
///
/// A failure here would be an upstream type whose `Serialize` refuses, not
/// anything a caller did, so it reports as a store-shaped failure rather
/// than inventing a variant nothing can reach.
fn to_json<T: serde::Serialize>(value: &T) -> Result<String, MachineError> {
    serde_json::to_string(value).map_err(|_upstream| store_failed())
}

/// Restores this account's private signing keys from server-side storage.
///
/// `secret` is **either** the passphrase [`create_recovery`] derived the key
/// from **or** the base58 recovery key it returned. Upstream tries the
/// passphrase first and falls back to the recovery key, so one parameter
/// serves both and a product need not ask the user which one they are
/// holding.
///
/// `account_data` is what the product read back from the homeserver. Five
/// events are needed and a complete recovery has all five:
/// `m.secret_storage.default_key`, the `m.secret_storage.key.<id>` it names,
/// and `m.cross_signing.master`, `m.cross_signing.self_signing` and
/// `m.cross_signing.user_signing`. They may be fetched individually with
/// `GET /_matrix/client/v3/user/{userId}/account_data/{eventType}`, or taken
/// out of a `/sync` response's global account data, which carries all of
/// them. Entries this call does not need are ignored, so handing over the
/// whole of an account's global account data is fine.
///
/// **The key description's type is not known in advance**, because it ends
/// in the key's own id: read `m.secret_storage.default_key` first, and its
/// `key` field is that id. A product fetching events one at a time
/// therefore needs two rounds, which is the cost this shape was chosen with
/// (M4 design section 5.2).
///
/// # What this does not do
///
/// It asks the server nothing and it sends nothing. The device that
/// recovers still has to publish its own device keys, and the identity it
/// has just rejoined still has to sign that device, which is
/// [`crate::bootstrap_identity`]'s republication. What recovery restores is
/// the ability to do those things at all, and every verification anyone
/// else had made of this account, which is the part a second device could
/// not give back.
///
/// # Refusals, and the one distinction a product's error message needs
///
/// [`MachineError::RecoveryKeyIncorrect`] means the secret is wrong and the
/// stored recovery is intact: ask again.
/// [`MachineError::RecoveryDataMalformed`] means no secret will ever open
/// it: stop asking, and set recovery up again from a device that still
/// holds the keys. **These two are never folded together**, because folding
/// them either tells a user with a typo that their identity is destroyed or
/// leaves a user whose recovery really is destroyed retyping forever. The
/// line comes from upstream rather than from a guess here: a passphrase or
/// recovery key is verified against a MAC stored beside the key
/// description, and `DecodeError::Mac` is that check failing.
///
/// [`MachineError::RecoveryNotSetUp`] means the account data handed over
/// carries no complete recovery. Either there is none, or not all of it was
/// fetched; see the variant's own documentation for why this call cannot
/// tell those apart.
///
/// [`MachineError::AccountKeysNotFetched`] and
/// [`MachineError::IdentityNotKnown`] are the same pair
/// [`crate::bootstrap_identity`] and [`crate::request_self_flow`] report,
/// and they are checked first, before the passphrase is even derived. The
/// reason is upstream's: importing private keys needs the account's
/// **public** identity already in the store, so that each seed can be
/// checked against the key it claims to be. Without it upstream logs and
/// does nothing, which is the silent success this call exists not to
/// return. `AccountKeysNotFetched` queues the key query that lifts it, so
/// the remedy is the ordinary loop: drain the pump, send, report sent, call
/// this again.
pub async fn recover_identity(
    secret: &str,
    account_data: &[AccountDataEntry],
) -> Result<(), MachineError> {
    let secret = secret.to_string();
    let account_data = account_data.to_vec();
    with_machine(move |machine| {
        Box::pin(async move { restore(machine, &secret, &account_data).await })
    })
    .await?
}

/// Which upstream decode failure is a wrong secret and which is a stored
/// recovery that cannot be read.
///
/// **The whole point of keeping [`MachineError::RecoveryKeyIncorrect`] and
/// [`MachineError::RecoveryDataMalformed`] apart lives in this function**,
/// so the question it answers is asked once, of every variant, by name.
///
/// # The rule
///
/// Upstream's `DecodeError` mixes two subjects that its own name does not
/// separate: some variants describe the string the user just typed, and
/// some describe the key description this library read back from the
/// server. The first set is a wrong secret and the user retypes it; the
/// second is a recovery no secret will ever open.
///
/// # Why this was wrong once, and what it cost
///
/// This was a single `Mac` arm and a wildcard, on the reasoning that
/// "every other variant describes input that could not be parsed at all".
/// That premise is false, and the case it is false in is the one a product
/// most needs right. `SecretStorageKey::from_account_data`
/// (`matrix-sdk-crypto-0.18.0/src/secret_storage.rs`) branches on whether
/// the key description carries a `passphrase` block. **With** one it tries
/// the passphrase, falls back to base58, and on double failure returns the
/// passphrase error, which is `Mac`. **Without** one, which the
/// specification permits, which upstream handles explicitly and which
/// another client's recovery can perfectly well be, it goes straight to the
/// base58 path, whose failures are `Base58`, `Prefix`, `Parity` and
/// `KeyLength`. Every one of those describes the typed secret, and every
/// one of them landed in the wildcard.
///
/// So a user with a one-character typo in their recovery key was told their
/// stored data was unreadable, whose documented remedy is to set recovery
/// up again, which is the single action that destroys the recovery they
/// were trying to open. That is precisely the harm this pair of variants
/// exists to prevent, arrived at through the one path no fixture reached,
/// because `create_recovery` always writes a passphrase block.
///
/// # Exhaustive, and no wildcard
///
/// `DecodeError` is not `#[non_exhaustive]`, so every variant is named. A
/// variant upstream adds later must fail this build rather than fall
/// through to whichever answer the wildcard happened to give, which is
/// exactly how the defect above survived.
fn classify_decode_error(upstream: DecodeError) -> MachineError {
    // Matched by variant, not by text, like every other upstream error this
    // crate classifies.
    match upstream {
        // The typed secret. `Mac` is the reconstructed key failing its own
        // check, which a wrong passphrase and a wrong recovery key both
        // produce. The other four come out of `parse_base58_key` and
        // describe the characters the user entered: not base58 at all, the
        // wrong length once decoded, the wrong two-byte prefix, or a parity
        // byte that does not match the key it is meant to check.
        DecodeError::Mac(_)
        | DecodeError::Base58(_)
        | DecodeError::KeyLength(_, _)
        | DecodeError::Prefix(_, _)
        | DecodeError::Parity(_, _) => MachineError::RecoveryKeyIncorrect,
        // The stored key description. The iteration count is the one that
        // looks like it could be about the secret and is not: it is the
        // count the *description* asks for, refused because it does not fit
        // in this platform's `usize`, and no secret changes it. `IvLength`
        // and `MacLength` are the description's own check fields being the
        // wrong size, and `UnsupportedAlgorithm` is a scheme this build
        // does not implement.
        //
        // `Base64` is unreachable from this call in
        // `matrix-sdk-crypto` 0.18.0: it exists as a `#[from]` conversion
        // and nothing on the path from `from_account_data` constructs one.
        // Named rather than left to a wildcard anyway, and put here because
        // if it ever becomes reachable it will be a field of the stored
        // description that failed to decode.
        DecodeError::Base64(_)
        | DecodeError::IvLength(_, _)
        | DecodeError::MacLength(_, _)
        | DecodeError::UnsupportedAlgorithm(_)
        | DecodeError::KdfIterationCount(_) => MachineError::RecoveryDataMalformed,
    }
}

/// The whole of [`recover_identity`] once a machine is in hand.
///
/// Separate so that the `with_machine` closure stays a single expression
/// and the ordering below can be read as one sequence.
async fn restore(
    machine: &OlmMachine,
    secret: &str,
    account_data: &[AccountDataEntry],
) -> Result<(), MachineError> {
    // The cheap preconditions first, and they are preconditions rather than
    // courtesies: without the account's public identity in the store,
    // upstream's import checks nothing and stores nothing. Deriving a key
    // from a passphrase costs half a million PBKDF2 iterations, so a caller
    // that has not asked the server yet is turned away before paying for
    // it.
    //
    // **The gate is checked first and on its own**, and it used to be
    // nested inside `!identity_known`, which meant a store that already
    // held a public identity skipped it entirely. This comment and
    // `recover_identity`'s own doc both said this call "carries the same
    // gate" as `bootstrap_identity` and `create_recovery`; for that one
    // shape it did not.
    //
    // The shape is not exotic. It is the restored backup: a store holding a
    // *stale* public identity and the private keys that match it, in a
    // process that has asked the server nothing. Reached there, this call
    // imports a recovery's private keys, checks them against the stale
    // public identity, finds them consistent, and leaves the device holding
    // keys for an identity the account has replaced -- the same destruction
    // `tests/identity_bootstrap_contradicted_answer.rs` closes for the
    // other two callers, arrived at through the one that was not checking.
    let status = crate::signing::read_status(machine).await?;
    if status.account_keys_fetched && status.identity_publication_pending {
        // Importing into an identity no homeserver has accepted. Upstream
        // checks each imported seed against the store's **public** identity,
        // which here is one this device minted and nothing has confirmed, so
        // a successful import would leave the device holding keys for an
        // identity the account may never have. The remedy is the same one
        // `create_recovery` names: finish the publication first.
        return Err(MachineError::IdentityNotKnown);
    }
    if !status.account_keys_fetched {
        // Queued by the refusal, exactly as `bootstrap_identity` does and
        // for the same reason: upstream volunteers an own-account key query
        // only while the account is not yet tracked, so on any process that
        // has already shared a key this refusal would otherwise be
        // permanent.
        let (id, request) = machine.query_keys_for_users(std::iter::once(machine.user_id()));
        crate::session::queue_account_key_query(id, request);
        return Err(MachineError::AccountKeysNotFetched);
    }
    if !status.identity_known {
        return Err(MachineError::IdentityNotKnown);
    }

    // Through [`pointed_key_id`], so that this and `create_recovery` cannot
    // come to disagree about what a pointer says. They did: this read used
    // to parse the content into ruma's own type and report a parse failure
    // as `RecoveryDataMalformed`, which meant a *cleared* pointer, the state
    // `create_recovery`'s remedy tells a product to create, was reported as
    // damaged stored data. The remedy for damaged stored data is to set
    // recovery up again, so a user whose recovery was intact and one `PUT`
    // away from working was told to destroy it.
    let key_id = pointed_key_id(account_data).ok_or(MachineError::RecoveryNotSetUp)?;

    // The key description's event type carries the key id, so it is built
    // here rather than searched for by prefix: an account may hold several
    // key descriptions, and the default key names exactly one of them.
    let description_type = format!("m.secret_storage.key.{key_id}");
    let description =
        entry(account_data, &description_type).ok_or(MachineError::RecoveryNotSetUp)?;
    let description = serde_json::value::RawValue::from_string(description.to_string())
        .map_err(|_| MachineError::RecoveryDataMalformed)?;
    // `from_parts`, not a plain deserialise: the key id lives in the event
    // type rather than in the content, and this is upstream's own way of
    // putting the two back together.
    let description = SecretStorageKeyEventContent::from_parts(&description_type, &description)
        .map_err(|_| MachineError::RecoveryDataMalformed)?;

    let key =
        SecretStorageKey::from_account_data(secret, description).map_err(classify_decode_error)?;

    let mut seeds = Vec::with_capacity(SECRETS.len());
    for name in &SECRETS {
        let stored = entry(account_data, name.as_str()).ok_or(MachineError::RecoveryNotSetUp)?;
        let stored: SecretEventContent =
            serde_json::from_str(stored).map_err(|_| MachineError::RecoveryDataMalformed)?;
        // Absent under *this* key id is `RecoveryNotSetUp` rather than
        // malformed: the event is well formed and simply does not carry a
        // copy encrypted to the key the account calls its default, which is
        // an incomplete recovery and not damaged data.
        let encrypted = stored
            .encrypted
            .get(&key_id)
            .ok_or(MachineError::RecoveryNotSetUp)?
            .deserialize_as_unchecked()
            .map_err(|_| MachineError::RecoveryDataMalformed)?;
        // A MAC failure here is not a wrong secret: the secret already
        // passed its own MAC check above, so what failed is this
        // ciphertext.
        let plaintext = key
            .decrypt(&encrypted, name)
            .map_err(|_| MachineError::RecoveryDataMalformed)?;
        seeds.push(String::from_utf8(plaintext).map_err(|_| MachineError::RecoveryDataMalformed)?);
    }

    let mut seeds = seeds.into_iter();
    let export = CrossSigningKeyExport {
        master_key: seeds.next(),
        self_signing_key: seeds.next(),
        user_signing_key: seeds.next(),
    };

    let imported = machine
        .import_cross_signing_keys(export)
        .await
        .map_err(|upstream| match upstream {
            SecretImportError::Store(_) => store_failed(),
            // `Key` is a seed that is not a signing key;
            // `MismatchedPublicKeys` is a recovery written for an identity
            // this account has since replaced. Both are folded, and
            // `MachineError::RecoveryDataMalformed`'s own documentation
            // says why and what would change that.
            _other => MachineError::RecoveryDataMalformed,
        })?;

    // Upstream's import is documented to return the private identity's
    // status rather than an error when it declines to do anything, so the
    // one way this call could report a silent success is caught here rather
    // than trusted away. Every path that reaches this line supplied all
    // three seeds, so an incomplete identity means upstream stored none of
    // them.
    if !imported.is_complete() {
        return Err(MachineError::RecoveryDataMalformed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::machine::{
        create_machine, lock_for_test, reset_for_test, with_machine, MachineConfig,
    };
    use crate::runtime::in_runtime;
    use crate::session::{
        decrypt_event, mark_request_sent, receive_sync_changes, share_scope_key,
        take_outgoing_requests, OutgoingRequest, SenderTrustRequirement, SenderVerification,
    };
    use crate::signing::{create_identity, identity_status};
    use matrix_sdk_common::ruma::api::client::keys::claim_keys::v3::Response as KeysClaimResponse;
    use matrix_sdk_common::ruma::api::client::keys::get_keys::v3::Response as KeysQueryResponse;
    use matrix_sdk_common::ruma::api::client::keys::upload_keys::v3::Response as KeysUploadResponse;
    use matrix_sdk_common::ruma::api::IncomingResponse;
    use matrix_sdk_common::ruma::events::AnyMessageLikeEventContent;
    // `exports::http`, not a direct `http` dependency: the exact version
    // ruma's own `IncomingResponse::try_from_http_response` requires,
    // reached through ruma's re-export, as `session.rs` documents for
    // itself.
    use matrix_sdk_common::ruma::exports::http;
    use matrix_sdk_common::ruma::serde::Raw;
    use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedRoomId, OwnedUserId, TransactionId, UInt};
    use matrix_sdk_crypto::types::requests::AnyOutgoingRequest;
    use matrix_sdk_crypto::types::DeviceKeys;
    use matrix_sdk_crypto::{CrossSigningBootstrapRequests, EncryptionSettings, OlmMachine};

    const ALICE_USER: &str = "@alice:example.org";
    /// The device that holds the identity and writes the recovery.
    const FIRST_DEVICE: &str = "DEVICEONE";
    /// The reinstall. A different device id, because that is what a fresh
    /// login is: the store is gone and so is the device it belonged to.
    const SECOND_DEVICE: &str = "DEVICETWO";
    const PEER_USER: &str = "@peer:example.org";
    const PEER_DEVICE: &str = "PEERDEVICE";
    /// A scope only ever used to make the library ask who a user's devices
    /// are and to carry one event. Nothing about it is read back.
    const SCOPE: &str = "!recovery:example.org";
    const PAYLOAD: &str = r#"{"body":"sent after the reinstall","msgtype":"m.text"}"#;

    /// Literals with no account anywhere behind them, exactly like the
    /// `store_passphrase` every other test in this crate hands to
    /// `MachineConfig`. Neither opens anything outside this test process.
    const PASSPHRASE: &str = "recovery-test-passphrase";
    const WRONG_PASSPHRASE: &str = "not-the-recovery-test-passphrase";
    /// The one a user rotates *to*, in the test that drives what
    /// happens to the one they rotated away from.
    const NEW_PASSPHRASE: &str = "the-second-recovery-test-passphrase";

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

    fn config(store_path: String, device_id: &str) -> MachineConfig {
        MachineConfig {
            user_id: ALICE_USER.to_string(),
            device_id: device_id.to_string(),
            store_path,
            store_passphrase: Some("test-passphrase".to_string()),
        }
    }

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
    /// Every assertion about what crossed goes through this rather than
    /// stopping at the request kind: a withheld notice is a to-device
    /// request too, so the kind alone distinguishes nothing.
    fn declared_event_type(body: &str) -> String {
        serde_json::from_str::<serde_json::Value>(body)
            .ok()
            .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| "<no event_type in body>".to_string())
    }

    /// Turns one to-device request body into the to-device event the
    /// addressed device would have received from its homeserver. Reads the
    /// per-recipient content out of the request and wraps it with the
    /// sender and type the request itself declares; it reaches into neither
    /// machine.
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

    /// Wraps an encrypted content in the surrounding event a homeserver
    /// would have delivered.
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

    /// The device keys a bare machine holds for its own device.
    ///
    /// Read from the store rather than from the key upload request, because
    /// the upload was built before the bootstrap below and a bootstrap does
    /// not retroactively change what an already-built request carried.
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
    /// This is the homeserver's half and nothing more. A bootstrap does not
    /// write this signature into its own store copy of the device: it emits
    /// it in a signature upload, and the server is what stores it and hands
    /// it back on the next key query. Both the signature and the keys it
    /// covers come out of upstream. The same helper, and the same
    /// reasoning, as `tests/cross_signed_peer.rs`.
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
        // keyed by device id *and* by cross-signing key id, because a
        // bootstrap also signs its own master key with the device.
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

    /// Merges the signature the first device made over the peer's master
    /// key into that key, as a homeserver does with a signature upload.
    ///
    /// Only the signatures are taken, never the key object around them:
    /// upstream's `sign_user` *replaces* the master key's signature map
    /// with its own single signature rather than adding to it, so posting
    /// that object verbatim as the master key would drop the signature the
    /// peer's own device made over it.
    ///
    /// Asserts the merge actually added one. A key query body is just JSON,
    /// and one describing an unsigned master key reads exactly like one
    /// describing a signed one, so the fixture this whole file rests on is
    /// checked rather than trusted.
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
            "merging the uploaded signature must add one: the master key \
             carried {before} signatures before and {after} after. Equal \
             means this response is indistinguishable from one in which the \
             peer was never verified, and this file would assert nothing"
        );
        master_key
    }

    /// Drains the library's pump and returns the one request of `kind`,
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
    /// **Not `drain_for("keys_query", ..)`.** A query for this account and a
    /// query for anyone else are one endpoint with one wire tag, so taking
    /// whichever came first could answer the account's own query with the
    /// peer's keys while every assertion below still read plausibly.
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

    /// Everything the first device leaves behind, and everything the
    /// reinstalled one needs.
    struct BeforeTheReinstall {
        /// The store directory of the device that is about to be deleted.
        store_dir: std::path::PathBuf,
        /// The three public cross-signing keys the account published,
        /// exactly as a `/keys/query` for this account would return them.
        account_identity: serde_json::Value,
        /// The peer, still alive: a reinstall on our side is not a new
        /// device on theirs.
        peer: OlmMachine,
        peer_device_keys: serde_json::Value,
        /// Carrying the first device's user-signing signature, which is the
        /// thing a recovery has to give back.
        peer_master_key: serde_json::Value,
        peer_self_signing_key: serde_json::Value,
        recovery: RecoverySetup,
    }

    /// The device that has the identity: it creates one, verifies a peer
    /// with it, and writes the recovery.
    async fn before_the_reinstall() -> BeforeTheReinstall {
        // `keep()`: this directory has to outlive the guard, because the
        // caller deletes it by hand to model the uninstall.
        let store_dir = tempfile::tempdir().expect("temp dir").keep();
        create_machine(config(
            store_dir.join("store").to_string_lossy().into_owned(),
            FIRST_DEVICE,
        ))
        .await
        .expect("the library's machine must be creatable");

        // ---- The first device publishes its own keys --------------------
        let upload = drain_for("keys_upload", "a fresh machine must have keys to publish").await;
        mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
            .await
            .expect("a keys-upload response must be accepted");

        // ---- It creates the account's identity --------------------------
        let account_query = drain_for_query_about(
            ALICE_USER,
            "a fresh machine must owe a key query for its own account",
        )
        .await;
        mark_request_sent(&account_query.id, NO_IDENTITY)
            .await
            .expect("answering the account key query must not fail");

        create_identity().await.expect(
            "creating this account's identity after the keys have been fetched must \
                     be served",
        );

        // The publication the bootstrap queued is what a `/keys/query` for
        // this account answers with from here on, so the reinstalled device
        // is handed exactly these three keys and nothing invented here.
        let published = take_outgoing_requests()
            .await
            .expect("the pump must be drainable");
        let signing_keys = published
            .iter()
            .find(|request| request.kind == "signing_keys_upload")
            .expect("a served bootstrap always queues the signing keys upload");
        let signing_keys: serde_json::Value = serde_json::from_str(&signing_keys.body)
            .expect("the pump's own body is well-formed JSON");
        let account_identity = serde_json::json!({
            "master_keys": { ALICE_USER: signing_keys["master_key"] },
            "self_signing_keys": { ALICE_USER: signing_keys["self_signing_key"] },
            "user_signing_keys": { ALICE_USER: signing_keys["user_signing_key"] },
        });
        // **The confirming key query is answered with the identity, not with
        // `{}`.** The creation queues that query alongside the publication,
        // and only a homeserver's own answer carrying the identity back
        // records it as accepted. Answering it with an empty object leaves
        // the publication unconfirmed, and `create_recovery` now refuses
        // there, because a recovery written against an identity no
        // homeserver has ever accepted is one the user cannot use on the
        // device they will need it on. So this loop does what a product
        // does: it answers each request with what the server would send.
        let confirming_answer = serde_json::json!({
            "device_keys": { ALICE_USER: {} },
            "failures": {},
            "master_keys": { ALICE_USER: signing_keys["master_key"] },
            "self_signing_keys": { ALICE_USER: signing_keys["self_signing_key"] },
            "user_signing_keys": { ALICE_USER: signing_keys["user_signing_key"] },
        })
        .to_string();
        for request in &published {
            let body = if request.kind == "keys_query" && request.body.contains(ALICE_USER) {
                confirming_answer.as_str()
            } else {
                "{}"
            };
            mark_request_sent(&request.id, body)
                .await
                .expect("a bootstrap publication response must be accepted");
        }

        // ---- A peer, with an identity of its own ------------------------
        let peer_user: OwnedUserId = PEER_USER.parse().expect("a literal user id parses");
        let peer_device: OwnedDeviceId = PEER_DEVICE.into();
        let peer = OlmMachine::new(&peer_user, &peer_device).await;

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

        // `false`, not `true`: the device keys were published above, and
        // what this bootstrap is wanted for is the identity and the
        // signature it puts on that device.
        let bootstrap = peer
            .bootstrap_cross_signing(false)
            .await
            .expect("a bare machine must be able to bootstrap its own identity");
        let peer_device_keys = with_owner_signature(
            device_keys_of(&peer, &peer_user, &peer_device).await,
            &bootstrap,
            &peer_user,
            &peer_device,
        );
        let peer_device_keys =
            serde_json::to_value(&peer_device_keys).expect("upstream device keys serialise");
        let peer_master_key = serde_json::to_value(&bootstrap.upload_signing_keys_req.master_key)
            .expect("an upstream master key serialises");
        let peer_self_signing_key =
            serde_json::to_value(&bootstrap.upload_signing_keys_req.self_signing_key)
                .expect("an upstream self-signing key serialises");
        assert_eq!(
            signature_count(&peer_device_keys),
            2,
            "a bootstrapped peer's device carries two signatures, its own and \
             its owner's self-signing key. One means the bootstrap did not \
             sign the device, and nothing below would be about recovery"
        );

        // ---- The first device verifies the peer -------------------------
        //
        // Reached one layer below this crate's own comparison flow, on
        // purpose. `OtherUserIdentity::verify` is the same `sign_user` call
        // upstream makes inside `mark_as_done` when a comparison completes,
        // so the signature produced here is the signature a completed
        // comparison produces; what is skipped is six relayed to-device
        // messages, which are `tests/sas_two_party.rs`'s subject and not
        // this file's. What is not skipped, and is the point, is that this
        // signature is made with the first device's real user-signing key
        // and is checked by the reinstalled device with the recovered one.
        share_scope_key(SCOPE, &[PEER_USER.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let query = drain_for_query_about(
            PEER_USER,
            "the machine must ask who exists before it can verify anyone",
        )
        .await;
        mark_request_sent(
            &query.id,
            &serde_json::json!({
                "device_keys": { PEER_USER: { PEER_DEVICE: peer_device_keys.clone() } },
                "master_keys": { PEER_USER: peer_master_key.clone() },
                "self_signing_keys": { PEER_USER: peer_self_signing_key.clone() },
            })
            .to_string(),
        )
        .await
        .expect("a keys-query response must be accepted");

        let signed_keys = with_machine(move |machine| {
            Box::pin(async move {
                machine
                    .get_identity(&peer_user, None)
                    .await
                    .expect("the store must be readable")
                    .expect("the peer's identity has just been fetched")
                    .other()
                    .expect("the peer is another user")
                    .verify()
                    .await
                    .expect("a device holding the private user-signing key can sign a peer")
                    .signed_keys
            })
        })
        .await
        .expect("the library's machine must be live");
        let signed_keys =
            serde_json::to_value(&signed_keys).expect("an upstream signature upload serialises");
        let uploaded = signed_keys
            .get(PEER_USER)
            .and_then(serde_json::Value::as_object)
            .unwrap_or_else(|| {
                panic!("the signature upload must name the peer it signed: {signed_keys}")
            });
        assert_eq!(
            uploaded.len(),
            1,
            "a user signature covers exactly the master key, so exactly one \
             entry is expected here: {signed_keys}"
        );
        let signatures = uploaded
            .values()
            .next()
            .and_then(|signed| signed.get("signatures"))
            .cloned()
            .expect("a signed master key always carries the signature that signed it");
        let peer_master_key = with_our_signature(peer_master_key, &signatures);

        // ---- The recovery -----------------------------------------------
        // `&[]`: this account has no recovery yet, and saying so is what
        // this argument is for. `a_second_recovery_refuses_rather_than_
        // taking_the_first_one_away` is where the other answer is driven.
        let recovery = create_recovery(PASSPHRASE, &[])
            .await
            .expect("a device holding the private signing keys can write a recovery");

        // Anything the traffic above queued is drained, so the reinstalled
        // device's pump carries only its own.
        take_outgoing_requests()
            .await
            .expect("the pump must be drainable");

        BeforeTheReinstall {
            store_dir,
            account_identity,
            peer,
            peer_device_keys,
            peer_master_key,
            peer_self_signing_key,
            recovery,
        }
    }

    /// What one run of the reinstall produced.
    struct Outcome {
        /// What the library reported about the sender of the event it
        /// decrypted.
        verification: Option<SenderVerification>,
        /// The plaintext the library recovered. The control on every
        /// authenticity assertion: if decryption itself broke, the value
        /// above is meaningless rather than wrong, and this says which of
        /// the two happened.
        recovered: Vec<u8>,
        /// Whether the reinstalled device holds the account's private
        /// signing keys by the time the event arrives.
        private_keys_held: bool,
        /// The store this reinstall created, so the caller can delete it
        /// once the machine holding it open has been released. A `TempDir`
        /// guard cannot do that job here, which is why the directory is
        /// kept and handed back instead: see [`destroy`].
        store_dir: std::path::PathBuf,
    }

    /// The reinstall: a brand new store, a new device id, and one axis.
    ///
    /// `recover` is the single difference between this file's two
    /// scenarios. Everything else, the account, the peer, the signature the
    /// peer's master key carries and the payload, is identical, so the only
    /// thing that can explain two different values at the end is whether
    /// the identity came back.
    async fn after_the_reinstall(before: BeforeTheReinstall, recover: bool) -> Outcome {
        // Destructured, so a field added to the fixture later has to be
        // given a use here rather than being silently ignored.
        let BeforeTheReinstall {
            store_dir: _,
            account_identity,
            peer,
            peer_device_keys,
            peer_master_key,
            peer_self_signing_key,
            recovery,
        } = before;

        // `keep()`, and it leaves a directory behind on purpose: the
        // machine created from it lives in the process-wide registry past
        // the end of this function, so a `TempDir` guard dropped here would
        // delete a store that is still open. The same trade `session.rs`'s
        // own `test_config` documents, and the same one every other store
        // in this file's tests takes.
        let dir = tempfile::tempdir().expect("temp dir").keep();
        create_machine(config(
            dir.join("store").to_string_lossy().into_owned(),
            SECOND_DEVICE,
        ))
        .await
        .expect("the reinstalled device's machine must be creatable");

        // ---- The reinstalled device publishes its own keys --------------
        let upload = drain_for(
            "keys_upload",
            "a machine on a fresh store must have keys to publish",
        )
        .await;
        let upload_body: serde_json::Value =
            serde_json::from_str(&upload.body).expect("the pump's own body is well-formed JSON");
        let device_keys = upload_body
            .get("device_keys")
            .cloned()
            .expect("a fresh machine's upload carries its device keys");
        let (one_time_key_id, one_time_key) = upload_body
            .get("one_time_keys")
            .and_then(serde_json::Value::as_object)
            .and_then(|keys| keys.iter().next())
            .map(|(id, key)| (id.clone(), key.clone()))
            .expect("a fresh machine's upload carries one-time keys");
        mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
            .await
            .expect("a keys-upload response must be accepted");

        // ---- It learns what identity the account has --------------------
        //
        // Answered with what the first device published, which is what a
        // homeserver returns. Without this the store holds no public
        // identity for the account, and upstream's import has nothing to
        // check a recovered seed against.
        let account_query = drain_for_query_about(
            ALICE_USER,
            "a machine on a fresh store must owe a key query for its own account",
        )
        .await;
        mark_request_sent(&account_query.id, &account_identity.to_string())
            .await
            .expect("answering the account key query must not fail");

        // ---- The axis ---------------------------------------------------
        if recover {
            recover_identity(PASSPHRASE, &recovery.account_data)
                .await
                .expect("the passphrase that wrote this recovery must open it");
        }

        let private_keys_held = identity_status()
            .await
            .expect("reading the identity status must not fail")
            .private_keys_held;

        // ---- The peer's keys reach the reinstalled device ---------------
        share_scope_key(SCOPE, &[PEER_USER.to_string()])
            .await
            .expect("sharing a scope key must not fail");
        let query =
            drain_for_query_about(PEER_USER, "the reinstalled device must ask who the peer is")
                .await;
        mark_request_sent(
            &query.id,
            &serde_json::json!({
                "device_keys": { PEER_USER: { PEER_DEVICE: peer_device_keys } },
                "master_keys": { PEER_USER: peer_master_key },
                "self_signing_keys": { PEER_USER: peer_self_signing_key },
            })
            .to_string(),
        )
        .await
        .expect("a keys-query response must be accepted");

        // The mirror image on the bare side: the peer learns the new
        // device, claims one of its one-time keys, and opens a session.
        let alice_user: OwnedUserId = ALICE_USER.parse().expect("a literal user id parses");
        peer.mark_request_as_sent(
            &TransactionId::new(),
            &keys_query_response(
                &serde_json::json!({
                    "device_keys": { ALICE_USER: { SECOND_DEVICE: device_keys } }
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
            .expect("the bare machine has no session to the reinstalled device yet");
        peer.mark_request_as_sent(
            &claim_id,
            &keys_claim_response(
                &serde_json::json!({
                    "one_time_keys": {
                        ALICE_USER: { SECOND_DEVICE: { one_time_key_id: one_time_key } }
                    }
                })
                .to_string(),
            ),
        )
        .await
        .expect("the bare machine must accept a keys-claim response");

        // ---- The peer's group key, then one event -----------------------
        let room_id: OwnedRoomId = SCOPE.parse().expect("a literal room id parses");
        let shares = peer
            .share_room_key(
                &room_id,
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
            .filter_map(|body| relay_to(&body, PEER_USER, ALICE_USER, SECOND_DEVICE))
            .map(|event| {
                serde_json::from_str(&event).expect("this test builds its own well-formed event")
            })
            .collect();
        assert_eq!(
            key_events.len(),
            1,
            "the peer must produce exactly one to-device message carrying its \
             session key to the reinstalled device; zero means it produced a \
             withheld notice instead, which is not what this file is about"
        );

        let outcome = receive_sync_changes(
            &serde_json::json!({ "to_device_events": key_events }).to_string(),
        )
        .await
        .expect("the library must accept a sync carrying a session key");
        assert_eq!(
            outcome.new_session_count, 1,
            "the relayed to-device message must give the reinstalled device \
             exactly one new inbound session"
        );

        let content = Raw::<AnyMessageLikeEventContent>::from_json_string(PAYLOAD.to_owned())
            .expect("a literal payload is well-formed JSON");
        let encrypted = peer
            .encrypt_room_event_raw(&room_id, "m.room.message", &content)
            .await
            .expect("the bare machine must be able to encrypt for its own session");
        let event = scoped_event(
            PEER_USER,
            "$after-the-reinstall:example.org",
            encrypted.content.json().get(),
        );
        let envelope = decrypt_event(SCOPE, &event, SenderTrustRequirement::Any)
            .await
            .expect("the library must decrypt what the peer encrypted");

        Outcome {
            verification: envelope.sender_verification,
            recovered: envelope.ciphertext,
            private_keys_held,
            store_dir: dir,
        }
    }

    /// Deletes the first device's store, and proves it is gone.
    ///
    /// The uninstall, made literal. `reset_for_test` above releases the
    /// machine that held it open; this is what makes the bytes stop
    /// existing, so nothing below can be resting on a file that survived.
    ///
    /// # The reinstall must return on a different path, and this is why
    ///
    /// [`after_the_reinstall`] builds its machine at a **new** store path
    /// with a **new** device id, which is what a fresh login is. Do not
    /// simplify it to reuse the path this deletes. `create_machine` and
    /// `open_store` on a path whose directory has been removed return
    /// `Ok(())` without recreating anything, and a machine already built
    /// over the deleted file goes on serving from it, so a version of this
    /// scenario that reopened the same path would look exactly like a
    /// reinstall and be a relaunch. It would stay green while proving
    /// nothing, which is the shape of defect this repository keeps finding,
    /// and the assertion below would still pass because the directory
    /// really was deleted.
    fn destroy(store_dir: &std::path::Path) {
        std::fs::remove_dir_all(store_dir).expect("the first device's store must be deletable");
        assert!(
            !store_dir.exists(),
            "the store this scenario destroys must actually be gone; a \
             surviving one would let every assertion below pass for the \
             wrong reason"
        );
    }

    /// **The milestone's promise.** Write the recovery, destroy the store,
    /// restore from the passphrase on a brand new device, and read a
    /// decrypted event's sender.
    ///
    /// Nothing in this test is a stand-in for the value under test. The
    /// peer is a bare upstream machine, the signature on its master key was
    /// made by the first device's real user-signing key, the store really
    /// is deleted from disk, and the reinstalled device recovers the seeds
    /// from account data and nothing else. `Verified` at the end means the
    /// recovered user-signing key was used to check that signature, which
    /// is the whole claim: a person who verified this account before the
    /// reinstall does not have to verify it again.
    ///
    /// Driven by `block_on` inside `in_runtime`, because the bare machine
    /// needs a tokio context this crate does not supply for it: upstream's
    /// `share_room_key` reaches `tokio::task::spawn`.
    #[test]
    fn a_recovered_identity_makes_a_decrypted_event_read_verified_again() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let before = futures::executor::block_on(in_runtime(before_the_reinstall()));
        let store_dir = before.store_dir.clone();

        // The uninstall. `reset_for_test` releases the machine holding the
        // store open, and `destroy` deletes it.
        reset_for_test();
        destroy(&store_dir);

        let outcome = futures::executor::block_on(in_runtime(after_the_reinstall(before, true)));
        let reinstalled_store = outcome.store_dir.clone();

        assert!(
            outcome.private_keys_held,
            "recovering from the passphrase must leave the reinstalled device \
             holding the account's private signing keys; without them nothing \
             below can be about a recovery"
        );
        assert_eq!(
            outcome.recovered,
            PAYLOAD.as_bytes(),
            "the reinstalled device must recover the peer's payload byte for \
             byte, or the value under test is meaningless rather than wrong"
        );
        assert_eq!(
            outcome.verification,
            Some(SenderVerification::Verified),
            "after a recovery, an event from a peer this account had verified \
             before the reinstall reads `Verified` again. Anything below it \
             means the recovered user-signing key did not check the signature \
             on the peer's master key, which is the one thing a recovery is \
             for"
        );

        // The reinstalled device's store, released and deleted. The first
        // device's went at the uninstall above; this is the other one this
        // scenario creates.
        reset_for_test();
        destroy(&reinstalled_store);
    }

    /// The mirror image, and the reason the test above is not asserting a
    /// constant.
    ///
    /// The same account, the same peer, the same signature on the same
    /// master key, the same payload, the same reinstall. One difference:
    /// the account data is never handed to `recover_identity`. If this
    /// still read `Verified`, the value would be coming from somewhere
    /// other than the recovered key and the test above would prove nothing.
    #[test]
    fn a_reinstall_without_the_recovery_reads_below_verified() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let before = futures::executor::block_on(in_runtime(before_the_reinstall()));
        let store_dir = before.store_dir.clone();

        reset_for_test();
        destroy(&store_dir);

        let outcome = futures::executor::block_on(in_runtime(after_the_reinstall(before, false)));
        let reinstalled_store = outcome.store_dir.clone();

        assert!(
            !outcome.private_keys_held,
            "a reinstall that does not recover holds no private signing keys; \
             if it does, the axis this file turns on is not the axis"
        );
        assert_eq!(
            outcome.recovered,
            PAYLOAD.as_bytes(),
            "decryption itself still works without a recovery, and saying so \
             is what makes the value below a statement about authenticity \
             rather than about decryption"
        );
        assert_eq!(
            outcome.verification,
            Some(SenderVerification::UnverifiedIdentity),
            "without the recovery the peer's identity is one this device has \
             never verified, so the event stops one rung short. `Verified` \
             here would mean the value does not depend on the recovered key \
             at all"
        );

        reset_for_test();
        destroy(&reinstalled_store);
    }

    /// A wrong passphrase and a recovery that cannot be read are different
    /// answers, and this is the test that says so.
    ///
    /// All four outcomes are driven against **one** fixture, in one
    /// process, and the correct passphrase is tried last. That ordering is
    /// the control: it proves the three refusals were caused by what was
    /// changed rather than by a fixture that could never have opened.
    #[test]
    fn a_wrong_secret_is_told_apart_from_a_recovery_that_cannot_be_read() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let before = futures::executor::block_on(in_runtime(before_the_reinstall()));
        let store_dir = before.store_dir.clone();

        reset_for_test();
        destroy(&store_dir);

        let second_store = futures::executor::block_on(in_runtime(async move {
            let BeforeTheReinstall {
                account_identity,
                recovery,
                ..
            } = before;

            // `keep()`, for the reason `after_the_reinstall` above gives:
            // the machine outlives this block in the process-wide registry.
            // The path is handed back so this test can delete it once the
            // machine has been released.
            let dir = tempfile::tempdir().expect("temp dir").keep();
            create_machine(config(
                dir.join("store").to_string_lossy().into_owned(),
                SECOND_DEVICE,
            ))
            .await
            .expect("the reinstalled device's machine must be creatable");

            let upload = drain_for(
                "keys_upload",
                "a machine on a fresh store must have keys to publish",
            )
            .await;
            mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
                .await
                .expect("a keys-upload response must be accepted");
            let account_query = drain_for_query_about(
                ALICE_USER,
                "a machine on a fresh store must owe a key query for its own account",
            )
            .await;
            mark_request_sent(&account_query.id, &account_identity.to_string())
                .await
                .expect("answering the account key query must not fail");

            // (1) A typo. The stored recovery is untouched.
            assert_eq!(
                recover_identity(WRONG_PASSPHRASE, &recovery.account_data).await,
                Err(MachineError::RecoveryKeyIncorrect),
                "a wrong passphrase must report exactly that, so a product can \
                 ask its user to try again"
            );

            // (2) Damage, with the right passphrase. One byte of one
            //     ciphertext is changed and nothing else, so the key's own
            //     MAC still verifies and the secret's does not. That is
            //     precisely the case a folded error would report as a wrong
            //     passphrase, sending a user to retype something that was
            //     already right.
            let damaged = with_a_damaged_secret(&recovery.account_data);
            assert_eq!(
                recover_identity(PASSPHRASE, &damaged).await,
                Err(MachineError::RecoveryDataMalformed),
                "a recovery whose stored secret has been altered must report \
                 that no secret will open it, not that the secret was wrong"
            );

            // (3) Content that is not JSON at all, in the key description.
            let unparseable = with_replaced_content(
                &recovery.account_data,
                |event_type| event_type.starts_with("m.secret_storage.key."),
                "not json at all",
            );
            assert_eq!(
                recover_identity(PASSPHRASE, &unparseable).await,
                Err(MachineError::RecoveryDataMalformed),
                "a key description that is not JSON must report the same thing \
                 as damaged ciphertext: nothing a user types will fix it"
            );

            // (4) An incomplete recovery: one of the three secrets was
            //     never written. Different from both of the above, and the
            //     remedy is different too.
            let incomplete: Vec<AccountDataEntry> = recovery
                .account_data
                .iter()
                .filter(|entry| entry.event_type != SecretName::CrossSigningUserSigningKey.as_str())
                .cloned()
                .collect();
            assert_eq!(
                recover_identity(PASSPHRASE, &incomplete).await,
                Err(MachineError::RecoveryNotSetUp),
                "account data missing one of the three secrets is neither a \
                 wrong passphrase nor damaged data"
            );

            // (5) A mistyped recovery key, against a recovery whose key
            //     description carries no passphrase block.
            //
            //     That shape is legal, upstream branches on it explicitly,
            //     and this library promises to restore a recovery another
            //     client wrote, so it is a shape that arrives here. With no
            //     passphrase block upstream goes straight to the base58
            //     path, whose failures describe the string the user just
            //     typed. **This is the case the whole pair of variants
            //     exists for**, and it is the one no fixture on this branch
            //     could reach until now, because `create_recovery` always
            //     writes a passphrase block.
            let key_only = without_the_passphrase_block(&recovery.account_data);
            assert_eq!(
                recover_identity(&mistyped(&recovery.recovery_key), &key_only).await,
                Err(MachineError::RecoveryKeyIncorrect),
                "a recovery key with one character wrong is a wrong secret, \
                 whatever the key description does or does not carry. Reporting \
                 it as unreadable data sends a user whose only mistake was a \
                 typo to set recovery up again, which is the one action that \
                 destroys what they were trying to recover"
            );
            assert_eq!(
                recover_identity(PASSPHRASE, &key_only).await,
                Err(MachineError::RecoveryKeyIncorrect),
                "a passphrase typed at a recovery that has no passphrase block \
                 is a wrong secret too, for the same reason: nothing about the \
                 stored data is wrong"
            );

            //     The control for that pair, and what makes the two above
            //     statements about the secret rather than about the
            //     fixture: the same key-only description opens with the
            //     right recovery key.
            recover_identity(&recovery.recovery_key, &key_only)
                .await
                .expect(
                    "a recovery with no passphrase block must still open with \
                     the recovery key it was created with",
                );

            // (6) The other control, and it is what stops the fix for (5)
            //     from being `report every secret as wrong`. The
            //     **passphrase is right** and the key description names an
            //     encryption scheme this build does not implement, so the
            //     answer must still be that the stored data cannot be read.
            //
            //     The passphrase block is deliberately left in place. With
            //     it removed, upstream never reaches the algorithm at all:
            //     it takes the base58 path, fails to parse a passphrase as
            //     a key, and answers about the secret. Which is correct,
            //     and is why this fixture changes one field rather than
            //     replacing the description.
            let unsupported = with_an_unsupported_algorithm(&recovery.account_data);
            assert_eq!(
                recover_identity(PASSPHRASE, &unsupported).await,
                Err(MachineError::RecoveryDataMalformed),
                "a key description naming an encryption algorithm this build \
                 does not implement describes the stored data, not the secret, \
                 and no secret will open it"
            );

            // (7) The control. The same fixture, the same machine, the
            //     right passphrase: it opens. Without this, every refusal
            //     above would be equally consistent with a fixture that was
            //     never openable at all.
            recover_identity(PASSPHRASE, &recovery.account_data)
                .await
                .expect("the untouched fixture must open with the passphrase that wrote it");
            assert!(
                identity_status()
                    .await
                    .expect("reading the identity status must not fail")
                    .private_keys_held,
                "the control must actually restore the identity, or it is not \
                 a control"
            );

            // (8) And the other secret opens it too. `secret` is documented
            //     as either the passphrase or the recovery key, and the
            //     recovery key is the half a product shows a human once and
            //     the only thing that survives a forgotten passphrase, so
            //     the claim is pinned rather than left to the doc comment.
            recover_identity(&recovery.recovery_key, &recovery.account_data)
                .await
                .expect(
                    "the recovery key this call returned must open the recovery \
                     it returned it for",
                );

            dir
        }));

        reset_for_test();
        destroy(&second_store);
    }

    /// A copy of `account_data` with one byte of the master key's
    /// ciphertext changed.
    ///
    /// Base64, so a character is swapped for a different one from the same
    /// alphabet rather than truncating the string: the result is still a
    /// well-formed event carrying a well-formed ciphertext of the right
    /// length, which is what makes the MAC the only thing that catches it.
    fn with_a_damaged_secret(account_data: &[AccountDataEntry]) -> Vec<AccountDataEntry> {
        let target = SecretName::CrossSigningMasterKey.as_str();
        let mut damaged = account_data.to_vec();
        let entry = damaged
            .iter_mut()
            .find(|entry| entry.event_type == target)
            .expect("a recovery always carries the master key");
        let mut content: serde_json::Value =
            serde_json::from_str(&entry.content).expect("this module wrote well-formed JSON");
        let encrypted = content
            .get_mut("encrypted")
            .and_then(serde_json::Value::as_object_mut)
            .expect("a stored secret always carries an encrypted map");
        let data = encrypted
            .values_mut()
            .next()
            .expect("a stored secret always carries one entry");
        let ciphertext = data
            .get_mut("ciphertext")
            .expect("a stored secret always carries a ciphertext");
        let original = ciphertext
            .as_str()
            .expect("a ciphertext is a base64 string")
            .to_string();
        let first = original.chars().next().expect("a ciphertext is not empty");
        let replacement = if first == 'A' { 'B' } else { 'A' };
        let altered: String = std::iter::once(replacement)
            .chain(original.chars().skip(1))
            .collect();
        assert_ne!(
            altered, original,
            "the damage must actually change the ciphertext, or this fixture \
             is the undamaged one under another name"
        );
        *ciphertext = serde_json::Value::String(altered);
        entry.content = content.to_string();
        damaged
    }

    /// A second reader of the default-key pointer is refused, and this test
    /// is what makes the refusal real rather than a comment.
    ///
    /// # What it is defending
    ///
    /// Two functions read this account data and disagreed about what an
    /// empty content object means; one said "cleared", the other said
    /// "destroyed", and a user with an intact recovery was told to destroy
    /// it. The correction routed both through [`pointed_key_id`]. A review
    /// then built the third reader that correction is supposed to prevent, a
    /// function calling [`entry`] with the same event type and parsing the
    /// bytes itself, and observed it compile, format, pass
    /// `clippy -D warnings`, pass every gate, and leave all eight recovery
    /// tests green. One function with a doc comment on it is a paragraph
    /// with better placement, and a paragraph is exactly what failed here
    /// before.
    ///
    /// The `debug_assert!` in `entry` is what changed that, and this is what
    /// keeps it. Deleting the assertion makes this test fail.
    ///
    /// # What it is not
    ///
    /// Not a compile-time guarantee. In a release build the assertion is
    /// compiled out and nothing stands in the way, and even in a test build
    /// a reader determined to scan `account_data` by hand never calls
    /// `entry` at all. What it removes is the accident: the reader that
    /// reaches for the obvious helper, which is the one the review built to
    /// prove the point.
    #[test]
    #[should_panic(expected = "pointed_key_id")]
    fn reading_the_pointer_around_the_one_reader_is_refused() {
        // The review's own sabotage, the same in shape: the same helper, the
        // same event type, a second opinion about the same bytes.
        let account_data = [AccountDataEntry {
            event_type: "m.secret_storage.default_key".to_string(),
            content: "{}".to_string(),
        }];
        let _second_opinion = entry(&account_data, "m.secret_storage.default_key");
    }

    /// Every `DecodeError` this build can construct, classified one by one.
    ///
    /// # Why this exists, and what it replaces
    ///
    /// [`classify_decode_error`] is an exhaustive ten-arm match, and an
    /// exhaustive match reads as decided. It was not: the fixtures in this
    /// file reach four of the ten, so moving `Parity` alone onto the
    /// malformed arm left the whole suite green. A match that looks settled
    /// and is untested is worse than the wildcard it replaced, because it
    /// no longer invites anybody to check.
    ///
    /// No machine, no store, no runtime and no fixture: `DecodeError`'s
    /// variants are public tuple variants of a type that is not
    /// `#[non_exhaustive]`, so most of them can simply be built and handed
    /// over. That is why this runs in no measurable time.
    ///
    /// # The three that are missing, and where they are covered instead
    ///
    /// `Mac`, `Base58` and `Base64` wrap types from crates this one does
    /// not depend on (`digest`'s `MacError`, `bs58`'s decode error, and
    /// vodozemac's base64 error), so they cannot be named here. Taking a
    /// dependency in order to construct a test fixture would be the wrong
    /// trade for this repository. `Mac` and `Base58` are both reached by
    /// [`a_wrong_secret_is_told_apart_from_a_recovery_that_cannot_be_read`],
    /// whose own fixtures say which reaches which. `Base64` is reached by
    /// nothing, here or upstream: `matrix-sdk-crypto` 0.18.0 constructs it
    /// nowhere on this path, and its arm exists so that a version which
    /// starts constructing it fails this build rather than silently picking
    /// a side.
    #[test]
    fn every_decode_failure_is_classified_by_what_it_describes() {
        // The typed secret. Every one of these comes out of
        // `parse_base58_key`, which sees the user's input and nothing else,
        // so a user meeting any of them fixes it by typing again.
        for (name, failure) in [
            ("Prefix", DecodeError::Prefix([0x8b, 0x01], [0x00, 0x00])),
            ("Parity", DecodeError::Parity(0x11, 0x22)),
            ("KeyLength", DecodeError::KeyLength(35, 36)),
        ] {
            assert_eq!(
                classify_decode_error(failure),
                MachineError::RecoveryKeyIncorrect,
                "DecodeError::{name} describes the string the user typed, so reporting it \
                 as unreadable stored data tells somebody whose recovery is intact to set \
                 it up again"
            );
        }

        // The stored key description. Every one of these comes out of
        // `check_zero_message` or the passphrase derivation, both of which
        // read what the server returned, so no secret a user types will
        // change the answer.
        for (name, failure) in [
            ("IvLength", DecodeError::IvLength(16, 17)),
            ("MacLength", DecodeError::MacLength(32, 33)),
            (
                "UnsupportedAlgorithm",
                DecodeError::UnsupportedAlgorithm("m.secret_storage.v1.something-else".to_owned()),
            ),
            (
                "KdfIterationCount",
                DecodeError::KdfIterationCount(UInt::MAX),
            ),
        ] {
            assert_eq!(
                classify_decode_error(failure),
                MachineError::RecoveryDataMalformed,
                "DecodeError::{name} describes the account data, not the secret, so \
                 reporting it as a wrong secret leaves a user retyping something that was \
                 already right"
            );
        }
    }

    /// A copy of `account_data` whose key description carries no
    /// `passphrase` block.
    ///
    /// Legal, and not a corruption: the Matrix specification defines the
    /// block as optional, upstream's `from_account_data` branches on its
    /// absence, and a client that offered its user only a recovery key
    /// writes exactly this. `create_recovery` always writes one, so this is
    /// the only way to build the shape from inside this file.
    ///
    /// Nothing else is touched, which is what makes the assertions using it
    /// about the branch rather than about the fixture.
    fn without_the_passphrase_block(account_data: &[AccountDataEntry]) -> Vec<AccountDataEntry> {
        let mut stripped = account_data.to_vec();
        let entry = stripped
            .iter_mut()
            .find(|entry| entry.event_type.starts_with("m.secret_storage.key."))
            .expect("a recovery always carries a key description");
        let mut content: serde_json::Value =
            serde_json::from_str(&entry.content).expect("this module wrote well-formed JSON");
        let removed = content
            .as_object_mut()
            .expect("a key description is an object")
            .remove("passphrase");
        assert!(
            removed.is_some(),
            "the fixture must have carried a passphrase block for removing it \
             to mean anything"
        );
        entry.content = content.to_string();
        stripped
    }

    /// The same recovery key with one character replaced by another from
    /// the same alphabet.
    ///
    /// A typo, not a truncation: the string handed to upstream is base58
    /// throughout and the same number of characters long, which is the
    /// shape a real mistyping takes and is what keeps this a statement
    /// about the secret rather than about the length of the input.
    ///
    /// **Which failure it lands on was measured, not assumed**, because
    /// this comment used to claim the opposite. The character replaced is
    /// the leading one, which carries the high-order bits, so the decoded
    /// value comes out a byte longer and upstream answers
    /// `DecodeError::KeyLength(35, 36)`. That is still one of the five that
    /// describe the typed secret, and it was one of the four the old
    /// wildcard swallowed, so the assertion is a real regression case; it
    /// is simply not the parity check this said it was.
    ///
    /// Between them the fixtures in this file reach four of the ten
    /// variants: `Mac` from a wrong passphrase against a description that
    /// has a passphrase block, `KeyLength` from here, `Base58` from a
    /// passphrase typed at a description that has none, and
    /// `UnsupportedAlgorithm` from [`with_an_unsupported_algorithm`]. The
    /// arm-by-arm coverage is
    /// [`every_decode_failure_is_classified_by_what_it_describes`]'s job.
    fn mistyped(recovery_key: &str) -> String {
        let mut wrong = String::with_capacity(recovery_key.len());
        let mut swapped = false;
        for character in recovery_key.chars() {
            if !swapped && character.is_ascii_alphanumeric() {
                wrong.push(if character == 'a' { 'b' } else { 'a' });
                swapped = true;
            } else {
                wrong.push(character);
            }
        }
        assert!(swapped, "a recovery key always carries a base58 character");
        assert_ne!(wrong, recovery_key, "the typo must change the key");
        wrong
    }

    /// A copy of `account_data` whose key description names an encryption
    /// scheme this build does not implement.
    ///
    /// One field changed and nothing else, in particular **not** the
    /// passphrase block: that is what makes the failure reachable. Upstream
    /// only looks at the algorithm once it has a candidate key, so a
    /// description with no passphrase block is rejected on the base58 path
    /// before the algorithm is consulted, and the answer is then correctly
    /// about the secret rather than about the stored data.
    fn with_an_unsupported_algorithm(account_data: &[AccountDataEntry]) -> Vec<AccountDataEntry> {
        let mut altered = account_data.to_vec();
        let entry = altered
            .iter_mut()
            .find(|entry| entry.event_type.starts_with("m.secret_storage.key."))
            .expect("a recovery always carries a key description");
        let mut content: serde_json::Value =
            serde_json::from_str(&entry.content).expect("this module wrote well-formed JSON");
        let object = content
            .as_object_mut()
            .expect("a key description is an object");
        assert!(
            object.contains_key("passphrase"),
            "this fixture depends on the passphrase block being present, or \
             the algorithm is never reached"
        );
        let replaced = object.insert(
            "algorithm".to_string(),
            serde_json::Value::String("m.secret_storage.v1.something-else".to_string()),
        );
        assert!(
            replaced.is_some(),
            "a key description always names an algorithm, so replacing it \
             must have replaced something"
        );
        entry.content = content.to_string();
        altered
    }

    /// A copy of `account_data` with the content of the first entry whose
    /// type satisfies `matches` replaced.
    fn with_replaced_content(
        account_data: &[AccountDataEntry],
        matches: impl Fn(&str) -> bool,
        content: &str,
    ) -> Vec<AccountDataEntry> {
        let mut replaced = account_data.to_vec();
        let entry = replaced
            .iter_mut()
            .find(|entry| matches(&entry.event_type))
            .expect("this fixture carries the entry being replaced");
        entry.content = content.to_string();
        replaced
    }

    /// A copy of `account_data` whose default-key pointer has been cleared,
    /// which is the one thing a product can do to an account data event it
    /// wants gone.
    ///
    /// `PUT {}`, not a delete: the client-server API has no way to remove a
    /// global account data event, so an empty content object is what
    /// "cleared" looks like on a real homeserver.
    ///
    /// **This is not what [`create_recovery`]'s recommended route does**,
    /// and this comment said it was until the route changed under it. The
    /// recommendation writes nothing to the server; it drops the pointer
    /// from the list handed over. Clearing on the server is the second of
    /// the routes past the refusal, the one documented with a window, and
    /// it is also the state a product that stopped halfway is left in,
    /// which is why this file goes on constructing it.
    fn with_the_pointer_cleared(account_data: &[AccountDataEntry]) -> Vec<AccountDataEntry> {
        with_replaced_content(
            account_data,
            |event_type| event_type == "m.secret_storage.default_key",
            "{}",
        )
    }

    /// The `encrypted` map of one stored secret, as key id to ciphertext.
    fn ciphertexts_of(
        account_data: &[AccountDataEntry],
        name: &SecretName,
    ) -> serde_json::Map<String, serde_json::Value> {
        let content = account_data
            .iter()
            .find(|entry| entry.event_type == name.as_str())
            .map(|entry| entry.content.as_str())
            .expect("this fixture carries the secret being read");
        let content: serde_json::Value =
            serde_json::from_str(content).expect("this module wrote well-formed JSON");
        content
            .get("encrypted")
            .and_then(serde_json::Value::as_object)
            .cloned()
            .expect("a stored secret always carries an encrypted map")
    }

    /// A copy of `account_data` with the default-key pointer entry removed
    /// entirely, as a product hands it over when it means to write a new
    /// recovery without touching the one the account has.
    ///
    /// The difference from [`with_the_pointer_cleared`] is where it
    /// happens. This one drops an entry from a list in memory and writes
    /// nothing anywhere; that one models a `PUT {}` the product actually
    /// made. Both lift `create_recovery`'s refusal, by the one rule
    /// [`pointed_key_id`] states, and only this one leaves the account
    /// untouched while the new recovery is being written.
    fn without_the_pointer(account_data: &[AccountDataEntry]) -> Vec<AccountDataEntry> {
        let kept: Vec<AccountDataEntry> = account_data
            .iter()
            .filter(|entry| entry.event_type != "m.secret_storage.default_key")
            .cloned()
            .collect();
        assert_eq!(
            kept.len(),
            account_data.len() - 1,
            "the fixture must have carried exactly one pointer for removing \
             it to mean anything"
        );
        kept
    }

    /// **A cleared pointer is not a destroyed recovery, and this is where
    /// the library stops saying it is.**
    ///
    /// # The harm this closes
    ///
    /// `create_recovery` refuses to write over a recovery the account
    /// already has and tells a product how to get past that. Every route
    /// past it involves the account's pointer no longer naming a key **in
    /// the list handed over**, and one of them, the one a product is left
    /// in the middle of if it stops halfway, spells that on the homeserver
    /// as `PUT {}`, because the client-server API has no delete for account
    /// data.
    ///
    /// The recommended route does not write that, and this paragraph said
    /// it was the only spelling until the route changed under it. The state
    /// still arrives, from the route that clears on the server and from any
    /// interrupted replacement, and what this test is about is what the
    /// library says when it does.
    ///
    /// `restore` used to parse that pointer into ruma's own content type
    /// and report the parse failure as `RecoveryDataMalformed`, whose
    /// documented remedy, at the variant, at `recoverIdentity` and in both
    /// READMEs, is to stop asking for a secret and set recovery up again.
    /// So a user holding the correct passphrase, whose key description and
    /// all three ciphertexts were still on the server and one `PUT` away
    /// from working, was told their recovery was destroyed and sent to do
    /// the one thing that would destroy it. On the library's own
    /// recommended path.
    ///
    /// # The three answers, and the control that settles which is right
    ///
    /// A cleared pointer and an absent one must give the same answer,
    /// because a homeserver cannot express the second once the first has
    /// been written. And the control is the one that makes this a
    /// misreport rather than a fact: put the pointer back, and the same
    /// secret opens the same recovery. Nothing was ever destroyed.
    #[test]
    fn a_cleared_pointer_is_not_a_destroyed_recovery() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let before = futures::executor::block_on(in_runtime(before_the_reinstall()));
        let first_store = before.store_dir.clone();

        // The uninstall, before the recovering device exists: the registry
        // holds one machine at a time, and the store this releases is the
        // one the assertions below must not be able to read from.
        reset_for_test();
        destroy(&first_store);

        let second_store = futures::executor::block_on(in_runtime(async move {
            let BeforeTheReinstall {
                account_identity,
                recovery,
                ..
            } = before;

            // `keep()`, for the reason `after_the_reinstall` gives: the
            // machine outlives this block in the process-wide registry. The
            // path is handed back so the test can delete it once the
            // machine has been released.
            let dir = tempfile::tempdir().expect("temp dir").keep();
            create_machine(config(
                dir.join("store").to_string_lossy().into_owned(),
                SECOND_DEVICE,
            ))
            .await
            .expect("the reinstalled device's machine must be creatable");

            let upload = drain_for(
                "keys_upload",
                "a machine on a fresh store must have keys to publish",
            )
            .await;
            mark_request_sent(&upload.id, r#"{"one_time_key_counts":{}}"#)
                .await
                .expect("a keys-upload response must be accepted");
            let account_query = drain_for_query_about(
                ALICE_USER,
                "a machine on a fresh store must owe a key query for its own account",
            )
            .await;
            mark_request_sent(&account_query.id, &account_identity.to_string())
                .await
                .expect("answering the account key query must not fail");

            // (1) The state a product is looking at after clearing the
            //     pointer on the server: the second documented route, and
            //     also where any interrupted replacement stops. `PUT {}` is
            //     the only way to clear account data, so this is what
            //     "cleared" is.
            let cleared = with_the_pointer_cleared(&recovery.account_data);
            assert_eq!(
                recover_identity(PASSPHRASE, &cleared).await,
                Err(MachineError::RecoveryNotSetUp),
                "a cleared pointer means this account data carries no recovery \
                 to follow, which is what `RecoveryNotSetUp` says and what a \
                 product should do something about. `RecoveryDataMalformed` \
                 here tells a user with the right passphrase and an intact \
                 recovery that no secret will ever open it, and sends them to \
                 set recovery up again, which is the one action that makes \
                 that true"
            );

            // (2) And a pointer that was never written at all gives the
            //     same answer, which it must: a homeserver cannot express
            //     absent once an event has been written, so these two are
            //     the same state seen before and after a clear.
            let absent = without_the_pointer(&recovery.account_data);
            assert_eq!(
                recover_identity(PASSPHRASE, &absent).await,
                Err(MachineError::RecoveryNotSetUp),
                "absent and cleared are one state as far as any client can \
                 tell, so they must be one answer"
            );

            // (3) The control that settles it. Put the pointer back and the
            //     same secret opens the same recovery: the key description
            //     and all three ciphertexts were on the server the whole
            //     time, and nothing about (1) was a report of damage.
            recover_identity(PASSPHRASE, &recovery.account_data)
                .await
                .expect(
                    "restoring the pointer must restore the recovery, or the \
                     two refusals above are describing real damage and this \
                     test is asserting the wrong thing",
                );
            assert!(
                identity_status()
                    .await
                    .expect("reading the identity status must not fail")
                    .private_keys_held,
                "the control must actually restore the identity, or it is not \
                 a control"
            );

            dir
        }));

        reset_for_test();
        destroy(&second_store);
    }

    /// **Writing a recovery must not take away the recovery that is already
    /// there**, and this is the test that says what it does instead.
    ///
    /// # The situation, and why a doc comment could not be the fix
    ///
    /// Two callers reach `create_recovery` looking identical and needing
    /// opposite things. One is a user replacing their own passphrase, where
    /// the old recovery key is *meant* to stop working. The other is a
    /// product writing what it believes is a first recovery for a user who
    /// already set one up in Element, where the key that stops working is
    /// one somebody wrote down and was told to keep forever. Before this
    /// change the call could not see the difference, because it was never
    /// handed the account's existing account data, and it silently did the
    /// destructive thing in both cases.
    ///
    /// It still cannot see the difference, and that is why it refuses rather
    /// than choosing. What this test covers is the half that is safe for
    /// both callers: adding a key without taking one away. The other half,
    /// which only the first caller wants, is a further act performed by the
    /// product on what this call hands back.
    ///
    /// # What is asserted, in order
    ///
    /// 1. Handed a recovery, it refuses, and the refusal is its own variant
    ///    rather than one of the four that already existed.
    /// 2. Handed the same account data with the pointer **omitted**, which
    ///    is the recommended route and writes nothing to the server, it is
    ///    served.
    /// 3. What it then produces **merges** rather than replaces: the master
    ///    key's `encrypted` map carries the old key id with its original
    ///    ciphertext, byte for byte, alongside the new one. That is the
    ///    difference between adding a key to this account's secret storage
    ///    and evicting every other client's key from it.
    /// 4. The account's existing recovery still opens while the new one is
    ///    being written, which is the property the recommended route has
    ///    and the other two do not.
    /// 5. The two other routes past the refusal, with what each costs: an
    ///    empty list is pinned at one ciphertext and a cleared pointer at
    ///    two, so the documentation's claims about both are checkable
    ///    rather than prose.
    /// 6. The new secret opens the merged result.
    ///
    /// # What is deliberately not asserted here
    ///
    /// That the old key stops working. It does not, and
    /// [`replacing_a_recovery_re_points_it_and_revoking_it_is_a_further_act`]
    /// is where that is driven. Act 3's merge is precisely why: the entry it
    /// keeps under the old key id is, for a caller replacing their own
    /// passphrase, their own old key. Revoking is a further act and it has
    /// its own test.
    #[test]
    fn a_second_recovery_refuses_rather_than_taking_the_first_one_away() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let before = futures::executor::block_on(in_runtime(before_the_reinstall()));
        let store_dir = before.store_dir.clone();

        futures::executor::block_on(in_runtime(async move {
            let first = before.recovery;

            // (1) The refusal, and it is not one of the four that existed
            //     before. `RecoveryNotSetUp` here would be the worst of the
            //     wrong answers: it says "this account has no recovery", to
            //     a caller that just handed one over.
            //
            //     `.err()` rather than `expect_err`: `RecoverySetup`
            //     carries the recovery key and so has no `Debug` derive,
            //     which is what `expect_err` would need in order to print
            //     the success case.
            assert_eq!(
                create_recovery(PASSPHRASE, &first.account_data).await.err(),
                Some(MachineError::RecoveryAlreadyExists),
                "a recovery this account already has must be protected by a \
                 refusal of its own, because the alternative is a call that \
                 silently invalidates a recovery key a user was told to keep \
                 forever, including one another Matrix client wrote"
            );

            // (2) **The route the documentation recommends**: hand over
            //     the account data with the pointer entry left out.
            //     Nothing is written to the server to arrange this. The
            //     account still has its recovery, intact, the whole time.
            let without_pointer = without_the_pointer(&first.account_data);
            let second = create_recovery(PASSPHRASE, &without_pointer).await.expect(
                "omitting the pointer is what the refusal tells a product to do, so it must \
                     be what lets the write through",
            );

            // (3) The merge. Nothing the account already held is dropped.
            let before_write =
                ciphertexts_of(&first.account_data, &SecretName::CrossSigningMasterKey);
            let after_write =
                ciphertexts_of(&second.account_data, &SecretName::CrossSigningMasterKey);
            assert_eq!(
                before_write.len(),
                1,
                "the first recovery stored one ciphertext for the master key"
            );
            assert_eq!(
                after_write.len(),
                2,
                "the second write must add its ciphertext to the map rather than replace \
                 it: the specification's shape is a map from key id to ciphertext so that \
                 more than one key can open one secret, and another client's entry is not \
                 this library's to remove. Got {after_write:?}"
            );
            let (old_key_id, old_ciphertext) = before_write
                .iter()
                .next()
                .expect("just asserted there is exactly one");
            assert_eq!(
                after_write.get(old_key_id),
                Some(old_ciphertext),
                "the entry that was already there must survive byte for byte"
            );

            // (4) And the account's existing recovery still opens while the
            //     new one is being written, because nothing has been sent
            //     yet. That is the property this route has and the other
            //     two do not: there is no window in which the account has
            //     no working recovery.
            recover_identity(PASSPHRASE, &first.account_data)
                .await
                .expect(
                    "this route writes nothing, so the recovery the account had must go on \
                     working right up to the final PUT of the new pointer",
                );

            // (5) The two other routes past the refusal, and what each
            //     costs. Both are served, so nobody is trapped; neither is
            //     what the documentation should send a product to.
            //
            //     An empty list asserts the account has nothing, and the
            //     refusal believes it. The cost is not the refusal: it is
            //     the merge. `existing_ciphertexts` is handed nothing, so it
            //     merges into nothing, so every other key's ciphertext is
            //     evicted. One entry where there were two, silently.
            let from_nothing = create_recovery(PASSPHRASE, &[])
                .await
                .expect("an empty list lifts the refusal, by the same rule");
            assert_eq!(
                ciphertexts_of(
                    &from_nothing.account_data,
                    &SecretName::CrossSigningMasterKey
                )
                .len(),
                1,
                "passing an empty list discards the merge along with the refusal, which is \
                 the whole thing the merge was added to prevent. Asserted rather than \
                 merely documented, because the documentation used to sanction this route \
                 without naming this cost"
            );

            //     And the pointer cleared on the server, which is what a
            //     product holding an already-cleared account is looking at.
            //     Served, and the merge survives, because everything except
            //     the pointer is still in the list. What this route costs is
            //     time, not data: between the clearing PUT and the final
            //     one the account has no working recovery, and
            //     `a_cleared_pointer_is_not_a_destroyed_recovery` is what
            //     stops the library calling that state destruction.
            let cleared = with_the_pointer_cleared(&first.account_data);
            let from_cleared = create_recovery(PASSPHRASE, &cleared)
                .await
                .expect("a cleared pointer lifts the refusal, by the same rule");
            assert_eq!(
                ciphertexts_of(
                    &from_cleared.account_data,
                    &SecretName::CrossSigningMasterKey
                )
                .len(),
                2,
                "clearing the pointer keeps the rest of the account data, so the merge \
                 survives this route too"
            );

            // (6) And the result is a working recovery for the new key.
            //     Written out as a homeserver would store it: the merged
            //     entries replace their predecessors, one event per type.
            let mut stored = first.account_data.clone();
            for entry in &second.account_data {
                match stored
                    .iter_mut()
                    .find(|existing| existing.event_type == entry.event_type)
                {
                    Some(existing) => existing.content = entry.content.clone(),
                    None => stored.push(entry.clone()),
                }
            }
            recover_identity(&second.recovery_key, &stored)
                .await
                .expect("the second recovery must open with its own recovery key");
        }));

        reset_for_test();
        destroy(&store_dir);
    }

    /// The account data a homeserver would hold after `written` has been
    /// `PUT` over `server`, one event per type, last write wins.
    fn applied_over(
        server: &[AccountDataEntry],
        written: &[AccountDataEntry],
    ) -> Vec<AccountDataEntry> {
        let mut stored = server.to_vec();
        for entry in written {
            match stored
                .iter_mut()
                .find(|existing| existing.event_type == entry.event_type)
            {
                Some(existing) => existing.content = entry.content.clone(),
                None => stored.push(entry.clone()),
            }
        }
        stored
    }

    /// A copy of `account_data` whose pointer names `key_id`.
    ///
    /// Used to ask the one question `recover_identity` will not ask by
    /// itself: whether a key the account no longer resolves is still
    /// openable. Following the pointer is this library's rule; it is not a
    /// rule that binds a homeserver operator, anyone holding an access
    /// token, or another client that remembers an old key id, so putting the
    /// pointer back is the honest way to model what those readers reach.
    fn pointed_at(account_data: &[AccountDataEntry], key_id: &str) -> Vec<AccountDataEntry> {
        with_replaced_content(
            account_data,
            |event_type| event_type == "m.secret_storage.default_key",
            &serde_json::json!({ "key": key_id }).to_string(),
        )
    }

    /// A copy of `account_data` with `key_id` dropped from every secret's
    /// `encrypted` map.
    ///
    /// The revocation step, performed as a product performs it: on the
    /// entries this library handed back, before they are written.
    fn without_the_key(account_data: &[AccountDataEntry], key_id: &str) -> Vec<AccountDataEntry> {
        let mut stripped = account_data.to_vec();
        let mut removed = 0;
        for entry in stripped.iter_mut() {
            if !SECRETS.iter().any(|name| name.as_str() == entry.event_type) {
                continue;
            }
            let mut content: serde_json::Value =
                serde_json::from_str(&entry.content).expect("this module wrote well-formed JSON");
            let encrypted = content
                .get_mut("encrypted")
                .and_then(serde_json::Value::as_object_mut)
                .expect("a stored secret always carries an encrypted map");
            if encrypted.remove(key_id).is_some() {
                removed += 1;
            }
            entry.content = content.to_string();
        }
        assert_eq!(
            removed,
            SECRETS.len(),
            "revoking a key must drop it from all three secrets, or the \
             fixture is not the one this test says it is"
        );
        stripped
    }

    /// **Replacing a recovery re-points the account. It does not revoke the
    /// key it replaced**, and this test is what stops the documentation
    /// pretending otherwise.
    ///
    /// # Why this exists
    ///
    /// `create_recovery` refuses to write over a recovery the account
    /// already has, and the first caller its own rationale names is a user
    /// replacing a passphrase they no longer trust, "where the old recovery
    /// key is meant to stop working". The route the documentation recommends
    /// does not do that. Two instructions guarantee it, and each is right on
    /// its own: the ciphertexts **merge**, which is the reason that route is
    /// recommended, and the old key description is left alone, which is what
    /// keeps the merge reversible. Between them the old key stays openable
    /// by anyone who reads the account data without following the pointer.
    ///
    /// A reader of the prose could not have known that. Every other route
    /// past the refusal has its cost named; this one did not, on the path
    /// being recommended, for the caller named first.
    ///
    /// # What is asserted
    ///
    /// 1. After the replacement this library refuses the old passphrase,
    ///    because `restore` follows the pointer.
    /// 2. **And the old key is still open**, which makes act 1 a property of
    ///    this library rather than of the account: put the pointer back and
    ///    the old passphrase imports a complete identity.
    /// 3. Revocation, performed as the documentation now describes it,
    ///    closes that, and its two steps are asserted separately because
    ///    they do different work. Dropping the old key id from each secret
    ///    is what revokes: the key still reconstructs and there is nothing
    ///    left encrypted to it. Clearing the old description afterwards
    ///    changes the answer again, which is how each step is shown to be
    ///    load-bearing rather than riding on the other. The new passphrase
    ///    is unaffected throughout.
    /// 4. And the prohibition gains an executable reason: clearing the
    ///    description **before** the switchover, while the account still
    ///    resolves that key, leaves a recovery no secret can open and that
    ///    restoring the pointer does not bring back.
    #[test]
    fn replacing_a_recovery_re_points_it_and_revoking_it_is_a_further_act() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let before = futures::executor::block_on(in_runtime(before_the_reinstall()));
        let store_dir = before.store_dir.clone();

        futures::executor::block_on(in_runtime(async move {
            let first = before.recovery;
            let old_key_id = pointed_key_id(&first.account_data)
                .expect("the fixture's account data names the key it wrote");

            // The recommended route, driven: nothing is written to arrange
            // it, and what comes back is applied as a homeserver would.
            let second = create_recovery(NEW_PASSPHRASE, &without_the_pointer(&first.account_data))
                .await
                .expect("the recommended route lifts the refusal");
            let server = applied_over(&first.account_data, &second.account_data);

            // (1) Through this library the old passphrase is now wrong,
            //     because `restore` follows the pointer and the pointer
            //     names the new key.
            assert_eq!(
                recover_identity(PASSPHRASE, &server).await,
                Err(MachineError::RecoveryKeyIncorrect),
                "after the switchover the account resolves the new key, so \
                 the old passphrase is a wrong secret for it"
            );

            // (2) And that is a fact about this library, not about the
            //     account. The old description and the old ciphertext are
            //     both still on the server, so a reader that does not follow
            //     the pointer opens the identity with the old passphrase. A
            //     homeserver operator, anyone holding an access token, and
            //     any client that remembers the old key id are such readers.
            recover_identity(PASSPHRASE, &pointed_at(&server, &old_key_id))
                .await
                .expect(
                    "the old key is still openable after the recommended \
                     route, which is what the documentation has to say and \
                     for one release did not",
                );

            // (3a) Revocation, step one: drop the old key id from each
            //      secret. Asserted on its own, before the description is
            //      touched, because the two steps do different work and a
            //      test that ran them together would pin neither. The old
            //      passphrase still reconstructs its key here, since the
            //      description is untouched, and finds nothing stored under
            //      it: that answer is what says the ciphertext is gone
            //      rather than the key.
            let revoked = without_the_key(&second.account_data, &old_key_id);
            let server = applied_over(&server, &revoked);
            assert_eq!(
                recover_identity(PASSPHRASE, &pointed_at(&server, &old_key_id)).await,
                Err(MachineError::RecoveryNotSetUp),
                "dropping the old key id from the secrets is what actually \
                 revokes it: the key still reconstructs from its description \
                 and there is no longer anything encrypted to it"
            );

            // (3b) Step two, and only now: clear the old description, so
            //      nothing on the account describes a key it no longer
            //      uses. The answer changes, which is how this assertion
            //      shows the step did something rather than riding on the
            //      one before.
            let server = with_replaced_content(
                &server,
                |event_type| event_type == format!("m.secret_storage.key.{old_key_id}"),
                "{}",
            );
            assert_eq!(
                recover_identity(PASSPHRASE, &pointed_at(&server, &old_key_id)).await,
                Err(MachineError::RecoveryDataMalformed),
                "with the description gone the key cannot be reconstructed at \
                 all, which is a different answer from (3a) and the reason \
                 this step is last rather than first"
            );
            assert_eq!(
                recover_identity(PASSPHRASE, &server).await,
                Err(MachineError::RecoveryKeyIncorrect),
                "and through the pointer it is still simply the wrong secret"
            );

            // The point of the whole exercise: the new passphrase works.
            recover_identity(NEW_PASSPHRASE, &server)
                .await
                .expect("revoking the old key must not touch the new one");

            // (4) The prohibition, with its reason executable. Clearing the
            //     description while the account still resolves that key is
            //     the same write at the wrong time, and it is not a window
            //     but a loss: putting the pointer back does not help,
            //     because there is nothing left to reconstruct the key from.
            let too_early = with_replaced_content(
                &first.account_data,
                |event_type| event_type.starts_with("m.secret_storage.key."),
                "{}",
            );
            assert_eq!(
                recover_identity(PASSPHRASE, &too_early).await,
                Err(MachineError::RecoveryDataMalformed),
                "a cleared description is unreadable stored data, which is \
                 the one thing no secret fixes"
            );
            assert_eq!(
                recover_identity(PASSPHRASE, &pointed_at(&too_early, &old_key_id)).await,
                Err(MachineError::RecoveryDataMalformed),
                "and unlike a cleared pointer, restoring what was cleared \
                 does not bring it back: the salt, the iteration count and \
                 the MAC went with it. That is why the description is \
                 cleared after the switchover and never before"
            );
        }));

        reset_for_test();
        destroy(&store_dir);
    }

    /// An empty passphrase is accepted, and this test is where that stops
    /// being an accident.
    ///
    /// The encrypted keys live on the homeserver, so the passphrase is what
    /// stands between anyone who can read this account's account data and
    /// the account's private signing keys. This library still imposes no
    /// minimum, and `create_recovery`'s own documentation says why: any
    /// threshold picked here would be arbitrary, wrong for somebody, and
    /// enforced in the one place a product cannot adjust it.
    ///
    /// The second half is what the recovery key does and does not buy, and
    /// this test is what keeps the doc comment honest about it. It is
    /// thirty-two random bytes whatever the passphrase is, and it opens the
    /// recovery here, so the user's own access does not depend on the
    /// passphrase. It offsets nothing about confidentiality: the assertions
    /// below open the same ciphertext with `""` and with the recovery key,
    /// which is the demonstration that an attacker faces the weaker of the
    /// two rather than the stronger.
    #[test]
    fn an_empty_passphrase_is_accepted_and_the_recovery_key_is_still_strong() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();
        let before = futures::executor::block_on(in_runtime(before_the_reinstall()));
        let store_dir = before.store_dir.clone();

        futures::executor::block_on(in_runtime(async move {
            let cleared = with_the_pointer_cleared(&before.recovery.account_data);
            let weak = create_recovery("", &cleared)
                .await
                .expect("this library imposes no passphrase policy, deliberately");

            let mut stored = cleared.clone();
            for entry in &weak.account_data {
                match stored
                    .iter_mut()
                    .find(|existing| existing.event_type == entry.event_type)
                {
                    Some(existing) => existing.content = entry.content.clone(),
                    None => stored.push(entry.clone()),
                }
            }

            // The empty passphrase really does open it, which is the half
            // that makes this a documented decision rather than an
            // oversight nobody measured.
            recover_identity("", &stored)
                .await
                .expect("an empty passphrase opens what an empty passphrase wrote");

            // And the recovery key opens it too, and is not derived from the
            // passphrase: a recovery written with no passphrase at all is
            // still protected for a user who keeps the key.
            recover_identity(&weak.recovery_key, &stored)
                .await
                .expect("the recovery key is random whatever the passphrase is");
            assert!(
                weak.recovery_key.len() > 40,
                "the recovery key is thirty-two bytes of base58 however weak \
                 the passphrase was: {}",
                weak.recovery_key.len()
            );
        }));

        reset_for_test();
        destroy(&store_dir);
    }

    /// What a recovery is made of, asserted against the specification's own
    /// names rather than against whatever this module happens to emit.
    ///
    /// A product writes these five event types and no others, and another
    /// Matrix client reads them, so the set is part of the contract and not
    /// an implementation detail.
    #[test]
    fn a_recovery_is_five_account_data_events_a_matrix_client_would_recognise() {
        let _guard = futures::executor::block_on(lock_for_test());
        reset_for_test();

        let (setup, store_dir) = futures::executor::block_on(in_runtime(async {
            let before = before_the_reinstall().await;
            (before.recovery, before.store_dir)
        }));

        // Released and deleted here rather than at the end: nothing below
        // touches the machine, and a test that builds a crypto store and
        // leaves it in the temporary directory is one more store on disk
        // for every run of this suite.
        reset_for_test();
        destroy(&store_dir);

        let types: Vec<&str> = setup
            .account_data
            .iter()
            .map(|entry| entry.event_type.as_str())
            .collect();
        assert_eq!(types.len(), 5, "a recovery is five events: {types:?}");
        assert!(
            types[0].starts_with("m.secret_storage.key."),
            "the key description's type ends in the key's own id: {types:?}"
        );
        assert_eq!(
            types[4], "m.secret_storage.default_key",
            "the pointer is written last, so an interrupted write never leaves \
             the account resolving a key whose secrets are not there yet: \
             {types:?}"
        );
        for name in SECRETS {
            assert!(
                types.contains(&name.as_str()),
                "a recovery carries {}: {types:?}",
                name.as_str()
            );
        }

        // The key description names the same key the pointer points at. A
        // mismatch here would produce account data no client, this one
        // included, could ever open.
        let pointer: serde_json::Value = serde_json::from_str(&setup.account_data[4].content)
            .expect("this module wrote well-formed JSON");
        let key_id = pointer
            .get("key")
            .and_then(serde_json::Value::as_str)
            .expect("the pointer names a key");
        assert_eq!(types[0], format!("m.secret_storage.key.{key_id}"));

        // The recovery key is the base58 form the specification describes,
        // shown in groups of four. Asserted because it is the one value a
        // product shows a human and can never produce again.
        assert!(
            setup.recovery_key.contains(' ') && setup.recovery_key.len() > 40,
            "the recovery key is a grouped base58 string: {}",
            setup.recovery_key.len()
        );
    }
}
