//! Which core error variant becomes which FFI error variant.
//!
//! This crate mirrors two core error enums by hand,
//! `From<matrix_crypto_core::SessionError> for SessionFfiError` and
//! `From<matrix_crypto_core::MachineError> for MachineFfiError`. Both matches
//! are exhaustive with no wildcard arm, so a *new* upstream variant fails the
//! build. Nothing checked that the existing arms point anywhere sensible:
//! **swapping two same-shaped variants compiles, passes
//! `clippy -D warnings`, and passes every Rust and TypeScript test**, because
//! the mapping is only exercised on failure paths and the TypeScript layer
//! drives its own `toCryptoError` from hand-written fixtures rather than from
//! these impls. `gate:drift` cannot see it either: the enum *declarations* are
//! unchanged, so the regenerated bindings are byte-identical.
//!
//! That is the same "two values, one type" hazard `delegate_order.rs` exists
//! for, one layer over, and it matters more than its size suggests: the
//! decryption taxonomy these variants carry took a full review round to settle
//! in Task 6, precisely because `MissingKey`, `UnsharedSession`,
//! `SessionRefused`, `UnknownDevice` and `Undecryptable` call for five
//! different product responses. A swap here silently tells a product to
//! retry what it should never retry, or to give up on what a retry would
//! fix -- `UnsharedSession` and `SessionRefused` are the sharpest version of
//! that risk: same shape, opposite retriability, split apart for exactly
//! this reason (G26 in the milestone's own ledger).
//!
//! No machine, no store, no runtime, and no failure path: both `From` impls
//! are public, both core enums are public and not `#[non_exhaustive]`, and
//! their variants are constructible from outside the crate. So the mapping is
//! asserted directly, which is why this file runs in no measurable time.

use matrix_crypto_core::{MachineError, SessionError};
use matrix_crypto_ffi::{MachineFfiError, SessionFfiError};

/// All eleven `SessionError` variants, each to its own kind.
///
/// One assertion per variant rather than a loop: a loop would need the two
/// enums to be relatable by something other than this mapping, which is the
/// very thing under test.
#[test]
fn every_session_error_maps_to_the_matching_ffi_variant() {
    assert!(
        matches!(
            SessionFfiError::from(SessionError::MalformedPayload),
            SessionFfiError::MalformedPayload
        ),
        "SessionError::MalformedPayload must not arrive as another kind"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::NotInitialised),
            SessionFfiError::NotInitialised
        ),
        "SessionError::NotInitialised must not arrive as another kind"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::Failed),
            SessionFfiError::Failed
        ),
        "SessionError::Failed must not arrive as another kind"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::UnknownRequest),
            SessionFfiError::UnknownRequest
        ),
        "SessionError::UnknownRequest must not arrive as another kind"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::MalformedIdentifier),
            SessionFfiError::MalformedIdentifier
        ),
        "SessionError::MalformedIdentifier must not arrive as another kind -- \
         it is fieldless and same-shaped as MalformedPayload, and the whole \
         point of the split is that a caller with a bad scope is not sent to \
         inspect a payload that is fine"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::NotAFailureStatus),
            SessionFfiError::NotAFailureStatus
        ),
        "SessionError::NotAFailureStatus must not arrive as another kind. It \
         is the only sign a product gets that it has swapped markRequestFailed \
         for markRequestSent, and arriving as MalformedPayload would send it to \
         inspect a body that is not the problem"
    );

    // The five decryption kinds. These are the ones a swap damages most:
    // each names a different product response, and all five are fieldless,
    // so the compiler cannot tell them apart.
    assert!(
        matches!(
            SessionFfiError::from(SessionError::MissingKey),
            SessionFfiError::MissingKey
        ),
        "SessionError::MissingKey must not arrive as another kind -- it is \
         retriable, and a product told UnsharedSession or SessionRefused \
         instead may stop asking, or ask forever"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::UnsharedSession),
            SessionFfiError::UnsharedSession
        ),
        "SessionError::UnsharedSession must not arrive as another kind -- it \
         is the circumstantial half of the withheld-code split and stays \
         retriable, and a product told SessionRefused instead may give up on \
         a withheld session a later attempt could still resolve"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::SessionRefused),
            SessionFfiError::SessionRefused
        ),
        "SessionError::SessionRefused must not arrive as another kind -- it \
         is the policy half of the withheld-code split (G26) and is never \
         retriable, and a product told UnsharedSession instead may retry a \
         deliberate blacklist or unauthorised refusal forever, at real cost \
         in battery and network for a retry that can never succeed"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::UnknownDevice),
            SessionFfiError::UnknownDevice
        ),
        "SessionError::UnknownDevice must not arrive as another kind"
    );
    assert!(
        matches!(
            SessionFfiError::from(SessionError::Undecryptable),
            SessionFfiError::Undecryptable
        ),
        "SessionError::Undecryptable must not arrive as another kind -- it is \
         the one that is never worth retrying"
    );
}

/// All twenty-three `MachineError` variants, each to its own kind, and both
/// `detail`-carrying variants checked for the payload as well as the kind.
///
/// This header said eleven for two milestones after the enum passed it, and
/// the body was right the whole time: the assertions were added and this
/// count was not. Recovery took it to seventeen and verification by a
/// scannable code to twenty-three. A number in a header that the body does
/// not derive is exactly what went wrong, so if you add a variant, the
/// assertion below is what fails if you forget it; this sentence is not.
///
/// The two field-carrying variants are the ones a swap could hide behind a
/// kind-only check: `MalformedIdentifier` and `Store` have identical shapes,
/// so mapping either to the other type-checks and would carry the detail
/// along with it.
#[test]
fn every_machine_error_maps_to_the_matching_ffi_variant() {
    assert!(
        matches!(
            MachineFfiError::from(MachineError::NotInitialised),
            MachineFfiError::NotInitialised
        ),
        "MachineError::NotInitialised must not arrive as another kind"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::AlreadyInitialised),
            MachineFfiError::AlreadyInitialised
        ),
        "MachineError::AlreadyInitialised must not arrive as another kind"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::MismatchedAccount),
            MachineFfiError::MismatchedAccount
        ),
        "MachineError::MismatchedAccount must not arrive as another kind -- it \
         is the recoverable configuration mistake, deliberately kept distinct \
         from the storage failure Store covers"
    );

    // Distinguishable per variant, so a swap between the two same-shaped
    // variants changes the observed detail as well as the kind. Neither
    // value is a real identifier: this crate's `detail` carries a category
    // label, never the identifier itself.
    let identifier_detail = "detail-from-the-identifier-variant";
    assert!(
        matches!(
            MachineFfiError::from(MachineError::MalformedIdentifier {
                detail: identifier_detail.to_string()
            }),
            MachineFfiError::MalformedIdentifier { detail } if detail == identifier_detail
        ),
        "MachineError::MalformedIdentifier must arrive as the same kind, carrying \
         the same detail"
    );

    let store_detail = "detail-from-the-store-variant";
    assert!(
        matches!(
            MachineFfiError::from(MachineError::Store {
                detail: store_detail.to_string()
            }),
            MachineFfiError::Store { detail } if detail == store_detail
        ),
        "MachineError::Store must arrive as the same kind, carrying the same \
         detail -- it has the same shape as MalformedIdentifier, so a swap \
         between them type-checks and carries the detail along with it"
    );

    // The three verification-flow kinds. Fieldless and mutually
    // indistinguishable to the compiler, like the five decryption kinds
    // above and with the same consequence: each tells a product to do
    // something different -- start over with a flow that still exists, wait
    // for the stage this call needs, or go and report the request it
    // drained as sent -- and a swap sends it to do the wrong one.
    assert!(
        matches!(
            MachineFfiError::from(MachineError::UnknownFlow),
            MachineFfiError::UnknownFlow
        ),
        "MachineError::UnknownFlow must not arrive as another kind -- it is \
         the only one of the three that means the identifier itself is no \
         longer worth holding on to"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::WrongStage),
            MachineFfiError::WrongStage
        ),
        "MachineError::WrongStage must not arrive as another kind -- a \
         product told MaterialNotReady instead would wait for a string that \
         is never coming"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::MaterialNotReady),
            MachineFfiError::MaterialNotReady
        ),
        "MachineError::MaterialNotReady must not arrive as another kind -- it \
         is the one that names a caller's own omission, and a product told \
         WrongStage instead would abandon a flow that is still live and one \
         report away from completing"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::UnknownDevice),
            MachineFfiError::UnknownDevice
        ),
        "MachineError::UnknownDevice must not arrive as another kind -- it is \
         fixed by querying that user's devices and trying again, which is not \
         what any other variant of this enum asks for"
    );

    // The two identity-bootstrap kinds. Same shape, adjacent in both enums,
    // and **opposite in what they ask of a product**: one says ask the
    // server and call again, the other says never call again for this
    // account because doing so would destroy an identity somebody else's
    // devices already trust. Swapping the two arms compiles, and before this
    // pair of assertions existed it passed the entire suite -- which is
    // precisely the hazard this file was written for.
    assert!(
        matches!(
            MachineFfiError::from(MachineError::AccountKeysNotFetched),
            MachineFfiError::AccountKeysNotFetched
        ),
        "MachineError::AccountKeysNotFetched must not arrive as another kind -- \
         it is the recoverable one, lifted by draining the pump and reporting \
         the key query it queued, and a product told IdentityAlreadyExists \
         instead would give up on an account that has no identity at all"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::IdentityAlreadyExists),
            MachineFfiError::IdentityAlreadyExists
        ),
        "MachineError::IdentityAlreadyExists must not arrive as another kind -- \
         a product told AccountKeysNotFetched instead would fetch the keys and \
         call again, and calling again is the one thing that must never work \
         here: this device joins the identity the account already has, it does \
         not replace it"
    );

    // The self-verification refusal, which completes the same triangle. It
    // is the mirror image of `IdentityAlreadyExists`: that one says "there is
    // an identity and you are not it", this one says "there is no identity at
    // all", and a product told the wrong one either creates a second identity
    // over the account's or waits forever for one that does not exist.
    assert!(
        matches!(
            MachineFfiError::from(MachineError::IdentityNotKnown),
            MachineFfiError::IdentityNotKnown
        ),
        "MachineError::IdentityNotKnown must not arrive as another kind -- a \
         product told AccountKeysNotFetched instead would drain the pump and \
         ask again forever, and one told IdentityAlreadyExists would conclude \
         the account has an identity it must not touch when the truth is that \
         it has none and creating one is exactly what is needed"
    );

    // The five server-side recovery refusals. All fieldless, so any
    // permutation of the five arms compiles and passes every other test in
    // this repository, and `RecoveryKeyIncorrect` and
    // `RecoveryDataMalformed` are the pair that must never be confused.
    // This said four and asserted five from the day it was written: `RecoveryKeyIncorrect` is a typo the user retypes,
    // `RecoveryDataMalformed` is a recovery no secret will ever open. A
    // product told the first when the truth is the second leaves a user
    // retyping a correct passphrase forever; told the second when the truth
    // is the first, it tells a user with a typo that their identity is
    // destroyed and sends them to set recovery up again, which is the one
    // action that makes it destroyed.
    assert!(
        matches!(
            MachineFfiError::from(MachineError::PrivateKeysNotHeld),
            MachineFfiError::PrivateKeysNotHeld
        ),
        "MachineError::PrivateKeysNotHeld must not arrive as another kind"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::RecoveryNotSetUp),
            MachineFfiError::RecoveryNotSetUp
        ),
        "MachineError::RecoveryNotSetUp must not arrive as another kind -- a \
         product told a passphrase was wrong would ask its user to retype one \
         against account data that carries no recovery at all"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::RecoveryKeyIncorrect),
            MachineFfiError::RecoveryKeyIncorrect
        ),
        "MachineError::RecoveryKeyIncorrect must not arrive as another kind -- \
         it is the one refusal on this surface a user fixes by typing again"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::RecoveryDataMalformed),
            MachineFfiError::RecoveryDataMalformed
        ),
        "MachineError::RecoveryDataMalformed must not arrive as another kind -- \
         no secret opens this one, and reporting it as a wrong passphrase is \
         the fold both variants exist to prevent"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::RecoveryAlreadyExists),
            MachineFfiError::RecoveryAlreadyExists
        ),
        "MachineError::RecoveryAlreadyExists must not arrive as another kind -- \
         a product told `RecoveryNotSetUp` instead would conclude the account \
         has no recovery and write one over the recovery it does have"
    );

    // The six refusals verification by a scannable code adds. Four of them
    // are about one scanned payload and they are the sharpest instance in
    // this file of the hazard it exists for: fieldless, adjacent, declared
    // in one block, and describing four *different* things to say to a
    // person. Any permutation of the four arms compiles and passes every
    // other test in this repository, and the design's section 4 is a
    // requirement that a product be able to tell three of them apart.
    assert!(
        matches!(
            MachineFfiError::from(MachineError::PeerIdentityNotKnown),
            MachineFfiError::PeerIdentityNotKnown
        ),
        "MachineError::PeerIdentityNotKnown must not arrive as another kind -- \
         swapped with `IdentityNotKnown` it sends a user to set up an identity \
         that is already in place, over a gap only the other person can close"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::CodeNotOffered),
            MachineFfiError::CodeNotOffered
        ),
        "MachineError::CodeNotOffered must not arrive as another kind -- read as \
         a stage, a product waits for a code the peer will never be able to \
         scan instead of offering a short string"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::PeerCannotScan),
            MachineFfiError::PeerCannotScan
        ),
        "MachineError::PeerCannotScan must not arrive as another kind, and least \
         of all as `CodeNotOffered`, which is the one it was split out of: the \
         two have opposite remedies, one is the product's own switch and the \
         other is a fact about the far side, and folded together they sent a \
         product that had answered correctly to go and re-check its answer"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::ScannedCodeRefused),
            MachineFfiError::ScannedCodeRefused
        ),
        "MachineError::ScannedCodeRefused must not arrive as another kind -- it \
         is the only one of the four that can mean an interposed party rather \
         than a mis-aimed camera, and reporting it as any of the other three \
         tells a person to try again at exactly the moment they must not"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::ScannedCodeUnrecognised),
            MachineFfiError::ScannedCodeUnrecognised
        ),
        "MachineError::ScannedCodeUnrecognised must not arrive as another kind -- \
         a product told the code was damaged asks for the same square to be \
         scanned again, when the answer is to point the camera somewhere else"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::ScannedCodeMalformed),
            MachineFfiError::ScannedCodeMalformed
        ),
        "MachineError::ScannedCodeMalformed must not arrive as another kind -- it \
         is the one signal that a product's scanner is handing this library \
         text rather than bytes, and it is invisible from anywhere else"
    );
    assert!(
        matches!(
            MachineFfiError::from(MachineError::ScannedCodeForAnotherFlow),
            MachineFfiError::ScannedCodeForAnotherFlow
        ),
        "MachineError::ScannedCodeForAnotherFlow must not arrive as another kind \
         -- nothing is damaged and nothing is suspicious, and a product that \
         said either would alarm a person who simply read the wrong screen"
    );
}

/// All three `OprfError` variants, each to its own kind. `ProofRejected`
/// above all stays apart from `MalformedPayload`: an answer that fails its
/// proof is one a product refuses, and an answer that does not parse is one
/// it may ask for again.
#[test]
fn every_oprf_error_maps_to_the_matching_ffi_variant() {
    use matrix_crypto_core::OprfError;
    use matrix_crypto_ffi::OprfFfiError;

    assert!(matches!(
        OprfFfiError::from(OprfError::Rejected),
        OprfFfiError::Rejected
    ));
    assert!(matches!(
        OprfFfiError::from(OprfError::MalformedPayload),
        OprfFfiError::MalformedPayload
    ));
    assert!(matches!(
        OprfFfiError::from(OprfError::ProofRejected),
        OprfFfiError::ProofRejected
    ));
}
