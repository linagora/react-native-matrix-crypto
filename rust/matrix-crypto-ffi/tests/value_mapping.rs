//! Which core value becomes which FFI value.
//!
//! `error_mapping.rs`'s hazard, one file over and with three more shapes of
//! it. This crate mirrors core types by hand -- `FlowStage`, `TrustState`,
//! `SasMaterial`, `DeviceStatus`, `IdentityStatus`, `ScannableCode`,
//! `Envelope`, `SenderVerification`, `RecoverySetup`, `AccountDataEntry`
//! and `CryptoSignal` -- and every one of them has the property that a
//! wrong arm compiles, passes `clippy -D warnings`, and passes every other
//! test in this repository. This paragraph named five and the file has
//! exercised more than five for two milestones:
//!
//! * **Two fieldless enums.** Every variant of `FlowStage` is
//!   interchangeable with every other as far as the compiler is concerned,
//!   and so is every variant of `TrustState`. Mapping `Done` to `Cancelled`
//!   presents a refused verification as a completed one; mapping
//!   `Unverified` to `Verified` presents an unverified device as a verified
//!   one, which is the single worst sentence this library could say.
//!   Neither is reachable from the core's own tests, which never cross this
//!   boundary, nor from the TypeScript tests, which mock the boundary away.
//! * **Three same-typed fields on one record, twice.** `SasMaterial`'s three
//!   decimals are `u16`, `u16`, `u16`. Swapping two of them is invisible to
//!   the compiler and produces a short authentication string that differs
//!   from the far side's in a way that looks exactly like a genuine
//!   mismatch -- so the observable symptom of this defect is a verification
//!   that a careful person correctly refuses, every time, for no reason.
//!   `IdentityStatus`'s five fields are all `bool`, which is the same hazard
//!   with a smaller alphabet and a worse consequence: four of those five
//!   exist precisely to be told apart, and reporting them the wrong way
//!   round tells a product it may publish an identity over one the account
//!   already has.
//!
//! * **A boolean grid whose polarity is invisible.** `ScannableCode`
//!   crosses as a width and `width * width` booleans, `true` for a dark
//!   square. Reversing every one of them compiles, and produces the
//!   photographic negative of a valid code: a product draws it, a camera
//!   reads nothing, and no error is returned to anybody. Reversing the row
//!   order, or crossing the width off by one, is the same class. Nothing
//!   in the core's own tests can see any of it, because none of them
//!   crosses this boundary.
//!
//! No machine, no store and no runtime: every `From` impl under test is
//! public, every core type is public and constructible from outside the
//! crate, and none of the conversions touches state. That is why this file
//! runs in no measurable time.

use matrix_crypto_core::{
    AccountDataEntry, CryptoSignal, DeviceStatus, Envelope, FlowStage, IdentityStatus,
    RecoverySetup, SasEmoji, SasMaterial, ScannableCode, SenderVerification, TrustState,
};
use matrix_crypto_ffi::{
    AccountDataEntry as FfiAccountDataEntry, CryptoSignal as FfiCryptoSignal,
    DeviceStatus as FfiDeviceStatus, Envelope as FfiEnvelope, IdentityStatus as FfiIdentityStatus,
    RecoverySetup as FfiRecoverySetup, SasMaterial as FfiSasMaterial,
    ScannableCode as FfiScannableCode, SenderVerification as FfiSenderVerification,
    TrustState as FfiTrustState, VerificationStage,
};

/// All eight stages, each to its own. One assertion per variant rather than
/// a loop, for `error_mapping.rs`'s reason: a loop would need the two enums
/// to be relatable by something other than this mapping, which is the very
/// thing under test.
#[test]
fn every_flow_stage_maps_to_the_matching_ffi_variant() {
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Requested),
            VerificationStage::Requested
        ),
        "FlowStage::Requested must not arrive as another stage"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Ready),
            VerificationStage::Ready
        ),
        "FlowStage::Ready must not arrive as another stage -- it is the one \
         stage at which a comparison may be started, so a product told \
         anything else waits forever and a product told this one when it is \
         false starts a comparison that is refused"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Started),
            VerificationStage::Started
        ),
        "FlowStage::Started must not arrive as another stage"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::KeysExchanged),
            VerificationStage::KeysExchanged
        ),
        "FlowStage::KeysExchanged must not arrive as another stage -- it is \
         the one stage at which there is a string to show a person"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Confirmed),
            VerificationStage::Confirmed
        ),
        "FlowStage::Confirmed must not arrive as another stage -- confirmed \
         is not done, and a product told Done here reports a device verified \
         two messages before it is"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Done),
            VerificationStage::Done
        ),
        "FlowStage::Done must not arrive as another stage"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::Cancelled),
            VerificationStage::Cancelled
        ),
        "FlowStage::Cancelled must not arrive as another stage -- Done and \
         Cancelled are the two outcomes of a verification and they are \
         opposites, so this pair is the one a swap damages most: a refusal \
         would be presented as a success"
    );
    assert!(
        matches!(
            VerificationStage::from(FlowStage::CodeScanned),
            VerificationStage::CodeScanned
        ),
        "FlowStage::CodeScanned must not arrive as another stage -- it is the \
         only stage at which a flow verified by a code asks a person \
         anything, and the only one at which confirming a scan is accepted, \
         so a product told anything else here waits until the flow times out"
    );
}

/// All three trust values, each to its own.
#[test]
fn every_trust_state_maps_to_the_matching_ffi_variant() {
    assert!(
        matches!(
            FfiTrustState::from(TrustState::Unverified),
            FfiTrustState::Unverified
        ),
        "TrustState::Unverified must not arrive as another value -- reported \
         as Verified it would tell a product a device had been through a \
         comparison that never happened, which is the one sentence this \
         library exists to be able to say truthfully"
    );
    assert!(
        matches!(
            FfiTrustState::from(TrustState::Recognized),
            FfiTrustState::Recognized
        ),
        "TrustState::Recognized must not arrive as another value -- nothing \
         produces it today, which is exactly why nothing else would notice"
    );
    assert!(
        matches!(
            FfiTrustState::from(TrustState::Verified),
            FfiTrustState::Verified
        ),
        "TrustState::Verified must not arrive as another value"
    );
}

/// The three decimals keep their order, and the symbols keep theirs.
///
/// Three distinguishable values, not three equal ones: the point of the
/// test is position, and `(1, 1, 1)` would pass against any permutation.
/// Same for the symbols, which are compared as a sequence rather than a
/// set.
#[test]
fn the_short_authentication_string_crosses_in_the_order_it_was_computed() {
    let crossed = FfiSasMaterial::from(SasMaterial {
        emoji: Some(vec![
            SasEmoji {
                symbol: "first-symbol".to_string(),
                description: "first-word".to_string(),
            },
            SasEmoji {
                symbol: "second-symbol".to_string(),
                description: "second-word".to_string(),
            },
        ]),
        decimals: (1111, 2222, 3333),
    });

    assert_eq!(
        (
            crossed.decimal_one,
            crossed.decimal_two,
            crossed.decimal_three
        ),
        (1111, 2222, 3333),
        "the three decimals must cross in the order they were computed -- a \
         swap here produces a string that differs from the far side's and \
         looks exactly like a genuine mismatch"
    );

    let symbols = crossed
        .emoji
        .expect("a material carrying symbols must still carry them after crossing");
    assert_eq!(
        symbols
            .iter()
            .map(|emoji| emoji.symbol.as_str())
            .collect::<Vec<_>>(),
        vec!["first-symbol", "second-symbol"],
        "the symbols must cross in order"
    );
    assert_eq!(
        symbols
            .iter()
            .map(|emoji| emoji.description.as_str())
            .collect::<Vec<_>>(),
        vec!["first-word", "second-word"],
        "each symbol must keep its own word -- symbol and description have \
         the same type, so a swap between the two fields compiles"
    );
}

/// The symbol-less case, which the protocol produces whenever both sides
/// did not negotiate the symbol form.
///
/// Asserted because `Option::map` over an absent value and an empty vector
/// are easy to confuse in either direction, and a surface that showed seven
/// blank symbols instead of falling back to the digits would be showing a
/// person nothing to compare.
#[test]
fn a_material_with_no_symbols_crosses_with_none_rather_than_an_empty_list() {
    let crossed = FfiSasMaterial::from(SasMaterial {
        emoji: None,
        decimals: (4444, 5555, 6666),
    });

    assert!(
        crossed.emoji.is_none(),
        "an absent symbol form must stay absent, not become an empty list"
    );
    assert_eq!(
        (
            crossed.decimal_one,
            crossed.decimal_two,
            crossed.decimal_three
        ),
        (4444, 5555, 6666),
    );
}

/// A code crosses as both of its forms, with the grid in the order it was
/// drawn.
///
/// Three fields and three separate hazards, which is why this is asserted
/// rather than assumed of a three-line `From`:
///
/// * **The payload must cross byte for byte.** It carries the shared secret
///   the whole method rests on, and a payload that lost a byte draws a code
///   the other phone refuses with nothing to say about why.
/// * **The grid must keep its order.** It is row-major and square; a
///   reversed or rotated sequence is still `width * width` booleans, still
///   type-checks, still draws a plausible-looking square, and decodes to
///   nothing.
/// * **`width` must be the symbol's own.** A product draws `width * width`
///   squares out of `modules`, so a width that crossed as anything else
///   either draws a fraction of the code or runs off the end of the vector.
///
/// The fixture is deliberately asymmetric in every direction -- a payload
/// whose bytes are all different, a grid that is not a palindrome and does
/// not read the same by rows as by columns, and a width that is not the
/// length of anything else here.
#[test]
fn a_scannable_code_crosses_as_both_of_its_forms() {
    // Three by three, dark on one diagonal only: reversing the sequence,
    // transposing it, or inverting it all give a different vector.
    let modules = vec![true, false, false, false, true, false, false, false, false];
    let crossed = FfiScannableCode::from(ScannableCode {
        payload: vec![1, 2, 3, 4, 250, 251, 252, 253],
        width: 3,
        modules: modules.clone(),
    });

    assert_eq!(
        crossed.payload,
        vec![1, 2, 3, 4, 250, 251, 252, 253],
        "the payload must cross byte for byte -- it is the code, and the bytes \
         above are all distinct so a reordering fails here rather than passing \
         on a length check"
    );
    assert_eq!(
        crossed.width, 3,
        "the width must be the symbol's own; a product draws `width * width` \
         squares out of the grid below"
    );
    assert_eq!(
        crossed.modules, modules,
        "the grid must cross in the order it was drawn -- it is row-major, and \
         a reversed or transposed one is the same length and draws a square \
         that decodes to nothing"
    );
    // The payload and the grid are different lengths on purpose: a mapping
    // that built one out of the other would satisfy both assertions above
    // for a symbol whose sizes happened to agree.
    assert_ne!(crossed.payload.len(), crossed.modules.len());
}

/// A device status keeps its identifier and its trust together.
///
/// The pairing is the whole content of this record: one device reported
/// under another device's identifier is a product showing a verification
/// tick beside the wrong entry in a list.
#[test]
fn a_device_status_keeps_its_identifier_and_its_trust_together() {
    let crossed = FfiDeviceStatus::from(DeviceStatus {
        device_id: "A-DEVICE-IDENTIFIER".to_string(),
        trust: TrustState::Verified,
    });

    assert_eq!(crossed.device_id, "A-DEVICE-IDENTIFIER");
    assert!(matches!(crossed.trust, FfiTrustState::Verified));

    let other = FfiDeviceStatus::from(DeviceStatus {
        device_id: "ANOTHER-DEVICE-IDENTIFIER".to_string(),
        trust: TrustState::Unverified,
    });

    assert_eq!(other.device_id, "ANOTHER-DEVICE-IDENTIFIER");
    assert!(
        matches!(other.trust, FfiTrustState::Unverified),
        "the second status is here so this test fails against an \
         implementation that returns a constant"
    );
}

/// Every sender-verification value, each to its own.
///
/// # Why `Verified` is an input here now, and was not before
///
/// Until M4 this list stopped one variant short of the enum, and the
/// omission was deliberate rather than careless. The M3 design ruling on
/// this type (spec section 7, question 3) bound the implementation to two
/// things: document the unreachable values at the type, and keep the test
/// suite free of any case that appears to produce `Verified`. A `From`
/// test taking `SenderVerification::Verified` as a literal was exactly
/// such a case. Read out of context it said this library produces that
/// value, and at the time this library did not.
///
/// It does now. `matrix-crypto-core/tests/verified_sender.rs` reaches
/// `Verified` through the whole chain (bootstrap, publish, sign, upload,
/// re-query, decrypt) against a counterparty that process does not
/// control, with nothing anywhere fabricating the value on the way. So the
/// literal below is no longer a fiction a reader has to take on trust: it
/// is a value the core demonstrably makes, and carrying it across this
/// boundary is the next hop.
///
/// The ruling was replaced rather than dropped, and the replacement is
/// stricter rather than looser: **nothing except the real chain produces
/// `Verified`.** It is written at the type, on
/// `matrix_crypto_core::SenderVerification`, which is where a reader meets
/// the claim. The complement is
/// [`only_verified_crosses_the_boundary_as_verified`] below: every other
/// value must still arrive as itself, which is the mapping defect that
/// would turn "a device this machine has merely heard of" into "this
/// message is authentic" on a product's screen.
///
/// # The name lost a word
///
/// It was `every_reachable_sender_verification_maps_to_the_matching_ffi_variant`,
/// and that qualifier existed only to excuse the arm it was leaving out.
/// With the arm present there is no subset left for the word to describe,
/// and keeping it would offer the next omission somewhere to hide. This is
/// the shape the M4 design calls the dangerous one: a test that keeps
/// passing while its name turns into a false statement, so nothing ever
/// forces the correction.
///
/// One assertion per variant rather than a loop, for the reason the flow
/// stage test above gives: a loop would need the two enums to be relatable
/// by something other than this mapping, which is the thing under test.
#[test]
fn every_sender_verification_maps_to_the_matching_ffi_variant() {
    assert!(
        matches!(
            FfiSenderVerification::from(SenderVerification::Verified),
            FfiSenderVerification::Verified
        ),
        "the one value that guarantees authenticity must cross as itself; \
         anything else here discards, without a sound, a verification a \
         product paid all seven steps of the chain for"
    );
    assert!(
        matches!(
            FfiSenderVerification::from(SenderVerification::UnsignedDevice),
            FfiSenderVerification::UnsignedDevice
        ),
        "the ordinary case for every peer in this build must not arrive as \
         another value"
    );
    assert!(
        matches!(
            FfiSenderVerification::from(SenderVerification::NoDeviceMissing),
            FfiSenderVerification::NoDeviceMissing
        ),
        "a missing device and an insecure source are different reasons and \
         must stay apart across the boundary"
    );
    assert!(
        matches!(
            FfiSenderVerification::from(SenderVerification::NoDeviceInsecureSource),
            FfiSenderVerification::NoDeviceInsecureSource
        ),
        "an insecure source must not arrive as a merely missing device"
    );
    assert!(
        matches!(
            FfiSenderVerification::from(SenderVerification::MismatchedSender),
            FfiSenderVerification::MismatchedSender
        ),
        "the impersonation signal must not arrive as one of its neighbours; \
         folding it is the failure the design ruling on this type names"
    );

    // `UnverifiedIdentity` **is** produced by this build, and this file said
    // otherwise until 0.1.0. It depends on the sender's cross-signing
    // identity rather than on ours, so any peer whose client has
    // cross-signing set up produces it here.
    // `matrix-crypto-core/tests/cross_signed_peer.rs` decrypts an event from
    // one and asserts the value; this assertion is the boundary half of the
    // same claim, and it belongs in the reachable list for that reason.
    assert!(
        matches!(
            FfiSenderVerification::from(SenderVerification::UnverifiedIdentity),
            FfiSenderVerification::UnverifiedIdentity
        ),
        "a device its owner cross-signed, whose owner we have not verified, \
         must not arrive as one of its neighbours: `UnsignedDevice` would \
         understate what is known about the sender and `Verified` would \
         overstate it"
    );

    // `VerificationViolation` needs the sender's identity to have been
    // verified by us once and to have changed since. This file used to say
    // the first half was impossible, because it needs a cross-signing
    // identity of our own and this build had no way to create one. M4
    // gives it one, so the value now sits one step *past* `Verified`
    // rather than beside it: reachable only for a sender whose chain
    // completed and whose identity then changed. No test in this
    // repository constructs that situation, which is a fact about the
    // fixtures and is no longer a fact about the build.
    assert!(matches!(
        FfiSenderVerification::from(SenderVerification::VerificationViolation),
        FfiSenderVerification::VerificationViolation
    ));
}

/// `Verified` crosses this boundary as `Verified`, and nothing else does.
///
/// The complement of the test above, and the one that would catch the
/// expensive defect. A `From` arm sending `UnsignedDevice` to `Verified`
/// compiles, passes clippy, and passes every other test in this
/// repository, and it turns "a device this machine has merely heard of"
/// into "this message is guaranteed to be authentic" on a product's
/// screen.
///
/// # What the old name said, and why a rename was the fix
///
/// This was `nothing_this_build_produces_crosses_as_verified`. It iterated
/// the six values that were not `Verified`, because those were the only
/// ones the build produced, and it asserted that none of them arrived as
/// `Verified`. The body never stopped being correct. The name stopped
/// being true the day cross-signing bootstrap landed, and because the body
/// stays green forever, nothing was ever going to force the correction:
/// exactly the failure the M4 design names as the dangerous one. The
/// property worth keeping is not "nothing produces `Verified`" but
/// **"nothing except the real chain does"**, and that is what the name now
/// says.
///
/// # The list is the whole enum now, and the assertion is two-sided
///
/// A prohibition became a biconditional, which is strictly stronger than
/// what it replaces. While `Verified` could never arrive, a mapping that
/// *dropped* it was harmless. Now that the chain reaches it, dropping it
/// loses a verification a product paid seven steps for, silently, and the
/// old shape of this test could not have seen that. Both directions were
/// watched failing before this was committed.
#[test]
fn only_verified_crosses_the_boundary_as_verified() {
    for produced in [
        // The one value that must arrive as `Verified`. Reached through
        // the real chain in `matrix-crypto-core/tests/verified_sender.rs`,
        // which is what makes it an input here rather than a fixture
        // fabricating an authenticity claim: see the test above.
        SenderVerification::Verified,
        SenderVerification::UnsignedDevice,
        SenderVerification::NoDeviceMissing,
        SenderVerification::NoDeviceInsecureSource,
        SenderVerification::MismatchedSender,
        // `UnverifiedIdentity` is produced by this build, so it is a live
        // entry rather than a precaution: a cross-signed device whose owner
        // we have not verified crossing as `Verified` is exactly the
        // sentence this test exists to forbid, and it is the value most
        // likely to be folded into `Verified` by someone reading
        // "cross-signed" as "trusted".
        SenderVerification::UnverifiedIdentity,
        // Reachable only past `Verified`, for a sender whose chain
        // completed and whose identity then changed. No fixture here
        // constructs that, and this entry is what makes the mapping hold
        // on the day one does.
        SenderVerification::VerificationViolation,
    ] {
        assert_eq!(
            matches!(
                FfiSenderVerification::from(produced),
                FfiSenderVerification::Verified
            ),
            matches!(produced, SenderVerification::Verified),
            "only `Verified` may cross this boundary as `Verified`, and it \
             must. Left is whether {produced:?} crossed as `Verified`, right \
             is whether it was entitled to: left `true` means the mapping \
             invented authenticity for a value that carries none, and left \
             `false` means it threw away a verification the chain really did \
             earn"
        );
    }
}

/// An envelope carries its authenticity across, and an absent one stays
/// absent.
///
/// Two envelopes, not one: an implementation that hard-codes either answer
/// passes a single-case test. The absent case is the encrypt direction,
/// where there is no such thing as a verification state and `None` says so
/// rather than a value being invented.
#[test]
fn an_envelope_carries_its_authenticity_across_and_an_absent_one_stays_absent() {
    let decrypted = FfiEnvelope::from(Envelope {
        scope: "!s:example.org".to_string(),
        algorithm: "an.algorithm".to_string(),
        event_type: "an.event.type".to_string(),
        ciphertext: b"plaintext".to_vec(),
        sender: "@someone:example.org".to_string(),
        sender_verification: Some(SenderVerification::MismatchedSender),
    });
    assert!(matches!(
        decrypted.sender_verification,
        Some(FfiSenderVerification::MismatchedSender)
    ));

    let encrypted = FfiEnvelope::from(Envelope {
        scope: "!s:example.org".to_string(),
        algorithm: "an.algorithm".to_string(),
        event_type: "an.event.type".to_string(),
        ciphertext: b"ciphertext".to_vec(),
        sender: "@someone:example.org".to_string(),
        sender_verification: None,
    });
    assert!(
        encrypted.sender_verification.is_none(),
        "an absent authenticity must stay absent, not acquire a default -- \
         a default here would be a claim about an event nobody decrypted"
    );
}

/// A trust change keeps the user and the state it belongs to.
#[test]
fn a_trust_change_crosses_with_the_user_it_belongs_to() {
    let crossed = FfiCryptoSignal::from(CryptoSignal::TrustChanged {
        user: "@someone:example.org".to_string(),
        state: TrustState::Verified,
    });

    let FfiCryptoSignal::TrustChanged { user, state } = crossed else {
        panic!("a trust change must cross as one");
    };
    assert_eq!(user, "@someone:example.org");
    assert!(matches!(state, FfiTrustState::Verified));

    let other = FfiCryptoSignal::from(CryptoSignal::TrustChanged {
        user: "@another:example.org".to_string(),
        state: TrustState::Unverified,
    });

    let FfiCryptoSignal::TrustChanged { user, state } = other else {
        panic!("a trust change must cross as one");
    };
    assert_eq!(user, "@another:example.org");
    assert!(
        matches!(state, FfiTrustState::Unverified),
        "the second signal is here so this test fails against an \
         implementation that returns a constant"
    );
}

/// The three strings of an inbound announcement stay in their own fields.
///
/// This is the file's opening hazard in its purest form: `user`,
/// `device_id` and the identifier are all `String`, so any permutation of
/// the three compiles and passes every other test in this repository. The
/// consequence is not cosmetic. The identifier is what a receiving product
/// passes to `acceptVerification`, and it is the whole reason this variant
/// exists -- a swap would hand a product a user id to accept a verification
/// with, and every call it then made would reject with `unknown_flow` for a
/// reason no error message could explain.
///
/// The three fixtures are deliberately distinguishable from one another and
/// from anything a permutation could make look right.
#[test]
fn an_inbound_announcement_keeps_its_three_strings_apart() {
    let crossed = FfiCryptoSignal::from(CryptoSignal::VerificationRequested {
        user: "@the-user:example.org".to_string(),
        device_id: "THE-DEVICE-IDENTIFIER".to_string(),
        flow_id: "the-flow-identifier".to_string(),
    });

    let FfiCryptoSignal::VerificationRequested {
        user,
        device_id,
        verification_id,
    } = crossed
    else {
        panic!("an inbound announcement must cross as one");
    };
    assert_eq!(user, "@the-user:example.org");
    assert_eq!(device_id, "THE-DEVICE-IDENTIFIER");
    assert_eq!(
        verification_id, "the-flow-identifier",
        "the core calls this a flow id and this crate calls it a verification id; they \
         must be the same value, because it is the one a product hands back"
    );
}

/// A completed scan crosses as itself and keeps its one string.
///
/// One field rather than three, so the permutation hazard above does not
/// apply; what does apply is the variant itself. The `From` is exhaustive,
/// so this cannot be forgotten, but nothing in the compiler stops it being
/// pointed at a neighbour: crossing as `VerificationRequested` would give a
/// product a completion it read as an invitation, and it would then try to
/// accept a flow that had already finished.
///
/// The identifier is the whole payload here. A product correlates it with
/// the one `requestVerification` returned, or the one an invitation carried,
/// and a value that arrived from any other field would name nothing.
#[test]
fn a_completed_scan_keeps_the_identifier_it_names() {
    let crossed = FfiCryptoSignal::from(CryptoSignal::VerificationCompleted {
        flow_id: "the-flow-identifier".to_string(),
    });

    let FfiCryptoSignal::VerificationCompleted { verification_id } = crossed else {
        panic!("a completed scan must cross as a completed scan and not as its neighbour");
    };
    assert_eq!(
        verification_id, "the-flow-identifier",
        "the core calls this a flow id and this crate calls it a verification id; they \
         must be the same value, because it is the one a product correlates with the \
         flow it started"
    );
}

/// The signing identity's five booleans stay in their own fields.
///
/// The file's opening hazard again, with the smallest alphabet it has: five
/// `bool` fields, so every permutation of the mapping compiles, passes
/// `clippy -D warnings` and passes every other test in this repository.
///
/// It is not the cosmetic member of the set. The core's own doc comment
/// exists to keep `account_keys_fetched` and `identity_known` apart, because
/// `identity_known == false` means "nobody has asked" under one and "the
/// server says there is none" under the other, and only the second is a
/// basis for minting an identity. A product reading them the wrong way round
/// is a product that believes it may publish a new identity over one the
/// account already has, which resets the trust of every device and every
/// user who had verified the old one. That is the exact destruction
/// `signing.rs`'s gate exists to prevent, arrived at by crossing a boundary
/// rather than by asking the wrong question.
///
/// The fourth field widens that hazard rather than diluting it.
/// `account_keys_answer_unsettled` is the negative of the first: it says a
/// key query about this account **was** answered and settled nothing, which
/// is the one situation where asking again cannot help. Delivered in
/// `account_keys_fetched`'s place it would tell a product the gate is open,
/// which is the minting sentence again; delivered nowhere it would leave the
/// caller in the loop this field exists to end.
///
/// One assertion per field, each with the others false, so that no
/// permutation can make any of the five look right: a swap moves a `true` to
/// a field this test expects `false` in, and both halves of that fail.
#[test]
fn an_identity_status_keeps_its_five_facts_apart() {
    let asked_only = FfiIdentityStatus::from(IdentityStatus {
        account_keys_fetched: true,
        identity_known: false,
        private_keys_held: false,
        account_keys_answer_unsettled: false,
        identity_publication_pending: false,
    });
    assert!(
        asked_only.account_keys_fetched,
        "asking the server must not arrive as anything else -- it is the one \
         fact that authorises minting"
    );
    assert!(!asked_only.identity_known);
    assert!(!asked_only.private_keys_held);
    assert!(!asked_only.account_keys_answer_unsettled);

    let known_only = FfiIdentityStatus::from(IdentityStatus {
        account_keys_fetched: false,
        identity_known: true,
        private_keys_held: false,
        account_keys_answer_unsettled: false,
        identity_publication_pending: false,
    });
    assert!(!known_only.account_keys_fetched);
    assert!(
        known_only.identity_known,
        "the account having an identity must not arrive as having asked \
         about one"
    );
    assert!(!known_only.private_keys_held);
    assert!(!known_only.account_keys_answer_unsettled);

    let holding_only = FfiIdentityStatus::from(IdentityStatus {
        account_keys_fetched: false,
        identity_known: false,
        private_keys_held: true,
        account_keys_answer_unsettled: false,
        identity_publication_pending: false,
    });
    assert!(!holding_only.account_keys_fetched);
    assert!(!holding_only.identity_known);
    assert!(
        holding_only.private_keys_held,
        "holding the private keys must not arrive as either of the other two: \
         it is the field that says this device can sign rather than only \
         recognise"
    );
    assert!(!holding_only.account_keys_answer_unsettled);

    let unsettled_only = FfiIdentityStatus::from(IdentityStatus {
        account_keys_fetched: false,
        identity_known: false,
        private_keys_held: false,
        account_keys_answer_unsettled: true,
        identity_publication_pending: false,
    });
    assert!(
        !unsettled_only.account_keys_fetched,
        "an answer that settled nothing must never arrive as an answer that \
         did: that is the same sentence as telling a product it may mint"
    );
    assert!(!unsettled_only.identity_known);
    assert!(!unsettled_only.private_keys_held);
    assert!(
        unsettled_only.account_keys_answer_unsettled,
        "and it must arrive at all: dropped, the caller is back in a \
         drain-send-report loop that cannot terminate and is told nothing"
    );
    assert!(!unsettled_only.identity_publication_pending);

    let pending_only = FfiIdentityStatus::from(IdentityStatus {
        account_keys_fetched: false,
        identity_known: false,
        private_keys_held: false,
        account_keys_answer_unsettled: false,
        identity_publication_pending: true,
    });
    assert!(!pending_only.account_keys_fetched);
    assert!(
        !pending_only.identity_known,
        "an identity this device minted and has not published must never \
         arrive as one the account has: that is the pair whose confusion \
         bricked an account for a whole round"
    );
    assert!(!pending_only.private_keys_held);
    assert!(!pending_only.account_keys_answer_unsettled);
    assert!(
        pending_only.identity_publication_pending,
        "and it must arrive at all: dropped, a product cannot tell the one \
         state where `identity_known` is true and the account still has no \
         identity"
    );
}

/// A recovery's account data keeps its type and its content apart, in both
/// directions.
///
/// The file's opening hazard again, and this record crosses the boundary
/// **both ways**: out of `create_recovery` and back into
/// `recover_identity`. Both fields are `String`, so swapping them compiles,
/// passes `clippy -D warnings` and passes every other test in this
/// repository, including the core's own round trip, because a swap on the
/// way out that is matched by a swap on the way back cancels itself
/// exactly.
///
/// It would not cancel itself anywhere else. What a product does with these
/// two values is send the content as the body of a `PUT` whose path ends in
/// the type, so a swap writes a JSON object to a path named after a JSON
/// object, and the account data that comes back is unreadable by this
/// library and by every other Matrix client. The symptom is a recovery that
/// works perfectly until it is written to a real homeserver.
///
/// The two fixtures are deliberately distinguishable, and neither is valid
/// in the other's place.
#[test]
fn an_account_data_entry_keeps_its_type_and_its_content_apart() {
    let outbound = FfiAccountDataEntry::from(AccountDataEntry {
        event_type: "m.secret_storage.default_key".to_string(),
        content: r#"{"key":"ABCD"}"#.to_string(),
    });
    assert_eq!(
        outbound.event_type, "m.secret_storage.default_key",
        "the event type must not arrive as the content: a product puts this \
         in the path of a PUT"
    );
    assert_eq!(
        outbound.content, r#"{"key":"ABCD"}"#,
        "the content must not arrive as the event type: a product puts this \
         in the body of a PUT"
    );

    let inbound = AccountDataEntry::from(FfiAccountDataEntry {
        event_type: "m.cross_signing.master".to_string(),
        content: r#"{"encrypted":{}}"#.to_string(),
    });
    assert_eq!(
        inbound.event_type, "m.cross_signing.master",
        "the same rule on the way in: a swap here makes every recovery report \
         `RecoveryNotSetUp` for account data that is complete"
    );
    assert_eq!(inbound.content, r#"{"encrypted":{}}"#);
}

/// A recovery setup keeps its secret out of its account data, and its
/// account data in order.
///
/// Not a swap hazard, because the two fields have different types. Two
/// different hazards instead, and both are silent:
///
/// * The recovery key is the one value a product shows a human and can
///   never produce again. A mapping that dropped it, or that handed back an
///   entry's content in its place, would be a product showing its user a
///   string that opens nothing.
/// * The account data is a `Vec` whose order is part of the contract: the
///   key description is written before the pointer that names it, so a
///   product interrupted between the two has never advertised a key
///   description it failed to write. A mapping that reversed or reordered
///   the list would break that with nothing to show for it.
#[test]
fn a_recovery_setup_keeps_its_key_and_the_order_of_its_account_data() {
    let mapped = FfiRecoverySetup::from(RecoverySetup {
        recovery_key: "EsTx first second third".to_string(),
        account_data: vec![
            AccountDataEntry {
                event_type: "first".to_string(),
                content: "1".to_string(),
            },
            AccountDataEntry {
                event_type: "second".to_string(),
                content: "2".to_string(),
            },
            AccountDataEntry {
                event_type: "third".to_string(),
                content: "3".to_string(),
            },
        ],
    });

    assert_eq!(
        mapped.recovery_key, "EsTx first second third",
        "the recovery key must survive the crossing verbatim; it cannot be \
         produced again, so a product that shows a corrupted one has no way \
         back"
    );
    let types: Vec<&str> = mapped
        .account_data
        .iter()
        .map(|entry| entry.event_type.as_str())
        .collect();
    assert_eq!(
        types,
        vec!["first", "second", "third"],
        "the account data must keep the order the core handed it back in"
    );
    // The recovery key's fixture deliberately contains the entries' own
    // words, so a mapping that built it out of the account data rather than
    // carrying it across would still look plausible above and fails here.
    assert_ne!(mapped.account_data[0].content, mapped.recovery_key);
}

/// Two fields of the same type whose places matter more than any other
/// pair's in this crate: `blinded_elements` are what a product sends the
/// server, and `client_states`, which hold the blinds, stay on the device. A
/// mapping that crossed them would compile and pass every other test; this
/// one tells them apart.
///
/// Built from the real call rather than a literal, so each field has its real
/// shape: a blinded element is 32 bytes, a client state 64, the blind then
/// the element.
#[test]
fn an_oprf_blinding_keeps_what_is_sent_apart_from_what_is_kept() {
    let core = futures::executor::block_on(matrix_crypto_core::blind_oprf(vec![
        b"+33612345678".to_vec(),
        b"+33698765432".to_vec(),
    ]))
    .unwrap();
    let expected_elements = core.blinded_elements.clone();
    let expected_states = core.client_states.clone();

    let ffi = matrix_crypto_ffi::OprfBlinding::from(core);

    assert_eq!(ffi.blinded_elements, expected_elements);
    assert_eq!(ffi.client_states, expected_states);
    assert!(ffi.blinded_elements.iter().all(|e| e.len() == 32));
    assert!(ffi.client_states.iter().all(|s| s.len() == 64));
}
