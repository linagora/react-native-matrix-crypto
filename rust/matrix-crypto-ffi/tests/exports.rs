// The FFI crate must expose the core's probe unchanged. This test does not
// cross the FFI boundary; it only proves the re-export compiles and delegates.
#[tokio::test]
async fn ffi_probe_delegates_to_core() {
    let report = matrix_crypto_ffi::probe("hi".to_string(), vec![9, 8])
        .await
        .unwrap();
    assert_eq!(report.echoed, "hi");
    assert_eq!(report.payload, vec![8, 9]);
}

#[tokio::test]
async fn ffi_probe_propagates_typed_error() {
    let err = matrix_crypto_ffi::probe(String::new(), vec![])
        .await
        .unwrap_err();
    assert!(
        matches!(err, matrix_crypto_ffi::ProbeFfiError::Rejected { reason } if reason == "input must not be empty")
    );
}

/// The signing identity's two calls exist on this crate's surface and reach
/// the core, which is the whole content of the bridge: both are one-line
/// delegations, so what can go wrong is that they are absent, or wired to
/// the wrong core function, or swallow the core's error.
///
/// No machine is created in this test binary, so the core answers
/// `NotInitialised` for both, and asserting on that particular variant is
/// what separates a real delegation from a stub that succeeds: a function
/// returning `Ok(())` or a default record passes a test that only checks it
/// can be called, and fails this one.
///
/// **It does not separate it from a stub that fails the same way.** A body
/// of `Err(MachineFfiError::NotInitialised)` passes this, and no test
/// reachable from here can tell it apart, because reaching the core's other
/// answers means creating a machine and this binary deliberately creates
/// none. The stronger check lives where a machine exists: the core's own
/// `tests/identity_bootstrap*.rs` drive both refusals and the served path
/// against a real store. Said rather than left implied, because a comment
/// claiming more than its assertion is the defect this milestone keeps
/// finding.
#[tokio::test]
async fn the_signing_identity_calls_reach_the_core() {
    let err = matrix_crypto_ffi::identity_status().await.unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));

    let err = matrix_crypto_ffi::bootstrap_identity().await.unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));

    // The creating call is exported and delegates too. It is asserted here
    // beside the publishing one rather than folded into it, because the two
    // are now different acts and an export that existed for only one of them
    // would leave a product unable to reach the other at all. Which of the
    // two a caller gets is checked where a swap is visible: the core's own
    // `tests/identity_race_with_a_stale_answer.rs`, and the facade's
    // "publishing and creating are not the same native call".
    let err = matrix_crypto_ffi::create_identity().await.unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));
}

/// The call a device joins an identity with reaches the core too, and is the
/// same one-line delegation with the same three ways of going wrong.
///
/// Separate from the test above rather than a third line inside it, because
/// it belongs to a different call on the product's surface: joining is a
/// verification, not a bootstrap, and the two must never be reached for
/// interchangeably. The same limit applies as above -- a body of
/// `Err(MachineFfiError::NotInitialised)` would pass this, and the core's own
/// `tests/self_verification*.rs` are what drive the served path and both
/// refusals against a real store.
#[tokio::test]
async fn the_self_verification_call_reaches_the_core() {
    let err = matrix_crypto_ffi::request_self_verification()
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));
}

/// The two server-side recovery calls reach the core, with the same three
/// ways of going wrong as the calls above: absent, wired to the wrong core
/// function, or swallowing the core's error.
///
/// The same limit applies as above, and is worth restating because these two
/// have four refusals between them: a body of
/// `Err(MachineFfiError::NotInitialised)` would pass this, and no test
/// reachable from here can tell it apart. What drives the served path and
/// every refusal against a real store is the core's own
/// `src/recovery.rs` tests and `tests/recovery_refusals.rs`.
#[tokio::test]
async fn the_recovery_calls_reach_the_core() {
    // `unwrap_err` is unavailable here: `RecoverySetup` has no `Debug`
    // derive on purpose, because it carries the recovery key. Matched
    // instead, which asserts the same thing.
    assert!(matches!(
        matrix_crypto_ffi::create_recovery("passphrase".to_string(), Vec::new()).await,
        Err(matrix_crypto_ffi::MachineFfiError::NotInitialised)
    ));

    let err = matrix_crypto_ffi::recover_identity("passphrase".to_string(), Vec::new())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));
}

/// The three calls that carry a scannable code reach the core, with the same
/// three ways of going wrong as every delegation above: absent, wired to the
/// wrong core function, or swallowing the core's error.
///
/// Wiring one to another core function is not a hypothetical for this group.
/// All three take a verification identifier and two of them return nothing,
/// so `submit_scanned_code` wired to `confirm_scan` -- which is the pair a
/// product calls one after the other -- compiles, and every test that only
/// checked the call could be made would pass against it. What that build
/// would do is confirm a scan that never happened.
///
/// The same limit applies as above: a body of
/// `Err(MachineFfiError::NotInitialised)` would pass this, and no test
/// reachable from here can tell it apart, because this binary creates no
/// machine. The core's own `tests/qr_refusals.rs` and the three mode tests
/// beside it are what drive the served path and all four scanning refusals
/// against a real store.
#[tokio::test]
async fn the_scannable_code_calls_reach_the_core() {
    // `unwrap_err` is unavailable here: `ScannableCode` has no `Debug`
    // derive on purpose, because the payload is authentication material.
    // Matched instead, which asserts the same thing.
    assert!(matches!(
        matrix_crypto_ffi::verification_code("a-flow".to_string()).await,
        Err(matrix_crypto_ffi::MachineFfiError::NotInitialised)
    ));

    let err = matrix_crypto_ffi::submit_scanned_code("a-flow".to_string(), vec![1, 2, 3])
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));

    let err = matrix_crypto_ffi::confirm_scan("a-flow".to_string())
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        matrix_crypto_ffi::MachineFfiError::NotInitialised
    ));
}

/// The code switch reaches the core, and carries **both** of its fields.
///
/// **The one delegation in this crate with an observable effect and no return
/// value**, which is why it is asserted through the core's own reader rather
/// than through an error. A body of `{}` compiles, exports, and passes every
/// other test in this repository: nothing else in either crate can see that
/// the switch never moved. What a product would see is a build that asked for
/// codes, announced none, and was told `CodeNotOffered` on the first flow it
/// tried, with the one call that could have fixed it already made.
///
/// **All four answers, and each field read on its own**, which is the shape
/// this test grew when the switch stopped being a boolean. A bridge that
/// carried `can_show` and dropped `can_scan` passes any test that only ever
/// sets both together, and a bridge that carried one field into both passes
/// any test that only ever sets them to the same value. Dropping a field is
/// not a hypothetical hazard here: a product claiming a camera it does not
/// have is the defect this whole record exists to end, and a bridge is the
/// one place that claim could be re-introduced with nothing to see it.
///
/// Neither first, because the default is what the design's exit criteria
/// rest on.
#[test]
fn both_halves_of_the_code_switch_reach_the_core() {
    assert!(
        !matrix_crypto_core::code_capabilities().can_show
            && !matrix_crypto_core::code_capabilities().can_scan,
        "a fresh process must claim neither half: every assertion below is \
         about a switch that starts silent, and this one is the criterion that \
         a build which never asks says on the wire what it always said"
    );

    for can_show in [false, true] {
        for can_scan in [false, true] {
            matrix_crypto_ffi::offer_codes(matrix_crypto_ffi::CodeCapabilities {
                can_show,
                can_scan,
            });
            let carried = matrix_crypto_core::code_capabilities();
            assert_eq!(
                (carried.can_show, carried.can_scan),
                (can_show, can_scan),
                "the bridge must carry both fields through to the core's own \
                 switch, unchanged and unswapped. A bridge that raised a field \
                 rather than storing what it was handed passes whichever half of \
                 this loop happens to agree with it and fails the other"
            );
        }
    }

    matrix_crypto_ffi::offer_codes(matrix_crypto_ffi::CodeCapabilities {
        can_show: false,
        can_scan: false,
    });
    assert!(
        !matrix_crypto_core::code_capabilities().can_show
            && !matrix_crypto_core::code_capabilities().can_scan,
        "and the switch must be a switch and not a latch, or a product that \
         stopped offering codes would go on announcing them"
    );
}

/// Both OPRF calls exist on this crate's surface and reach the core: one
/// blinded element per input from the first, and the core's typed refusal
/// from the second, handed one evaluated element for two inputs.
#[tokio::test]
async fn ffi_oprf_calls_delegate_to_core() {
    let inputs = vec![b"+33612345678".to_vec(), b"+33698765432".to_vec()];
    let blinding = matrix_crypto_ffi::blind_oprf(inputs.clone()).await.unwrap();
    assert_eq!(blinding.blinded_elements.len(), 2);

    let refused = matrix_crypto_ffi::finalize_oprf(
        inputs,
        blinding.client_states,
        blinding.blinded_elements[..1].to_vec(),
        vec![0; 64],
        vec![0; 32],
    )
    .await
    .unwrap_err();
    assert!(matches!(refused, matrix_crypto_ffi::OprfFfiError::Rejected));
}
