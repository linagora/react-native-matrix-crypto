//! Level 2 for M4's last uncovered path: the user-interactive authentication
//! loop that publishing a signing identity needs, driven end to end against a
//! refusal a real homeserver wrote.
//!
//! # The gap this closes
//!
//! [`bootstrap_identity`] queues a `signing_keys_upload` and hands it to a
//! product to send. Upstream `matrix-sdk-crypto` surfaces no authentication
//! for it at all -- its request type is three key fields where the real
//! endpoint's request has a fourth -- so the loop belongs to the product:
//! send, read the challenge out of the `401`, ask the user, send the same
//! body again with an `auth` object merged into it. Spec section 1.1 records
//! why no parameter can stand in for that: the challenge is only known after
//! the first request has already been refused.
//!
//! That is the one path this library hands over whole, and until this file
//! **no test executed it.** The teardown guard in `interop/harness.rs`
//! answers a challenge on `/delete_devices`, which is a different endpoint
//! reached by different code and never through this library's surface.
//!
//! `level_two_identity.rs` explains why it does not drive the loop, and is
//! right about its own run: the signing-keys upload it sends is accepted
//! outright, so there is no challenge there to answer. Its step 9 carries an
//! assertion saying exactly that, and telling a reader what to do if a
//! homeserver ever answers otherwise. This file is what to do.
//!
//! # WHEN A HOMESERVER ACTUALLY CHALLENGES, MEASURED
//!
//! The reason no run had met a challenge is not that continuwuity is unusual.
//! It is that **both mainstream homeservers implement the same rule**, and on
//! a fresh account that rule says no authentication is needed. Measured
//! 2026-08-30 rather than assumed:
//!
//! * **Continuwuity v26.7.2**, the image this harness pins. Probed directly
//!   over HTTP on throwaway accounts. A first publication on an account
//!   holding no cross-signing key is accepted `200 {}`. A byte-identical
//!   re-publication is accepted `200 {}`. An upload that would *replace* any
//!   key the account already holds is refused `401` with
//!   `{"flows":[{"stages":["m.login.password"]}],"params":null,"session":...}`.
//!   Answering that session with the account's password is accepted `200 {}`;
//!   answering it with the wrong password returns `401` again, carrying the
//!   same session and an added `errcode`.
//! * **Synapse 1.159.0.** The same three answers, read off
//!   `SigningKeyUploadServlet.on_POST` in the published image rather than
//!   inferred: `has_different_keys` short-circuits an identical re-upload to
//!   `200`, first-time setup is allowed without authentication "per MSC3967",
//!   and only a replacement reaches `validate_user_via_ui_auth`.
//!
//! Two consequences, and both are worth stating because a product author
//! would otherwise plan around the opposite:
//!
//! 1. **No homeserver setting makes a fresh account's first bootstrap meet a
//!    challenge.** Continuwuity has no configuration key for it; its whole
//!    key list was dumped from the pinned binary and there is none. Standing
//!    up Synapse instead buys nothing, because Synapse decides it the same
//!    way. So a product's first publication normally succeeds outright, and
//!    a product that treats a `200` there as an anomaly is wrong about the
//!    common case.
//! 2. **No mock is needed to meet one either.** The challenge is reached by
//!    the upload being a *replacement*, which is a state a real account
//!    reaches without anything unusual happening.
//!
//! # THE CONSTRUCTION, AND WHAT IN IT IS STAGED
//!
//! One thing is staged, and it is named here rather than left to be found:
//! **step 6 publishes a second identity for this account over plain HTTP,
//! in the window between the bootstrap that mints ours and the send that
//! would publish it.** Everything else is real.
//!
//! That window is not invented. It is the ordinary race between two devices
//! of one account, both freshly logged in, both told by the server that the
//! account has no identity, both minting one: whichever posts first is
//! accepted, and the second meets the challenge this file drives. Racing a
//! second process to reproduce it would make the outcome depend on which
//! process won, so the other identity is put there deliberately and the race
//! comes out the same way on every run.
//!
//! What is **not** staged, which is the whole point:
//!
//! * the `401` is continuwuity's, produced by its own policy applied to a
//!   state it can see, and not a body this test wrote;
//! * the challenge in it -- the flow list and the session id -- is
//!   continuwuity's, and the session is read out of that body rather than
//!   chosen here;
//! * the body sent is the one [`bootstrap_identity`] queued, taken from the
//!   pump and not rewritten except by merging `auth` into it;
//! * the second send is accepted by continuwuity for real, and step 9 reads
//!   the identity back off the homeserver to show it. The master key the
//!   server serves afterwards is the one out of this library's own request
//!   body, and it is **not** the one step 6 put there.
//!
//! # WATCHED FAILING
//!
//! Three mutations, each applied to this file, run against this same
//! homeserver, and restored. What each actually printed, rather than what it
//! was expected to:
//!
//! * **The retry removed.** The loop sends once, reports the refusal with
//!   `mark_request_failed`, and moves on. Caught at **step 9**, on the
//!   homeserver's own view:
//!   `left: {"ed25519:StandInMasterKey": ...}` against
//!   `right: {"ed25519:bcvCm6P9B/...": ...}`. The stand-in from step 6 is
//!   still what the server serves, and this library's minted key never
//!   reached it.
//!
//!   **Step 8 passed**, and that is the finding rather than a gap. Holding
//!   the account's private signing keys is a local fact that publishing
//!   nothing does not change, so `identity_status` reads exactly the same
//!   after a publication that never happened. A product cannot tell from
//!   this library whether its identity is on the server. Only the server can
//!   say, which is why step 9 exists and why it is the assertion that
//!   carries this file's claim.
//! * **The `auth` data wrong.** The password replaced with a value that is
//!   not the account's. The second send is refused rather than accepted, and
//!   the assertion on it fails with `left: 401, right: 200` over
//!   `{"flows":...,"session":"...","errcode":"M_FORBIDDEN",
//!   "error":"Invalid identifier or password"}`. The session is the *same*
//!   one, and the added `errcode` is what a product shows its user as "that
//!   was not your password" while keeping the same challenge open.
//! * **The challenge ignored.** The session is not read out of the refusal
//!   and an invented one is sent instead. The second send fails with
//!   `left: 400, right: 200` over
//!   `{"errcode":"M_INVALID_PARAM","error":"Invalid session"}`. Worth
//!   noticing that this is a `400` and not another `401`: a product that
//!   invents a session gets an error it cannot retry its way out of, which
//!   is a different bug from a wrong password and reads differently here.
//!
//! Recorded because a mutation nobody watched fail is a mutation nobody ran,
//! and this milestone has had four sabotages pass on their first run. Two of
//! the three above did something other than what this comment first claimed,
//! and the comment was corrected to the run rather than the other way round.
//!
//! # The account this needs
//!
//! Its own, named by `MATRIX_INTEROP_CHALLENGE_USER`, and not the one the
//! other three proofs share. The reason is structural rather than tidiness:
//! this file must begin on an account that holds no cross-signing identity,
//! and `level_two_identity.rs` leaves the shared account holding one. An
//! account's identity cannot be deleted, so sharing would make the two files
//! order-dependent in a way no reader could see. `scripts/run-level-two-interop.sh`
//! creates both accounts in the container it starts, with the one password it
//! generates per run.
//!
//! # Running it
//!
//! `./scripts/run-level-two-interop.sh`, which starts a throwaway homeserver
//! and runs this and its three siblings. No counterparty subprocess: nothing
//! here involves a third-party client, so this is the library, the pump and a
//! homeserver.
//!
//! `#[ignore]`, so an ordinary `cargo test` needs no network, no container
//! and no credential.

use matrix_crypto_core::{
    create_identity, create_machine, identity_status, mark_request_failed, mark_request_sent,
    take_outgoing_requests, MachineConfig, OutgoingRequest,
};
use serde_json::{json, Value};

// The homeserver, the login and the teardown, none of which is what this file
// proves. See its own header for why it is a module rather than a fourth copy.
#[path = "interop/harness.rs"]
mod harness;
use harness::{
    endpoint, login, required_env, run, Homeserver, Teardown, HOMESERVER_ENV, PASSWORD_ENV,
};

/// The account this file needs to itself. See the header.
const CHALLENGE_USER_ENV: &str = "MATRIX_INTEROP_CHALLENGE_USER";

/// Not a credential: the store this test creates lives in a temporary
/// directory it also deletes.
const STORE_PASSPHRASE: &str = "level-two-identity-challenge";

/// The other identity, published for this account in the window between
/// minting ours and publishing it. The header says what it stands for and
/// why it is the one staged thing here.
///
/// A real Ed25519 public key and nothing more: the base64 (unpadded, as a
/// key id requires) of thirty-two bytes of 0x11. It is still deliberately
/// not key material in the sense that matters -- no private half of it
/// exists anywhere, so the identity can sign nothing and this run can leave
/// nothing behind that works -- but the value itself has to parse as a
/// public key now. Synapse deserialises the master key before storing it
/// and answers `400 M_INVALID_PARAM "Invalid master key"` to anything that
/// is not exactly thirty-two bytes of base64 (measured, 2026-09-01, against
/// v1.159.0); earlier values that merely satisfied the base64 alphabet were
/// accepted by continuwuity and refused by Synapse. The only other
/// constraint is the one this test has always had: the value must differ
/// from what this library mints, which a fixed never-used key satisfies.
const OTHER_MASTER: &str = "ERERERERERERERERERERERERERERERERERERERERERE";

/// One `/keys/query` for this account, asked of the homeserver directly.
///
/// Not through the library: this is the homeserver's own view, and it is what
/// makes "the identity was really published" a fact about somewhere neither
/// side controls rather than about this process's memory.
fn homeserver_view(homeserver: &Homeserver, token: &str, user_id: &str) -> Value {
    homeserver.ok(
        "POST",
        "/_matrix/client/v3/keys/query",
        Some(token),
        Some(&json!({ "device_keys": { user_id: [] } }).to_string()),
    )
}

/// The master key the homeserver currently serves for this account, if any.
fn published_master_key(view: &Value, user_id: &str) -> Option<Value> {
    view.get("master_keys")?.get(user_id)?.get("keys").cloned()
}

/// The master key a `signing_keys_upload` body carries.
///
/// Read out of the request rather than out of any library accessor, so that
/// step 9 compares the homeserver's answer against the exact bytes that were
/// sent to it.
fn requested_master_key(request: &OutgoingRequest) -> Value {
    serde_json::from_str::<Value>(&request.body)
        .expect("the pump's own signing-keys body is well-formed JSON")
        .get("master_key")
        .and_then(|key| key.get("keys"))
        .cloned()
        .expect("a signing-keys upload carries a master key")
}

/// The same body, with an `auth` object merged in at the top level.
///
/// The body is opaque JSON this library never interprets, so this parses it,
/// adds one member and re-serialises. Nothing here is formatted into any
/// message: the result contains the account's password, and the only thing
/// any assertion below may quote is the homeserver's response.
fn with_auth(body: &str, user_id: &str, password: &str, session: &str) -> String {
    let mut body: Value =
        serde_json::from_str(body).expect("the pump's own body is well-formed JSON");
    body.as_object_mut()
        .expect("a signing-keys upload body is a JSON object")
        .insert(
            "auth".to_string(),
            json!({
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": user_id },
                "password": password,
                "session": session,
            }),
        );
    body.to_string()
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// M4's authentication loop, over a real homeserver's real refusal.
///
/// One `#[test]` fn, because the machine registry and the pump's bookkeeping
/// are process-wide and Cargo gives this file its own process. It spawns no
/// child: everything it proves happens to one machine in one process.
#[test]
#[ignore = "needs a real homeserver and a credential in the environment; \
            run ./scripts/run-level-two-interop.sh"]
fn a_signing_keys_upload_refused_by_a_real_challenge_answered_and_published() {
    let homeserver = Homeserver::new(required_env(HOMESERVER_ENV));
    let user = required_env(CHALLENGE_USER_ENV);
    let password = required_env(PASSWORD_ENV);

    let dir = tempfile::tempdir().expect("temp dir");
    let store = dir.path().join("library-store");

    // ---- 1. The library's device ----------------------------------------
    let library = login(
        &homeserver,
        &user,
        &password,
        "level-two-identity-challenge",
    );
    let _teardown = Teardown::new(&homeserver, &library, &password);

    // ---- 2. The homeserver's view, before anything is published ----------
    // The control for step 9, and the precondition for step 6: an account
    // that already held an identity would meet a challenge on the stand-in
    // itself, and this file would then be driving the loop against a
    // different request than the one it claims.
    let before = homeserver_view(&homeserver, &library.token, &library.user_id);
    assert!(
        published_master_key(&before, &library.user_id).is_none(),
        "this account must start with no published identity. It has one, which means \
         it is not the account this file was given -- see the header on why it needs \
         its own -- or a previous run left one behind. The homeserver reports {}",
        before["master_keys"]
    );

    // ---- 3. The machine, and its keys on the wire ------------------------
    run(create_machine(MachineConfig {
        user_id: library.user_id.clone(),
        device_id: library.device_id.clone(),
        store_path: store.to_string_lossy().into_owned(),
        store_passphrase: Some(STORE_PASSPHRASE.to_string()),
    }))
    .expect("the library's machine must be creatable");

    // Drained until it stops producing, which also answers the account key
    // query the gate below waits on. Everything is sent and reported here,
    // key queries included: unlike `level_two_identity.rs`, this file is not
    // trying to observe the gate shut.
    let mut drains = 0;
    loop {
        let batch = harness::pump_and_send(&homeserver, &library.token);
        drains += 1;
        if batch.is_empty() || drains >= 8 {
            break;
        }
    }

    // ---- 4. The gate, open ----------------------------------------------
    let status = run(identity_status()).expect("the machine is live");
    assert!(
        status.account_keys_fetched,
        "a key query naming this account has been sent and answered, which is what \
         authorises the bootstrap below: {status:?}"
    );
    assert!(
        !status.identity_known && !status.private_keys_held,
        "the server has just said this account has no identity, which is the one fact \
         that authorises minting one: {status:?}"
    );

    // ---- 5. The identity, minted --------------------------------------
    run(create_identity()).expect("an account the server says has no identity may mint one");

    let batch = run(take_outgoing_requests()).expect("the pump must be drainable");
    let kinds: Vec<&str> = batch.iter().map(|request| request.kind.as_str()).collect();
    assert!(
        kinds.contains(&"signing_keys_upload"),
        "the bootstrap must queue the signing keys, or there is nothing here to refuse: \
         {kinds:?}"
    );

    // ---- 6. THE ONE STAGED THING: another client publishes first ---------
    // In the window between minting ours and sending it. The header says why
    // this is here, what real event it stands for, and why it is done
    // deliberately rather than by racing a second process.
    //
    // Accepted without a challenge because the account holds no key yet,
    // which is the same MSC3967 rule that is about to refuse ours.
    //
    // Only the master key is staged, and that is Synapse's doing, measured
    // against v1.159.0: it validates what this endpoint stores, and the two
    // subordinate keys are each required to carry a signature from the
    // master key -- which a stand-in that exists to occupy the account
    // cannot produce, because no private half of it exists. Synapse accepts
    // a master key alone, and a master key alone is all this step needs:
    // what makes our upload below a replacement, and so challengeable, is
    // that the account holds a master key at all.
    let other = json!({
        "master_key": {
            "user_id": library.user_id,
            "usage": ["master"],
            "keys": { format!("ed25519:{OTHER_MASTER}"): OTHER_MASTER },
        },
    })
    .to_string();
    let (status_code, response) = homeserver.call(
        "POST",
        "/_matrix/client/v3/keys/device_signing/upload",
        Some(&library.token),
        Some(&other),
    );
    assert_eq!(
        status_code, 200,
        "a first publication on an account that holds no cross-signing key is accepted \
         without authentication, on continuwuity and on Synapse alike. If this is a 401 \
         then the account was not clean and step 2's control did not catch it; if it is \
         a 4xx of any other kind the endpoint has started validating what it stores, and \
         this stand-in has to become a real key rather than the assertion being relaxed. \
         The response was: {response}"
    );

    // Read back, so the refusal below is caused by a state this test can see
    // rather than by one it assumes it created.
    let staged = homeserver_view(&homeserver, &library.token, &library.user_id);
    let staged_master = published_master_key(&staged, &library.user_id).unwrap_or_else(|| {
        panic!("the homeserver must serve the identity it just accepted back: {staged}")
    });
    assert!(
        staged_master
            .get(format!("ed25519:{OTHER_MASTER}"))
            .is_some(),
        "and it must be the one step 6 published, or what refuses our upload below is \
         not what this test thinks it is: {staged_master}"
    );

    // ---- 7. THE LOOP ----------------------------------------------------
    // The whole reason this file exists. Everything from here to the end of
    // the batch is what a product has to write, and `scripts/assert-uia-example.sh`
    // holds the README's worked example to the same ordered steps.
    let mut answered_a_challenge = false;
    let mut our_master_key = None;

    for request in &batch {
        if request.kind != "signing_keys_upload" {
            let response = harness::send_outgoing(&homeserver, &library.token, request);
            run(mark_request_sent(&request.id, &response)).unwrap_or_else(|error| {
                panic!(
                    "the homeserver's own response to a {} request was rejected by \
                     mark_request_sent: {error:?}",
                    request.kind
                )
            });
            continue;
        }

        our_master_key = Some(requested_master_key(request));

        // uia-step: send
        let (method, path, body) = endpoint(request);
        let (status_code, refusal) =
            homeserver.call(method, &path, Some(&library.token), Some(&body));

        // uia-step: accepted
        if (200..300).contains(&status_code) {
            panic!(
                "this upload was accepted, and step 6 arranged for it not to be. The \
                 account was made to hold a different identity first, so this send is a \
                 replacement and both continuwuity and Synapse refuse one without \
                 authentication. An acceptance here means the endpoint's rule changed \
                 under this proof, and the fix is to find out how rather than to delete \
                 the loop below. The response was: {refusal}"
            );
        }

        // uia-step: refusal
        assert_eq!(
            status_code, 401,
            "a replacement must be refused with a challenge, not with {status_code}: \
             {refusal}"
        );
        run(mark_request_failed(&request.id, status_code))
            .expect("a refused request is reportable as refused, and changes nothing");

        // uia-step: challenge
        let challenge: Value = serde_json::from_str(&refusal)
            .unwrap_or_else(|_| panic!("a challenge is a JSON body: {refusal}"));
        let flows = challenge["flows"]
            .as_array()
            .unwrap_or_else(|| panic!("a challenge names the flows it will accept: {refusal}"));
        assert!(
            flows.iter().any(|flow| {
                flow["stages"]
                    .as_array()
                    .is_some_and(|stages| stages.iter().any(|stage| stage == "m.login.password"))
            }),
            "this test can only answer a password flow, and the homeserver offered \
             {flows:?}. That is a finding about the homeserver rather than about this \
             library: a product must read the flows it is given rather than assume this \
             one."
        );
        let session = challenge["session"].as_str().unwrap_or_else(|| {
            panic!("a challenge carries the session to answer it under: {refusal}")
        });

        // uia-step: merge
        let authenticated = with_auth(&body, &library.user_id, &password, session);

        // uia-step: resend
        // The same id and the same body, which is what makes this a retry
        // rather than a second request: `mark_request_failed` left the entry
        // pending and `mark_request_sent` looks one up without removing it.
        let (status_code, answer) =
            homeserver.call(method, &path, Some(&library.token), Some(&authenticated));
        assert_eq!(
            status_code, 200,
            "the same body, with the challenge answered, must be accepted. It was not, \
             and the homeserver said: {answer}"
        );

        // uia-step: sent
        run(mark_request_sent(&request.id, &answer)).expect(
            "the id must have survived the refusal, or a product could not answer a \
             challenge at all: the whole loop is a second send of the same pending id",
        );
        answered_a_challenge = true;
    }

    assert!(
        answered_a_challenge,
        "the batch carried no signing-keys upload to refuse, so nothing above ran. \
         Step 5 asserted one was queued, so this can only mean the loop skipped it: \
         {kinds:?}"
    );

    // ---- 8. What this library now holds ---------------------------------
    // Necessary and nowhere near sufficient, and the header records the run
    // that shows it: with the retry removed from step 7 this assertion still
    // passes, because holding the private keys is a local fact that
    // publishing nothing does not change. It is here to catch a bootstrap
    // that left the machine in some other state, not to stand for the claim.
    // Step 9 is where the claim is.
    let status = run(identity_status()).expect("the machine is live");
    assert!(
        status.identity_known && status.private_keys_held,
        "after a served bootstrap this machine holds the account's identity and can \
         sign with it: {status:?}"
    );

    // ---- 9. THE HOMESERVER'S OWN VIEW, AFTER ------------------------------
    // The claim, checked where it counts: the identity that survived is the
    // one this library minted, and it replaced the one step 6 put there.
    let after = homeserver_view(&homeserver, &library.token, &library.user_id);
    let published = published_master_key(&after, &library.user_id)
        .unwrap_or_else(|| panic!("the homeserver must serve a master key back: {after}"));
    let ours = our_master_key.expect("step 7 read the master key out of the request it sent");
    assert_eq!(
        published, ours,
        "the master key the homeserver serves must be the one out of this library's own \
         request body. Anything else means the answered retry published something other \
         than what the pump handed over."
    );
    assert!(
        published.get(format!("ed25519:{OTHER_MASTER}")).is_none(),
        "and the identity step 6 staged must be gone, or nothing was replaced and the \
         401 above was about something else: {published}"
    );
    assert!(
        after["self_signing_keys"]
            .get(&library.user_id)
            .and_then(|key| key.get("keys"))
            .and_then(Value::as_object)
            .is_some_and(|keys| !keys.is_empty()),
        "the self-signing key goes up in the same request as the master key, so it must \
         be there too: {after}"
    );
}
