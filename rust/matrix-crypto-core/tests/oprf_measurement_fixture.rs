//! Writes the fixture the example app times the OPRF client with.
//!
//! Ignored, because it is a generator rather than a check: run it by hand
//! when the fixture has to change, and commit what it writes.
//!
//! ```sh
//! cargo test --manifest-path rust/Cargo.toml -p matrix-crypto-core \
//!   --test oprf_measurement_fixture -- --ignored
//! ```
//!
//! # Why a fixture
//!
//! Timing `finalizeOprf` on a device needs a server's answer to a batch, and
//! the library ships no server half: that is the point of it. So the answer
//! is computed here, once, by `voprf`'s own server, for two thousand inputs
//! blinded by this crate's public `blind_oprf`. The app then finalises those
//! client states against that answer, and compares a checksum of all the
//! outputs with the one this file records.
//!
//! The inputs are not stored. Both sides derive them from their index, as
//! `+3361` followed by the index on seven digits, which is what the app's
//! `oprfTiming.ts` does too.

use std::fs;
use std::path::Path;

use matrix_crypto_core::{blind_oprf, finalize_oprf};
use rand_core::OsRng;
use voprf::{BlindedElement, Group, Ristretto255, VoprfServer};

const COUNT: usize = 2_000;

fn input(index: usize) -> Vec<u8> {
    format!("+3361{index:07}").into_bytes()
}

/// Standard base64 with padding, which is what the app decodes. Written out
/// rather than taken from a crate, since this is the only file that needs it.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> shift) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// 32-bit FNV-1a over `bytes`, as lower-case hex: not a cryptographic hash,
/// only enough to tell two lists of outputs apart, and short to write in
/// JavaScript, where the app computes the same.
fn fnv1a(bytes: &[u8]) -> String {
    let mut hash: u32 = 0x811c_9dc5;
    for byte in bytes {
        hash = (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193);
    }
    format!("{hash:08x}")
}

#[test]
fn fnv1a_matches_its_published_vectors() {
    assert_eq!(fnv1a(b""), "811c9dc5");
    assert_eq!(fnv1a(b"a"), "e40c292c");
    assert_eq!(fnv1a(b"foobar"), "bf9cf968");
}

#[test]
fn base64_matches_the_rfc_4648_vectors() {
    for (plain, encoded) in [
        ("", ""),
        ("f", "Zg=="),
        ("fo", "Zm8="),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg=="),
        ("fooba", "Zm9vYmE="),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64(plain.as_bytes()), encoded);
    }
}

#[test]
#[ignore = "a generator: run it by hand when the fixture has to change"]
fn write_the_example_app_fixture() {
    let inputs: Vec<Vec<u8>> = (0..COUNT).map(input).collect();
    let blinding = futures::executor::block_on(blind_oprf(inputs.clone())).unwrap();

    let server = VoprfServer::<Ristretto255>::new_from_seed(
        &[0x4d; 32],
        b"react-native-matrix-crypto example app",
    )
    .unwrap();
    let blinded = blinding
        .blinded_elements
        .iter()
        .map(|element| BlindedElement::<Ristretto255>::deserialize(element).unwrap())
        .collect::<Vec<_>>();
    let answer = server.batch_blind_evaluate(&mut OsRng, &blinded).unwrap();
    let evaluation_elements: Vec<Vec<u8>> = answer
        .messages
        .iter()
        .map(|message| message.serialize().to_vec())
        .collect();
    let proof = answer.proof.serialize().to_vec();
    let public_key = Ristretto255::serialize_elem(server.get_public_key()).to_vec();

    let outputs = futures::executor::block_on(finalize_oprf(
        inputs.clone(),
        blinding.client_states.clone(),
        evaluation_elements.clone(),
        proof.clone(),
        public_key.clone(),
    ))
    .unwrap();
    // What the app will compare with is what the server computes from each
    // input directly, not merely what this crate unblinded.
    let direct: Vec<Vec<u8>> = inputs
        .iter()
        .map(|input| server.evaluate(input).unwrap().to_vec())
        .collect();
    assert_eq!(outputs, direct);

    let fixture = serde_json::json!({
        "count": COUNT,
        "clientStates": base64(&blinding.client_states.concat()),
        "evaluationElements": base64(&evaluation_elements.concat()),
        "proof": base64(&proof),
        "publicKey": base64(&public_key),
        "outputsChecksum": fnv1a(&direct.concat()),
    });
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../packages/example-app/src/oprfFixture.json");
    fs::write(path, format!("{fixture:#}\n")).unwrap();
}
