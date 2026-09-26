//! The client half of an oblivious pseudorandom function: RFC 9497, suite
//! ristretto255-SHA512, in its verifiable mode.
//!
//! # What it is for
//!
//! A server holds a key and computes a keyed function of an input for whoever
//! asks, without ever receiving the input; the device receives the result and
//! nothing about the key. Contact discovery is the use it was added for: a
//! device masks the numbers of its address book, and matches them against the
//! masks of the accounts that chose to be found, while the server receives
//! blinded elements and never a number.
//!
//! # The client half, and nothing else
//!
//! [`blind_oprf`] blinds a batch; [`finalize_oprf`] checks the server's answer
//! and unblinds it. The server half, its key, and everything a product does
//! with the outputs -- asking the server, comparing masks -- stay on the
//! product's side of the line, with every HTTP request this library does not
//! make.
//!
//! # The proof is checked, always
//!
//! In the verifiable mode, the server answers a batch with one proof that it
//! evaluated every element with the key whose public half the product holds.
//! [`finalize_oprf`] refuses an answer whose proof does not verify against
//! that public key, so every output it returns comes from the one published
//! key, and there is no call that skips the check.
//!
//! # What crosses the boundary
//!
//! Bytes, as the RFC serialises them: a blinded element and an evaluated
//! element are 32 bytes, a proof and an output 64, a public key 32. Beside the
//! blinded elements, [`blind_oprf`] returns one client state per input, which
//! [`finalize_oprf`] takes back. A state holds the blind that hides its input
//! from the server: it never leaves the device, and only the blinded elements
//! are meant to. The TypeScript facade keeps the states out of a product's
//! reach for that reason.
//!
//! # Off the async workers
//!
//! Blinding and finalising two thousand inputs holds a thread for a noticeable
//! moment and awaits nothing, so both run on this library's blocking pool
//! rather than on one of the two workers every other call shares.

use rand_core::{CryptoRng, OsRng, RngCore};
use voprf::{EvaluationElement, Group, Proof, Ristretto255, VoprfClient};

use crate::runtime::on_blocking_pool;

/// The largest batch the RFC's batch proof can cover.
///
/// The proof's transcript counts the elements in two bytes, so neither this
/// module nor a server can go beyond it; a product with more inputs splits
/// them into several batches.
const MAX_BATCH: usize = u16::MAX as usize;

/// The longest input the RFC allows, in bytes, for the same reason:
/// finalising writes its length in two bytes. An empty input is a valid one.
///
/// Upstream blinds a longer input without complaint and refuses it only when
/// finalising, after the server has answered, so [`blind_oprf`] checks it
/// first.
const MAX_INPUT_BYTES: usize = u16::MAX as usize;

/// Whether `inputs` inputs make a batch: at least one, and no more than the
/// proof can count.
fn is_a_batch(inputs: usize) -> bool {
    (1..=MAX_BATCH).contains(&inputs)
}

/// A batch, blinded: what to send the server, and what to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OprfBlinding {
    /// One per input, in the order of the inputs: the only part of a
    /// blinding meant for the server.
    pub blinded_elements: Vec<Vec<u8>>,
    /// One per input, in the same order, for [`finalize_oprf`]. Each holds
    /// the blind that hides its input from the server, so none is ever sent.
    pub client_states: Vec<Vec<u8>>,
}

/// What went wrong, at the granularity a product can act on.
///
/// Fieldless, like `VaultError`, so that no error ever carries an input: the
/// inputs are what a product keeps to itself.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OprfError {
    /// The batch cannot be processed as given: it is empty or larger than
    /// the proof covers, an input is longer than the RFC allows, or the parts
    /// handed to [`finalize_oprf`] do not have one entry per input.
    #[error("the input was rejected")]
    Rejected,
    /// Something handed to [`finalize_oprf`] does not parse: an evaluated
    /// element or a public key that is not a point of the group, a proof
    /// that is not two scalars, or a client state this module did not make.
    #[error("the payload could not be parsed")]
    MalformedPayload,
    /// The server's proof does not verify against the public key given.
    ///
    /// Either the batch was evaluated with another key, or what came back is
    /// not what the server computed. No output is returned, not even for
    /// the elements the proof would have covered.
    #[error("the proof does not verify against the public key")]
    ProofRejected,
}

/// Every kind upstream has, matched without a wildcard, so that a kind added
/// later fails the build here instead of landing on a guess.
fn from_upstream(error: voprf::Error) -> OprfError {
    use voprf::Error as Upstream;
    match error {
        Upstream::Input | Upstream::Batch => OprfError::Rejected,
        Upstream::Deserialization => OprfError::MalformedPayload,
        Upstream::ProofVerification => OprfError::ProofRejected,
        // Upstream reports `DeriveKeyPair` and `Protocol` when deriving a key
        // pair, which only a server does, and `Info` in the partially
        // oblivious mode. The client of the verifiable mode, all this module
        // calls, reaches none of the three.
        Upstream::Info | Upstream::DeriveKeyPair | Upstream::Protocol => OprfError::Rejected,
    }
}

/// Blinds a batch of inputs for a server to evaluate.
///
/// Each input gets a fresh blind from the operating system's generator, so
/// blinding the same input twice gives two different blinded elements, and
/// the server cannot tell they hide the same input.
pub async fn blind_oprf(inputs: Vec<Vec<u8>>) -> Result<OprfBlinding, OprfError> {
    on_blocking_pool(move || blind_with(&mut OsRng, &inputs)).await
}

fn blind_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    inputs: &[Vec<u8>],
) -> Result<OprfBlinding, OprfError> {
    if !is_a_batch(inputs.len()) || inputs.iter().any(|input| input.len() > MAX_INPUT_BYTES) {
        return Err(OprfError::Rejected);
    }
    let mut blinded_elements = Vec::with_capacity(inputs.len());
    let mut client_states = Vec::with_capacity(inputs.len());
    for input in inputs {
        let blinded = VoprfClient::<Ristretto255>::blind(input, rng).map_err(from_upstream)?;
        blinded_elements.push(blinded.message.serialize().to_vec());
        client_states.push(blinded.state.serialize().to_vec());
    }
    Ok(OprfBlinding {
        blinded_elements,
        client_states,
    })
}

/// Checks the server's answer to a batch, and unblinds it.
///
/// `inputs` and `client_states` are the ones [`blind_oprf`] was given and
/// returned, in the same order. `evaluation_elements` and `proof` are the
/// server's answer: one element per input, and one proof for all of them.
/// `public_key` is the public half of the key the answer must come from, which
/// a product obtains from somewhere other than the answer itself.
///
/// Returns one output per input, in the same order: 64 bytes, the same the
/// server computes when it evaluates an input it holds itself. All or
/// nothing: an answer that fails the check returns no output at all.
pub async fn finalize_oprf(
    inputs: Vec<Vec<u8>>,
    client_states: Vec<Vec<u8>>,
    evaluation_elements: Vec<Vec<u8>>,
    proof: Vec<u8>,
    public_key: Vec<u8>,
) -> Result<Vec<Vec<u8>>, OprfError> {
    on_blocking_pool(move || {
        finalize(
            &inputs,
            &client_states,
            &evaluation_elements,
            &proof,
            &public_key,
        )
    })
    .await
}

fn finalize(
    inputs: &[Vec<u8>],
    client_states: &[Vec<u8>],
    evaluation_elements: &[Vec<u8>],
    proof: &[u8],
    public_key: &[u8],
) -> Result<Vec<Vec<u8>>, OprfError> {
    if !is_a_batch(inputs.len())
        || client_states.len() != inputs.len()
        || evaluation_elements.len() != inputs.len()
    {
        return Err(OprfError::Rejected);
    }
    let clients = client_states
        .iter()
        .map(|state| VoprfClient::<Ristretto255>::deserialize(state))
        .collect::<Result<Vec<_>, _>>()
        .map_err(from_upstream)?;
    let messages = evaluation_elements
        .iter()
        .map(|element| EvaluationElement::<Ristretto255>::deserialize(element))
        .collect::<Result<Vec<_>, _>>()
        .map_err(from_upstream)?;
    let proof = Proof::<Ristretto255>::deserialize(proof).map_err(from_upstream)?;
    let public_key = Ristretto255::deserialize_elem(public_key).map_err(from_upstream)?;
    // Slices rather than the vectors themselves: upstream iterates `&inputs`
    // and needs a sized collection to do it.
    let inputs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();

    VoprfClient::batch_finalize(&inputs, &clients, &messages, &proof, public_key)
        .map_err(from_upstream)?
        .map(|output| output.map(|bytes| bytes.to_vec()).map_err(from_upstream))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::VecDeque;

    use rand_core::{CryptoRng, RngCore};
    use voprf::{BlindedElement, VoprfServer};

    /// A generator that yields chosen scalars, one per draw, as RFC 9497's
    /// vectors fix every blind. The library draws 64 bytes and reduces them:
    /// a scalar's 32 bytes followed by zeros reduce to that scalar.
    struct Scalars(VecDeque<[u8; 32]>);

    impl Scalars {
        fn of(scalars: &[&str]) -> Self {
            Self(scalars.iter().map(|s| hex(s).try_into().unwrap()).collect())
        }
    }

    impl RngCore for Scalars {
        fn next_u32(&mut self) -> u32 {
            unimplemented!("only fill_bytes is drawn from")
        }
        fn next_u64(&mut self) -> u64 {
            unimplemented!("only fill_bytes is drawn from")
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let scalar = self.0.pop_front().expect("one chosen scalar per draw");
            dest.fill(0);
            let n = dest.len().min(32);
            dest[..n].copy_from_slice(&scalar[..n]);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for Scalars {}

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 9497, appendix A.1.2: VOPRF mode, ristretto255-SHA512.
    const INPUT_1: &str = "00";
    const INPUT_2: &str = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a";
    const BLIND_1: &str = "64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706";
    const BLINDED_1: &str = "863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945";
    const BLINDED_2: &str = "cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c";

    const PK_SM: &str = "c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e";
    const EVALUATED_1: &str = "aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e";
    const EVALUATED_2: &str = "60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468";
    const PROOF_1: &str = "ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd06\
                           6d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d";
    const PROOF_2: &str = "401a0da6264f8cf45bb2f5264bc31e109155600babb3cd4e5af7d181a2c9dc0a\
                           67154fabf031fd936051dec80b0b6ae29c9503493dde7393b722eafdf5a50b02";
    const OUTPUT_1: &str = "b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7d\
                            a4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c";
    const OUTPUT_2: &str = "8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60\
                            356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6";
    // Test vector 3: the two inputs above in one batch, the second under a
    // blind of its own.
    const BATCH_BLIND_2: &str = "222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e";
    const BATCH_BLINDED_2: &str =
        "90a0145ea9da29254c3a56be4fe185465ebb3bf2a1801f7124bbbadac751e654";
    const BATCH_EVALUATED_2: &str =
        "cc5ac221950a49ceaa73c8db41b82c20372a4c8d63e5dded2db920b7eee36a2a";
    const BATCH_PROOF: &str = "cc203910175d786927eeb44ea847328047892ddf8590e723c37205cb74600b0a\
                               5ab5337c8eb4ceae0494c2cf89529dcf94572ed267473d567aeed6ab873dee08";

    /// The RFC's batch of two, blinded with the RFC's blinds.
    fn rfc_batch() -> (Vec<Vec<u8>>, OprfBlinding) {
        let inputs = vec![hex(INPUT_1), hex(INPUT_2)];
        let blinding = blind_with(&mut Scalars::of(&[BLIND_1, BATCH_BLIND_2]), &inputs).unwrap();
        (inputs, blinding)
    }

    #[test]
    fn finalizing_the_rfc_evaluation_gives_the_rfc_output() {
        for (input, evaluated, proof, output) in [
            (INPUT_1, EVALUATED_1, PROOF_1, OUTPUT_1),
            (INPUT_2, EVALUATED_2, PROOF_2, OUTPUT_2),
        ] {
            let inputs = vec![hex(input)];
            let blinding = blind_with(&mut Scalars::of(&[BLIND_1]), &inputs).unwrap();

            let outputs = finalize(
                &inputs,
                &blinding.client_states,
                &[hex(evaluated)],
                &hex(proof),
                &hex(PK_SM),
            )
            .unwrap();

            assert_eq!(outputs, vec![hex(output)]);
        }
    }

    #[test]
    fn a_batch_of_two_gives_the_rfc_elements_and_outputs_under_one_proof() {
        let (inputs, blinding) = rfc_batch();
        assert_eq!(
            blinding.blinded_elements,
            vec![hex(BLINDED_1), hex(BATCH_BLINDED_2)]
        );

        let outputs = finalize(
            &inputs,
            &blinding.client_states,
            &[hex(EVALUATED_1), hex(BATCH_EVALUATED_2)],
            &hex(BATCH_PROOF),
            &hex(PK_SM),
        )
        .unwrap();

        assert_eq!(outputs, vec![hex(OUTPUT_1), hex(OUTPUT_2)]);
    }

    /// The server of the RFC's vectors, and another with a key of its own.
    fn server(seed: &str) -> VoprfServer<Ristretto255> {
        VoprfServer::new_from_seed(&hex(seed), &hex("74657374206b6579")).unwrap()
    }
    const SEED: &str = "a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3";
    const OTHER_SEED: &str = "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c";

    fn public_key(server: &VoprfServer<Ristretto255>) -> Vec<u8> {
        Ristretto255::serialize_elem(server.get_public_key()).to_vec()
    }

    #[test]
    fn the_rfc_seed_gives_the_rfc_public_key() {
        assert_eq!(public_key(&server(SEED)), hex(PK_SM));
    }

    /// The whole exchange through the public calls, with fresh blinds and no
    /// ambient runtime: what the device unblinds is what the server computes
    /// from the input directly.
    #[test]
    fn what_the_device_unblinds_is_what_the_server_computes_directly() {
        let server = server(SEED);
        let inputs: Vec<Vec<u8>> = ["+33612345678", "+33698765432", "+4915112345678"]
            .iter()
            .map(|n| n.as_bytes().to_vec())
            .collect();

        let blinding = futures::executor::block_on(blind_oprf(inputs.clone())).unwrap();
        let blinded = blinding
            .blinded_elements
            .iter()
            .map(|e| BlindedElement::<Ristretto255>::deserialize(e).unwrap())
            .collect::<Vec<_>>();
        let answer = server.batch_blind_evaluate(&mut OsRng, &blinded).unwrap();
        let outputs = futures::executor::block_on(finalize_oprf(
            inputs.clone(),
            blinding.client_states,
            answer
                .messages
                .iter()
                .map(|m| m.serialize().to_vec())
                .collect(),
            answer.proof.serialize().to_vec(),
            public_key(&server),
        ))
        .unwrap();

        let direct: Vec<Vec<u8>> = inputs
            .iter()
            .map(|input| server.evaluate(input).unwrap().to_vec())
            .collect();
        assert_eq!(outputs, direct);
    }

    #[test]
    fn the_same_input_blinded_twice_gives_two_blinded_elements() {
        let input = vec![b"+33612345678".to_vec()];
        let first = futures::executor::block_on(blind_oprf(input.clone())).unwrap();
        let second = futures::executor::block_on(blind_oprf(input)).unwrap();

        assert_ne!(first.blinded_elements, second.blinded_elements);
    }

    /// Finalises the RFC's batch of two with the answer given, changed as
    /// each refusal test needs.
    fn finalize_rfc_batch(
        evaluated: &[&str],
        proof: &str,
        public_key: &[u8],
    ) -> Result<Vec<Vec<u8>>, OprfError> {
        let (inputs, blinding) = rfc_batch();
        let evaluated: Vec<Vec<u8>> = evaluated.iter().map(|e| hex(e)).collect();
        finalize(
            &inputs,
            &blinding.client_states,
            &evaluated,
            &hex(proof),
            public_key,
        )
    }

    #[test]
    fn an_answer_checked_against_another_key_is_refused() {
        let refused = finalize_rfc_batch(
            &[EVALUATED_1, BATCH_EVALUATED_2],
            BATCH_PROOF,
            &public_key(&server(OTHER_SEED)),
        );

        assert_eq!(refused, Err(OprfError::ProofRejected));
    }

    #[test]
    fn a_proof_made_for_another_batch_is_refused() {
        let refused = finalize_rfc_batch(&[EVALUATED_1, BATCH_EVALUATED_2], PROOF_1, &hex(PK_SM));

        assert_eq!(refused, Err(OprfError::ProofRejected));
    }

    #[test]
    fn evaluated_elements_in_the_wrong_order_are_refused() {
        let refused =
            finalize_rfc_batch(&[BATCH_EVALUATED_2, EVALUATED_1], BATCH_PROOF, &hex(PK_SM));

        assert_eq!(refused, Err(OprfError::ProofRejected));
    }

    #[test]
    fn an_evaluated_element_that_is_not_a_point_does_not_parse() {
        let not_a_point = "ff".repeat(32);
        let refused = finalize_rfc_batch(&[EVALUATED_1, &not_a_point], BATCH_PROOF, &hex(PK_SM));

        assert_eq!(refused, Err(OprfError::MalformedPayload));
    }

    #[test]
    fn a_public_key_or_a_proof_of_the_wrong_length_does_not_parse() {
        let evaluated = [EVALUATED_1, BATCH_EVALUATED_2];
        let short_key = &hex(PK_SM)[..31];
        assert_eq!(
            finalize_rfc_batch(&evaluated, BATCH_PROOF, short_key),
            Err(OprfError::MalformedPayload)
        );
        assert_eq!(
            finalize_rfc_batch(&evaluated, &BATCH_PROOF[..126], &hex(PK_SM)),
            Err(OprfError::MalformedPayload)
        );
    }

    #[test]
    fn a_client_state_this_module_did_not_make_does_not_parse() {
        let (inputs, mut blinding) = rfc_batch();
        blinding.client_states[1].truncate(40);

        let refused = finalize(
            &inputs,
            &blinding.client_states,
            &[hex(EVALUATED_1), hex(BATCH_EVALUATED_2)],
            &hex(BATCH_PROOF),
            &hex(PK_SM),
        );

        assert_eq!(refused, Err(OprfError::MalformedPayload));
    }

    #[test]
    fn a_batch_that_cannot_be_processed_as_given_is_rejected() {
        let mut rng = Scalars::of(&[BLIND_1]);
        assert_eq!(blind_with(&mut rng, &[]), Err(OprfError::Rejected), "empty");
        assert_eq!(
            blind_with(&mut rng, &[vec![0x5a; MAX_INPUT_BYTES + 1]]),
            Err(OprfError::Rejected),
            "an input longer than the RFC allows"
        );

        let (inputs, blinding) = rfc_batch();
        let one_answer_for_two_inputs = finalize(
            &inputs,
            &blinding.client_states,
            &[hex(EVALUATED_1)],
            &hex(BATCH_PROOF),
            &hex(PK_SM),
        );
        assert_eq!(one_answer_for_two_inputs, Err(OprfError::Rejected));
        let one_state_for_two_inputs = finalize(
            &inputs,
            &blinding.client_states[..1],
            &[hex(EVALUATED_1), hex(BATCH_EVALUATED_2)],
            &hex(BATCH_PROOF),
            &hex(PK_SM),
        );
        assert_eq!(one_state_for_two_inputs, Err(OprfError::Rejected));
        assert_eq!(
            finalize(&[], &[], &[], &hex(BATCH_PROOF), &hex(PK_SM)),
            Err(OprfError::Rejected),
            "empty"
        );
    }

    #[test]
    fn blinding_with_the_rfc_blind_gives_the_rfc_blinded_element() {
        for (input, blinded) in [(INPUT_1, BLINDED_1), (INPUT_2, BLINDED_2)] {
            let blinding = blind_with(&mut Scalars::of(&[BLIND_1]), &[hex(input)]).unwrap();

            assert_eq!(blinding.blinded_elements, vec![hex(blinded)]);
        }
    }
}
