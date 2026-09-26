/**
 * The client half of an oblivious pseudorandom function: RFC 9497, suite
 * ristretto255-SHA512, in its verifiable mode.
 *
 * The one part of this library that has nothing to do with Matrix, in a
 * module of its own for that reason. `rust/matrix-crypto-core/src/oprf.rs`
 * carries the protocol and the tests against the RFC's vectors; this file
 * keeps the client states out of a product's reach, and normalises errors.
 */
import {
  blindOprf as nativeBlindOprf,
  finalizeOprf as nativeFinalizeOprf,
} from './generated/matrix_crypto'
import { toCryptoError } from './errors'
import { toArrayBuffer } from './probe'

/**
 * A batch of inputs blinded by {@link blindOprf}, for a server to evaluate.
 *
 * Send {@link OprfBlinding.blindedElements} to the server, and keep this
 * object for {@link finalizeOprf}. It also carries, out of sight, the inputs
 * as they were blinded and one client state per input. A client state holds
 * the blind that hides its input from the server, so none is a property of
 * this object, and no serialisation of it can carry one.
 *
 * A blinding lasts as long as this object, in this process. A product that
 * restarts between blinding and the server's answer blinds again.
 */
export interface OprfBlinding {
  /**
   * One per input, in the order given, 32 bytes each: the only part of a
   * blinding meant for the server.
   */
  readonly blindedElements: readonly Uint8Array[]
}

/**
 * What {@link finalizeOprf} needs beside the server's answer, kept beside
 * each blinding rather than on it. Keyed by the object {@link blindOprf}
 * returned, so a product that holds the blinding holds everything, and a
 * blinding it drops takes its states with it.
 */
const KEPT = new WeakMap<
  OprfBlinding,
  { inputs: ArrayBuffer[]; clientStates: ArrayBuffer[] }
>()

/**
 * Blinds a batch of inputs, for a server to evaluate with a key only it
 * holds: the client half of RFC 9497's oblivious pseudorandom function,
 * suite ristretto255-SHA512, in its verifiable mode.
 *
 * The server receives the blinded elements and never an input; the device
 * receives, from {@link finalizeOprf}, the keyed function of each input and
 * nothing about the key. Masking the numbers of an address book, so that
 * they can be matched against the numbers of accounts that chose to be
 * found, is what this was added for.
 *
 * Each input gets a fresh blind from the operating system's generator, so
 * the same input blinded twice gives two different blinded elements.
 *
 * # What a product does between the two calls
 *
 * Sends {@link OprfBlinding.blindedElements} to its server, in that order,
 * and receives one evaluated element per blinded element and one proof for
 * the batch. This library makes no request, as everywhere else.
 *
 * # Limits
 *
 * A batch holds between one and 65,535 inputs, which is what the RFC's batch
 * proof can count; a product with more splits them. An input is at most
 * 65,535 bytes. Beyond either, the call rejects with `'rejected'`.
 *
 * @param inputs The inputs, as bytes. The same input must be encoded the
 *   same way the server encodes it when it evaluates one itself, or the two
 *   outputs will never match.
 */
export async function blindOprf(
  inputs: readonly Uint8Array[],
): Promise<OprfBlinding> {
  // Copies, so that what is finalised is what was blinded, even if the
  // product reuses its arrays in between.
  const copies = inputs.map(input => input.slice().buffer)
  let blinded
  try {
    blinded = await nativeBlindOprf(copies)
  } catch (e) {
    throw toCryptoError(e)
  }
  const blinding: OprfBlinding = Object.freeze({
    blindedElements: Object.freeze(
      blinded.blindedElements.map(element => new Uint8Array(element)),
    ),
  })
  KEPT.set(blinding, { inputs: copies, clientStates: blinded.clientStates })
  return blinding
}

/**
 * Checks a server's answer to a blinded batch, and unblinds it.
 *
 * Returns one output per input, in the order the inputs were given to
 * {@link blindOprf}: 64 bytes each, the same bytes the server computes when
 * it evaluates an input it holds itself. That equality is what makes the
 * outputs worth having: a product compares them with outputs the server
 * computed directly, and neither side learns an input the other did not
 * have.
 *
 * # The proof is checked, always
 *
 * The server answers a batch with one proof that it evaluated every element
 * with the key whose public half is `publicKey`. An answer whose proof does
 * not verify rejects with `'proof_rejected'` and returns nothing, not even
 * the outputs the proof would have covered. There is no call that skips the
 * check, so every output this returns comes from the one key the product
 * named.
 *
 * `publicKey` is therefore something a product obtains apart from the
 * answer: published by the server once, and read by every device alike.
 * When a server replaces its key, fetching the public keys again and asking
 * again is the one retry worth making after `'proof_rejected'`.
 *
 * # Rejections
 *
 * - `'proof_rejected'`: the proof does not verify against `publicKey`.
 * - `'malformed_payload'`: an evaluated element or `publicKey` is not a
 *   point of the group, or `proof` is not two scalars.
 * - `'rejected'`: the answer does not have one evaluated element per input,
 *   or `blinding` is not an object {@link blindOprf} returned in this
 *   process.
 *
 * @param blinding What {@link blindOprf} returned for this batch.
 * @param evaluationElements The server's answer, one per blinded element,
 *   in the same order, 32 bytes each.
 * @param proof The server's proof for the whole batch, 64 bytes.
 * @param publicKey The public half of the key the answer must come from,
 *   32 bytes.
 */
export async function finalizeOprf(
  blinding: OprfBlinding,
  evaluationElements: readonly Uint8Array[],
  proof: Uint8Array,
  publicKey: Uint8Array,
): Promise<Uint8Array[]> {
  const kept = KEPT.get(blinding)
  if (kept === undefined) {
    throw toCryptoError({ name: 'Rejected' })
  }
  let outputs
  try {
    outputs = await nativeFinalizeOprf(
      kept.inputs,
      kept.clientStates,
      evaluationElements.map(toArrayBuffer),
      toArrayBuffer(proof),
      toArrayBuffer(publicKey),
    )
  } catch (e) {
    throw toCryptoError(e)
  }
  return outputs.map(output => new Uint8Array(output))
}
