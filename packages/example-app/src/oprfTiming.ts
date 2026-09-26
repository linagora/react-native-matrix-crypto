/**
 * Times the OPRF client on two thousand inputs, under whatever JavaScript
 * engine this build runs, and logs what it measured.
 *
 * - `PROBE_OPRF_BLIND_MS n` -- `blindOprf` on two thousand inputs, through
 *   the public API.
 * - `PROBE_OPRF_FINALIZE_MS n` -- finalising two thousand client states
 *   against one server answer, batch proof checked.
 * - `PROBE_OPRF_OUTPUTS match n` -- a checksum of all `n` outputs equals the
 *   one of the outputs the server computed from those inputs directly;
 *   `differ` when it does not.
 * - `PROBE_OPRF_REFUSAL kind` -- the public `finalizeOprf`, handed an answer
 *   whose proof was made for another batch, and the kind it rejected with:
 *   `proof_rejected` is the expected one.
 * - `PROBE_OPRF_FAILED kind` -- a call rejected where none should have.
 *
 * # Why finalising goes through the generated binding
 *
 * A server's answer is needed, and the library ships no server half. So the
 * answer comes from `oprfFixture.json`, which the core's
 * `tests/oprf_measurement_fixture.rs` wrote with `voprf`'s own server for
 * client states blinded by the public `blind_oprf`. The facade's
 * `finalizeOprf` accepts only a blinding it returned in this process, whose
 * states are fresh and match no fixture, so the fixture's states go through
 * the generated `finalizeOprf` the facade itself calls. What the facade adds
 * on top is a map lookup and copying the outputs: nothing this measures.
 *
 * Not a check: nothing here moves `PROBE_SUMMARY`, and a failure is logged
 * rather than thrown, on the rule `ProbeHarness.tsx` states for its other
 * instruments. The lines carry durations and counts, and no input.
 */
import {
  blindOprf,
  finalizeOprf,
  isCryptoError,
} from 'react-native-matrix-crypto'
import { finalizeOprf as nativeFinalizeOprf } from 'react-native-matrix-crypto/src/generated/matrix_crypto'
import fixture from './oprfFixture.json'

/** The inputs the fixture was made for: see the generator's own comment. */
function input(index: number): Uint8Array {
  const text = `+3361${String(index).padStart(7, '0')}`
  return Uint8Array.from(text, character => character.charCodeAt(0))
}

const ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

/** Standard base64 with padding, which is what the generator writes. */
export function fromBase64(text: string): Uint8Array {
  const clean = text.replace(/[=]+$/, '')
  const bytes = new Uint8Array(Math.floor((clean.length * 3) / 4))
  let bits = 0
  let value = 0
  let at = 0
  for (const character of clean) {
    const index = ALPHABET.indexOf(character)
    if (index === -1) throw new Error('not base64')
    value = (value << 6) | index
    bits += 6
    if (bits >= 8) {
      bits -= 8
      bytes[at++] = (value >> bits) & 0xff
    }
  }
  return bytes
}

/** `bytes`, cut into consecutive buffers of `size` bytes. */
export function chunks(bytes: Uint8Array, size: number): ArrayBuffer[] {
  const out: ArrayBuffer[] = []
  for (let at = 0; at < bytes.length; at += size) {
    out.push(bytes.slice(at, at + size).buffer)
  }
  return out
}

/**
 * 32-bit FNV-1a over every byte of `buffers`, in order, as lower-case hex:
 * what the fixture's generator computes over the server's own outputs.
 */
export function fnv1a(buffers: readonly ArrayBuffer[]): string {
  let hash = 0x811c9dc5
  for (const buffer of buffers) {
    for (const byte of new Uint8Array(buffer)) {
      hash = Math.imul(hash ^ byte, 0x01000193) >>> 0
    }
  }
  return hash.toString(16).padStart(8, '0')
}

/** The kind a rejection carries, or a word saying it carried none. */
function kindOf(e: unknown): string {
  return isCryptoError(e) ? e.kind : 'not-a-crypto-error'
}

export async function timeOprfMasking(): Promise<void> {
  try {
    const inputs = Array.from({ length: fixture.count }, (_, i) => input(i))

    let calledAt = Date.now()
    await blindOprf(inputs)
    console.log(`PROBE_OPRF_BLIND_MS ${Date.now() - calledAt}`)

    const states = chunks(fromBase64(fixture.clientStates), 64)
    const evaluated = chunks(fromBase64(fixture.evaluationElements), 32)
    const proof = fromBase64(fixture.proof).buffer as ArrayBuffer
    const publicKey = fromBase64(fixture.publicKey).buffer as ArrayBuffer
    calledAt = Date.now()
    const outputs = await nativeFinalizeOprf(
      inputs.map(bytes => bytes.buffer as ArrayBuffer),
      states,
      evaluated,
      proof,
      publicKey,
    )
    console.log(`PROBE_OPRF_FINALIZE_MS ${Date.now() - calledAt}`)

    const matches =
      outputs.length === fixture.count &&
      fnv1a(outputs) === fixture.outputsChecksum
    console.log(
      `PROBE_OPRF_OUTPUTS ${matches ? 'match' : 'differ'} ${outputs.length}`,
    )
  } catch (e) {
    console.log(`PROBE_OPRF_FAILED ${kindOf(e)}`)
    return
  }

  // Through the public API this time, which the timing above could not use:
  // one fresh input, answered with an element and a proof that belong to the
  // fixture's batch. The proof cannot verify, and the call must say so.
  try {
    const one = await blindOprf([input(0)])
    await finalizeOprf(
      one,
      [new Uint8Array(chunks(fromBase64(fixture.evaluationElements), 32)[0])],
      fromBase64(fixture.proof),
      fromBase64(fixture.publicKey),
    )
    console.log('PROBE_OPRF_REFUSAL none')
  } catch (e) {
    console.log(`PROBE_OPRF_REFUSAL ${kindOf(e)}`)
  }
}
