import { describe, expect, it, vi } from 'vitest'
import type { CryptoError } from './errors'
import { isCryptoError } from './errors'
import { blindOprf, finalizeOprf } from './oprf'
import {
  blindOprf as nativeBlindOprf,
  finalizeOprf as nativeFinalizeOprf,
  OprfFfiError,
} from './generated/matrix_crypto'

vi.mock('./generated/matrix_crypto', async importOriginal => {
  const actual =
    await importOriginal<typeof import('./generated/matrix_crypto')>()
  return {
    ...actual,
    // One byte per value, and a different leading byte for each kind of
    // value, so that a module crossing two of them -- the client states where
    // the blinded elements belong, above all -- hands back bytes a test can
    // see are the wrong ones.
    blindOprf: vi.fn(async (inputs: ArrayBuffer[]) => ({
      blindedElements: inputs.map((_, i) => new Uint8Array([0xb0 + i]).buffer),
      clientStates: inputs.map((_, i) => new Uint8Array([0xc0 + i]).buffer),
    })),
    finalizeOprf: vi.fn(async (inputs: ArrayBuffer[]) =>
      inputs.map((_, i) => new Uint8Array([0xf0 + i]).buffer),
    ),
  }
})

describe('the OPRF client', () => {
  const bytes = (...values: number[]) => new Uint8Array(values)
  const listed = (buffers: readonly (ArrayBuffer | Uint8Array)[]) =>
    buffers.map(b => [...new Uint8Array(b)])

  it('hands back the blinded elements, and nothing else a product could send', async () => {
    const blinding = await blindOprf([bytes(1), bytes(2)])

    expect(listed(blinding.blindedElements)).toEqual([[0xb0], [0xb1]])
    // The client states stay on the device: they are not a property of what
    // comes back, so no serialisation of it can carry them.
    expect(Object.getOwnPropertyNames(blinding)).toEqual(['blindedElements'])
    expect(JSON.stringify(blinding)).not.toContain('192')
    expect(listed(vi.mocked(nativeBlindOprf).mock.calls.at(-1)![0])).toEqual([
      [1],
      [2],
    ])
  })

  it('finalises with the inputs and states it kept, in the order the native call takes them', async () => {
    const blinding = await blindOprf([bytes(1, 1), bytes(2, 2)])

    const outputs = await finalizeOprf(
      blinding,
      [bytes(0xe0), bytes(0xe1)],
      bytes(0x9f),
      bytes(0x7a),
    )

    expect(listed(outputs)).toEqual([[0xf0], [0xf1]])
    const [inputs, states, evaluated, proof, publicKey] = vi
      .mocked(nativeFinalizeOprf)
      .mock.calls.at(-1)!
    expect(listed(inputs)).toEqual([
      [1, 1],
      [2, 2],
    ])
    expect(listed(states)).toEqual([[0xc0], [0xc1]])
    expect(listed(evaluated)).toEqual([[0xe0], [0xe1]])
    expect(listed([proof])).toEqual([[0x9f]])
    expect(listed([publicKey])).toEqual([[0x7a]])
  })

  it('finalises the inputs as they were when blinded, whatever became of them since', async () => {
    const input = bytes(1, 2, 3)
    const blinding = await blindOprf([input])
    input[0] = 9

    await finalizeOprf(blinding, [bytes(0xe0)], bytes(0x9f), bytes(0x7a))

    expect(listed(vi.mocked(nativeFinalizeOprf).mock.calls.at(-1)![0])).toEqual(
      [[1, 2, 3]],
    )
  })

  it('refuses a blinding it did not return, before anything reaches native code', async () => {
    const callsBefore = vi.mocked(nativeFinalizeOprf).mock.calls.length
    const lookalike = { blindedElements: [bytes(0xb0)] }

    const error = await finalizeOprf(
      lookalike,
      [bytes(0xe0)],
      bytes(0x9f),
      bytes(0x7a),
    ).catch((e: unknown) => e)

    expect(isCryptoError(error)).toBe(true)
    expect((error as CryptoError).kind).toBe('rejected')
    expect(vi.mocked(nativeFinalizeOprf).mock.calls.length).toBe(callsBefore)
  })

  it('tells a proof that does not verify apart from an answer that does not parse', async () => {
    const blinding = await blindOprf([bytes(1)])

    vi.mocked(nativeFinalizeOprf).mockRejectedValueOnce(
      new OprfFfiError.ProofRejected(),
    )
    const unproven = await finalizeOprf(
      blinding,
      [bytes(0xe0)],
      bytes(0x9f),
      bytes(0x7a),
    ).catch((e: unknown) => e)
    expect((unproven as CryptoError).kind).toBe('proof_rejected')

    vi.mocked(nativeFinalizeOprf).mockRejectedValueOnce(
      new OprfFfiError.MalformedPayload(),
    )
    const garbled = await finalizeOprf(
      blinding,
      [bytes(0xe0)],
      bytes(0x9f),
      bytes(0x7a),
    ).catch((e: unknown) => e)
    expect((garbled as CryptoError).kind).toBe('malformed_payload')
  })

  it('reports a batch it cannot blind as rejected', async () => {
    vi.mocked(nativeBlindOprf).mockRejectedValueOnce(
      new OprfFfiError.Rejected(),
    )

    const error = await blindOprf([]).catch((e: unknown) => e)

    expect((error as CryptoError).kind).toBe('rejected')
  })
})
