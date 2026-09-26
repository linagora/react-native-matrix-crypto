import { describe, expect, it } from 'vitest'

import fixture from './oprfFixture.json'
import { chunks, fnv1a, fromBase64 } from './oprfTiming'

describe('reading the OPRF fixture', () => {
  it('decodes base64 as RFC 4648 writes it', () => {
    const decoded = (text: string) => String.fromCharCode(...fromBase64(text))
    expect(decoded('')).toBe('')
    expect(decoded('Zg==')).toBe('f')
    expect(decoded('Zm8=')).toBe('fo')
    expect(decoded('Zm9v')).toBe('foo')
    expect(decoded('Zm9vYg==')).toBe('foob')
    expect(decoded('Zm9vYmFy')).toBe('foobar')
  })

  it('computes FNV-1a as its published vectors and the generator have it', () => {
    const bytes = (text: string) => [
      Uint8Array.from(text, c => c.charCodeAt(0)).buffer,
    ]
    expect(fnv1a(bytes(''))).toBe('811c9dc5')
    expect(fnv1a(bytes('a'))).toBe('e40c292c')
    expect(fnv1a(bytes('foobar'))).toBe('bf9cf968')
    expect(fnv1a([...bytes('foo'), ...bytes('bar')])).toBe('bf9cf968')
  })

  it('holds one client state and one evaluated element per input', () => {
    const states = chunks(fromBase64(fixture.clientStates), 64)
    const evaluated = chunks(fromBase64(fixture.evaluationElements), 32)

    expect(states).toHaveLength(fixture.count)
    expect(evaluated).toHaveLength(fixture.count)
    expect(states.every(state => state.byteLength === 64)).toBe(true)
    expect(evaluated.every(element => element.byteLength === 32)).toBe(true)
    expect(fromBase64(fixture.proof)).toHaveLength(64)
    expect(fromBase64(fixture.publicKey)).toHaveLength(32)
    expect(fixture.outputsChecksum).toMatch(/^[0-9a-f]{8}$/)
  })
})
