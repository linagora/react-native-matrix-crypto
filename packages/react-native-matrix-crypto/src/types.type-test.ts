import { asCryptoScopeId } from './types'
import type {
  CryptoAlgorithm,
  CryptoScopeId,
  EventEnvelope,
  SasMaterial,
  ScannableCode,
  SenderTrustRequirement,
  SenderVerification,
  TrustState,
  VerificationStage,
} from './types'

// A bare string must NOT be assignable to CryptoScopeId.
// @ts-expect-error bare strings must go through asCryptoScopeId
const bad: CryptoScopeId = '!room:example.org'

// The branded constructor is the only way in.
const good: CryptoScopeId = asCryptoScopeId('!room:example.org')

// The algorithm union must stay open: an unknown algorithm is assignable,
// so adding MLS later is an additive change, not a breaking one.
const known: CryptoAlgorithm = 'megolm'
const future: CryptoAlgorithm = 'mls'
const fabricated: CryptoAlgorithm = 'x-fabricated-suite'

// The authenticity field is optional, because one type describes both
// directions and only one of them has a value for it. An envelope without
// it is the encrypt direction and must still compile.
const envelope: EventEnvelope = {
  scope: good,
  algorithm: fabricated,
  eventType: 'm.room.message',
  ciphertext: new Uint8Array([1, 2, 3]),
  sender: '@a:server1',
}

const decrypted: EventEnvelope = {
  ...envelope,
  senderVerification: { state: 'unverified', reason: 'mismatched_sender' },
}

// `TrustState` and `VerificationStage` are CLOSED, unlike `CryptoAlgorithm`
// above. That is the opposite property and it needs the opposite assertion:
// a value outside the union must be a compile error, so a product can switch
// on either exhaustively and be told by the compiler when a later version
// adds a case.
// @ts-expect-error TrustState is closed: a value outside the union is not assignable
const fabricatedTrust: TrustState = 'x-fabricated-trust'
// @ts-expect-error VerificationStage is closed: a value outside the union is not assignable
const fabricatedStage: VerificationStage = 'x-fabricated-stage'

const trust: TrustState = 'verified'
const stage: VerificationStage = 'keys-exchanged'
// The member the code-scanning milestone appended. **Closed does not mean
// final**, and this is what the two words together are worth: the union
// grew, so an exhaustive `switch` in a consuming product stopped compiling
// and the compiler named every place that has to decide what to show for a
// code somebody has scanned. That is the outcome closing this union was
// for. Appending is wire-safe -- the layer underneath numbers its variants
// by declaration order and this one was added last, so nothing already
// decoded changed meaning -- and it is a minor version bump rather than a
// break of the wire.
// The assignment IS the assertion: this file is compiled, never run, and a
// value nothing reads is exactly what a type test declares.
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const scannedStage: VerificationStage = 'code-scanned'

// `SenderVerification` is CLOSED too, and closed in two places at once: the
// `state` tag and the `reason` behind it. A product switching on both
// exhaustively must be told by the compiler when a later version adds a
// case, which is the entire argument for declaring values a product cannot
// meet yet rather than adding them later. This said "the three values this
// release cannot produce"; the count was wrong before 0.1.0 shipped and is
// wrong again since M4, which is the argument for not carrying one.
// @ts-expect-error SenderVerification is closed: a fabricated state is not assignable
const fabricatedState: SenderVerification = { state: 'x-fabricated-state' }
// @ts-expect-error SenderVerification is closed: a fabricated reason is not assignable
const fabricatedReason: SenderVerification = { state: 'unverified', reason: 'x-fabricated' }
// `no_device` is the one member carrying a third field, and it is required:
// "we could not link this event to a device" is not a complete answer
// without which of the two reasons it was.
// @ts-expect-error no_device must say which problem it is
const problemless: SenderVerification = { state: 'unverified', reason: 'no_device' }
// And `verified` carries no reason, because there is nothing to explain.
// @ts-expect-error a verified sender has no reason to give
const reasoned: SenderVerification = { state: 'verified', reason: 'unsigned_device' }

// The values a decrypted event actually arrives with. This said "the values
// this release can actually produce" while listing three of them, and the
// omission was `'unverified_identity'`, which has been produced since before
// 0.1.0 by any peer whose client has cross-signing set up. A list with a
// completeness claim over it and no assertion behind it stays green forever,
// which is how the omission survived a milestone: nothing here can fail.
// `'verified'` was absent for a different reason, and a temporary one: the
// core reached it through the whole chain and the call that would let a
// product start that chain was not bridged. It is bridged, so this list
// gained the entry it was said to be waiting for rather than losing one.
const authentic: SenderVerification = { state: 'verified' }
const unsigned: SenderVerification = { state: 'unverified', reason: 'unsigned_device' }
const crossSigned: SenderVerification = { state: 'unverified', reason: 'unverified_identity' }
const impersonated: SenderVerification = { state: 'unverified', reason: 'mismatched_sender' }
const undeliverable: SenderVerification = {
  state: 'unverified',
  reason: 'no_device',
  problem: 'insecure_source',
}
const undelivered: SenderVerification = {
  state: 'unverified',
  reason: 'no_device',
  problem: 'missing',
}

// `SenderTrustRequirement` is CLOSED too, for the same reason as the three
// unions above: a product switching on it exhaustively must be told by the
// compiler when a later version adds a tier, rather than handed a silent
// default on a trust decision.
// @ts-expect-error SenderTrustRequirement is closed: a value outside the union is not assignable
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const fabricatedRequirement: SenderTrustRequirement = 'x-fabricated-requirement'

const permissive: SenderTrustRequirement = 'any'
const legacyTolerant: SenderTrustRequirement = 'identity_signed_or_legacy'
const strict: SenderTrustRequirement = 'identity_signed'
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const requirements: readonly SenderTrustRequirement[] = [
  permissive,
  legacyTolerant,
  strict,
]

// The digits are a fixed-length tuple, not an array: a caller cannot index
// past the end of something it believed had three entries, and a record
// carrying the wrong number of them does not compile.
// @ts-expect-error the short authentication string has exactly three digits
const shortMaterial: SasMaterial = { decimals: [1, 2] }

// The symbol form is optional, because the protocol only produces it when
// both sides negotiated it. A screen offering only symbols has a live path
// with nothing to show, and this is where that is visible.
const digitsOnly: SasMaterial = { decimals: [1, 2, 3] }
const withSymbols: SasMaterial = {
  decimals: [1, 2, 3],
  emoji: [{ symbol: 'x', description: 'a word' }],
}

// The code crosses as bytes, and the type is what makes a product that
// treats it as an `ArrayBuffer` fail here rather than draw nothing. The
// generated record really does carry an `ArrayBuffer`, so this is the one
// place the conversion the facade performs is pinned by the compiler.
// @ts-expect-error the payload is bytes, not the buffer behind them
const rawBuffer: ScannableCode = { payload: new ArrayBuffer(4), width: 2, modules: [] }
// And the grid is a flat, row-major list rather than rows of rows: a
// product that nested it draws nothing, and the nesting is exactly what
// somebody writing the drawing code reaches for first.
const nestedGrid: ScannableCode = {
  payload: new Uint8Array([1]),
  width: 2,
  modules: [
    // @ts-expect-error the grid is flat and row-major, not an array of rows
    [true, false],
    // @ts-expect-error the grid is flat and row-major, not an array of rows
    [false, true],
  ],
}
const code: ScannableCode = {
  payload: new Uint8Array([1, 2, 3]),
  width: 2,
  modules: [true, false, false, true],
}

void bad; void known; void future; void envelope; void decrypted
void rawBuffer; void nestedGrid; void code
void fabricatedTrust; void fabricatedStage; void trust; void stage
void shortMaterial; void digitsOnly; void withSymbols
void fabricatedState; void fabricatedReason; void problemless; void reasoned
void authentic; void unsigned; void crossSigned; void impersonated
void undeliverable; void undelivered
