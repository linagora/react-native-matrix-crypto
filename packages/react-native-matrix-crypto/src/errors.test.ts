import { describe, expect, it } from 'vitest'
import { isCryptoError, toCryptoError } from './errors'
// The generated tag enums, imported rather than restated: the walk at the
// bottom of this file has to enumerate what the bindings really declare, or
// it is a hand-written list wearing a derivation's clothes.
import {
  MachineFfiError_Tags,
  ProbeFfiError_Tags,
  SessionFfiError_Tags,
} from './generated/matrix_crypto'

describe('toCryptoError', () => {
  it('maps a generated Rejected error to a typed CryptoError', () => {
    const raw = { name: 'Rejected', reason: 'input must not be empty' }
    const err = toCryptoError(raw)
    expect(err.kind).toBe('rejected')
    expect(err.message).toContain('input must not be empty')
    expect(err.retriable).toBe(false)
  })

  it('maps an unknown error to a stable unknown kind rather than throwing', () => {
    const err = toCryptoError(new Error('something else'))
    expect(err.kind).toBe('unknown')
    expect(err.retriable).toBe(false)
  })

  it('carries the sender verbatim when present, per spec section 10', () => {
    const err = toCryptoError({ name: 'MissingKey', sender: '@b:server2' })
    expect(err.kind).toBe('missing_key')
    expect(err.sender).toBe('@b:server2')
  })

  it('never places payload content in the message, per spec section 7', () => {
    const err = toCryptoError({ name: 'Undecryptable', ciphertext: 'SECRET' })
    expect(err.message).not.toContain('SECRET')
  })

  it('recognises its own errors', () => {
    expect(isCryptoError(toCryptoError(new Error('x')))).toBe(true)
    expect(isCryptoError(new Error('x'))).toBe(false)
  })

  it('rejects bare objects that are not Error instances', () => {
    const fakeErr = {
      [Symbol.for('react-native-matrix-crypto.CryptoError')]: true,
    }
    expect(isCryptoError(fakeErr)).toBe(false)
  })

  it('maps prototype collision name "constructor" to unknown, not a function', () => {
    const err = toCryptoError({ name: 'constructor' })
    expect(err.kind).toBe('unknown')
    expect(typeof err.kind).toBe('string')
  })

  it('maps prototype collision name "toString" to unknown, not a function', () => {
    const err = toCryptoError({ name: 'toString' })
    expect(err.kind).toBe('unknown')
    expect(typeof err.kind).toBe('string')
  })

  it('maps prototype collision name "__proto__" to unknown, not an object', () => {
    const err = toCryptoError({ name: '__proto__' })
    expect(err.kind).toBe('unknown')
    expect(typeof err.kind).toBe('string')
  })
})

/**
 * The tests above use `{ name: 'Rejected', reason: '...' }` fixtures, which
 * is how a hand-built binding may still shape an error. It is not how a real
 * generated one does. `@ubjs/core`'s `UniffiError` base class (confirmed by
 * reading its source, `node_modules/@ubjs/core/src/errors.ts`) never sets
 * `.name` -- it stays the inherited `"Error"` -- and always sets `.message`
 * to exactly `"<EnumTypeName>.<VariantName>"`, optionally followed by
 * `": <message>"`; the variant's payload lives under `.inner`, set by the
 * generated per-variant subclass (confirmed against the actual generated
 * `ProbeFfiError.Rejected` in `src/generated/matrix_crypto.ts`), never at
 * the top level. This is exactly the shape `interop/reference.ts` throws.
 *
 * This gap -- tests and the reference binding restating a contract nothing
 * implements -- is why 19 green tests missed a real bug: `toCryptoError`
 * read `.name`/top-level `.reason`, which happened to satisfy these old
 * fixtures and nothing else. See `errors.ts`'s `variantNameFromMessage` and
 * `stringField` doc comments, and Task 11's report.
 */
describe('toCryptoError against the real UniFFI error shape', () => {
  it('maps a real UniFFI-shaped Rejected error end to end: name inherited "Error", variant in .message, payload under .inner', () => {
    const raw = Object.assign(new Error('ProbeFfiError.Rejected'), {
      inner: { reason: 'input must not be empty' },
    })
    // Sanity check that this fixture is the real shape, not the fiction the
    // tests above use.
    expect(raw.name).toBe('Error')

    const err = toCryptoError(raw)
    expect(err.kind).toBe('rejected')
    expect(err.message).toContain('input must not be empty')
    expect(err.retriable).toBe(false)
  })

  it('maps a real UniFFI-shaped MachineFfiError.NotInitialised to kind not_initialised', () => {
    // A fieldless ("flat") variant carries no `.inner` at all -- confirmed
    // against the actual generated `MachineFfiError.NotInitialised` in
    // src/generated/matrix_crypto.ts, whose constructor takes no arguments
    // and so calls `super("MachineFfiError", "NotInitialised")` with no
    // third `message` argument, leaving `.message` exactly
    // "MachineFfiError.NotInitialised" with no trailing ": <message>".
    const raw = new Error('MachineFfiError.NotInitialised')
    expect(raw.name).toBe('Error')

    const err = toCryptoError(raw)
    expect(err.kind).toBe('not_initialised')
    expect(err.retriable).toBe(false)
  })

  /**
   * Regression for FIX 2: `errors.ts` used to map `['StoreCorrupt',
   * 'store_corrupt']`, a Rust variant that has never existed --
   * `MachineFfiError`'s real variant is `Store` (see the generated
   * `MachineFfiError_Tags` in src/generated/matrix_crypto.ts), so a genuine
   * store failure fell through `KIND_BY_NAME` to `kind: 'unknown'`. `Store`
   * is a fielded variant (it carries `.inner.detail`), but its `.message` is
   * still exactly "MachineFfiError.Store" with no ": <message>" suffix: the
   * generated `Store_` constructor calls `super("MachineFfiError", "Store")`
   * with no third argument, matching `NotInitialised` above.
   */
  it('maps a real UniFFI-shaped MachineFfiError.Store to kind store_unavailable, not store_corrupt', () => {
    const raw = new Error('MachineFfiError.Store')
    expect(raw.name).toBe('Error')

    const err = toCryptoError(raw)
    expect(err.kind).toBe('store_unavailable')
    expect(err.kind).not.toBe('store_corrupt')
    expect(err.retriable).toBe(false)
  })

  /**
   * A parked finding from Task 2's review, addressed in Task 6: opening a
   * store that belongs to a different account is a recoverable
   * configuration mistake, not a storage failure like a full disk --
   * conflating the two under 'store_unavailable' would send a product
   * down the wrong recovery path. `MismatchedAccount` is a fieldless
   * variant, like `NotInitialised` above, so `.message` carries no
   * ": <message>" suffix either.
   */
  it('maps a real UniFFI-shaped MachineFfiError.MismatchedAccount to kind mismatched_account, not store_unavailable', () => {
    const raw = new Error('MachineFfiError.MismatchedAccount')
    expect(raw.name).toBe('Error')

    const err = toCryptoError(raw)
    expect(err.kind).toBe('mismatched_account')
    expect(err.kind).not.toBe('store_unavailable')
    expect(err.retriable).toBe(false)
  })

  it('recovers the variant from the "<Type>.<Variant>" prefix of .message when .name is not a recognized kind', () => {
    const err = toCryptoError({
      name: 'Error',
      message: 'ProbeFfiError.Rejected',
    })
    expect(err.kind).toBe('rejected')
  })

  it('reads the payload from .inner rather than the top level', () => {
    const err = toCryptoError({
      name: 'MissingKey',
      inner: { reason: 'no room key for this session', sender: '@b:server2' },
    })
    expect(err.kind).toBe('missing_key')
    expect(err.message).toContain('no room key for this session')
    expect(err.sender).toBe('@b:server2')
  })

  /**
   * The three `SessionFfiError` variants Task 6 could not yet exercise
   * end to end (its own F9): `SessionError` had no FFI mirror at all, so
   * these were forward scaffolding, present in `KIND_BY_NAME` but
   * unreachable from a real generated error. Task 7 gives `SessionError`
   * that mirror; this proves the map entry was already correct, not that
   * it becomes correct now.
   */
  it('maps a real UniFFI-shaped SessionFfiError.MalformedPayload to kind malformed_payload', () => {
    const err = toCryptoError(new Error('SessionFfiError.MalformedPayload'))
    expect(err.kind).toBe('malformed_payload')
    expect(err.retriable).toBe(false)
  })

  it('maps a real UniFFI-shaped SessionFfiError.Failed to kind failed', () => {
    const err = toCryptoError(new Error('SessionFfiError.Failed'))
    expect(err.kind).toBe('failed')
    expect(err.retriable).toBe(false)
  })

  it('maps a real UniFFI-shaped SessionFfiError.NotAFailureStatus to kind not_a_failure_status', () => {
    const err = toCryptoError(new Error('SessionFfiError.NotAFailureStatus'))
    expect(err.kind).toBe('not_a_failure_status')
    // Pinned like every neighbour in this block: retrying the same call with
    // the same status changes nothing, so this kind must stay out of
    // RETRIABLE. A review found this the one case here asserting only half.
    expect(err.retriable).toBe(false)
  })

  it('maps a real UniFFI-shaped SessionFfiError.UnknownRequest to kind unknown_request', () => {
    const err = toCryptoError(new Error('SessionFfiError.UnknownRequest'))
    expect(err.kind).toBe('unknown_request')
    expect(err.retriable).toBe(false)
  })

  /**
   * `KIND_BY_NAME` is keyed on the variant name alone, so the entry written
   * for `MachineFfiError.MalformedIdentifier` already serves the
   * `SessionFfiError` variant a malformed scope now raises. That is
   * convenient rather than obviously correct, and it is exactly the shape
   * that goes unnoticed: nothing in errors.ts names either enum, so a
   * reader cannot tell from this file that two of them reach one entry.
   * Both are asserted, and asserted to agree.
   */
  it('maps SessionFfiError.MalformedIdentifier to the same kind as the machine variant', () => {
    const fromSession = toCryptoError(
      new Error('SessionFfiError.MalformedIdentifier'),
    )
    const fromMachine = toCryptoError(
      new Error('MachineFfiError.MalformedIdentifier'),
    )
    expect(fromSession.kind).toBe('malformed_identifier')
    expect(fromMachine.kind).toBe('malformed_identifier')
    expect(fromSession.retriable).toBe(false)
  })

  /**
   * The reason the variant exists at all: a bad scope and a bad payload
   * must not land on one kind. Asserted here as well as in the Rust,
   * because this is the layer a consumer actually reads a kind off.
   */
  it('keeps a malformed identifier and a malformed payload on distinct kinds', () => {
    const identifier = toCryptoError(
      new Error('SessionFfiError.MalformedIdentifier'),
    )
    const payload = toCryptoError(new Error('SessionFfiError.MalformedPayload'))
    expect(identifier.kind).not.toBe(payload.kind)
  })

  /**
   * G26 in the milestone's own ledger, dispatched: policy withheld codes
   * (`m.blacklisted`, `m.unauthorised`) must not be retriable, while the
   * circumstantial ones `unshared_session` still covers (`m.unavailable`,
   * `m.no_olm`) must stay retriable. Both are asserted together, not just
   * the new kind alone, because the property this proves is the contrast
   * between the two siblings, not either one in isolation -- the same
   * reasoning `error_mapping.rs`'s Rust-side test gives for asserting
   * `SessionRefused` and `UnsharedSession` side by side.
   */
  it('maps a real UniFFI-shaped SessionFfiError.SessionRefused to a non-retriable kind, unlike its sibling UnsharedSession', () => {
    const refused = toCryptoError(new Error('SessionFfiError.SessionRefused'))
    expect(refused.kind).toBe('session_refused')
    expect(refused.retriable).toBe(false)

    const unshared = toCryptoError(new Error('SessionFfiError.UnsharedSession'))
    expect(unshared.kind).toBe('unshared_session')
    expect(unshared.retriable).toBe(true)
  })

  /**
   * Regression for the `RevokedDevice` cleanup (flagged by Task 6's review,
   * finding F3, fixed here): `KIND_BY_NAME` used to map
   * `['RevokedDevice', 'revoked_device']`, a name that exists in neither
   * Rust crate -- confirmed by a whole-tree grep. Unlike the `StoreCorrupt`
   * bug it is modelled on, it shadowed no real condition, but it was dead
   * scaffolding and a trap for whoever next assumed the map was
   * authoritative. This asserts the entry is gone: an error naming that
   * variant now falls through to 'unknown' like any other unrecognised
   * name, rather than continuing to "work" by accident.
   */
  it('no longer maps RevokedDevice specially: it falls through to unknown', () => {
    const err = toCryptoError(new Error('MachineFfiError.RevokedDevice'))
    expect(err.kind).toBe('unknown')
  })

  it('still recovers the variant when .message carries a trailing ": <message>" suffix', () => {
    // `UniffiError`'s constructor (`node_modules/@ubjs/core/src/errors.ts`)
    // takes an optional third `message` argument and, when given one,
    // formats it as "<Type>.<Variant>: <message>". `ProbeFfiError.Rejected`
    // never takes this path (it is a fielded/tagged variant, generated by
    // ubrn's TaggedEnumTemplate.ts, which never passes a third argument) --
    // but ubrn's ErrorTemplate.ts `flat_error` macro does, for fieldless
    // ("flat") UniFFI error enums, so this is a real shape the same base
    // class produces elsewhere, not a hypothetical one.
    const err = toCryptoError({
      name: 'Error',
      message:
        'ProbeFfiError.Rejected: probe rejected: input must not be empty',
    })
    expect(err.kind).toBe('rejected')
  })
})

/**
 * The verification kinds.
 *
 * `MachineFfiError` grew three fieldless variants when verification by a
 * short string landed, and six more when verification by a scannable code
 * did. The Rust side proves the right *variant* is produced for each
 * condition. Nothing on the Rust side can see whether this map has an entry
 * for it: without one, a real `MachineFfiError.MaterialNotReady` arrives as
 * kind `'unknown'` with the message "crypto error: unknown", every Rust
 * test still green. That is the whole gap these tests close, and it is the
 * same gap the `StoreCorrupt` entry above sat in for four tasks.
 *
 * **This heading said "(Task 3)" and named three variants, and the block
 * under it covered four of the fourteen the core's verification module can
 * produce.** The distinctness test at the end of the block now walks all
 * fourteen, counted against `verification.rs`'s own sibling list rather
 * than against a number carried forward; the walk over every generated
 * variant further down covers them a second time. A milestone number in a
 * heading is what let this go stale, so there is not one any more, and the
 * count that replaced it was itself wrong for a commit.
 *
 * Fieldless variants, so `.message` is exactly "<Type>.<Variant>" with no
 * suffix -- the shape `NotInitialised` above documents in full.
 */
describe('toCryptoError for the verification kinds', () => {
  it('maps a real UniFFI-shaped MachineFfiError.UnknownFlow to kind unknown_flow, not unknown', () => {
    const err = toCryptoError(new Error('MachineFfiError.UnknownFlow'))
    expect(err.kind).toBe('unknown_flow')
    expect(err.kind).not.toBe('unknown')
    expect(err.retriable).toBe(false)
  })

  it('maps a real UniFFI-shaped MachineFfiError.WrongStage to kind wrong_stage', () => {
    const err = toCryptoError(new Error('MachineFfiError.WrongStage'))
    expect(err.kind).toBe('wrong_stage')
    expect(err.retriable).toBe(false)
  })

  /**
   * The one that matters most, and the one a well-meaning edit is most
   * likely to get wrong in the other direction. It reads transient -- "not
   * ready *yet*" -- but the state it names does not resolve on its own: the
   * flow advances when the caller reports what it drained from the pump as
   * sent, so a product that read `retriable` as permission to loop would
   * spin forever against a machine that will never move. Both halves are
   * asserted, because the kind alone would pass with the wrong
   * retriability.
   */
  it('maps MachineFfiError.MaterialNotReady to kind material_not_ready, and reports it non-retriable', () => {
    const err = toCryptoError(new Error('MachineFfiError.MaterialNotReady'))
    expect(err.kind).toBe('material_not_ready')
    expect(err.retriable).toBe(false)
  })

  /**
   * Every verification-related machine variant lands on a kind of its own.
   * Asserted as a set rather than one by one: each asks a product to do
   * something different -- pump and try again, wait for a stage, stop
   * holding this identifier, query that user's devices, turn codes on, ask
   * the other person to set up an identity, point the camera somewhere
   * else, or refuse and start over -- and any two of them collapsing onto
   * one kind is invisible to a test that only checks each in isolation.
   *
   * **This said "the four" and listed four.** The core's verification
   * module produces fourteen, and the first correction of this comment
   * listed eleven while claiming "every", which is the same defect one
   * size smaller. The list below is now the same fourteen
   * `every_refusal_this_module_produces_is_its_own_error` enumerates in
   * `rust/matrix-crypto-core/src/verification.rs`, and the two are meant to
   * be read together: that one proves the core keeps them apart, this one
   * proves the crossing does.
   *
   * The four code-refusal kinds are what this most needed to cover: they
   * are four sentences a product shows a person about the same failed scan,
   * and a fold between any two of them is exactly what the design's
   * section 4 forbids and what nothing else on this side would catch.
   *
   * `CodeNotOffered` and `PeerCannotScan` are the pair to watch after them.
   * They were one variant until the code switch stopped being a single
   * boolean, they still read almost alike, and they have opposite remedies:
   * the first is a line the product writes, the second is a fact about the
   * far side that no line will change.
   *
   * `MalformedIdentifier` carries a `detail`, so its message has a suffix.
   * It is included with one, because a product meets it that way and
   * because `toCryptoError` reads the name off the front.
   */
  it('keeps every verification-related machine variant on a kind of its own', () => {
    const variants = [
      'MachineFfiError.UnknownFlow',
      'MachineFfiError.WrongStage',
      'MachineFfiError.MaterialNotReady',
      'MachineFfiError.UnknownDevice',
      'MachineFfiError.AccountKeysNotFetched',
      'MachineFfiError.IdentityNotKnown',
      'MachineFfiError.PrivateKeysNotHeld',
      'MachineFfiError.MalformedIdentifier: flow id',
      'MachineFfiError.PeerIdentityNotKnown',
      'MachineFfiError.CodeNotOffered',
      'MachineFfiError.PeerCannotScan',
      'MachineFfiError.ScannedCodeRefused',
      'MachineFfiError.ScannedCodeUnrecognised',
      'MachineFfiError.ScannedCodeMalformed',
      'MachineFfiError.ScannedCodeForAnotherFlow',
    ]
    const kinds = variants.map(
      message => toCryptoError(new Error(message)).kind,
    )

    expect(new Set(kinds).size).toBe(variants.length)
    expect(kinds).not.toContain('unknown')
  })

  /**
   * `MachineFfiError.UnknownDevice` reaches the same entry as
   * `SessionFfiError.UnknownDevice`, because this map is keyed on the
   * variant name alone. Convenient rather than obviously correct, and
   * invisible from `errors.ts`, which names neither enum -- the same
   * situation `MalformedIdentifier` above is asserted for, and asserted the
   * same way.
   */
  it('maps MachineFfiError.UnknownDevice to the same kind as the session variant', () => {
    const fromMachine = toCryptoError(
      new Error('MachineFfiError.UnknownDevice'),
    )
    const fromSession = toCryptoError(
      new Error('SessionFfiError.UnknownDevice'),
    )
    expect(fromMachine.kind).toBe('unknown_device')
    expect(fromSession.kind).toBe('unknown_device')
  })

  /**
   * The three kinds with no Rust variant at all, synthesised in `facade.ts`
   * the way `not_implemented` is. They are asserted here, beside the ones
   * that do cross the boundary, so this file stays the single list of every
   * kind this library can produce.
   */
  it('maps the three facade-synthesised verification names to their own kinds', () => {
    expect(toCryptoError({ name: 'ComparisonAlreadyStarted' }).kind).toBe(
      'comparison_already_started',
    )
    expect(toCryptoError({ name: 'VerificationEnded' }).kind).toBe(
      'verification_ended',
    )
    expect(toCryptoError({ name: 'MaterialMismatch' }).kind).toBe(
      'material_mismatch',
    )
  })
})

/**
 * Every variant the generated bindings can throw maps to a kind of its own.
 *
 * # The class of defect this ends
 *
 * `KIND_BY_NAME` is the only thing standing between a typed Rust refusal
 * and a product being handed kind `'unknown'` with the message "crypto
 * error: unknown". Nothing on the Rust side can see it: the core proves the
 * right *variant* is produced, every Rust test stays green, and the entry is
 * simply absent.
 *
 * The repository has now met that three times. `StoreCorrupt` sat in the map
 * pointing at nothing for four tasks. M4's bridge found
 * `AccountKeysNotFetched` and `IdentityAlreadyExists` had no entries at all,
 * because they were declared on the Rust side a task before anything
 * returned them, so nothing could notice. And a review of that fix found the
 * other half: entries that exist and that no test defends, so deleting one
 * passes the whole suite. It named three, `IdentityAlreadyExists`,
 * `Undecryptable` and `AlreadyInitialised`, and observed that nothing
 * structural prevented a fourth.
 *
 * This is the structural thing. It is derived from the generated bindings
 * rather than from a list written here, so it grows with the Rust surface
 * instead of rotting against it, and every future variant is defended the
 * day it is generated rather than the day someone remembers.
 *
 * # Why the tag enums rather than the error classes
 *
 * `@ubjs/core`'s `UniffiError` sets `.message` to exactly
 * `"<EnumTypeName>.<VariantName>"`, which is the shape `toCryptoError` reads
 * and the shape this file's other tests use. Constructing a real instance
 * would need each variant's `inner` payload; the tag enums carry every
 * variant name with no payload at all, and they are generated from the same
 * declaration, so walking them covers exactly the same set.
 */
describe('every generated error variant maps to a kind of its own', () => {
  const GENERATED: ReadonlyArray<readonly [string, Record<string, string>]> = [
    ['MachineFfiError', MachineFfiError_Tags],
    ['SessionFfiError', SessionFfiError_Tags],
    ['ProbeFfiError', ProbeFfiError_Tags],
  ]

  /**
   * Pinned, and it is a floor against this walk collapsing rather than a
   * claim about the world: an enumeration that silently went to zero would
   * make every assertion below trivially pass, which is the failure the
   * shell gates in `scripts/` all carry a guard for. When the Rust surface
   * grows a variant this number changes here, deliberately, in the same
   * change that adds the mapping.
   */
  const EXPECTED_VARIANTS = 37

  it('refuses to pass having walked nothing', () => {
    for (const [name, tags] of GENERATED) {
      expect(
        Object.values(tags).length,
        `${name} enumerated no variants`,
      ).toBeGreaterThan(0)
    }
    const total = GENERATED.reduce(
      (sum, [, tags]) => sum + Object.values(tags).length,
      0,
    )
    expect(total).toBe(EXPECTED_VARIANTS)
  })

  it.each(
    GENERATED.flatMap(([enumName, tags]) =>
      Object.values(tags).map(variant => [`${enumName}.${variant}`] as const),
    ),
  )('maps %s to a kind rather than to unknown', message => {
    const err = toCryptoError(new Error(message))
    expect(err.kind).not.toBe('unknown')
    expect(typeof err.kind).toBe('string')
  })

  /**
   * And no two variants of the *same* enum share a kind by accident.
   *
   * Deliberately per enum rather than across all three: `UnknownDevice` and
   * `MalformedIdentifier` are each reached from two different enums and land
   * on one kind on purpose, which is asserted directly elsewhere in this
   * file. Within one enum there is no such case, so a collision there is a
   * copy-paste in the map rather than a decision, and it would silently make
   * two conditions a product must tell apart indistinguishable.
   */
  it.each(GENERATED.map(([name, tags]) => [name, tags] as const))(
    'keeps every variant of %s on a distinct kind',
    (_name, tags) => {
      const variants = Object.values(tags)
      const kinds = variants.map(
        variant => toCryptoError(new Error(`${_name}.${variant}`)).kind,
      )
      expect(new Set(kinds).size).toBe(variants.length)
    },
  )
})

/**
 * The gate refusals arrive carrying a remedy, not a bare tag.
 *
 * These four are fieldless on the Rust side, so nothing crosses the FFI
 * boundary with them: before `MESSAGE_BY_KIND` existed, a developer saw
 * `crypto error: identity_not_known` in a log line and nothing else, while
 * every explanation of what to do sat in documentation for a function they
 * had not opened yet. That is the surface half of how a product ends up
 * wiring the destructive call to a launch-path error handler.
 *
 * The message is asserted for content rather than byte for byte: pinning the
 * whole string would make every wording improvement a test edit, and what
 * matters is that the remedy and, for the one that needs it, the warning are
 * both in the text a developer will actually see.
 */
describe('a fieldless gate refusal carries its remedy in the message', () => {
  it.each([
    [
      'MachineFfiError.AccountKeysNotFetched',
      'account_keys_not_fetched',
      'markRequestSent',
    ],
    [
      'MachineFfiError.IdentityNotKnown',
      'identity_not_known',
      'createCrossSigningIdentity',
    ],
    [
      'MachineFfiError.IdentityAlreadyExists',
      'identity_already_exists',
      'requestSelfVerification',
    ],
    [
      'MachineFfiError.PrivateKeysNotHeld',
      'private_keys_not_held',
      'getIdentityStatus',
    ],
  ])('%s names its remedy', (variant, kind, remedy) => {
    const err = toCryptoError(new Error(variant))
    expect(err.kind).toBe(kind)
    expect(err.message).not.toBe(`crypto error: ${kind}`)
    expect(err.message).toContain(remedy)
    expect(err.message.length).toBeGreaterThan(60)
  })

  it('warns, in the message itself, against wiring the mint to this handler', () => {
    const err = toCryptoError(new Error('MachineFfiError.IdentityNotKnown'))
    // The one refusal whose obvious-looking remedy is the destructive call.
    // The warning has to be in the string, because the string is what a
    // developer meets first and the documentation is what they read after
    // deciding.
    expect(err.message).toContain('do not call it from this handler')
    expect(err.message).toContain('destructive')
  })

  it('leaves a reason from the Rust side alone', () => {
    // The map is a fallback, not an override: a variant that carries its own
    // detail keeps it, or a store error would start reporting a remedy for a
    // condition it is not in.
    const err = toCryptoError({
      name: 'MachineFfiError.Store',
      detail: 'the crypto store could not be opened',
    })
    expect(err.message).toBe('the crypto store could not be opened')
  })
})
