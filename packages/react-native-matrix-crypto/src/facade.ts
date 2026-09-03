import type {
  CodeCapabilities,
  CryptoAlgorithm,
  CryptoScopeId,
  EventEnvelope,
  SenderTrustRequirement,
  SenderVerification,
  SasEmoji,
  SasMaterial,
  ScannableCode,
  SyncDelta,
  TrustState,
  VerificationStage,
} from './types'
import { asCryptoScopeId } from './types'
import { toCryptoError } from './errors'
import {
  acceptVerification as nativeAcceptVerification,
  bootstrapIdentity as nativeBootstrapIdentity,
  cancelVerification as nativeCancelVerification,
  confirmScan as nativeConfirmScan,
  confirmVerification as nativeConfirmVerification,
  createCryptoMachine as nativeCreateCryptoMachine,
  createRecovery as nativeCreateRecovery,
  decryptEvent as nativeDecryptEvent,
  deviceIdentityKeys as nativeDeviceIdentityKeys,
  deviceStatuses as nativeDeviceStatuses,
  encryptEvent as nativeEncryptEvent,
  createIdentity as nativeCreateIdentity,
  identityStatus as nativeIdentityStatus,
  markRequestFailed as nativeMarkRequestFailed,
  markRequestSent as nativeMarkRequestSent,
  offerCodes as nativeOfferCodes,
  openCryptoStore as nativeOpenCryptoStore,
  receiveSyncChanges as nativeReceiveSyncChanges,
  recoverIdentity as nativeRecoverIdentity,
  requestSelfVerification as nativeRequestSelfVerification,
  requestVerification as nativeRequestVerification,
  shareScopeKey as nativeShareScopeKey,
  startVerificationComparison as nativeStartVerificationComparison,
  submitScannedCode as nativeSubmitScannedCode,
  takeOutgoingRequests as nativeTakeOutgoingRequests,
  SenderTrustRequirement as NativeSenderTrustRequirement,
  SenderVerification as NativeSenderVerification,
  TrustState as NativeTrustState,
  verificationCode as nativeVerificationCode,
  verificationMaterial as nativeVerificationMaterial,
  verificationStage as nativeVerificationStage,
  VerificationStage as NativeVerificationStage,
} from './generated/matrix_crypto'
// Type-only, and imported rather than restated structurally: a field renamed
// in the Rust record must be a compile error here rather than a silently
// absent value. `sasMaterialOf` below is the one place that reads it.
import type { SasMaterial as NativeSasMaterial } from './generated/matrix_crypto'
// Shared with `runProbe` rather than restated here, and the sharing is the
// point: the conversion has one trap in it -- a `Uint8Array` that is a view
// onto a longer buffer must cross as the view and not as the whole backing
// store -- and a second copy is a second place to get it wrong.
// `submitScannedCode` below is this file's only caller, and a scanner's
// output is exactly the kind of value that arrives as a view.
import { toArrayBuffer } from './probe'
// Imported for the documentation in this file and used by nothing in it, on
// the terms `types.ts` states in full: `{@link}` resolves against what the
// file has in scope. Type-only, so it is erased and adds no runtime edge,
// and `signals.ts` imports nothing from here, so it adds no cycle.
/* eslint-disable @typescript-eslint/no-unused-vars -- The import below is
   the paragraph above put into effect: these names are in scope so that the
   `{@link}`s resolve, and `scripts/assert-doc-links.mjs` fails the build if
   one of them is missing. ESLint sees an unused binding and would have them
   deleted; the gate that owns this question wants them kept, so the rule is
   switched off for this statement and nothing else in the file. */
import type { onCryptoSignal } from './signals'
/* eslint-enable @typescript-eslint/no-unused-vars */

function notImplemented(name: string): Promise<never> {
  return Promise.reject(
    toCryptoError({
      name: 'NotImplemented',
      reason: `${name} is not implemented yet`,
    }),
  )
}

/**
 * `JSON.stringify` returns the *value* `undefined`, not a string, for
 * `undefined` itself and for a few other top-level inputs that type-check
 * fine against `unknown` (a function, a symbol). Passed straight through,
 * that `undefined` would reach a native `string` parameter as `undefined`,
 * surfacing later as an untyped `kind: 'unknown'` error rather than
 * `malformed_payload` at the boundary that actually rejected it. Rejected
 * here instead, before any native call -- shared by every function below
 * that stringifies an `unknown` payload.
 */
function stringifyOrMalformed(value: unknown): string {
  let json: string | undefined
  try {
    json = JSON.stringify(value)
  } catch {
    // `JSON.stringify` has two failure modes and this one was missed until
    // server-side recovery's own tests hit it: a value it cannot represent
    // returns `undefined`, and a value that *refers to itself* throws a
    // `TypeError` instead. Uncaught, that leaves the boundary as a raw
    // `TypeError` rather than a `CryptoError`, so `isCryptoError` is false
    // and a product's error handling has nothing to read. A cycle is an
    // ordinary shape for an object a product assembled itself, which is
    // what every caller of this helper is handed.
    throw toCryptoError({ name: 'MalformedPayload' })
  }
  if (json === undefined) {
    throw toCryptoError({ name: 'MalformedPayload' })
  }
  return json
}

// Spec section 5's surface, re-typed onto the branded scope and the open
// algorithm tag. Written when the types were real and the runtime was not;
// M2 landed the runtime behind all of it, and the sentence is kept because
// it records why the shapes were frozen before anything implemented them.

export interface CryptoMachineConfig {
  userId: string
  deviceId: string
  storePath: string
  /**
   * Required, not optional: an optional field lets a caller omit it by
   * accident and get unencrypted key material with no signal. `string |
   * null` forces the caller to write `null` deliberately, where a code
   * review can see it. Spec section 6: the store is encrypted with whatever
   * passphrase the product supplies here.
   */
  storePassphrase: string | null
}

export interface DeviceStatus {
  deviceId: string
  trust: TrustState
}

/**
 * What the product must send to its homeserver, or feed to another device
 * -- design doc section 3bis. `body` is JSON this library never
 * interprets, sent as-is; `kind` is an open tag mirroring upstream's own
 * request kinds, deliberately typed `string` rather than a union for the
 * same reason `CryptoAlgorithm` is open (the set grows upstream, and a
 * consumer must already handle a value it does not recognise).
 *
 * Today's values, the endpoint each addresses, and what
 * {@link markRequestSent}'s own `responseJson` must contain to report one
 * sent -- that endpoint's response body, unwrapped, exactly as the
 * homeserver returned it, and nothing this library adds or removes. No
 * count stands over the table: the tag is open, the table grew by a row in
 * this release, and a count is the part of a claim most likely to go stale
 * and least likely to be re-read.
 *
 * **A wrong `responseJson` is not reliably rejected**, so do not treat the
 * column below as validated input. A body that is *not* shaped like that
 * endpoint's response is always rejected with `malformed_payload`: being an
 * object with no keys, or carrying at least one of the fields in its row
 * below, is what that means.
 *
 * **Being shaped right is necessary, not sufficient.** A body carrying a real
 * field alongside a Matrix error's `errcode`, a gateway's `error` or a
 * challenge's `flows` is still rejected, and `{}` is rejected for
 * `keys_upload`, `keys_claim` and `room_message`, whose responses each have
 * one required field. What survives all of that, and why, is set out once in
 * {@link markRequestFailed}.
 *
 * | `kind` | Method & path | `responseJson` must contain |
 * |---|---|---|
 * | `'keys_upload'` | `POST /_matrix/client/v3/keys/upload` | `{ one_time_key_counts: { [algorithm: string]: number } }` |
 * | `'keys_query'` | `POST /_matrix/client/v3/keys/query` | `{ device_keys?, master_keys?, self_signing_keys?, user_signing_keys?, failures? }` (all optional; `{}` is valid). **Accepted is not the same as answered here.** A query about your own account only satisfies {@link bootstrapCrossSigning}'s ordering gate when the body names that account in one of the four user-keyed maps, which is what every measured homeserver sends even for an account it holds nothing for. See {@link markRequestFailed} |
 * | `'keys_claim'` | `POST /_matrix/client/v3/keys/claim` | `{ one_time_keys: {...}, failures? }` |
 * | `'to_device'` | `PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}` | `{}`, and only `{}`. The machine ignores the contents and the response type declares no fields, so there is no field that could widen the shape: an object with any key at all is rejected here |
 * | `'signature_upload'` | `POST /_matrix/client/v3/keys/signatures/upload` | `{ failures? }` (optional; `{}` is valid) |
 * | `'room_message'` | `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}` | `{ event_id: string }` |
 * | `'signing_keys_upload'` | `POST /_matrix/client/v3/keys/device_signing/upload` | `{}`, and only `{}`, for the reason `'to_device'` gives: the response type declares no fields, so no key could widen the shape. **This is the row where that costs you something.** The endpoint is user-interactive, its refusal is a `401` with a challenge, and `{}` is also what a 502 with no body arrives as. Branch on the status and send anything that is not a 2xx to {@link markRequestFailed}: reporting a challenge here would mark an identity published that never was |
 *
 * `'to_device'` and `'room_message'` carry their own path segments
 * (`eventType`/`txnId`, and for the latter `roomId` too) inside `body`
 * itself, alongside the wire content, since this library has no other way
 * to hand them to the product -- see the two disclosed exceptions the
 * core's own `describe_outgoing` documents for itself.
 *
 * See {@link shareScopeKey}'s own doc comment for the order a key has to
 * travel in, which is not optional: design doc section 3ter. See
 * {@link takeOutgoingRequests} for the separate rule that a *batch* must be
 * sent in the order it was handed to you, while marking stays unordered.
 */
export interface OutgoingRequest {
  /** Opaque; hand it back verbatim to {@link markRequestSent}. */
  id: string
  kind: string
  body: string
}

export async function createCryptoMachine(
  config: CryptoMachineConfig,
): Promise<void> {
  try {
    await nativeCreateCryptoMachine({
      userId: config.userId,
      deviceId: config.deviceId,
      storePath: config.storePath,
      // The generated binding's field is UniFFI's `Option<String>`, spelled
      // in TS as optional-with-undefined, not `| null`. This is the one
      // place that translates the facade's deliberate `null` into the shape
      // the native call expects.
      storePassphrase: config.storePassphrase ?? undefined,
    })
  } catch (e) {
    throw toCryptoError(e)
  }
}

export async function openCryptoStore(
  config: CryptoMachineConfig,
): Promise<void> {
  try {
    await nativeOpenCryptoStore({
      userId: config.userId,
      deviceId: config.deviceId,
      storePath: config.storePath,
      // See createCryptoMachine above: null -> undefined for the native call.
      storePassphrase: config.storePassphrase ?? undefined,
    })
  } catch (e) {
    throw toCryptoError(e)
  }
}

export function restoreCryptoMachine(_bundle: Uint8Array): Promise<void> {
  return notImplemented('restoreCryptoMachine')
}

/**
 * The five field names `receiveSyncChanges` actually reads -- matching
 * `matrix-sdk-crypto`'s own `EncryptionSyncChanges`, snake_case, not the
 * camelCase a product's own HTTP client may re-case a `/sync` response
 * into. Used only to decide whether an object payload names *any*
 * recognised field at all; see `receiveSyncChanges`'s own doc comment.
 */
const RECOGNISED_SYNC_FIELDS = [
  'to_device_events',
  'changed_devices',
  'one_time_keys_counts',
  'unused_fallback_keys',
  'next_batch_token',
]

/**
 * True for a non-empty object naming none of `RECOGNISED_SYNC_FIELDS`. The
 * core's own `SyncChangesPayload` defaults every field independently
 * (`#[serde(default)]`) and silently ignores unknown keys (no
 * `deny_unknown_fields` -- a homeserver adding a field this library does
 * not consume must keep working), so a differently-cased or entirely
 * unrecognised payload parses into an all-default value and reports
 * success while teaching the machine nothing. An empty object is *not*
 * flagged: `{}` is the shape an ordinary, uneventful sync sends, and doing
 * nothing with it is correct.
 */
function syncDeltaNamesNoRecognisedField(syncDelta: unknown): boolean {
  if (typeof syncDelta !== 'object' || syncDelta === null) return false
  const keys = Object.keys(syncDelta)
  return (
    keys.length > 0 && !keys.some(key => RECOGNISED_SYNC_FIELDS.includes(key))
  )
}

/**
 * Maps a `/sync` response to the slice {@link receiveSyncChanges} consumes
 * -- the five-row rename table on that function's own doc comment, as code,
 * so a product never hand-writes it. A field is copied when its source key
 * is present at all, `null` included; it is not copied when the source key
 * is absent, which is what leaves it to `SyncDelta`'s own per-field default
 * rather than forwarding `undefined`.
 *
 * A transcription of `encryption_slice` in
 * `rust/matrix-crypto-core/tests/level_two_interop.rs`, which is the same
 * mapping exercised against a real homeserver and a third-party client, and
 * the two must stay identical in behaviour -- that Rust function is this
 * one's source of truth, not the other way around.
 */
export function encryptionSlice(sync: Record<string, unknown>): SyncDelta {
  const slice: SyncDelta = {}
  const toDevice = sync.to_device as Record<string, unknown> | undefined
  if (toDevice?.events !== undefined)
    slice.to_device_events = toDevice.events as unknown[]
  if (sync.device_lists !== undefined) slice.changed_devices = sync.device_lists
  if (sync.device_one_time_keys_count !== undefined) {
    slice.one_time_keys_counts = sync.device_one_time_keys_count as Record<
      string,
      number
    >
  }
  if (sync.device_unused_fallback_key_types !== undefined) {
    slice.unused_fallback_keys =
      sync.device_unused_fallback_key_types as string[]
  }
  if (sync.next_batch !== undefined)
    slice.next_batch_token = sync.next_batch as string
  return slice
}

/**
 * Feeds the encryption-relevant slice of a `/sync` response into the
 * crypto machine -- design doc section 7. This is how the machine learns
 * which devices exist: a product that never calls this encrypts to
 * nobody.
 *
 * **Accepted shape.** `syncDelta` must be a plain object using exactly
 * `matrix-sdk-crypto`'s own snake_case field names below, every one
 * optional and defaulting independently when absent:
 *
 * ```ts
 * {
 *   to_device_events?: object[]                         // raw to-device events, as received
 *   changed_devices?: { changed: string[]; left: string[] }
 *   one_time_keys_counts?: Record<string, number>
 *   unused_fallback_keys?: string[]
 *   next_batch_token?: string
 * }
 * ```
 *
 * **This is not a `/sync` response, and a `/sync` response is rejected.**
 * It is the encryption-relevant slice of one, under `matrix-sdk-crypto`'s
 * field names, and the two sets of names have no member in common: a real
 * `/sync` body's top-level keys are `next_batch`, `rooms`, `presence`,
 * `account_data`, `to_device`, `device_lists`,
 * `device_one_time_keys_count` and `device_unused_fallback_key_types`,
 * none of which is one of the five above. So passing the response verbatim
 * throws `malformed_payload` before native is called -- deliberately and
 * loudly, because the alternative was a call that resolves and teaches the
 * machine nothing.
 *
 * An earlier version of this paragraph said the whole response could be
 * handed over verbatim. That was false, and the guard eleven lines above
 * proved it false; it was corrected by the level 2 interoperability test,
 * which is the first thing that ever fed this function a payload a real
 * homeserver produced.
 *
 * Five fields must be renamed, and nothing else forwarded:
 *
 * | in a `/sync` response | in `syncDelta` |
 * | --- | --- |
 * | `to_device.events` | `to_device_events` |
 * | `device_lists` | `changed_devices` |
 * | `device_one_time_keys_count` | `one_time_keys_counts` |
 * | `device_unused_fallback_key_types` | `unused_fallback_keys` |
 * | `next_batch` | `next_batch_token` |
 *
 * Omit a field the response does not carry rather than passing
 * `undefined`; each defaults independently. Everything else the response
 * holds -- `rooms`, `presence`, `account_data` -- is no part of this
 * payload.
 *
 * Use {@link encryptionSlice} to build `syncDelta` from a `/sync` response
 * rather than writing this mapping again -- it is this same rename table,
 * as code:
 *
 * ```ts
 * await receiveSyncChanges(encryptionSlice(await fetchSync()))
 * ```
 *
 * `{}` is the shape an ordinary, uneventful sync sends, and is accepted:
 * it reports nothing, correctly. **camelCase silently does nothing**, and
 * this is the one call where that matters most -- every field above
 * defaults independently and unknown keys are ignored, so
 * `{ toDeviceEvents: [...] }` parses into an entirely-default payload,
 * resolves successfully, and teaches the machine nothing, indistinguishable
 * from `{}` on the caller's side (the return type is frozen `void`). A
 * non-empty payload naming *none* of the five fields above -- the shape a
 * camelCase mistake, or any other wrong shape, produces -- is rejected
 * with `malformed_payload` before native is ever called. A payload naming
 * at least one recognised field alongside others this library does not
 * consume (a homeserver-added `/sync` field, for instance) is accepted,
 * and the extra field is ignored -- tolerance for exactly that case is why
 * this guard checks for *some* recognised field rather than rejecting any
 * unrecognised one.
 *
 * Returns `void`, not the native call's own to-device/session counts: that
 * return type is frozen from M1a. A product that needs those counts reads
 * them off the sync response it already holds.
 */
export async function receiveSyncChanges(syncDelta: SyncDelta): Promise<void> {
  if (syncDeltaNamesNoRecognisedField(syncDelta)) {
    throw toCryptoError({ name: 'MalformedPayload' })
  }
  const syncDeltaJson = stringifyOrMalformed(syncDelta)
  try {
    await nativeReceiveSyncChanges(syncDeltaJson)
  } catch (e) {
    throw toCryptoError(e)
  }
}

export async function encryptEvent(
  scope: CryptoScopeId,
  eventType: string,
  payload: unknown,
): Promise<EventEnvelope> {
  const payloadJson = stringifyOrMalformed(payload)
  try {
    const encrypted = await nativeEncryptEvent(scope, eventType, payloadJson)
    // Destructured, not returned/field-accessed directly: a field added to
    // the generated record later must be a deliberate choice to expose,
    // not something that leaks through this boundary unreviewed. See
    // Global Constraints and the M1 final review finding fixed below at
    // getDeviceIdentityKeys.
    const {
      scope: encryptedScope,
      algorithm,
      eventType: encryptedEventType,
      ciphertext,
      sender,
    } = encrypted
    return {
      scope: asCryptoScopeId(encryptedScope),
      algorithm,
      eventType: encryptedEventType,
      // The generated binding speaks ArrayBuffer; EventEnvelope speaks
      // Uint8Array, the idiomatic React Native shape -- same conversion
      // probe.ts's runProbe already makes for ProbeResult.payload.
      ciphertext: new Uint8Array(ciphertext),
      sender,
    }
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Decrypts a previously-received `m.room.encrypted` event for `scope` --
 * the same value passed to `encryptEvent`, since decryption needs it for
 * the same reason: the native call this delegates to requires an explicit
 * scope to look up the right group session, and reading one out of the
 * unauthenticated, not-yet-decrypted event JSON would mean trusting
 * attacker-influenced input for a security-relevant lookup.
 *
 * A deliberate break from the M1a-frozen `decryptEvent(rawEvent)`: that
 * shape cannot express a required scope without smuggling it into the
 * `unknown` (e.g. `{ scope, event }`), which compiles but hides a required
 * argument where the type system cannot see it and bypasses the branded
 * `CryptoScopeId` that exists precisely so a caller cannot pass a bare
 * string -- trading a compile error for a runtime one in a cryptographic
 * API. `getDeviceIdentityKeys` is the counter-case: its parameters stayed
 * because keeping them cost nothing. Here, keeping the frozen shape would
 * have cost the caller the type system.
 *
 * `rawEvent` is the `m.room.encrypted` event as received, verbatim --
 * JSON-stringified as-is before crossing to native.
 *
 * **This library decrypts events. It does not authenticate their
 * senders** -- spec section 7.1. The returned envelope's `sender` and
 * `algorithm` are read from the fields the homeserver delivered, not
 * independently verified, and are **unauthenticated transport metadata**.
 * That was scoped to "until cross-signing lands, which is M4" twice, and
 * cross-signing has now landed without changing it: these two fields are
 * never re-derived, whatever this library knows about the sender. What
 * cross-signing adds is the separate value below, not a promotion of these
 * two. Verifying the sending device does not change it either: see
 * {@link EventEnvelope.sender} and
 * {@link EventEnvelope.algorithm} for what that means and why. A product
 * that reads the sender of a successfully decrypted event as the
 * cryptographic sender has assumed something this milestone does not
 * provide, and that assumption is the shape impersonation takes.
 *
 * **What the returned envelope now adds is the size of that assumption.**
 * `senderVerification` carries what this library knew about the sender at
 * the moment it decrypted -- see {@link SenderVerification}. It does not
 * turn `sender` into an authenticated value. **It can read `'verified'`
 * through this surface from this release**, which it could not before: the
 * last missing step was the bridged call that lets a product create this
 * account's own cross-signing identity, and that call is
 * {@link createCrossSigningIdentity}. This named
 * {@link bootstrapCrossSigning}, which did the creating until the two were
 * split and now only publishes. Reaching the value is still a chain rather
 * than a setting, and the chain is the seven steps
 * {@link SenderVerification} sets out; what changed is that every one of
 * them can now be driven from TypeScript. What the value can already do
 * without any of that is tell three different things
 * apart: an ordinary unsigned device, a device its owner cross-signed whose
 * owner you have not verified (`'unverified_identity'`, which this release
 * does produce, from any peer whose client has cross-signing set up), and
 * an event whose claimed sender is not the owner of the session that
 * encrypted it. The last of those is an impersonation signal a product
 * should react to. It is a snapshot taken at decryption time, not a live
 * value; see the field.
 *
 * **`senderTrustRequirement` is the decision this call will not make for
 * you**, and it is new to this surface: what a sender's device must satisfy
 * before the plaintext is handed over. The default `'any'` is what every
 * caller before the parameter existed got. The two tightened tiers make
 * `'sender_not_trusted'` reachable for the first time -- its own kind
 * rather than a fold into `'unknown_device'`, because the two want opposite
 * things done about them: `'sender_not_trusted'` is a policy gap the user
 * fixes by verifying the device (or the product, by relaxing the
 * requirement), while `'unknown_device'` means the event's provenance is
 * broken and nothing fixes it. Read {@link SenderTrustRequirement} before
 * choosing: local trust is absent from every tier, so a product whose
 * users verify devices without cross-signing identities should stay on the
 * default and gate on the returned envelope's `senderVerification`
 * instead.
 */
export async function decryptEvent(
  scope: CryptoScopeId,
  rawEvent: unknown,
  senderTrustRequirement: SenderTrustRequirement = 'any',
): Promise<EventEnvelope> {
  // `CryptoScopeId` performs no runtime validation (see types.ts) --
  // enforced by the type system for a caller that goes through it, but a
  // caller that bypasses it (plain JS, or `as any`) can still reach this
  // with a non-string value. Rejected before native is ever called, the
  // same discipline the old `{ scope, event }` guard applied.
  //
  // `malformed_identifier`, not `malformed_payload`: what is wrong is the
  // scope argument, and `rawEvent` may be perfectly good. This matches what
  // the core reports for a scope that is a string but not a parseable
  // identifier, so both ways of getting the scope wrong name the scope.
  if (typeof scope !== 'string') {
    throw toCryptoError({ name: 'MalformedIdentifier' })
  }
  // The same discipline, for the same reason, on the requirement: a
  // caller that bypasses the closed union (plain JS, or `as any`) can
  // reach this with a value that is none of the three. The generated
  // enum converter has no default arm, so an unmatched value would
  // leave the wire buffer unwritten and cross the boundary as whatever
  // bytes happened to be there -- the one case that must be a refusal
  // rather than a garbage value, and `nativeSenderTrustRequirementOf`
  // deliberately cannot produce the refusal: its exhaustiveness is what
  // makes a future union member a compile error there, and a `default`
  // arm would have cost exactly that. So the runtime half lives here,
  // before native, like the scope guard above.
  //
  // `rejected`, the generic input refusal, rather than a malformed
  // kind: the value is a caller's own argument and nothing about it is
  // malformed wire content.
  if (
    senderTrustRequirement !== 'any' &&
    senderTrustRequirement !== 'identity_signed_or_legacy' &&
    senderTrustRequirement !== 'identity_signed'
  ) {
    throw toCryptoError({
      name: 'Rejected',
      reason:
        "senderTrustRequirement must be one of 'any', 'identity_signed_or_legacy' " +
        "or 'identity_signed'",
    })
  }
  const rawEventJson = stringifyOrMalformed(rawEvent)
  try {
    const decrypted = await nativeDecryptEvent(
      scope,
      rawEventJson,
      nativeSenderTrustRequirementOf(senderTrustRequirement),
    )
    // Destructured, not returned directly. See encryptEvent above.
    const {
      scope: decryptedScope,
      algorithm,
      eventType,
      ciphertext,
      sender,
      senderVerification,
    } = decrypted
    return {
      scope: asCryptoScopeId(decryptedScope),
      algorithm,
      eventType,
      // See encryptEvent above: ArrayBuffer -> Uint8Array.
      ciphertext: new Uint8Array(ciphertext),
      sender,
      // Derived from what native reported for this event, not inferred
      // from decryption having succeeded. Those are different questions,
      // and `mismatched_sender` is the case that proves it: the ciphertext
      // decrypts perfectly and the sender is still not who the event says.
      //
      // The absent case is handled here rather than inside
      // `senderVerificationOf`, which is not a style preference: a mapping
      // whose return type admits `undefined` is not exhaustive by compile
      // error, and that exhaustiveness is the only thing covering the one
      // arm no test may exercise. See the function's own doc comment.
      // Native only omits this on the encrypt path, which does not reach
      // here, so in practice this reads `Some` every time.
      senderVerification:
        senderVerification === undefined
          ? undefined
          : senderVerificationOf(senderVerification),
    }
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Ensures `scope` has a group session and shares it with `userIds`' known
 * devices -- the prerequisite `encryptEvent` documents for itself: a scope
 * must have a group session before encryption can succeed. Not a change to
 * the frozen surface; a new public name for what the core calls
 * `share_scope_key`, chosen to say what it does without naming an
 * algorithm (design doc section 3bis / spec section 6).
 *
 * **Delivering a key to a device with no prior session takes two calls to
 * this function, not one** -- design doc section 3ter, and the ordering is
 * not optional. A device this machine has never shared with has no Olm
 * session yet, and a session key can only reach a device over one; that
 * needs a `/keys/claim` round trip first. So the *first* call to
 * `shareScopeKey` for a new device queues a `'keys_claim'` request (among
 * {@link takeOutgoingRequests}' output) alongside a to-device request that
 * cannot yet carry the key -- it is an `m.room_key.withheld` notice, not
 * the key itself. Only once the product has sent that claim and reported
 * it with {@link markRequestSent} does calling `shareScopeKey` **again**,
 * for the same scope and users, produce the to-device request that
 * actually carries the session key. The full sequence, per device:
 *
 * 1. `shareScopeKey` (queues `'keys_claim'`, if no session yet)
 * 2. send the `'keys_claim'` request, `markRequestSent` it
 * 3. `shareScopeKey` again, same scope and users (now produces the
 *    key-carrying `'to_device'` request)
 * 4. send that request, `markRequestSent` it
 *
 * A product that calls this once, sends what {@link takeOutgoingRequests}
 * returns, and moves on silently under-delivers to every device it has not
 * already shared with -- the same silent-failure shape design doc section
 * 3bis is named for, one step further in. `receiveSyncChanges` (which
 * queues the `'keys_query'` step that must come before either of the above,
 * so this machine knows the device exists at all) and this function
 * together are what section 3ter's ordering describes.
 */
export async function shareScopeKey(
  scope: CryptoScopeId,
  userIds: string[],
): Promise<void> {
  try {
    await nativeShareScopeKey(scope, userIds)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Drains every outstanding request this library needs the product to send
 * to its homeserver, or feed to another device -- design doc section 3bis.
 * An addition to the frozen surface, not a change to it: `OlmMachine` has
 * an outbound side (device/one-time key uploads, key queries, key claims,
 * and the to-device requests that actually carry a shared session key),
 * and discarding what this returns is the mistake section 3bis is named
 * for -- a machine that encrypts to nobody and never learns that any of it
 * happened.
 *
 * **The returned order is significant, and you must preserve it. Send the
 * requests in the order this returns them** -- not "start them in that order
 * and let them race": each one has to reach your homeserver before the next
 * is sent, because the server relays them to the other device in the order
 * it receives them.
 *
 * That is a real constraint with exactly one source, and it is worth naming
 * so it is not optimised away. A verification flow's last two messages are a
 * confirmation and the acknowledgement that closes the flow, and the far
 * side **silently discards** an acknowledgement that arrives before the
 * confirmation it acknowledges. It then waits for one that has already been
 * sent. The failure is asymmetric -- your side completes and records the
 * other device as verified, the other side records nothing -- and neither
 * side is told. Both messages can land in the same batch, from two different
 * queues inside the library, so a product that pumps on a timer rather than
 * after every call is the one that meets this.
 *
 * **Resolving them with {@link markRequestSent} is a different matter and is
 * not ordered at all.** It is a lookup by id, so mark them in whatever order
 * the responses come back, and do not wait for request *n* to be marked
 * before sending request *n+1*.
 *
 * Requests from *different* batches were never orderable against each other
 * -- a batch is a snapshot -- and nothing here changes that. What this
 * function guarantees is that within one batch, the order it returns is the
 * order the requests were produced in, across both of the places inside the
 * library they come from.
 *
 * **What that guarantee is worth, stated so it is not read as more.** Two
 * requests this library produced in an order that matters come out in it,
 * which is the whole point and is what the verification pair needs. Two
 * requests with no ordering requirement between them may come out in either
 * order, run to run, and nothing here promises otherwise -- the last
 * paragraph of this comment is a measured example of exactly that. So:
 * preserve the order you are given, and do not read meaning into the
 * relative position of two requests that have none.
 *
 * Up to and including `0.1.0-rc.2` this comment said the opposite: that the
 * array was an unordered set and a product must not infer sequencing from
 * position. That was true of every request the library could then produce,
 * and it stopped being true when device verification arrived. The sentence
 * is recorded here rather than deleted because a consumer who read the old
 * one and built on it has to be able to find out that it changed.
 *
 * **{@link markRequestSent} is not the only thing that ends a request's
 * life. A later call to this function ends some of them too.** Four of the
 * kinds handed out here -- `keys_upload`, `keys_query`, `keys_claim` and
 * `signing_keys_upload` -- are evicted the moment a *subsequent* call hands
 * out a fresh request of the same kind, whether or not the older one was
 * ever marked sent. `markRequestSent` then rejects that older id with
 * `unknown_request`.
 *
 * That is designed, not a defect, and it is worth knowing why, because
 * `unknown_request` for an id a product is legitimately holding otherwise
 * reads as a library bug. The first three describe a standing need
 * ("these keys want uploading", "these users want querying") rather than
 * one message. `matrix-sdk-crypto` re-derives that need from current state
 * on every call, mints a new and uncorrelated id for it, and forgets the id
 * it handed out last. So once a fresh one exists, the older id names
 * nothing the machine is still waiting to hear about, and the fresh request
 * in that same batch carries what the older one was for.
 *
 * **`signing_keys_upload` is in that group for a different reason and on a
 * narrower trigger, and it is the one that will actually catch a product
 * out.** Nothing upstream forgets its id; this library re-derives it, and
 * only when {@link bootstrapCrossSigning} is called again. A second bootstrap
 * publishes the identical three keys, so keeping both entries would hand a
 * caller two ids for one publication and two rounds of user-interactive
 * authentication to finish it. **An ordinary second drain does not touch
 * it**, because no fresh one exists to evict it; a second bootstrap followed
 * by a drain does. That matters because this is the one id a product is
 * meant to hold across a slow loop with a person in the middle of it: it
 * survives any number of refused attempts, since only success consumes an
 * entry, and it does not survive being superseded. Do not call
 * `bootstrapCrossSigning` again while an authentication loop is in flight.
 *
 * **What a caller must do about it: resolve a batch before drawing the
 * next.** Drain, send in order, `markRequestSent` each response, and only
 * then call this again.
 *
 * Within one batch, marking may overlap sending -- nothing in one batch
 * evicts another member of it, so request *n* need not be marked before
 * request *n+1* is sent. **The sends themselves stay ordered**, which is
 * the half of this that changed after `0.1.0-rc.2`; see the ordering rule
 * at the top of this comment. This paragraph used to say sending and
 * marking within a single batch were both safe to do concurrently, which
 * is the sentence that section retracts.
 *
 * What is not safe is a second drain overlapping unresolved requests from
 * an earlier one: two pumps racing, or a drain on a timer alongside a drain
 * after a write, will produce `unknown_request` for ids the product still
 * holds.
 *
 * **On `unknown_request` for an id from an earlier batch, do not retry it.**
 * Discard the response that id was going to carry and pump again. Nothing
 * is lost: the need was re-derived rather than dropped, and the request that
 * supersedes it is either already in hand or waiting in the next drain.
 *
 * **`to_device`, `signature_upload` and `room_message` ids are never
 * evicted this way**, and two `keys_query` ids escape it as well. The
 * first three each name one independently deliverable message, so each
 * stays outstanding until `markRequestSent` resolves it. The other two are
 * standing needs that have to outlive an ordinary drain: the out-of-band
 * query about this account, which only another query of its own kind
 * evicts, and the query a verification finishing by a scanned code queues,
 * which nothing evicts at all, because its answer is the entire product of
 * that verification. Both arrive as `keys_query` and nothing on this
 * surface tells them apart from an ordinary one, so **a product can hold
 * two live `keys_query` ids at once**: a newer one is not evidence that an
 * older one is dead. For every kind,
 * marking is not optional bookkeeping; it is what advances the underlying
 * state machine. A product that calls this but never calls
 * `markRequestSent` keeps being handed the same requests, including -- for
 * a to-device request the machine could not yet deliver -- a stale
 * `m.room_key.withheld` notice sitting alongside the actual session key, in
 * no reliable order relative to it (measured across ten runs of the same
 * sequence: six with the notice first, four with the key first). That is
 * not a counter-example to the ordering rule above and is the reason it is
 * scoped as it is: neither of those two requests is order-significant
 * against the other, they are held keyed by transaction id rather than by
 * production order, and a transaction id is random. The
 * measured harm from that specific case is bounded -- that withheld notice
 * carries no scope and no session id of its own, so it names nothing for a
 * recipient to act on, and a `matrix-sdk-crypto`-based recipient's own
 * `add_withheld_info` deliberately ignores exactly this notice kind -- but
 * relying on that is not a substitute for calling `markRequestSent`: it is
 * the only thing that stops the duplication at the source.
 */
export async function takeOutgoingRequests(): Promise<OutgoingRequest[]> {
  try {
    const requests = await nativeTakeOutgoingRequests()
    // Destructured per element, not returned directly. See encryptEvent above.
    return requests.map(({ id, kind, body }) => ({ id, kind, body }))
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Reports that the request named by `id` (from {@link takeOutgoingRequests})
 * was sent, handing back the server's raw JSON response so the machine can
 * update its own state. An addition to the frozen surface, not a change to
 * it -- see {@link takeOutgoingRequests}.
 *
 * **`responseJson` must be that request's own endpoint's response body,
 * unwrapped** -- see {@link OutgoingRequest}'s own doc comment for the
 * table mapping each `kind` to what it must contain.
 *
 * **Call this only for a 2xx. Send everything else to
 * {@link markRequestFailed}.** `markRequestSent(id, await res.text())`
 * without branching on the status is the obvious wrapper and it is wrong.
 * No HTTP status crosses this boundary on this call, so a body shaped like
 * an answer *is* an answer here. Reported that way, an errored `keys_query`
 * tells the machine the server answered and this account has no signing
 * identity, which is exactly the fact that authorises minting a new one over
 * whatever the account already had.
 *
 * **What is rejected for you.** A body is rejected with `malformed_payload`
 * unless it is shaped like this endpoint's response, which means an object
 * with no keys, or an object carrying at least one field that endpoint
 * really returns (its row in {@link OutgoingRequest}'s table). So a Matrix
 * error (`errcode`), an authentication challenge (`flows`), a gateway's
 * `{"error":"Bad Gateway"}`, an array or a proxy's HTML page, and a plain
 * `{"message":"Internal server error"}` are all refused. Beyond that,
 * `keys_upload`, `keys_claim` and `room_message` also reject a body missing
 * their one required field. When a body is rejected the request named by
 * `id` stays outstanding, so the same `id` can be retried with corrected
 * input, and the ordinary "retry with `auth` merged in" flow after a 401
 * needs nothing special.
 *
 * **What that still leaves through is set out once in
 * {@link markRequestFailed}**, and it is not restated here so the two cannot
 * drift. Branch on `res.ok` and call that instead of this one.
 *
 * **This call is what stops `id` being handed out again**, not a courtesy
 * notification after the fact -- see {@link takeOutgoingRequests}'s own doc
 * comment for what a product observes if it is skipped.
 *
 * **`unknown_request` does not always mean the id was never real.** A
 * `keys_upload`, `keys_query`, `keys_claim` or `signing_keys_upload` id is
 * evicted when a later `takeOutgoingRequests` hands out a fresh request of
 * the same kind, so an id held across a second drain rejects here even
 * though this library did hand it out. The first three are re-derived on
 * every drain; a fresh `signing_keys_upload` exists only after another
 * {@link bootstrapCrossSigning}, so that one survives an ordinary second
 * drain and not a second bootstrap. See {@link takeOutgoingRequests} for why
 * that is deliberate and what to do instead of retrying.
 */
export async function markRequestSent(
  id: string,
  responseJson: string,
): Promise<void> {
  try {
    await nativeMarkRequestSent(id, responseJson)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Reports that the request named by `id` (from {@link takeOutgoingRequests})
 * was **refused**: you sent it, and what came back was not a success. Pass
 * the HTTP status you received, or `0` if nothing came back at all, such as
 * a dropped connection, a DNS failure, or a timeout.
 *
 * An addition to the frozen surface, not a change to it. This is the
 * counterpart to {@link markRequestSent}, and the reason that call is no
 * longer the only thing you can say. A 502 from a proxy, or a 503 with an
 * empty body, used to have nowhere to go but the success path.
 *
 * ```ts
 * const res = await fetch(url, { method, body: request.body })
 * if (res.ok) await markRequestSent(request.id, await res.text())
 * else await markRequestFailed(request.id, res.status)
 * ```
 *
 * **This changes nothing about what the library knows, deliberately.** A
 * refused request taught it nothing. The request stays outstanding, so the
 * retry is an ordinary second send, and nothing is recorded as answered.
 *
 * **Forgetting to call this is safe.** A request you never report stays
 * pending exactly as if you had reported it refused. Reporting a refusal and
 * reporting nothing are the same to this library, and both are the safe
 * direction: what advances its state is {@link markRequestSent}, and only
 * that. The cross-signing bootstrap this protects has since shipped as
 * {@link bootstrapCrossSigning}, and does exactly what this said it would:
 * it refuses with `'account_keys_not_fetched'` rather than mint an identity
 * on a question it was never told the answer to. This sentence said the
 * bootstrap was still to come for the whole of the release that shipped it. The failure mode of silence
 * is work that will not proceed, which you will notice, and never an
 * identity destroyed.
 *
 * **What is not safe is calling {@link markRequestSent} for a response the
 * server refused, and this library cannot detect that for you in every
 * case.** It sees a body and no status.
 *
 * A body is accepted there when it is shaped like that endpoint's response:
 * an object with no keys, or an object carrying at least one field that
 * endpoint really returns. That refuses a Matrix error, an authentication
 * challenge, a gateway's `{"error":"Bad Gateway"}`, an array, a proxy's HTML
 * page, and a bare `{"message":"Internal server error"}`. What it accepts is
 * every genuine success and, unavoidably, any failure whose body falls
 * inside the same shape. **The member that matters is the object with no
 * keys:** `{}` is the entire success response of the signing-keys upload, so
 * a 503 that carried nothing and a 200 with nothing to say are the same
 * bytes. An empty body is turned into `{}` before parsing.
 *
 * That is the gap this call exists to let you close, and it can only be
 * closed from your side, by branching on the status before you choose which
 * of the two calls to make.
 *
 * **On the key query, the same body no longer reaches as far as it did.**
 * This paragraph used to say `{}` was what `/keys/query` answers for an
 * account with no signing identity; measured against Synapse, Dendrite and
 * continuwuity, all three name the queried account even when they hold
 * nothing for it. So a key query answer that does not name your account is
 * accepted here and does not satisfy {@link bootstrapCrossSigning}'s ordering
 * gate, and a 503's empty body reported through {@link markRequestSent}
 * leaves that gate shut rather than authorising a mint. Reporting the status
 * is still the right thing to do, and still the only thing that closes the
 * same collision on the signing-keys upload.
 *
 * The one confusion of the pair this library *can* catch is a 2xx passed
 * here, which is rejected with `not_a_failure_status`: a success has a body
 * worth reporting, and it belongs in {@link markRequestSent}. Statuses
 * outside `0` and `300`-`599` are rejected the same way.
 *
 * `unknown_request` means the same thing it does on {@link markRequestSent},
 * including the eviction case described there.
 */
export async function markRequestFailed(
  id: string,
  status: number,
): Promise<void> {
  try {
    await nativeMarkRequestFailed(id, status)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * What this library will say about this account's signing identity, as
 * returned by {@link getIdentityStatus}.
 *
 * Five independent facts, none of which implies another. **The pair that
 * looks redundant is the pair that matters:** `identityKnown === false`
 * means something completely different depending on `accountKeysFetched`.
 * With that false it means "nobody has asked". With it true it means "the
 * server says there is none", and only the second is a basis for creating
 * one. That is why both are reported instead of one collapsed answer.
 *
 * `accountKeysAnswerUnsettled` splits the first of those in two, and is the
 * field to read when a refusal will not go away.
 */
export interface IdentityStatus {
  /**
   * Whether a key query naming this account has been sent **and answered**
   * in this process.
   *
   * Not persisted. A process that has just reopened a store has asked
   * nothing yet, whatever the process before it did, and the account may
   * have gained an identity in between. `false` is not a claim that the
   * account has no identity; it is a refusal to guess.
   */
  accountKeysFetched: boolean
  /**
   * Whether this library holds a public signing identity for the account.
   *
   * Read only alongside `accountKeysFetched`. A successful
   * {@link createCrossSigningIdentity} sets this true as a side effect, so
   * it is also how a caller sees that its own creation took effect. This
   * named {@link bootstrapCrossSigning}, which cannot set it: that call
   * refuses with `'identity_not_known'` unless it is already true.
   */
  identityKnown: boolean
  /**
   * Whether this device holds the account's complete private signing keys,
   * and can therefore sign with the identity rather than only recognise
   * it.
   *
   * **True does not mean the server agrees.** Until `accountKeysFetched` is
   * also true, these keys may belong to an identity the account has since
   * replaced: a restored backup holds a complete set that is simply out of
   * date. So this field is only trustworthy alongside that one.
   */
  privateKeysHeld: boolean
  /**
   * Whether a key query about this account was answered, and the answer left
   * this library still unable to say whether the account has an identity.
   *
   * **Read it when `accountKeysFetched` is false, and only then.** Those two
   * together say which of two situations a refusal is in, and the remedies
   * are different:
   *
   * - Both false: nobody has asked yet. The remedy is the documented one.
   *   Drain {@link takeOutgoingRequests}, send what it hands back, report
   *   each with {@link markRequestSent}, call again.
   * - This true: the query was sent, the server answered, the answer was
   *   accepted, and the library still does not know. **Calling again will do
   *   exactly the same thing.** Either the answer did not cover this
   *   account, which the Matrix specification prescribes for a user a
   *   reachable server does not know, or it carried cross-signing keys for
   *   the account that could not be assembled into an identity.
   *
   * The reachable cause is the account id. A homeserver compares the server
   * name half of a user id against its own case-sensitively, so an address
   * a user typed by hand, with `@you:Example.org` where the server calls
   * itself `example.org`, is treated as a remote account and federates to
   * itself. Compare the `userId` passed to {@link createCryptoMachine}
   * against the
   * canonical `user_id` your `/login` returned, and stop looping.
   *
   * Nothing is destroyed while this is true and nothing will be: refusing to
   * create a second identity is the safe direction, and this field exists so
   * that the refusal is not also silent.
   */
  accountKeysAnswerUnsettled: boolean
  /**
   * Whether this device holds an identity it created and has **not yet seen
   * the homeserver accept**.
   *
   * True from {@link createCrossSigningIdentity} until a homeserver's own
   * `'keys_query'` answer carries that identity back, and it survives a
   * relaunch, because the identity is on disk and the publication was in
   * memory. A process that is killed, offline, or whose upload times out in
   * that window reopens its store in exactly this state.
   *
   * **The remedy is {@link createCrossSigningIdentity} again, deliberately.**
   * It hands back the same publication that was lost, and
   * {@link bootstrapCrossSigning} refuses with `'identity_not_known'` while
   * this is true.
   *
   * That was the other way round for one release and it was wrong. Measured
   * on two homeservers: a device in this state, answered honestly that the
   * account has no identity, published over an identity a second device of
   * the account had legitimately created in the gap before that answer was
   * reported. The launch-time call did it. From inside a device, an identity
   * it holds and has never seen a homeserver accept is indistinguishable
   * from one the account has since replaced, and no answer settles that,
   * because an answer describes the instant the server computed it and
   * nothing later. What you know and this library does not is whether this
   * account is still in sign-up, which is why finishing is a decision.
   *
   * Read it because this is the one state where `identityKnown` is `true`
   * and the account still has no identity. A product that shows "encryption
   * is set up" on `identityKnown` alone is wrong here.
   */
  identityPublicationPending: boolean
}

/**
 * What this library will say about this account's signing identity right
 * now. Reads only: it asks the server nothing and creates nothing.
 *
 * See {@link IdentityStatus} for why two of the five fields have to be read
 * together, and why a third exists. Four calls change them:
 * {@link createCrossSigningIdentity} creates the account's first identity,
 * {@link bootstrapCrossSigning} publishes the one this device already holds,
 * {@link requestSelfVerification} joins one the account already has, and
 * {@link recoverIdentity} restores the private half from server-side
 * storage. This said `bootstrapCrossSigning` created it, which was true
 * while creating and publishing were one call.
 *
 * **This is the durable answer the signal channel sends you to.** Nothing
 * returns to a caller when a join's seeds arrive; what happens instead is a
 * `'trust_changed'` for your own user id on `onCryptoSignal`, and reading
 * `privateKeysHeld` here is what that signal means. It is the same variant a
 * completed comparison produces, so read this rather than counting signals.
 */
export async function getIdentityStatus(): Promise<IdentityStatus> {
  try {
    const status = await nativeIdentityStatus()
    // Destructured, not returned directly. See encryptEvent above.
    const {
      accountKeysFetched,
      identityKnown,
      privateKeysHeld,
      accountKeysAnswerUnsettled,
      identityPublicationPending,
    } = status
    return {
      accountKeysFetched,
      identityKnown,
      privateKeysHeld,
      accountKeysAnswerUnsettled,
      identityPublicationPending,
    }
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Publishes the cross-signing identity **this device already holds**.
 *
 * This is the call the rest of M4 hangs off. Until an account has a signing
 * identity of its own, a decrypted event can never report
 * `senderVerification.state === 'verified'`, however many people compare
 * however many strings: that value needs **our** user-signing key over the
 * sender's master key, read back out of our own store. See
 * {@link SenderVerification}.
 *
 * **Safe to call on every launch, and that is now true without
 * qualification: this call cannot create an identity.** It used to create
 * the account's first one when it judged there was none, and that judgement
 * rests on a single `/keys/query` answer, which is only ever true of the
 * instant the server sent it. Measured against a live homeserver, with no
 * misbehaviour anywhere: a device asked about its own fresh account, the
 * server honestly answered "no identity" because at that instant there was
 * none, another device of the account published one in the window, and this
 * call then created a second identity over it. The product had done nothing
 * wrong. It had called the function this library tells it to call on every
 * launch.
 *
 * Creating is now {@link createCrossSigningIdentity}, and a product reaches
 * it only by deciding to. **If you are upgrading, this call starts refusing
 * with `'identity_not_known'` on an account that has no identity yet**, and
 * that refusal is where the decision now lives.
 *
 * The first call in a process is still normally refused once, with the key
 * query that lifts the refusal already queued by the refusal itself.
 *
 * # Nothing here reaches the network
 *
 * This library performs no request, here or anywhere. On success, drain
 * {@link takeOutgoingRequests} and send what it hands back **in the order it
 * hands it back**, reporting each with {@link markRequestSent}. The order
 * matters here more than anywhere else on this surface, because a signature
 * may reference a key that is not published yet: device keys, then
 * `'signing_keys_upload'`, then `'signature_upload'`.
 *
 * **Four of the batch's entries come from this call, and the batch is
 * longer than four. Do not assert a length.** Observed after a served
 * bootstrap on a fresh machine: `['keys_upload', 'signing_keys_upload',
 * 'signature_upload', 'keys_upload', 'keys_query']`. The second
 * `'keys_upload'` carries the same device keys under a different id and is
 * harmless to send twice; the endpoint is idempotent.
 *
 * # The part your product has to write, and why this call cannot
 *
 * **The `'signing_keys_upload'` request needs user-interactive
 * authentication.** Expect the first attempt to be refused with a `401`
 * carrying a challenge, merge an `auth` object into `body`, and send the
 * same body again. `body` is opaque JSON this library never interprets, so
 * adding a field to it is an ordinary edit.
 *
 * **There is deliberately no `auth` parameter on this function, and there
 * will not be one.** The challenge is only known *after* the first request
 * is refused, so an argument here would have to be guessed before the
 * server has said what it wants. This library has never touched an account
 * credential and this is where that property would have gone if it were
 * going to. The cost is real and is named rather than hidden: a product
 * cannot complete this step without implementing an authentication flow
 * this library gives it no help with.
 *
 * **The id survives any number of refused attempts.** {@link markRequestSent}
 * removes an entry only on success, so loop on the `401` for as long as your
 * user needs. What retires the id is calling this function again and
 * draining again, because a second bootstrap re-derives the same three keys
 * and supersedes the pending publication: the held id then reports
 * `'unknown_request'`, and the recovery is to drain again and use the newer
 * id for the identical body. If an authentication loop is in flight, do not
 * call this again until it finishes. See {@link takeOutgoingRequests} for
 * the general rule this is one case of.
 *
 * # Report only what a success returned
 *
 * **Never report a non-2xx body through {@link markRequestSent}, and that
 * includes the `401` challenge.** Send it to {@link markRequestFailed}, or
 * report nothing at all, and report the eventual success through
 * `markRequestSent`. This matters more here than anywhere else on the
 * surface, in two different ways. A failed `'keys_query'` reported as a
 * success is read as "the server answered and this account has no identity",
 * which is the one fact that authorises creating one over whatever the
 * account already had. And the signing-keys upload's success response is
 * `{}`, so a reported challenge would mark an identity published that never
 * was.
 *
 * # Refusals
 *
 * `'account_keys_not_fetched'` means this process has not yet asked the
 * server about this account, so it cannot know whether publishing would
 * destroy an existing identity. **This call queues that key query before
 * returning the refusal**, so the remedy is the ordinary loop: drain, send,
 * report sent, call this again. Holding the private keys is not an
 * exemption, because a store restored from a backup holds a complete
 * identity the server may already have replaced.
 *
 * `'identity_already_exists'` means the answer named an identity this device
 * does not hold the private keys for. There is no remedy through this call
 * and there should not be: this device joins that identity, it does not
 * replace it. **{@link requestSelfVerification} is the call that joins it**,
 * and it is where a second login goes from here.
 *
 * `'identity_not_known'` is the refusal this call gained, and it is the one
 * an upgrading product meets first: the server was asked and named no
 * identity for this account, so there is nothing here to publish. Nothing is
 * wrong; this is the call declining to make a decision it used to make
 * silently.
 *
 * **Do not answer it by calling {@link createCrossSigningIdentity} from the
 * handler that caught it.** That is the shape this split exists to prevent:
 * it puts the destructive call back on the launch path, where an answer that
 * was true when the server sent it can be stale by the time it is acted on.
 * The decision belongs where your product knows something this library
 * cannot, and {@link createCrossSigningIdentity} lists what that can be.
 *
 * # After a join, this call starts being served again
 *
 * A device that has joined holds the account's private keys, so this
 * republishes the identity it now holds rather than being refused, and the
 * `'signing_keys_upload'` in the batch needs the same user-interactive
 * authentication as the first time. "Call it on every launch" is still the
 * right advice, but a joined device following it meets an authentication
 * challenge, and a product that only expected one during setup should expect
 * this one too.
 */
export async function bootstrapCrossSigning(): Promise<void> {
  try {
    await nativeBootstrapIdentity()
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Creates this account's **first** cross-signing identity.
 *
 * **This is the one destructive call on this surface, and it is destructive
 * exactly when it is wrong.** An identity created over one the account
 * already has replaces it, and replacing it resets the trust of every device
 * and every person who ever verified the old one. There is no undo, and
 * nothing afterwards can detect it.
 *
 * It is a separate call because that damage used to be reachable from
 * {@link bootstrapCrossSigning}, which this library tells you to call on
 * every launch. See that function for the measured race that made an honest
 * homeserver enough to do it.
 *
 * # What you must hold before calling this
 *
 * The library's own precondition is that this process has asked the server
 * and the answer said the account has no identity. **That is necessary and
 * it is not sufficient**, and it is the whole reason this call is separate.
 *
 * A `/keys/query` answer is only ever true of the instant the server sent
 * it. Between that instant and this call, another device of the same account
 * can publish an identity, and no answer already in hand can say so. So you
 * have to supply the fact the library cannot: **that this account is meant
 * to be getting its first identity now.** Your product knows things this
 * library does not, and any of them is a better basis than the answer alone:
 * the user has just created the account; this is the sign-up flow rather
 * than a relaunch; `GET /_matrix/client/v3/devices` lists no other session;
 * a person was asked and said yes.
 *
 * **Calling this on every launch, or as the automatic handler for
 * `'identity_not_known'`, puts the decision back where it was and the race
 * back with it.** If you do only one thing differently from
 * `bootstrapCrossSigning`, make it that.
 *
 * # The window is not closed, and the confirming query does not close it
 *
 * The batch this queues carries a `'keys_query'` for your own account after
 * the publication, so your ordinary send-and-report loop asks the server
 * once more straight afterwards.
 *
 * **Read what that is worth precisely, because it was overstated once and
 * the overstatement was measured.** It covers the branch where the
 * publication did *not* land: the answer then carries the identity the
 * account really has, the keys that disagree with it are dropped, and
 * {@link getIdentityStatus} reports the truth instead of a device that holds
 * an identity the account does not have and asks the server nothing further.
 *
 * **It does not cover the branch where the publication did land, and that is
 * the branch that does the damage.** If you sent the publication, answered
 * the authentication challenge and reported the `200`, the overwrite is
 * complete: the confirming answer then comes back carrying *your* identity,
 * it matches your store, and this library reports a completely healthy
 * device. Nothing in the status, in any error, or in any later answer says
 * the identity that was there before was replaced. There is no path back and
 * this library will not pretend to offer one.
 *
 * So the confirming query is worth having and is not a safety net. The thing
 * that keeps you out of this branch is the decision above.
 *
 * # Everything else is {@link bootstrapCrossSigning}'s
 *
 * The order the batch must be sent in, the user-interactive authentication
 * loop on `'signing_keys_upload'`, the rule about reporting only what a 2xx
 * returned, and the refusals `'account_keys_not_fetched'` and
 * `'identity_already_exists'` all apply here unchanged and are documented
 * there rather than twice. `'identity_already_exists'` is returned here
 * whether or not this device holds the private keys, because neither case
 * wants this call: holding them, it is `bootstrapCrossSigning`; not holding
 * them, it is {@link requestSelfVerification}.
 */
export async function createCrossSigningIdentity(): Promise<void> {
  try {
    await nativeCreateIdentity()
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Every device this library has been told about for `userId`, and the trust
 * it currently reports for each, sorted by device id.
 *
 * **This is the only place a completed verification becomes visible**, by
 * either method. A device that has been through
 * {@link requestVerification} to {@link confirmVerification}, with both
 * sides agreeing, reads `'verified'` here where it read `'unverified'`
 * before; so does one that went through {@link getVerificationCode} and
 * {@link confirmScan}, or {@link submitScannedCode}, with nobody comparing
 * a string at all. This paragraph named only the first pair, which is the
 * "verification is a short string" claim on the call the README itself
 * calls the only place a verification is visible.
 *
 * **It is also where a scanned verification becomes visible**, and it is
 * the only place the change itself is: a flow finished by a scan emits no
 * `trust_changed` down {@link onCryptoSignal}, only a
 * `verification_completed` that names the flow and carries no trust, so
 * this call is what a product reads when it gets one. See that function's
 * own doc for why the two are not one signal.
 *
 * Nothing else in this library changes as a result of a verification -- in
 * particular a decrypted event's sender does not become authenticated,
 * because that path consults cross-signing and a verification of either
 * kind sets local trust. See {@link TrustState}.
 *
 * # `'verified'` no longer means a person compared a string with this device
 *
 * **Read it as "trusted", and read nothing more into it.** This call maps
 * from one boolean underneath, which is "locally trusted OR signed by an
 * identity we have verified". The second half of that had no way to be true
 * until this library could hold a signing identity of its own. It can, from
 * {@link bootstrapCrossSigning}, and the consequence is immediate and
 * deliberate: **verifying one device of a user moves every device of that
 * user to `'verified'` at once, including devices that appear afterwards,
 * with nobody comparing anything on any of them.**
 *
 * That is correct rather than a defect. It is the entire point of
 * cross-signing: you verify a person once instead of once per device they
 * own. But it is a behaviour change a caller cannot see coming, so it is
 * said here rather than left to be discovered. **Anything that read this
 * value as "a human compared a string with this exact device" was right
 * before this release and is wrong from it.** If that is the question your
 * product is really asking, this call has never been the one to ask, and it
 * is now further from it than it was: what an individual event can be said
 * to prove is {@link EventEnvelope.senderVerification}, which is a different
 * question with a different and more expensive answer.
 *
 * # `'recognized'` stays folded into `'verified'`, deliberately
 *
 * {@link TrustState} declares a third value for exactly the state the
 * paragraph above creates -- a device believed because its owner's identity
 * signed it, with no person having compared anything -- and this call does
 * not produce it. That is a decision taken in this release rather than an
 * absence left over from an earlier one, and the reasoning is at
 * {@link TrustState} so a product reading the union meets it there too.
 *
 * **An empty array does not mean the user has no devices.** It means this
 * library has been told about none of them. Devices arrive through the
 * outbound pump: {@link receiveSyncChanges} flags a user as changed, that
 * produces a `'keys_query'` request among {@link takeOutgoingRequests}'
 * output, and only {@link markRequestSent} on that request puts anything in
 * the store. A caller that has never done that gets `[]` for a user with a
 * dozen devices, and gets it successfully. There is no way for this library
 * to tell the two apart, because it sends nothing itself.
 *
 * **Your own device always reads `'verified'`, and always has.** This
 * library marks it locally trusted the moment it creates the machine,
 * because this process holds its private keys and there is nothing left to
 * prove. That is correct, and it is a trap for anything reading this list:
 * "some device here reads verified" is true of an installation that has
 * never run a verification in its life. What carries a claim is a device of
 * *another* user changing from `'unverified'` to `'verified'`.
 *
 * # After verifying **another person** by code, pump once more
 *
 * A code verification with somebody else produces one thing: a signature
 * your account makes over their identity. Whether they read `'verified'`
 * here depends on that signature being in your store, and making it does
 * not put it there. Only the homeserver's answer to a `'keys_query'` about
 * them does.
 *
 * **This library queues that query for you**, on the sync that completes the
 * flow, so there is no extra call to find. But queued is not answered: the
 * request comes out of {@link takeOutgoingRequests} like any other, and this
 * value does not move until you have sent it and reported it with
 * {@link markRequestSent}. So when `onCryptoSignal` announces
 * `'verification_completed'` for a flow with another person, **drain the
 * pump once more before reading this**, and expect `'unverified'` if you
 * read it in between. Verifying one of your **own** devices needs none of
 * that: it reads `'verified'` the moment the flow finishes.
 */
export async function getDeviceStatuses(
  userId: string,
): Promise<DeviceStatus[]> {
  try {
    const statuses = await nativeDeviceStatuses(userId)
    // Destructured per element, not returned directly. See encryptEvent above.
    return statuses.map(({ deviceId, trust }) => ({
      deviceId,
      trust: trustStateOf(trust),
    }))
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Asks `deviceId`, belonging to `userId`, to verify itself against this
 * device, and returns the opaque identifier every other call below
 * addresses that flow by.
 *
 * The identifier is opaque: hand it back verbatim and parse nothing out of
 * it.
 *
 * **The device must already be known**, which means a `'keys_query'` for
 * that user must have been pumped and marked sent -- see
 * {@link getDeviceStatuses}. A device this library has never been told
 * about rejects with kind `'unknown_device'`, which is fixed by querying
 * and calling again, and is deliberately a different kind from
 * `'malformed_identifier'`, which no retry fixes.
 *
 * **Nothing reaches the other device until you pump.** This queues an
 * invitation among {@link takeOutgoingRequests}' output; the far side sees
 * nothing until you have sent it and reported it with
 * {@link markRequestSent}. That is true of every call in this group.
 *
 * The sequence by short string, for the side that asks:
 *
 * 1. `requestVerification` -> pump
 * 2. wait for {@link getVerificationStage} to read `'ready'` (the other
 *    side has called {@link acceptVerification} and you have pumped their
 *    answer in through {@link receiveSyncChanges})
 * 3. {@link startVerificationComparison} -> pump
 * 4. wait for the stage to read `'keys-exchanged'`, pumping throughout
 * 5. {@link getVerificationMaterial}, and show it to a person
 * 6. {@link confirmVerification} with what you showed, or
 *    {@link cancelVerification} if the person says it does not match
 * 7. pump again -- the flow reaches `'done'`, and only then does
 *    {@link getDeviceStatuses} report the device verified
 *
 * **That was the whole of this list until a scannable code arrived, and it
 * is now one of two ways to finish.** Steps 1 and 2 are the same for both;
 * from `'ready'` a flow that negotiated codes takes
 * {@link getVerificationCode} and {@link confirmScan} on the showing side,
 * or {@link submitScannedCode} on the reading side, and reaches step 7 the
 * same way. Nothing is negotiated unless the product asked, so a build that
 * never calls {@link offerScannableCodes} gets exactly the seven steps
 * above and nothing else. See {@link offerScannableCodes}.
 *
 * The side that was asked does the same from step 2, calling
 * {@link acceptVerification} first. Its `verificationId` is handed to it by
 * `onCryptoSignal` -- exported from this package's root alongside these,
 * and the thing that announces inbound invitations. See
 * `acceptVerification`'s own comment. Either side may call
 * {@link startVerificationComparison}; the other gets
 * `'comparison_already_started'`, answers the comparison with a second
 * {@link acceptVerification}, and carries on from step 4.
 *
 * # One sync between two verifications with the same person
 *
 * **Call {@link receiveSyncChanges} at least once between finishing one
 * verification with somebody and starting the next with that same person.**
 * Without it the new one comes back already cancelled: nothing was refused,
 * nothing failed, and {@link getVerificationStage} simply reads
 * `'cancelled'` from the start.
 *
 * This is the layer underneath, not a rule of this library, and it is not
 * something a workaround here could remove. It allows one live verification
 * per person, and a verification that **finished** is not a cancelled one,
 * so a second request opened while the first is still in its map cancels
 * both. The only thing that empties that map is the sweep it runs at the top
 * of every sync. An ordinary product never notices, because it syncs
 * continuously; a product that drives two verifications back to back from
 * one screen, or from a test, walks straight into it.
 *
 * The same applies after a verification you gave up on with
 * {@link cancelVerification}, and after one that ended any other way. Any
 * sync will do and it does not have to carry anything: an empty payload is
 * enough, because it is the sweep that matters and not the contents.
 */
export async function requestVerification(
  userId: string,
  deviceId: string,
): Promise<string> {
  try {
    return await nativeRequestVerification(userId, deviceId)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Asks this account's **other** devices to verify this one, so that this
 * device can join the cross-signing identity the account already has.
 *
 * This is what a second login does. A device that does not hold the account's
 * private signing keys joins the identity; it does not create one.
 * {@link bootstrapCrossSigning} refuses such a device with
 * `'identity_already_exists'`, and that refusal is the one thing standing
 * between an ordinary second login and an account whose identity has been
 * silently replaced, resetting the trust of every device and every person who
 * had verified it. **This call is the remedy that refusal points at, and it
 * is not a way around it.**
 *
 * # Three ways it differs from {@link requestVerification}
 *
 * **It names no device**, because a new login is in no position to choose
 * one. The invitation goes to every other device of yours that the account's
 * identity has signed, and whichever is in front of a person answers first;
 * the others are told the flow was taken. A device of yours that the identity
 * has never signed is not invited, which is deliberate: it is a login this
 * account's identity has never vouched for.
 *
 * **The signature at the end is made with a different key**, and by the other
 * side. The device that already holds the private keys signs this one with
 * the account's self-signing key. This device has nothing to sign with yet,
 * which is the whole reason it is asking.
 *
 * **It asks for the account's secrets, which verifying somebody else never
 * does.** Once the comparison completes, this library asks your other devices
 * for the cross-signing seeds it lacks. Those go out as ordinary entries in
 * {@link takeOutgoingRequests}' output, and the encrypted answer arrives in a
 * later {@link receiveSyncChanges}, which imports it.
 *
 * # Nothing returns to you when the seeds land
 *
 * The call that started all this resolved long before. Two things tell you it
 * happened, and you want the first:
 *
 * - **`onCryptoSignal`** announces `'trust_changed'` for your own user id on
 *   the sync that carried the seeds. That is the signal to read
 *   {@link getIdentityStatus} again. It is the same variant a completed
 *   comparison produces, so read the status rather than counting signals;
 *   see `onCryptoSignal`'s own comment.
 * - **{@link getIdentityStatus}** is the durable answer:
 *   `privateKeysHeld === true` means this device can now sign with the
 *   account's identity rather than only recognise it. Read it when you are
 *   told to, not on a timer.
 *
 * # Driving the flow
 *
 * Identical to {@link requestVerification} from the moment this resolves,
 * by either method. By short string: pump, wait for
 * {@link getVerificationStage} to read `'ready'`,
 * {@link startVerificationComparison}, pump, read
 * {@link getVerificationMaterial}, show it, and
 * {@link confirmVerification} or {@link cancelVerification}. The person is
 * comparing two of their own screens instead of talking to somebody else,
 * which changes none of the calls.
 *
 * **By a scanned code, if the product asked for one**, the person points
 * one of their own phones at the other instead of reading symbols off both,
 * and this is where that is most natural, because both screens are already
 * in front of them. Both self modes work: the established device may show
 * the code and the new login read it, or the other way round, and which
 * happens is decided by which phone is held up rather than by anything you
 * pass. Showing a code needs none of the account's private signing keys,
 * which is what makes it reachable on the device that is joining. See
 * {@link offerScannableCodes} and {@link getVerificationCode}.
 *
 * **Including the one sync between two verifications**, which for this call
 * means your own account: a second self-verification opened without a
 * {@link receiveSyncChanges} after the first comes back already cancelled.
 * `requestVerification` says why, and the reason is the layer underneath
 * rather than anything either call does.
 *
 * # Refusals
 *
 * `'account_keys_not_fetched'` means this process has not yet asked the
 * server about this account, so it cannot know whether there is an identity
 * to join. **This call queues that key query before returning the refusal**,
 * so the remedy is the ordinary loop: drain the pump, send, report sent, and
 * call this again. You do not have to reach for
 * {@link bootstrapCrossSigning} to get unstuck, and on a device that is
 * joining you should not: it is the call that would create a second identity
 * if the state ever moved under you.
 *
 * Expect this refusal on **every** launch, not only the first. Whether the
 * server has been asked is not persisted, and the layer underneath will not
 * volunteer the question for an account it already knows about, so a
 * relaunched store starts out having asked nothing.
 *
 * `'identity_not_known'` means one of two things, and
 * `getIdentityStatus().identityPublicationPending` tells them apart. False:
 * the server was asked and said this account has no identity, so there is
 * nothing to join and no retry helps. True: this device holds an identity it
 * minted that no homeserver has ever asserted back, so there is nothing yet
 * for another device to join it to, and the flow would sign under an
 * identity the account may never have.
 *
 * {@link createCrossSigningIdentity} is the call for both, and for the same
 * reason each time: creating a first identity and finishing a publication
 * that was interrupted are the same decision, and it is one your product
 * makes rather than something this handler calls. This is the same refusal,
 * with the same remedy, that {@link bootstrapCrossSigning} reports. The
 * paragraph used to name `bootstrapCrossSigning` as the answer, which
 * stopped being true when creating became its own call and left the two
 * surfaces saying different things about one error, and it used to give only
 * the first of the two meanings, which stopped being true when the gate
 * gained its second condition.
 */
export async function requestSelfVerification(): Promise<string> {
  try {
    return await nativeRequestSelfVerification()
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Agrees to a verification the other side asked for, and queues the answer
 * for the pump.
 *
 * For the side that *received* an invitation. The flow reaches `'ready'`
 * once the answer has been sent and reported.
 *
 * # Where `verificationId` comes from on this side
 *
 * **`onCryptoSignal` announces it**, which this package's root exports
 * alongside every function here. Forward the sync to
 * {@link receiveSyncChanges} as usual -- that is what makes the flow exist
 * at all -- and a subscriber receives:
 *
 * ```ts
 * onCryptoSignal((signal) => {
 *   if (signal.kind !== 'verification_requested') return
 *   // signal.user and signal.device say who is asking.
 *   // Ask the person, then:
 *   acceptVerification(signal.verificationId) // or cancelVerification
 * })
 * ```
 *
 * From there the flow is the one {@link requestVerification} documents,
 * from its step 2 onward, by whichever method the two sides negotiated.
 * **This is the side most likely to be holding the camera**, so if your
 * product scans, this is the flow {@link submitScannedCode} is called on.
 * Whether a code is available at all was settled before the flow existed,
 * by {@link offerScannableCodes}, and is not something answering an
 * invitation can change.
 *
 * # You may need to call this twice, and it is not a retry
 *
 * There are two things the other side can ask you, and this answers both.
 * The invitation asks *may we verify?*. The comparison -- which either side
 * may open once both are ready -- asks *here it is, will you take part?*.
 * If the other side opens it before you do, that second question is
 * outstanding and only this call answers it: they are waiting for your
 * answer and {@link getVerificationStage} sits at `'started'` until you
 * give it.
 *
 * You do not have to work out which is which. Call this whenever the stage
 * reads `'requested'` or `'started'` and the flow is waiting on you; it
 * rejects with `'wrong_stage'` when nothing is.
 *
 * **Subscribe before your first sync**, and prefer keeping the
 * subscription for the process's life. Nothing is queued for a subscriber
 * that is not there -- but for an ordinary invitation nothing is consumed
 * either, because the layer underneath does no work at all with nobody
 * subscribed. So one that arrives while you are unsubscribed is still
 * `'requested'` when you come back, and the first
 * {@link receiveSyncChanges} after you resubscribe announces it.
 * `useEffect(() => onCryptoSignal(h), [])` does not lose those. What you
 * cannot get back is an invitation that arrived before this process existed
 * at all; see the restart note below. **The one exception is the shape
 * described two sections down**, which cannot be re-offered.
 *
 * This used to be a listing of the `m.key.verification.request` to-device
 * event's JSON, with an instruction to filter your own `to_device_events`
 * for it and read `content.transaction_id` out of one. That was a real seam
 * -- one field of protocol JSON this library otherwise keeps to itself --
 * and the announcement is what closes it. The identifier still *is* that
 * transaction id on the wire; you no longer have to know that.
 *
 * # The other shape an invitation arrives in, and the one thing it costs
 *
 * Some clients -- `matrix-nio` among them, and it is the whole of what it
 * implements -- do not send an invitation at all. They open the comparison
 * directly, with the older message the specification deprecated but did not
 * remove. **Nothing about this call changes**: such a flow is announced on
 * the same channel, under the same `'verification_requested'` signal, and
 * this is still what you call to agree to it.
 *
 * Two differences are visible afterwards, and neither needs a branch in
 * your code:
 *
 * - the flow never reads `'ready'`. It is a comparison from the moment it
 *   exists, so it goes straight to `'started'` and
 *   {@link startVerificationComparison} on it rejects with
 *   `'comparison_already_started'` -- which already means "the other side
 *   started it, carry on and wait for the string";
 * - {@link confirmVerification} can finish it outright, rather than leaving
 *   it `'confirmed'` until the other side acknowledges. The device is
 *   verified when that call resolves; the `'trust_changed'` signal for it
 *   still arrives on your next {@link receiveSyncChanges}, because that is
 *   where the channel's producers run. Read {@link getDeviceStatuses} if
 *   you need the answer without waiting for a sync.
 *
 * **What it costs: this shape is not re-offered across an unsubscribe.** An
 * ordinary invitation is re-announced after you resubscribe because it can
 * be enumerated afresh on every sync; this one cannot -- the sync that
 * carried it is its only witness. Subscribing before your first sync is
 * therefore load-bearing for it rather than merely advisable.
 *
 * # An unmet sender's invitation is dropped on arrival, and not announced
 *
 * **If this library has never been told about the sender's device, the
 * invitation is discarded as it arrives.** The layer underneath needs the
 * sender's device keys to build the flow at all; without them it drops the
 * event. `receiveSyncChanges` still resolves successfully, no flow exists,
 * nothing is announced, and this function rejects that transaction id with
 * `'unknown_flow'`.
 *
 * The silence is deliberate rather than a gap. The channel announces flows,
 * and there is no flow: announcing the wire event's own identifier instead
 * would hand you a value every call in this group then rejects.
 *
 * **It is recoverable, and recovering it is your job because nothing here
 * kept the event.** What was discarded is that *arrival*, not the
 * invitation: the same event fed in again, once the device is known, does
 * create the flow -- and announces it, exactly as a first-time arrival
 * would. So:
 *
 * 1. keep the to-device events you could not act on. You never have to open
 *    one: what you keep is an opaque blob, and what you get back is the
 *    announcement. Keep the ones you *did* act on too, until their flow
 *    finishes -- see the restart note below;
 * 2. learn the sender's devices -- a real `/sync` names them in
 *    `device_lists.changed`, which {@link encryptionSlice} maps to
 *    `changed_devices`; forward that, then drain the resulting
 *    `'keys_query'` and report it with {@link markRequestSent}.
 *    {@link getDeviceStatuses} for that user answering non-empty is how you
 *    know it worked;
 * 3. pass the kept events to {@link receiveSyncChanges} a second time, and
 *    wait to be told.
 *
 * Promptly, though: an invitation expires ten minutes after it was sent, so
 * a recovery that takes longer than that leaves the other side to ask
 * again. A product that discards to-device events it could not act on has
 * no way back, which is the reason this is spelled out rather than left to
 * the error kind.
 *
 * # A restart loses the flow, and the recovery is the same one
 *
 * Flows live in memory, on both sides of this boundary. A process that
 * restarts mid-verification holds a `verificationId` that now rejects with
 * `'unknown_flow'`, and nothing is announced for it, because there is
 * nothing left to announce. The only way back is the one above: feed the
 * kept `m.key.verification.request` event in again, and be told the flow's
 * name as though it had just arrived.
 *
 * That is why the retention advice covers events you *did* act on and not
 * only ones you could not. An invitation you accepted a second before the
 * process died is exactly the event you now need, and the ten-minute expiry
 * is still running.
 *
 * **Skipping this call does not fail silently.** Nothing advances: the flow
 * stays at `'requested'`, and {@link startVerificationComparison} on it
 * rejects with `'wrong_stage'` rather than starting a comparison the other
 * side never agreed to.
 *
 * Rejects with `'wrong_stage'` for a flow this device asked for itself, or
 * one already answered, cancelled or finished. It is never a successful
 * no-op. Rejects with `'unknown_flow'` for a transaction id that names no
 * flow -- see the two sections above for the two ways that happens.
 *
 * # Two refusals that depend on whose flow it is
 *
 * Both apply only when the invitation came from **another device of your own
 * account**, and for one reason: completing a self-verification signs one of
 * your devices with this device's self-signing key and asks your other
 * devices for your cross-signing seeds, both under whatever identity this
 * store holds. So this call reads the same gate
 * {@link bootstrapCrossSigning} does. Either refusal leaves the invitation
 * answerable and sends nothing.
 *
 * Rejects with `'account_keys_not_fetched'` when this process has not yet
 * asked the homeserver about the account, so it cannot say what identity the
 * account has. The refusal queues that key query itself, and the remedy is
 * the ordinary loop: drain the pump, send, report sent, and call this again.
 *
 * Rejects with `'identity_not_known'` when the server has been asked and
 * this device holds an identity it minted that no homeserver has ever
 * asserted back, which `getIdentityStatus().identityPublicationPending`
 * reports. Signing under that identity is signing under one the account may
 * never have. The remedy is to finish the publication rather than to retry:
 * {@link createCrossSigningIdentity} re-queues it, and it is cleared by the
 * key query answer that comes back carrying the identity, not by your report
 * of the upload.
 *
 * **Accepting a verification from anybody else reads neither**, because
 * verifying another user needs nothing of your own identity. This section
 * exists because the sending side carried these warnings and the receiving
 * side did not, and the receiving side reaches the identical write.
 */
export async function acceptVerification(
  verificationId: string,
): Promise<void> {
  try {
    await nativeAcceptVerification(verificationId)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Starts the comparison itself, once both sides are ready, and queues its
 * opening message for the pump.
 *
 * Either side may call this, and only while {@link getVerificationStage}
 * reads `'ready'`. Two sides calling it at the same moment is safe: the
 * protocol settles which comparison survives.
 *
 * **The same side calling twice is refused, and that is deliberate.** A
 * double tap on a button, or a retry after an unrelated failure, would
 * otherwise build a second comparison under the same identifier and destroy
 * the flow while reporting success.
 *
 * **Three different rejections, because three different things have to
 * happen next.** The layer underneath reports one error for all of them;
 * this function reads {@link getVerificationStage} to tell them apart,
 * because a screen that shows a person one sentence for all three is
 * showing the wrong one most of the time:
 *
 * - `'comparison_already_started'` -- the *other* side started it first.
 *   Nothing is wrong, but there **is** something left for you to do:
 *   call {@link acceptVerification} again. Their start is a question, and
 *   until you answer it they are waiting and the flow does not move. This
 *   used to say "wait for `'keys-exchanged'`", which was wrong: waiting
 *   alone never produced one. Then read
 *   {@link getVerificationMaterial} as usual.
 *
 *   **A flow that went to a scanned code arrives at this same kind, and
 *   wants none of that done about it.** This kind is derived from
 *   {@link getVerificationStage} reading `'started'`, and a code flow reads
 *   `'started'` too, so the kind cannot tell the two apart. On a code flow
 *   {@link acceptVerification} answers `'wrong_stage'` and so does
 *   {@link getVerificationMaterial}, because there is no comparison and
 *   there will be no string: carry on with {@link getVerificationCode} and
 *   {@link confirmScan}, or with {@link submitScannedCode}. **What tells
 *   the two apart is your own state, not anything this library reports**: a
 *   build that never called {@link offerScannableCodes} can only be in the
 *   first case, and one that asked this flow for a code knows it is in the
 *   second.
 * - `'verification_ended'` -- the flow is over, whether it finished or was
 *   refused. There is nothing to carry on with; ask again with
 *   {@link requestVerification} if you still want to.
 * - `'wrong_stage'` -- anything else, which means either that the flow has
 *   not been agreed by both sides yet, or that it became a code rather
 *   than a comparison. Read {@link getVerificationStage}: `'requested'` is
 *   the first, and it wants a wait or an {@link acceptVerification} if the
 *   invitation was yours to answer; `'code-scanned'` is the second, and it
 *   wants {@link confirmScan}. `'ready'` is neither, and it is the one
 *   answer here that says nothing is wrong with the flow: the stage moved
 *   between this call and the stage read that followed it, so try again.
 *
 * **A code flow reaches two of these bullets, and which one is the code's
 * own state.** Before anybody has scanned it the stage is `'started'` and
 * this call answers `'comparison_already_started'`, whose advice is written
 * for a comparison and is the loop described in that bullet; once somebody
 * has scanned it the stage is `'code-scanned'` and the rejection stays
 * `'wrong_stage'`. Two assertions in `facade.test.ts` hold the pair apart:
 * `reports comparison_already_started for a flow that went to a scanned
 * code` and `leaves the rejection as wrong_stage for a flow that became a
 * code somebody scanned`.
 */
export async function startVerificationComparison(
  verificationId: string,
): Promise<void> {
  try {
    await nativeStartVerificationComparison(verificationId)
  } catch (e) {
    throw await unfoldStartRejection(e, verificationId)
  }
}

/**
 * How far along the flow is. The free discriminator: it is the one call in
 * this group that reads state without changing any, so it costs nothing to
 * poll and it is what tells apart conditions the calls below can only
 * report as one error.
 *
 * **On a flow proceeding by a scanned code it tells apart the one thing
 * that matters, and no more.** `'code-scanned'` is the moment a person is
 * being asked something, and reading it is what separates
 * {@link confirmScan}'s two `'wrong_stage'` causes: nobody has scanned yet,
 * versus the flow is over. This paragraph said the stage could not describe
 * a code flow at all, and adding `'code-scanned'` is what changed that.
 * What is still shared is `'started'` and `'confirmed'`, which both flow
 * shapes reach, so those two answers do not say which shape you are in and
 * {@link startVerificationComparison} still folds a code flow at `'started'`
 * into `'comparison_already_started'`.
 *
 * Rejects with `'unknown_flow'` for an identifier this library is not
 * taking part in -- including a flow that finished and has since been
 * released, which happens the next time a flow is *registered* rather than
 * on a timer. Registration is broader than starting one: an inbound
 * invitation announced down `onCryptoSignal` registers, and so does
 * the first call made against a flow this library is not already caching.
 * Nothing observable turns on the difference; it is stated because "started"
 * reads narrower than the rule is.
 */
export async function getVerificationStage(
  verificationId: string,
): Promise<VerificationStage> {
  try {
    return verificationStageOf(await nativeVerificationStage(verificationId))
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * The short authentication string for this flow, once there is one.
 *
 * **Show it to a person and ask whether it matches what the person at the
 * other device sees, over a channel this flow did not establish.** See
 * {@link SasMaterial}, including why the value is secret while the flow is
 * open.
 *
 * **`'material_not_ready'` has two causes, and they need opposite things
 * done about them.** Retrying this call alone fixes neither. Read
 * {@link getVerificationStage} to tell them apart, because doing the wrong
 * one waits forever:
 *
 * - **The peer opened the comparison and you have not answered it.** The
 *   stage is `'started'` and you never called
 *   {@link startVerificationComparison}. Their start is a question; call
 *   {@link acceptVerification} a second time, and the exchange proceeds.
 *   This is the ordinary receiving side against a client that starts
 *   directly, `matrix-nio` among them -- it is not an edge case, and
 *   nothing you pump will move it.
 * - **You drained the pump and never called {@link markRequestSent}.** The
 *   underlying state machine advances from "accepted" to "keys exchanged"
 *   on that report and on nothing else, so a caller that skips it parks the
 *   flow permanently with no error and no timeout anywhere else. This call
 *   names that state instead of resolving with an empty record or hanging.
 *   Supplying the missing report, and nothing else, completes the exchange.
 *
 * The other failure kind is worth keeping apart from both:
 *
 * - `'wrong_stage'` -- it never will: the flow is over, or no comparison was
 *   ever started on it. **A flow proceeding by a scanned code arrives here**,
 *   and it is neither over nor stuck: there is no string on such a flow and
 *   there never will be. A product that chose codes knows which it has, so
 *   this is not folded into a kind of its own; a product that offers both
 *   knows which call it made.
 *
 * Note that a code flow reads `'started'` from {@link getVerificationStage}
 * until somebody scans, so before that the stage does not tell that case
 * apart from the two causes above; after it, `'code-scanned'` does. Neither
 * matters here, because the kind already tells them apart: those two arrive
 * as `'material_not_ready'` and a code flow arrives as `'wrong_stage'` at
 * every stage it passes through.
 */
export async function getVerificationMaterial(
  verificationId: string,
): Promise<SasMaterial> {
  try {
    return sasMaterialOf(await nativeVerificationMaterial(verificationId))
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Says the strings matched, and queues the confirmation for the pump.
 *
 * **One of two confirmations on this surface.** {@link confirmScan} is the
 * other, for a flow that finished by a scanned code rather than a compared
 * string. They ask a person the same question and carry the same
 * obligation; only this one has material to hand back, because only this
 * one showed a person something a product could get wrong.
 *
 * **`data` is the material you showed the person**, exactly as
 * {@link getVerificationMaterial} returned it. It is checked against what
 * the flow currently holds, and a mismatch rejects with
 * `'material_mismatch'` rather than confirming.
 *
 * **What that argument does and does not guarantee.** It guarantees the
 * confirmation names *this flow's current string*: the caller cannot
 * produce a passing `data` without having read the material, because the
 * digits and symbols are derived from keys only this flow has, and the
 * layer underneath checks only that a string exists. So the material a
 * product confirms is material it obtained, for the flow it is confirming.
 *
 * It does not guarantee that anybody looked. `confirmVerification(id, await
 * getVerificationMaterial(id))` satisfies every check here while displaying
 * nothing, and no API can do better: whether a human read a string off a
 * screen and compared it with another human is not observable from inside
 * this process. **That last step is yours, and it is the step the whole
 * protocol rests on.** A product that confirms without asking a person has
 * verified nothing, however well-formed its arguments were.
 *
 * `'material_mismatch'` therefore means one thing: `data` is not this
 * flow's current string. In practice that is material obtained from a
 * different flow, or a value constructed rather than read.
 *
 * It is *not* what you get for a flow that ended while the string was on
 * screen -- cancelled by either side, timed out, or refused. A flow's
 * string does not change once the keys are exchanged, and a replacement
 * flow has a different id, so that case is caught one step earlier, by the
 * read this function makes before it compares anything: `'unknown_flow'` or
 * `'wrong_stage'`. Worth knowing which check catches what, because the two
 * kinds tell a product different things -- ask the person again on a new
 * flow, versus you are holding the wrong string.
 *
 * `data` was typed `unknown` up to `0.1.0-rc.2`, on a function that had only
 * ever rejected with `'not_implemented'`, so no caller has ever passed
 * anything to it successfully.
 *
 * **Confirming is not verifying.** When this resolves, the flow reads
 * `'confirmed'` and the other device is *not* verified: the other side has
 * still to say the same, and two more messages have to cross. Pump, and
 * watch for {@link getVerificationStage} to read `'done'`.
 *
 * Rejects with `'material_not_ready'` if the string is not available (see
 * {@link getVerificationMaterial}), and with `'wrong_stage'` if the flow is
 * over or never became a comparison. Both come from the read above, before
 * anything is confirmed.
 */
export async function confirmVerification(
  verificationId: string,
  data: SasMaterial,
): Promise<void> {
  // Read before confirming, not after: this is the check, and a check that
  // ran after the confirmation had already been queued would be reporting
  // on something it could no longer prevent. It also produces exactly the
  // error the confirmation itself would have -- 'material_not_ready' or
  // 'wrong_stage' -- for a flow with nothing to show, so nothing is lost by
  // reaching this first.
  const current = await getVerificationMaterial(verificationId)
  if (!sameMaterial(current, data)) {
    throw toCryptoError({ name: 'MaterialMismatch' })
  }
  try {
    await nativeConfirmVerification(verificationId)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Refuses the verification, or abandons it, and queues the refusal for the
 * pump.
 *
 * **The call a product must be able to make at any point a person can look
 * at a screen and say "that is not what I see".** Refusing is not a failure
 * of this library; a comparison that can only ever agree proves nothing.
 *
 * Cancels the comparison if one has started, the scannable code if the flow
 * became one, and the invitation otherwise. The first two also cancel the
 * invitation behind them. Nothing is verified, on either side.
 *
 * Rejects with `'wrong_stage'` for a flow that was already cancelled.
 * "Already refused" and "refused by this call" are the same outcome, but a
 * caller told `Ok` for a cancellation it did not perform has been told
 * something false.
 *
 * **Skipping this does not fail silently, but it does fail slowly.** A flow
 * nobody cancels sits open until the protocol's own ten-minute timeout
 * retires it.
 *
 * # The one screen this is the only way off
 *
 * A flow that reaches `'code-scanned'` is waiting for a person to answer
 * {@link confirmScan}, and some clients will already have declared
 * themselves finished by then. When that happens the flow never moves again:
 * the stage stays `'code-scanned'` however long you pump, and
 * {@link confirmScan} cannot end it because the other side has stopped
 * listening.
 *
 * **This is the call that ends it, and it matters more than it looks.** A
 * verification left in that state is still live as far as the layer
 * underneath is concerned, and it allows one live verification per person,
 * so it takes the next two attempts with that person down with it. Those two
 * die quietly: no rejection, no error, just a flow that reads `'cancelled'`
 * from the start. Cancel the stuck one, sync once (see
 * {@link requestVerification} for why), and the next verification with that
 * person behaves normally.
 *
 * A product that shows a code should therefore offer a way out of that
 * screen rather than only a way forward, and call this when a person takes
 * it.
 */
export async function cancelVerification(
  verificationId: string,
): Promise<void> {
  try {
    await nativeCancelVerification(verificationId)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Says what this product can do with a scannable code.
 *
 * **Nothing is claimed until you call this, and a build that never does says
 * on the wire exactly what it said before codes existed here.** Nothing
 * about a consumer's verifications changes because this library grew a
 * feature they do not use. Answering is a few lines and they are yours to
 * write, because the two claims a code makes are claims about the *product*:
 * it owns the camera, the screen and the scanner, and this library cannot
 * know whether you built any of them.
 *
 * See {@link CodeCapabilities} for what each field means, why there are two
 * of them, and which of the two mistakes is the expensive one.
 *
 * # A product with a screen and no scanner
 *
 * ```ts
 * offerScannableCodes({ canShow: true, canScan: false })
 * ```
 *
 * That is the truthful answer for most products, and it used to be
 * unsayable. Saying it removes a choice from the far side: told this one has
 * no camera, a peer cannot decide to show its own code and wait, so it scans
 * or the two of you compare the short string. Claiming a camera you do not
 * have leaves a person holding a phone in front of a square nothing will
 * ever read, with **no error reaching either product**, until the protocol's
 * own ten-minute timeout retires the flow.
 *
 * # Withholding a half does more than stay quiet
 *
 * `canShow: false` makes a code unavailable rather than merely
 * unadvertised, in both directions, and that is not this library's choice: a
 * code exists only if the side drawing it announced showing **and** the side
 * reading it announced scanning. So with both halves off, the peer's own
 * client produces no code either and falls through to the short string,
 * exactly as it did against every earlier release.
 *
 * # When to call it
 *
 * Before opening or answering any flow a code might be used on. What a flow
 * announces is fixed when that flow is created or agreed to, so calling this
 * afterwards changes nothing about a verification already under way. Once at
 * start-up, next to {@link createCryptoMachine}, is the usual place.
 *
 * It applies to the whole process rather than to one flow, because it
 * describes the product, and a product does not have a camera on some of its
 * verifications and not others.
 *
 * **Not asynchronous, unlike almost everything else here.** It sets one
 * process-wide value and cannot fail, and the shape is deliberate: an
 * awaitable call that a caller forgot to await could land after the flow it
 * was meant to affect had already said what it can do.
 */
export function offerScannableCodes(capabilities: CodeCapabilities): void {
  try {
    // Destructured and rebuilt rather than passed straight through: the two
    // records have the same field names today and nothing guarantees they
    // keep them, and a field this surface stopped forwarding would be a
    // claim a product never made travelling on its behalf, which is the
    // defect this whole call was reshaped to end.
    const { canShow, canScan } = capabilities
    nativeOfferCodes({ canShow, canScan })
  } catch (e) {
    // Cannot fail on the Rust side: it stores a boolean and returns nothing.
    // Wrapped anyway, because the layer between here and there can fail on
    // its own -- a native module that never installed throws from every call
    // that reaches for it -- and a product should catch one kind of thing
    // from this surface rather than two.
    throw toCryptoError(e)
  }
}

/**
 * The code for this flow, for a person to hold up to another camera.
 *
 * # What your product has to do, and what this library will not
 *
 * **You own the scanner, the camera permission and the screen.** Nothing in
 * this library sees an image, asks for a permission, or draws anything. It
 * produces the value a code carries and it consumes one back; everything
 * between that value and a person's eyes is yours.
 *
 * **Draw {@link ScannableCode.modules}, not {@link ScannableCode.payload}.**
 * That is the reason two forms come back rather than one, and it is not a
 * convenience. The payload is about 126 bytes of binary that is not text: it
 * carries two raw signing keys and a random shared secret. There is no
 * string it can honestly be turned into, so a JavaScript code-drawing
 * component -- which nearly always takes a string -- cannot be given it. The
 * grid is the symbol this protocol's own encoder built, at a version and
 * error-correction level it fixes deliberately, in its own words because
 * mobile clients have trouble decoding otherwise. Draw `width` rows of
 * `width` squares from it, leave a quiet margin, and what a camera reads is
 * what the protocol meant. Re-encoding the payload yourself produces a code
 * this library's own scanner would read back and another client may not.
 *
 * The payload is there because a product may need to move it -- to a
 * component of its own, to a test -- not because it should be turned into a
 * picture by hand.
 *
 * **Treat both as secret while the flow is open**, exactly as
 * {@link SasMaterial} is treated: anything that learns either learns what an
 * interposed party would need to answer the flow as though it had read the
 * screen.
 *
 * # After it is drawn
 *
 * The other device scans it and no call returns to tell you: watch
 * {@link getVerificationStage} for `'code-scanned'`, then ask a person and
 * call {@link confirmScan} when they say yes. That is the step this method's
 * security rests on, exactly as {@link confirmVerification} is for a short
 * string.
 *
 * # One thing that can go wrong here and is not yours
 *
 * **A flow where you show the code will not complete against a client that
 * announces itself finished as soon as it has scanned.** The specification
 * puts that message last, after the person on the showing side has confirmed
 * the scan, and that confirmation is the entire security argument of this
 * method. A client that sends it early spends it while this side is still
 * waiting for a person, and the layer underneath correctly ignores it. The
 * flow then sits at `'confirmed'` for ever.
 *
 * This has been measured against a real third-party client rather than
 * inferred: its own source calls the message "immediately", the two events
 * arrive in one sync batch before any confirmation could exist, and the
 * repository's `rust/matrix-crypto-core/tests/level_two_scanned.rs` asserts
 * exactly that off the wire. **The deviation is that client's**, and
 * nothing in this library can make such a flow finish. Scanning *their*
 * code with {@link submitScannedCode} completes normally against the same
 * client, and giving a person a way out with {@link cancelVerification} is
 * what makes the failure recoverable.
 *
 * # Refusals
 *
 * Every one of them is a sentence a product can show, which is the whole
 * point: the layer underneath answers seven different conditions with an
 * empty code and a warning nobody reads, and this call names them instead.
 *
 * - `'code_not_offered'` -- codes were not negotiated on this flow. Waiting
 *   will never help. Two causes, and you can always tell which: either this
 *   build never called {@link offerScannableCodes}, or the other device did
 *   not offer to scan, in which case offer a short-string comparison
 *   instead.
 * - `'identity_not_known'` -- this account has no signing identity for the
 *   code to carry. See {@link createCrossSigningIdentity}, which is the call
 *   that makes one; {@link bootstrapCrossSigning} publishes an identity this
 *   device already holds and answers this same refusal.
 * - `'peer_identity_not_known'` -- the *other* user has none, and nothing
 *   this device does will produce one.
 * - `'private_keys_not_held'` -- verifying another user puts this account's
 *   own key in the code and this device cannot prove it holds one. See
 *   {@link requestSelfVerification}, {@link recoverIdentity} or, on an
 *   account with no identity at all, {@link createCrossSigningIdentity}.
 *   Not {@link bootstrapCrossSigning}: it refuses a device holding no
 *   private keys with `'identity_already_exists'`. Verifying your own new
 *   login does not need them.
 * - `'wrong_stage'` -- nobody has agreed to this flow yet, or it is over.
 * - `'unknown_flow'` -- no flow of that id.
 * - `'malformed_identifier'` -- the flow's own identifier is too long to fit
 *   in a code. Only reachable from a peer that chose the identifier, since
 *   the ones this library mints are ordinary transaction ids, and nothing a
 *   product does about it will help: offer a short-string comparison.
 *
 * Calling it twice is legal and produces a code for the same flow. Draw the
 * newer one: it is the live one.
 */
export async function getVerificationCode(
  verificationId: string,
): Promise<ScannableCode> {
  try {
    const code = await nativeVerificationCode(verificationId)
    // Destructured, not returned directly: a field added to the generated
    // record later must be a deliberate choice to expose rather than
    // something that crosses this boundary unreviewed. See Global
    // Constraints.
    const { payload, width, modules } = code
    return {
      // The generated binding speaks ArrayBuffer; this surface speaks
      // Uint8Array, the idiomatic React Native shape and the one
      // `EventEnvelope.ciphertext` already uses.
      payload: new Uint8Array(payload),
      width,
      modules,
    }
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Hands in the payload your scanner read off the other device's screen.
 *
 * # The obligation this call puts on a product, and it is the sharp one
 *
 * **`payload` must be the raw bytes the code carried, not a decoded
 * string.** React Native's popular scanners -- vision camera's code scanner,
 * expo's barcode handler -- surface a decoded `value: string`, and that
 * string cannot carry this payload: it is binary, it is not valid text, and
 * a string round trip replaces every byte that could not be represented.
 * Reach for the raw byte output your scanner offers, and if it offers none,
 * that scanner cannot be used for this.
 *
 * This library cannot undo that damage; what it can do is name it. A payload
 * that went through a string arrives as `'scanned_code_malformed'`, which is
 * the one signal a product gets that its scanner is the problem rather than
 * the person holding the phone.
 *
 * **This is one call and two protocol steps.** The scan is registered and
 * the message that tells the other side the code was read is queued for the
 * pump. Drain it: a scan nobody hears about leaves both sides waiting.
 *
 * # Refusals, and why there are four of them
 *
 * A product must be able to say four different things here, so four
 * different kinds arrive:
 *
 * - `'scanned_code_unrecognised'` -- not one of these codes at all. Point
 *   the camera at the code the other device is showing.
 * - `'scanned_code_malformed'` -- the bytes did not survive. Scan again, and
 *   check that your scanner yields bytes rather than text.
 * - `'scanned_code_for_another_flow'` -- a real code, for a different
 *   verification. Nothing is wrong; the wrong screen was read.
 * - `'scanned_code_refused'` -- a code for this flow carrying keys that are
 *   not the ones this side holds for the device on the other end. **The only
 *   one of the four that can mean something is wrong rather than that
 *   somebody aimed badly.** Refuse and start again from a fresh request;
 *   scanning the same code again cannot help, because the keys it carries
 *   will not have changed.
 *
 * It means that and nothing else. A peer device this side has no record of
 * is a different answer, `'unknown_device'`, precisely because the remedy is
 * the opposite: drain {@link takeOutgoingRequests}, report the key query it
 * hands you, and scan the very same code again.
 *
 * Scanning also needs a signing identity on both sides, so
 * `'identity_not_known'` and `'peer_identity_not_known'` are reachable here
 * too, and name which side is missing one. It can also reject with
 * `'unknown_flow'`, for an identifier naming no flow this process is taking
 * part in, and with `'wrong_stage'`, for a flow that is not one a code can be
 * scanned into or is already over.
 *
 * **Scanning is not verifying.** When this resolves, nothing is verified
 * yet: the other side has still to confirm, and messages have to cross.
 * Pump, and watch {@link getVerificationStage}: it reads `'confirmed'` from
 * here, meaning this side has done everything asked of it, and `'done'` once
 * the other side has finished. It never reads `'code-scanned'` on this side,
 * because that stage belongs to whoever held up a screen.
 */
export async function submitScannedCode(
  verificationId: string,
  payload: Uint8Array,
): Promise<void> {
  try {
    await nativeSubmitScannedCode(verificationId, toArrayBuffer(payload))
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Says the other device really did scan the code this one showed.
 *
 * The one thing a person still has to do in a flow with no string to
 * compare, and it is the same act {@link confirmVerification} asks for:
 * *that was my other phone, not somebody's screenshot*. **Ask before calling
 * this.** A product that confirms on its own has verified nothing, however
 * well-formed its arguments were, because whether a person recognised the
 * device that scanned is not observable from inside this process.
 *
 * Rejects with `'unknown_flow'` for an identifier naming no flow this process
 * is taking part in, and with `'wrong_stage'` when nobody has scanned this
 * device's code yet, and also when the flow is over. Those two want opposite
 * things done -- wait, versus start again -- and this call still cannot tell
 * them apart on its own. **{@link getVerificationStage} now can**, which it
 * could not when this rejection was first written: `'started'` is nobody has
 * scanned yet, `'code-scanned'` is the one stage this call succeeds at, and
 * `'done'` or `'cancelled'` is over. Read it before calling this rather than
 * after, and the rejection stops being reachable for anything but a race.
 *
 * **Skipping it does not fail loudly, but it does fail.** A flow nobody
 * confirms sits open until the protocol's own ten-minute timeout retires it.
 *
 * **And calling it does not always end the flow, through no fault of yours.**
 * Some clients declare themselves finished the instant they accept a scan,
 * before you have been asked anything. That is a deviation from the
 * specification on their side, which puts that message after the
 * confirmation you are being asked for; the message that would have
 * completed this flow was spent then and no second one is coming. This call
 * still succeeds, the stage moves to `'confirmed'`, and it stays there. See
 * {@link getVerificationCode} for the measurement behind that. Give the
 * person a way out of that screen and call {@link cancelVerification} when
 * they take it, which is the only thing that frees them to verify that
 * contact again.
 */
export async function confirmScan(verificationId: string): Promise<void> {
  try {
    await nativeConfirmScan(verificationId)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * Maps the generated numeric enum onto the facade's closed string union.
 *
 * A `switch` with no `default`, over an enum the code generator emits from
 * the Rust source: a stage added to that source and not handled here is a
 * compile error, which is the only way this mapping can be kept honest
 * without a runtime test per variant. The `never` return is unreachable and
 * exists so the exhaustiveness is enforced rather than merely intended.
 */
function verificationStageOf(
  stage: NativeVerificationStage,
): VerificationStage {
  switch (stage) {
    case NativeVerificationStage.Requested:
      return 'requested'
    case NativeVerificationStage.Ready:
      return 'ready'
    case NativeVerificationStage.Started:
      return 'started'
    case NativeVerificationStage.KeysExchanged:
      return 'keys-exchanged'
    case NativeVerificationStage.CodeScanned:
      return 'code-scanned'
    case NativeVerificationStage.Confirmed:
      return 'confirmed'
    case NativeVerificationStage.Done:
      return 'done'
    case NativeVerificationStage.Cancelled:
      return 'cancelled'
  }
}

/**
 * See {@link verificationStageOf}: exhaustive by compile error.
 *
 * **The return type is what makes that true, and an earlier version of this
 * function did not have it.** It took `NativeSenderVerification | undefined`
 * and returned `SenderVerification | undefined`, to fold the encrypt
 * direction's absent value into the same call. That looked tidier and
 * silently destroyed the guarantee this comment claims: with `undefined` in
 * the return type, a missing `case` falls off the end, implicitly returns
 * `undefined`, and compiles. The `Verified` arm was deleted outright in
 * review and `tsc --noEmit` exited 0 with all 108 tests still green.
 * `tsconfig.json` sets `strict` but not `noImplicitReturns`, so nothing else
 * caught it either.
 *
 * So the absent case is handled at the call site instead, and this function
 * takes and returns non-optional values -- the same shape
 * {@link verificationStageOf} and {@link trustStateOf} already have, for the
 * same reason. Falling off the end is now
 * `TS2366: Function lacks ending return statement and return type does not
 * include 'undefined'`.
 *
 * That mattered more than a tidier signature because of what this arm was
 * for a whole milestone. **No test in this repository fed this function
 * `Verified`**, because the M3 design ruling required the suite to hold no
 * case that appeared to produce it, and the library could not produce it
 * anyway. The compiler was the only thing standing behind that arm, which
 * is precisely why it had to actually be standing there.
 *
 * That is history now. M4 gives the core a cross-signing identity, and the
 * ruling was replaced rather than dropped by the stricter form written at
 * `matrix_crypto_core::SenderVerification`: nothing except the real chain
 * produces `Verified`. `facade.test.ts` feeds this function every native
 * value including `Verified`, and asserts that `'verified'` comes out for
 * that one and for no other. Both directions matter now. Something else
 * arriving *as* `'verified'` is still the failure that hurts most, and a
 * `Verified` the chain earned being dropped here is the one M4 added.
 */
/**
 * The one direction of the requirement mapping, closed union to native
 * enum. Exhaustive by compile error, on the same terms
 * {@link senderVerificationOf} states for its own switch: the union is
 * closed, so a member added to `SenderTrustRequirement` fails this
 * function rather than silently defaulting to the permissive tier --
 * which is the one failure mode that must never be silent, since it would
 * hand a product plaintext it asked to be refused.
 */
function nativeSenderTrustRequirementOf(
  requirement: SenderTrustRequirement,
): NativeSenderTrustRequirement {
  switch (requirement) {
    case 'any':
      return NativeSenderTrustRequirement.Any
    case 'identity_signed_or_legacy':
      return NativeSenderTrustRequirement.IdentitySignedOrLegacy
    case 'identity_signed':
      return NativeSenderTrustRequirement.IdentitySigned
  }
}

function senderVerificationOf(
  verification: NativeSenderVerification,
): SenderVerification {
  switch (verification) {
    case NativeSenderVerification.Verified:
      return { state: 'verified' }
    case NativeSenderVerification.UnverifiedIdentity:
      return { state: 'unverified', reason: 'unverified_identity' }
    case NativeSenderVerification.VerificationViolation:
      return { state: 'unverified', reason: 'verification_violation' }
    case NativeSenderVerification.UnsignedDevice:
      return { state: 'unverified', reason: 'unsigned_device' }
    case NativeSenderVerification.NoDeviceMissing:
      return { state: 'unverified', reason: 'no_device', problem: 'missing' }
    case NativeSenderVerification.NoDeviceInsecureSource:
      return {
        state: 'unverified',
        reason: 'no_device',
        problem: 'insecure_source',
      }
    case NativeSenderVerification.MismatchedSender:
      return { state: 'unverified', reason: 'mismatched_sender' }
  }
}

/** See {@link verificationStageOf}: exhaustive by compile error. */
function trustStateOf(trust: NativeTrustState): TrustState {
  switch (trust) {
    case NativeTrustState.Unverified:
      return 'unverified'
    case NativeTrustState.Recognized:
      return 'recognized'
    case NativeTrustState.Verified:
      return 'verified'
  }
}

/**
 * Rebuilds the facade's `SasMaterial` from the generated record.
 *
 * The three decimals travel as three separate fields because the boundary
 * has no tuple type; they are a fixed-length tuple again here, so a consumer
 * cannot index past the end of something it believed was an array.
 */
function sasMaterialOf(material: NativeSasMaterial): SasMaterial {
  // Destructured, not returned directly. See encryptEvent above.
  const { emoji, decimalOne, decimalTwo, decimalThree } = material
  const rebuilt: SasMaterial = {
    decimals: [decimalOne, decimalTwo, decimalThree],
  }
  if (emoji !== undefined) {
    rebuilt.emoji = emoji.map(({ symbol, description }): SasEmoji => ({
      symbol,
      description,
    }))
  }
  return rebuilt
}

/**
 * Is `offered` the material the flow is actually showing?
 *
 * Compares the digits always and the symbols when either side has them. The
 * digits alone would be enough to catch a stale or fabricated argument --
 * they are always present, and they are derived from the same key material
 * the symbols are -- but comparing only them would let a caller pass a
 * record whose symbols are wrong, which is what a screen showing symbols
 * actually displayed. `description` is deliberately not compared: it is a
 * label for the symbol and a product may translate it.
 */
function sameMaterial(current: SasMaterial, offered: SasMaterial): boolean {
  // Read through `unknown` rather than through the declared type: this
  // argument is the check, and a caller that reaches this function from
  // plain JavaScript, or past an `as any`, is exactly the caller it exists
  // to stop. The same discipline `decryptEvent` applies to its `scope`.
  const raw: unknown = offered
  if (typeof raw !== 'object' || raw === null) return false
  const { decimals, emoji } = raw as { decimals?: unknown; emoji?: unknown }

  if (!Array.isArray(decimals) || decimals.length !== current.decimals.length)
    return false
  if (!current.decimals.every((digit, index) => digit === decimals[index]))
    return false

  const currentSymbols = current.emoji?.map(({ symbol }) => symbol)
  // A flow with no symbols must be confirmed with a record that has none:
  // a caller offering symbols for a comparison that negotiated none is
  // describing a different screen from the one this flow produced.
  if (currentSymbols === undefined) return emoji === undefined
  if (!Array.isArray(emoji) || emoji.length !== currentSymbols.length)
    return false
  return currentSymbols.every(
    (symbol, index) =>
      symbol === (emoji[index] as SasEmoji | undefined)?.symbol,
  )
}

/**
 * Splits {@link startVerificationComparison}'s one rejection into the three
 * a product has to answer differently. See that function's own doc comment
 * for what each means.
 *
 * Only a `'wrong_stage'` rejection is unfolded; everything else is passed
 * through unchanged, because everything else already says what it means. If
 * reading the stage itself fails -- the flow was released between the two
 * calls, say -- the original rejection is what the caller gets, since an
 * error about the diagnosis would be worse than the one it replaced.
 */
async function unfoldStartRejection(
  raw: unknown,
  verificationId: string,
): Promise<Error> {
  const original = toCryptoError(raw)
  if (original.kind !== 'wrong_stage') return original

  let stage: VerificationStage
  try {
    stage = await getVerificationStage(verificationId)
  } catch {
    return original
  }

  switch (stage) {
    case 'started':
    case 'keys-exchanged':
    case 'confirmed':
      return toCryptoError({ name: 'ComparisonAlreadyStarted' })
    case 'done':
    case 'cancelled':
      return toCryptoError({ name: 'VerificationEnded' })
    case 'requested':
    case 'ready':
      return original
    // A flow that became a code, and a comparison cannot be started on one.
    // Deliberately *not* `'comparison_already_started'`: that kind tells a
    // caller the other side opened a comparison and to answer it with
    // another {@link acceptVerification}, which here would be a sentence
    // about a comparison that does not exist and an instruction that moves
    // nothing. The unfolded rejection is passed through instead, and its own
    // documentation sends a caller to {@link getVerificationStage}, which is
    // the call that says `'code-scanned'` and therefore says
    // {@link confirmScan}.
    //
    // **The residue this leaves is named rather than hidden.** `'started'`
    // and `'confirmed'` are reached by both flow shapes and this function
    // cannot tell which it is in, so a flow that became a code and is sitting
    // at either still gets the comparison-flavoured explanation above. That
    // predates this stage existing; what closes it for a caller is reading
    // the stage, which no longer answers `'started'` for every state a code
    // passes through.
    case 'code-scanned':
      return original
  }
}

/**
 * One global account data event, as your homeserver stores it.
 *
 * `content` is the event's content object, already parsed: exactly the body
 * of a `PUT /_matrix/client/v3/user/{userId}/account_data/{eventType}` and
 * exactly what the matching `GET` answers with. This library adds no
 * envelope of its own, so these values move to and from your homeserver
 * unchanged.
 */
export interface AccountDataEntry {
  /** The global account data event type, such as `'m.secret_storage.default_key'`. */
  eventType: string
  /** The event's content object. */
  content: unknown
}

/**
 * What {@link createRecovery} produced: the one secret to show your user,
 * and the account data to write.
 */
export interface RecoverySetup {
  /**
   * The recovery key, in the base58 form the Matrix specification defines,
   * grouped in fours.
   *
   * **This value is never stored and can never be produced again.** It is
   * the passphrase's equal rather than a backup of it: either one opens the
   * recovery, and losing both loses the account's identity for good. See
   * {@link createRecovery} for what that costs.
   */
  recoveryKey: string
  /**
   * The account data to write, in the order to write it.
   *
   * Five events: the key description, one per private signing key, and the
   * pointer that makes the new key this account's default.
   *
   * **The pointer is last, and the order is load-bearing.** Everything
   * before it adds to the account without changing what any client
   * currently resolves, so a product interrupted partway through has
   * written a key description and some ciphertexts that nothing points at,
   * and whatever recovery the account had before still works. Writing the
   * pointer earlier would repoint the account at a key whose secrets do not
   * exist yet, which is a window in which neither the old recovery nor the
   * new one opens anything.
   */
  accountData: AccountDataEntry[]
}

/**
 * Writes this account's private signing keys into server-side storage,
 * under a key derived from `passphrase`, so that a device which has lost
 * its store can get the identity back.
 *
 * **This is what makes an identity survive a reinstall.** Delete the
 * application and install it again and the store goes with it. Without a
 * recovery, what is lost is not a cache: the private signing keys were only
 * ever on that device, so the new installation has to be verified against
 * another device the user still has, and every person who had verified this
 * account has to verify it again. With one, the new installation asks for
 * the passphrase and is the same identity it was before, and nobody else
 * has to do anything.
 *
 * `accountData` is the account's **existing** global account data, read
 * back from your homeserver the same way {@link recoverIdentity} takes it.
 * It is required rather than optional because this call will not write over
 * a recovery the account already has, and passing `[]` is you saying there
 * is none.
 *
 * # Say what this costs, at the moment you ask for the passphrase
 *
 * `recoveryKey` comes back exactly once and is never stored anywhere. If
 * your user loses it **and** forgets the passphrase, the account's identity
 * is gone: nothing on the server can open the stored keys without one of
 * them, and this library keeps no second copy. Showing the key on a screen
 * the user taps past is how that ends in a support request nobody can
 * answer. Make them record it.
 *
 * # The passphrase is the weak half, and this library imposes no rule on it
 *
 * The encrypted keys live on your homeserver, so the passphrase is what
 * stands between anyone who can read this account's account data and the
 * account's private signing keys. `createRecovery('')` is accepted, and so
 * is any other passphrase: **no minimum length, no strength estimate and no
 * refusal.** That is a decision rather than an omission. Any threshold this
 * library picked would be arbitrary, would be wrong for somebody, and would
 * sit in the one place your product cannot adjust it. You know your users
 * and your threat model; choose a policy and apply it before calling.
 *
 * **A strong recovery key does not make up for a weak passphrase.** Secret
 * storage opens on either credential, so anyone who can read this account
 * data has to beat only the weaker of the two: thirty-two random bytes are
 * no help while `''` opens the same ciphertext. What the recovery key
 * protects is your user's own access, not the secret's confidentiality, and
 * that is the reason to make them record it.
 *
 * # This is Matrix's own format, not one this library invented
 *
 * The account data written here is secret storage as the specification
 * defines it, the `m.secret_storage.v1.aes-hmac-sha2` scheme, produced by
 * `matrix-sdk-crypto`'s own implementation of it. Another Matrix client
 * signed into the same account reads the same five events with the same
 * passphrase or recovery key, and a recovery another client wrote is one
 * {@link recoverIdentity} restores. That interoperability is the reason
 * this call exists and {@link exportSecrets} does not.
 *
 * It is also why the ciphertexts are **merged** rather than replaced. Each
 * `m.cross_signing.*` event holds a map from key id to ciphertext so that
 * more than one key can open the same secret, and this call adds its entry
 * to whatever you handed it instead of writing a map of one. Another
 * client's entry under its own key id is not this library's to remove.
 *
 * # Nothing here reaches the network
 *
 * This library performs no request, here or anywhere. On success, `PUT`
 * each entry of `accountData` to
 * `/_matrix/client/v3/user/{userId}/account_data/{eventType}` with the
 * entry's `content` as the body, **in the order they are handed back**. The
 * default-key pointer is last, and sending it out of order gives up the
 * property described at {@link RecoverySetup.accountData}.
 *
 * Nothing is queued through {@link takeOutgoingRequests} for this, and that
 * is deliberate: the outbound pump is a body to send and a report that it
 * was sent, with no value coming back, and account data is a read then a
 * write. Rather than change what a pump entry means for every other kind of
 * request, these two calls take and return the JSON and leave the two
 * endpoints to you. It is the same shape {@link receiveSyncChanges} already
 * uses for the one other place this library needs something from your
 * server.
 *
 * # Refusals
 *
 * `'recovery_already_exists'` means `accountData` names a recovery already.
 * **This call will not write over one.** It cannot tell your two callers
 * apart: a user replacing their own passphrase, where the old recovery key
 * is meant to stop working, and a product writing what it believes is a
 * first recovery for a user who already set one up in another Matrix
 * client, where the key that stops working is one somebody wrote down and
 * was told to keep forever. Both arrive here as the same call.
 *
 * **To add a recovery deliberately, call this again with the same
 * `accountData` minus the `'m.secret_storage.default_key'` entry.** Filter
 * that one entry out of the array; write nothing to your homeserver to
 * arrange it. The refusal lifts because nothing points at a key any more,
 * everything else is still there so the ciphertexts still merge, and the
 * recovery the account has goes on working until your last `PUT`, of the
 * new pointer, switches it over. There is no window in which your user has
 * no working recovery, and nothing to undo if you stop halfway.
 *
 * # Adding a key is not revoking one
 *
 * **That route re-points the account. It does not revoke anything.** When it
 * finishes, the old key description is still on your homeserver and the old
 * key's ciphertext is still in every `encrypted` map, because keeping them
 * is what the merge is for. Anyone holding the old passphrase who can read
 * this account's account data can still open the account's private signing
 * keys, by reading the old key description directly instead of following
 * the pointer. {@link recoverIdentity} will not do that, because it follows
 * the pointer; a homeserver operator, anyone with a live access token, and
 * any client that remembers the old key id are not obliged to.
 *
 * That is the right default and it is not what every caller wants. **If your
 * user is replacing a passphrase they no longer trust, re-pointing is not
 * enough**, and this call cannot do the rest for you: the entry it would
 * have to drop is indistinguishable from another client's, which is the same
 * reason it refuses in the first place. Revocation is one further act, on
 * the array this call already handed you:
 *
 * 1. remove the **old** key id from each `'m.cross_signing.*'` entry's
 *    `encrypted` object, leaving the new one;
 * 2. `PUT` the entries in the order you were given them, pointer last;
 * 3. **afterwards**, and only afterwards, `PUT {}` to
 *    `'m.secret_storage.key.<old id>'`.
 *
 * After step 1 the old key opens nothing on this account, whoever it
 * belonged to. Do it only for a key your own product created.
 *
 * **Do not clear the key description before the new pointer is live.** The
 * ordering is the whole difference between a rotation and a loss: the
 * description holds the salt, the iteration count and the MAC, so a key
 * whose description is gone can never be reconstructed from any secret, and
 * clearing it while it is still the account's default leaves your user
 * pointing at something nothing can open. Step 3 is that same write after
 * the switchover, when the key it describes is no longer the one the account
 * resolves.
 *
 * Two other routes lift the refusal, and both cost something the one above
 * does not:
 *
 * - **Clearing the pointer on your homeserver** (`PUT {}`, which is how the
 *   client-server API deletes account data) works, and the merge survives.
 *   What it costs is a window: from that write until your last one the
 *   account resolves no recovery, and a crash in between leaves it there.
 * - **Passing `[]`** works too, and costs the merge. This call merges into
 *   what you hand it, so handed nothing it merges into nothing and every
 *   other key's ciphertext, including another client's, is dropped from
 *   the events you then write. Use it only for an account you know has no
 *   account data.
 *
 * **This call believes the account data you hand it**, which is what makes
 * all three possible. Passing `[]` asserts the account has no recovery and
 * the refusal believes you, exactly as {@link bootstrapCrossSigning}'s gate
 * believes a key query you reported as answered. That is unavoidable in a
 * library that performs no request, and it is said rather than left to be
 * discovered: what the refusal buys is not that destruction is impossible,
 * but that you have to have *looked*, and that the cheapest way past it is
 * also the one that destroys nothing. What it does not buy, and what no
 * argument to this call can buy, is that the key you replaced has stopped
 * working. That is the further act above.
 *
 * `'account_keys_not_fetched'` means this process has not yet asked the
 * server about this account. The private keys this device holds may belong
 * to an identity the account has already replaced, and a recovery written
 * for those opens perfectly and restores an identity that no longer exists,
 * with nothing said at the time. The call queues that key query as it
 * refuses, so the remedy is the ordinary loop: drain, send, report sent,
 * call again.
 *
 * `'private_keys_not_held'` means this device does not hold all three
 * private signing keys, so there is nothing to write. Read
 * {@link getIdentityStatus}: an account with no identity needs
 * {@link bootstrapCrossSigning}, and an identity this device has not joined
 * needs {@link requestSelfVerification}. A partial write is not offered as
 * an alternative, because account data that opens with the right passphrase
 * and restores half an identity is worse than none.
 */
export async function createRecovery(
  passphrase: string,
  accountData: AccountDataEntry[],
): Promise<RecoverySetup> {
  const existing = accountData.map(entry => ({
    eventType: entry.eventType,
    content: stringifyOrMalformed(entry.content),
  }))
  let setup
  try {
    setup = await nativeCreateRecovery(passphrase, existing)
  } catch (e) {
    throw toCryptoError(e)
  }
  // Outside the `catch` above, deliberately: a `CryptoError` thrown inside
  // it would be run through `toCryptoError` a second time and come back as
  // kind 'unknown', because its `name` is 'CryptoError' rather than a
  // variant name. Every other function here that maps after a native call
  // has the same shape for the same reason.
  //
  // Destructured, not returned directly. See encryptEvent above.
  const { recoveryKey, accountData: written } = setup
  return {
    recoveryKey,
    accountData: written.map(entry => ({
      eventType: entry.eventType,
      // Parsed here rather than handed over as a string, so a product
      // sends an object to an endpoint that takes an object.
      content: parseContent(entry.content),
    })),
  }
}

/**
 * Restores this account's private signing keys from server-side storage.
 *
 * `secret` is **either** the passphrase {@link createRecovery} derived the
 * key from **or** the recovery key it returned. One parameter serves both,
 * so you do not have to ask your user which one they are holding.
 *
 * `accountData` is what you read back from your homeserver. Five events are
 * needed and a complete recovery has all five:
 * `'m.secret_storage.default_key'`, the `'m.secret_storage.key.<id>'` it
 * names, and `'m.cross_signing.master'`, `'m.cross_signing.self_signing'`
 * and `'m.cross_signing.user_signing'`. Fetch them with
 * `GET /_matrix/client/v3/user/{userId}/account_data/{eventType}`, or take
 * them out of a `/sync` response's global account data, which carries all
 * of them. Entries this call does not need are ignored, so passing more
 * than the five is fine.
 *
 * **Pass one reading of the account, not two joined together.** A
 * homeserver never serves two events of one global type, so where a
 * duplicate can come from is a caller concatenating an older snapshot with
 * a newer one, and the first of the two wins here. Do that across a
 * `createRecovery` and the older pointer is the one followed, which reports
 * `'recovery_key_incorrect'` for the secret your user actually has: a
 * refusal no amount of retyping resolves.
 *
 * **The key description's event type is not known in advance**, because it
 * ends in the key's own id. Read `'m.secret_storage.default_key'` first and
 * its `key` field is that id, so fetching one event at a time takes two
 * rounds. Taking the account data from a sync you already perform costs
 * none.
 *
 * # What this restores, and what it does not
 *
 * It restores the identity and, with it, every verification anyone else had
 * made of this account. That is the part a second device cannot give back
 * and the reason this call exists. It does **not** publish anything: the
 * recovered device still has to publish its own device keys and be signed
 * into the identity it has just rejoined, which is
 * {@link bootstrapCrossSigning} republishing on a device that now holds the
 * private keys.
 *
 * After it succeeds, {@link getIdentityStatus} reports `privateKeysHeld`.
 * That is the durable answer; a `'trust_changed'` signal for your own user
 * id follows on the next {@link receiveSyncChanges}, exactly as it does
 * when the keys arrive by gossip instead.
 *
 * # Refusals, and the one distinction your error message needs
 *
 * `'recovery_key_incorrect'` means the secret is wrong and the stored
 * recovery is intact. Ask again. Both halves of `secret` report it: a
 * mistyped passphrase, and a recovery key with a character wrong, whatever
 * the stored key description does or does not carry. That second case is
 * the one worth naming, because a recovery written by another client need
 * not describe a passphrase at all, and this refusal is what a user with a
 * typo must be shown rather than the one below.
 *
 * `'recovery_data_malformed'` means no secret will ever open it. Stop
 * asking, and set recovery up again from a device that still holds the
 * keys. What lands here is damaged or unreadable account data, and also a
 * recovery written for an identity this account has since replaced.
 *
 * **These two are never folded together, and your product should not fold
 * them either.** Telling a user with a typo that their identity is
 * destroyed sends them to do the one thing that destroys it; telling a user
 * whose recovery really is unreadable that their passphrase is wrong leaves
 * them retyping forever. The line is drawn by the MAC stored beside the key
 * description, which is what a wrong secret fails and damaged data does not
 * reach.
 *
 * `'recovery_not_set_up'` means the account data you handed over carries no
 * complete recovery. Either this account has none, or you did not fetch all
 * of it, or its `'m.secret_storage.default_key'` has been **cleared** and
 * now points at nothing. This library sees only what it was given, so it
 * cannot tell those apart, and the list above is what to check.
 *
 * **A cleared pointer belongs here and not with the two refusals above**,
 * and the difference matters to your user. `PUT {}` is the only way the
 * client-server API can delete an account data event, so a cleared pointer
 * is what a half-finished replacement leaves behind: the key description
 * and every ciphertext are still on your homeserver, and writing the
 * pointer back makes the same passphrase work again. Nothing has been
 * destroyed, so do not show your user the sentence for
 * `'recovery_data_malformed'`, which sends them to set recovery up again
 * and is the one action that would destroy it.
 *
 * `'account_keys_not_fetched'` and `'identity_not_known'` are the same pair
 * {@link bootstrapCrossSigning} and {@link requestSelfVerification} report,
 * and they are checked before the passphrase is even derived. Importing a
 * private key checks it against the account's **published** identity, so
 * this call needs a `'keys_query'` for your own account answered first. The
 * refusal queues that query itself, so the remedy is the ordinary loop:
 * drain, send, report sent, call this again.
 */
export async function recoverIdentity(
  secret: string,
  accountData: AccountDataEntry[],
): Promise<void> {
  const entries = accountData.map(entry => ({
    eventType: entry.eventType,
    content: stringifyOrMalformed(entry.content),
  }))
  try {
    await nativeRecoverIdentity(secret, entries)
  } catch (e) {
    throw toCryptoError(e)
  }
}

/**
 * The inverse of {@link stringifyOrMalformed}, for account data content the
 * native side produced.
 *
 * Separate from the `try`/`catch` around the native call in
 * {@link createRecovery}, so that a parse failure is reported as a
 * malformed payload rather than as whatever the last native error happened
 * to be.
 */
function parseContent(json: string): unknown {
  try {
    return JSON.parse(json)
  } catch {
    throw toCryptoError({ name: 'MalformedPayload' })
  }
}

/**
 * **Not implemented, and not waiting on anything.** Rejects with kind
 * `'not_implemented'`. {@link createRecovery} is the call that does this
 * job, and it is the one to use.
 *
 * The signature has been frozen since the first milestone: a passphrase in,
 * a `Uint8Array` out. What has become clear since is that no such byte
 * array exists in Matrix. `matrix-sdk-crypto` provides the **payload** and
 * not the **container**: `export_secrets_bundle` yields the three signing
 * seeds as plain JSON, neither encrypted nor derived from a passphrase, and
 * its two passphrase primitives are the wrong shape for wrapping it. One is
 * the session-key export format, which is a different payload. The other is
 * secret storage itself, whose salt and iteration count belong in account
 * data rather than inside a byte array.
 *
 * So the container would be a format **this library invented**, and no
 * other Matrix client would read it. That is a defensible thing to build
 * for "move my identity to my other phone over a cable", and the wrong
 * thing to hand anyone who expects a Matrix recovery key. Since
 * {@link createRecovery} delivers the interoperable form, shipping a
 * private one beside it would invite exactly that confusion, so these two
 * stay unimplemented on purpose rather than pending.
 *
 * If you need the identity on a second device you still have, that is
 * {@link requestSelfVerification}. If you need it after the first one is
 * gone, that is {@link recoverIdentity}.
 */
export function exportSecrets(_passphrase: string): Promise<Uint8Array> {
  return notImplemented('exportSecrets')
}

/**
 * **Not implemented, and not waiting on anything.** Rejects with kind
 * `'not_implemented'`. The other half of {@link exportSecrets}; see that
 * function for why neither is coming, and for what to use instead.
 */
export function importSecrets(
  _bundle: Uint8Array,
  _passphrase: string,
): Promise<void> {
  return notImplemented('importSecrets')
}

/** Algorithms this build can carry. Open by design; see spec section 6. */
export function getSupportedAlgorithms(): CryptoAlgorithm[] {
  return ['megolm', 'olm']
}

// M1b: the first genuine cryptographic value to cross the whole chain, not
// the probe's echo. Everything above it was a NotImplemented stub when this
// was written. Three are still stubs, and this comment used to point at a
// roadmap that listed them as deferred: `exportSecrets` and `importSecrets`
// are refused on purpose rather than pending, and `restoreCryptoMachine` is
// the only one of the three still waiting on anything.

export interface IdentityKeys {
  curve25519: string
  ed25519: string
}

export async function getDeviceIdentityKeys(
  userId: string,
  deviceId: string,
): Promise<IdentityKeys> {
  try {
    // Destructured, not returned directly: the M1 final review's deferred
    // item (`facade.ts:87`), applied here. A field added to the generated
    // record later must be a deliberate choice to expose through this
    // boundary, not something that leaks through unreviewed because it
    // structurally satisfies this function's own `IdentityKeys` shape. See
    // Global Constraints.
    const { curve25519, ed25519 } = await nativeDeviceIdentityKeys(
      userId,
      deviceId,
    )
    return { curve25519, ed25519 }
  } catch (e) {
    throw toCryptoError(e)
  }
}
