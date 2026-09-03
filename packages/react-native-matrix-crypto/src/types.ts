// Imported for the documentation in this file and used by nothing in it.
// `{@link}` resolves against what is in scope in the file it is written in,
// so without this every name below that sends a reader to a facade call is
// plain text in an editor's hover -- a link promising navigation it does not
// deliver. **This list has to grow when the docs below do**, and it did not:
// four links to the scannable-code calls were written into the comments here
// without being added, which is the defect this paragraph exists to prevent,
// committed under the paragraph itself. `scripts/assert-doc-links.sh` checks
// it now, in both languages. Type-only, so it is erased: no runtime import, and the cycle it
// makes with `facade.ts`, which imports the types below, exists only for the
// typechecker, which resolves it. `tsconfig.json` sets
// `noUnusedLocals: false`, which is what lets an import exist for a reader
// rather than for the compiler.
/* eslint-disable @typescript-eslint/no-unused-vars -- The import below is
   the paragraph above put into effect: these names are in scope so that the
   `{@link}`s resolve, and `scripts/assert-doc-links.mjs` fails the build if
   one of them is missing. ESLint sees an unused binding and would have them
   deleted; the gate that owns this question wants them kept, so the rule is
   switched off for this statement and nothing else in the file. */
import type {
  acceptVerification,
  confirmScan,
  getDeviceStatuses,
  getVerificationCode,
  getVerificationMaterial,
  getVerificationStage,
  markRequestSent,
  offerScannableCodes,
  receiveSyncChanges,
  startVerificationComparison,
  submitScannedCode,
} from './facade'
/* eslint-enable @typescript-eslint/no-unused-vars */

/**
 * Opaque identifier for a cryptographic scope.
 *
 * Today this wraps a Matrix room id. Tomorrow it may wrap an MLS group id.
 * Nothing in the public API says "room", so spec section 6's agility
 * requirement holds by construction rather than by convention.
 */
export type CryptoScopeId = string & { readonly __brand: unique symbol }

/**
 * The only way to construct a CryptoScopeId.
 * Note: this performs no runtime validation — the guarantee is compile-time only.
 */
export function asCryptoScopeId(raw: string): CryptoScopeId {
  return raw as CryptoScopeId
}

/**
 * Deliberately open. Adding 'mls' is an additive change and therefore a minor
 * version bump, per spec section 4bis.4. Consumers must handle unknown values.
 */
export type CryptoAlgorithm = 'megolm' | 'olm' | (string & {})

/**
 * Product-facing trust signal. Only 'verified' has cryptographic value.
 *
 * **Closed, unlike `CryptoAlgorithm` and `CryptoErrorKind`.** A product may
 * switch on this exhaustively, and is meant to: a trust decision with a
 * silent default branch is the shape this library exists to prevent.
 *
 * - `'unverified'` — this library holds the device's keys and has no reason
 *   to trust it beyond that. Every device reads this until a comparison
 *   finishes. A device an administrator has blacklisted reads it too: this
 *   build exposes no call that can set that state, so folding it here says
 *   exactly as much as this build can honestly say.
 * - `'recognized'` — **not produced by this build, and that is now a
 *   decision rather than a limit.** It is reserved for exactly one state:
 *   a device believable without a person having compared anything, because
 *   its owner signed it with their cross-signing identity. That state used
 *   to be out of reach; since `bootstrapCrossSigning` it is the ordinary
 *   one, and it arrives as `'verified'` instead. See below for why it is
 *   folded and what it costs you.
 *   Declared now because widening a closed union later breaks every
 *   consumer that switched on it exhaustively, and would do so precisely
 *   when a product had stopped expecting the shape to move. Write the
 *   branch; it will not run yet.
 * - `'verified'` — this library has reason to trust the device, **by any of
 *   three routes that this value does not tell apart**. A person compared
 *   a short authentication string on this device and on the far one, both
 *   said it matched, and the flow completed. *Or* a person pointed one
 *   device's camera at the other's screen and the side showing the code
 *   confirmed the scan, which is the same act with a camera in place of a
 *   comparison. *Or* the device is signed by its owner's cross-signing
 *   identity and this library has verified that identity, in which case
 *   nobody compared or scanned anything on this device at all. The last two
 *   are new in this release and the third is the ordinary one from now on.
 *   This said "either of two routes" while the second was being added, which
 *   is the second time the count here has gone stale. See
 *   {@link getDeviceStatuses}, including why your own device reads this from
 *   the moment it exists and therefore proves nothing.
 *
 * **This is about a device, not about an event.** A completed verification
 * does not change what a decrypted event says about its sender, by either
 * method, because the event path consults cross-signing and a verification
 * sets local trust. M3 design, section 7, question 6.
 *
 * ## Why `'recognized'` stays folded into `'verified'`
 *
 * Recorded here rather than left silent, because a value a product was told
 * to write a branch for and that then quietly never runs is worse than one
 * that was never declared.
 *
 * The mapping underneath asks a single boolean -- locally trusted, or signed
 * by an identity we have verified -- and there is no third answer to carry.
 * Splitting it would mean asking a different question of the layer below,
 * and it would mean that a device this library trusts for the second reason
 * stopped reading `'verified'` and started reading `'recognized'`. That is a
 * behaviour change in the direction that hurts: a product's "is this device
 * trusted" branch would silently stop matching devices it had been matching,
 * on the same release that changes what `'verified'` covers. One change to
 * this value per release is the most a consumer can reasonably follow.
 *
 * So the fold stays, and the cost is stated instead of hidden: **you cannot
 * ask this call whether a person compared a string with, or scanned a code
 * off, one particular device.** If your product needs that distinction, it has to record its own
 * verifications as it performs them, or ask
 * {@link EventEnvelope.senderVerification} the event-level question instead.
 * If a later release does split them, `'recognized'` is already in this
 * union, so that release adds no member and breaks no exhaustive switch --
 * which is what declaring it early bought.
 */
export type TrustState = 'unverified' | 'recognized' | 'verified'

/**
 * How far along a verification flow is.
 *
 * **Closed**, like {@link TrustState} and for the same reason: a product
 * branches on this to decide what to show, and a stage it has never seen
 * must be a compile error rather than a silent default.
 *
 * **`'code-scanned'` was added after `0.1.1`, and the compile error an
 * exhaustive `switch` gets from it is the feature rather than the cost.**
 * Adding a member to a closed union is a minor version bump: nothing
 * already decoded changes meaning, because the value behind each of these
 * strings is a wire ordinal and the new one was appended rather than
 * inserted. What a consumer gets is the compiler pointing at every place
 * that has to decide what to show for it, which is precisely what closing
 * this union bought and why the alternative -- a silent default -- was
 * rejected when it was closed.
 *
 * The members are listed in the order a flow meets them, which is not the
 * order the wire numbers them in: the layer underneath may only be appended
 * to, and says so at its own declaration.
 *
 * Deliberately coarser than the nineteen states the layer underneath
 * distinguishes, across three enums of its own: six for the request, seven
 * for a short-string comparison and six for a scanned code. What a caller
 * has to decide is which of a small set of things to do next, and every
 * distinction that does not change that answer is one this surface would be
 * inviting a product to branch on for no reason.
 *
 * **These were the short string's vocabulary alone, and a flow that went to
 * a scannable code was described in it for want of one of its own. That
 * limit is lifted.** `'code-scanned'` names the one state such a flow
 * reaches that a comparison never does, so it is no longer reported as the
 * nearest string stage, and {@link confirmScan} can be told apart from a
 * wait by reading {@link getVerificationStage} first. What stays folded is
 * the two ways a code flow can have done its part -- scanned the other
 * device's code, or confirmed that the other device scanned this one's --
 * which are one `'confirmed'` on purpose, because a person is being asked
 * to wait either way.
 *
 * - `'requested'` — asked for, by one side or the other, and not yet
 *   answered. The other side must call {@link acceptVerification}.
 * - `'ready'` — both sides have agreed, and either may now call
 *   {@link startVerificationComparison}. On a flow that negotiated codes,
 *   either may instead call {@link getVerificationCode} or
 *   {@link submitScannedCode}; nothing has to choose between the two, and
 *   the first move settles it.
 * - `'started'` — the flow has begun and nothing is waiting on this side.
 *   For a comparison the keys are not exchanged yet, so there is nothing to
 *   show; for a flow that became a code the code exists and nobody has read
 *   it off the screen, so keep it up. **A comparison that stays here has one
 *   of two causes, and they need opposite things done about them.** If the
 *   *other* side opened the comparison, their start is a question this side
 *   has not answered: call {@link acceptVerification} again, and only then
 *   wait. Otherwise the flow's requests were drained and never reported
 *   sent, and {@link markRequestSent} is what moves it. Which one you are
 *   in follows from who started: a side that never called
 *   {@link startVerificationComparison} and finds itself here is in the
 *   first. See {@link getVerificationMaterial}, which reports both as
 *   `'material_not_ready'`. **A flow that became a code also reports this**,
 *   and neither cause applies to it: on such a flow this stage is
 *   describing a code nobody has read off the screen yet, which is the
 *   first sentence of this bullet rather than a comparison that stalled.
 *   That flow is not stuck, and {@link getVerificationMaterial} tells it
 *   apart from the two by kind rather than by stage: it answers a code flow
 *   with `'wrong_stage'`.
 * - `'keys-exchanged'` — the short authentication string is available.
 *   Show it, and ask. Not reached by a flow proceeding by a code, because
 *   there is no string on one.
 * - `'code-scanned'` — the other device has read the code this one is
 *   showing. Ask the person whether that was really their other device, and
 *   call {@link confirmScan} when they say yes. **The one moment a flow with
 *   no string to compare asks a person anything**, and the counterpart of
 *   `'keys-exchanged'` for a code. Only the side that showed a code ever
 *   reads it: the side that scanned one is never scanned in turn.
 * - `'confirmed'` — this side has done what was asked of it and the other
 *   side has not finished. Said the strings match, or scanned the other
 *   device's code and told it so, or confirmed that the other device
 *   scanned this one's. All three mean the same thing to a person looking
 *   at a screen: wait.
 * - `'done'` — the flow finished and the other device now reads
 *   `'verified'` from {@link getDeviceStatuses}, whether both sides said
 *   the strings matched or one scanned the other's code and the side
 *   showing it confirmed. This said "both sides said so", which a scanned
 *   flow reaches this value without anybody doing.
 * - `'cancelled'` — over without a verification, whether a side refused, a
 *   side abandoned it, a scanned code was refused, or it timed out.
 */
export type VerificationStage =
  | 'requested'
  | 'ready'
  | 'started'
  | 'keys-exchanged'
  | 'code-scanned'
  | 'confirmed'
  | 'done'
  | 'cancelled'

/**
 * One symbol of a short authentication string, with the word for it.
 *
 * `description` is the protocol's own English word for the symbol. A
 * product showing these in another language looks the word up from the
 * symbol's position in the array, which is why both travel together.
 */
export interface SasEmoji {
  symbol: string
  description: string
}

/**
 * The short authentication string, in both of the forms the protocol can
 * produce.
 *
 * **Show one of these to a person and ask whether it matches what the other
 * person sees, out of band.** Comparing them programmatically across a
 * channel this flow itself established proves nothing: that channel is what
 * is being verified.
 *
 * **Treat this value as secret while the flow is open.** Anything that
 * learns it learns what an interposed party would need to answer the
 * comparison correctly. Do not log it, do not persist it, do not put it in
 * a crash report. The Rust core hand-writes a redacting debug format for
 * exactly this reason and cannot reach across this boundary to do the same
 * for JavaScript.
 *
 * `emoji` is optional and `decimals` is not, and that asymmetry belongs to
 * the protocol rather than being a convenience: the symbol form exists only
 * when both sides negotiated it, so a screen offering only symbols has a
 * live path with nothing to show. The digits are always there once the keys
 * are exchanged.
 */
export interface SasMaterial {
  emoji?: SasEmoji[]
  decimals: [number, number, number]
}

/**
 * A code for a person to hold up to another camera, in both of the forms a
 * product needs to draw one.
 *
 * **Two forms and not one, and the second is not a convenience.** `payload`
 * is binary and is not text: it carries two raw signing keys and a random
 * shared secret, and there is no string it can honestly be turned into. A
 * product handed only bytes reaches for a JavaScript component that draws a
 * code from a string, and draws a square that decodes to something else.
 * `modules` is the symbol these bytes were encoded into on the way out, at
 * the version and error-correction level the protocol's own encoder fixes
 * because mobile clients have trouble decoding otherwise, so a product that
 * draws the grid draws what the protocol meant rather than a re-encoding of
 * it.
 *
 * **Drawing it.** `modules` is row-major and has exactly `width * width`
 * entries; `true` is a dark square. A product draws `width` rows of `width`
 * squares, leaves the usual quiet margin around them, and shows it. There is
 * no image here and there never will be: this library draws nothing, and has
 * no business choosing a size, a colour or a margin for somebody else's
 * screen.
 *
 * **Treat this value as secret while the flow is open**, exactly as
 * {@link SasMaterial} is treated. The payload carries the shared secret the
 * whole method rests on, and the grid is that same secret drawn as squares.
 * Anything that learns either learns what an interposed party would need to
 * answer the flow as though it had read the screen. Do not log it, do not
 * persist it, do not put it in a crash report. The Rust core redacts its own
 * copy and cannot reach across this boundary to do the same here.
 */
export interface ScannableCode {
  /** The bytes the protocol defines. About 126 of them, binary. */
  payload: Uint8Array
  /** The side length, in squares, of the symbol below. */
  width: number
  /** The symbol, row-major, `width * width` entries. `true` is dark. */
  modules: boolean[]
}

/**
 * What your product can do with a scannable code, as the two separate facts
 * it really is.
 *
 * Handed to {@link offerScannableCodes}. Both fields are required and
 * neither has a default, which is deliberate and is the whole shape of this
 * type.
 *
 * ## Why this is not a boolean
 *
 * It was one, and the single boolean announced showing and scanning
 * together. So a product could say "codes, both directions" or "no codes at
 * all", and a product with a screen and no scanner had to claim a camera in
 * order to get a code at all. A real client on the other end takes that
 * claim at its word: it may answer by showing *its* code and waiting for
 * yours to be pointed at it, and a product with no scanner then leaves a
 * person holding a phone in front of a square nothing will ever read. No
 * error reaches either side, because nothing was asked of either library.
 *
 * So the question is put to you, in two parts, and neither part has an
 * answer this library is willing to guess:
 *
 * - `canShow` is true if your product can draw {@link ScannableCode.modules}
 *   on a screen for another device's camera;
 * - `canScan` is true if your product has a scanner, has the camera
 *   permission, and can hand the raw bytes it reads to
 *   {@link submitScannedCode}.
 *
 * **`canScan: true` when you cannot really scan is the expensive mistake**,
 * and it is expensive because nobody is told. `canShow: false` when you
 * meant true is the cheap one: {@link getVerificationCode} refuses with
 * `'code_not_offered'` on the first flow you try, in front of the developer
 * who can fix it in one line.
 *
 * ## A product with a screen and no scanner
 *
 * `{ canShow: true, canScan: false }`. The other side is then told it has no
 * camera to aim at this one, so **it cannot choose to show**: it scans, or
 * the two of you compare the short string. That is a choice removed from the
 * far side by a claim withheld here, and it is what makes this the truthful
 * answer rather than a cautious one.
 */
export interface CodeCapabilities {
  /** This product can draw a code on a screen for another device's camera. */
  canShow: boolean
  /** This product can read a code off another device's screen. */
  canScan: boolean
}

/**
 * The five fields `receiveSyncChanges` reads. Named as the native call names
 * them, not as a `/sync` response names them: the two vocabularies have no
 * member in common, and renaming here would only move the rename into a
 * place with no compile-time help.
 *
 * Every field is optional and defaults independently, native-side, when
 * absent. Omit a field the caller has nothing for; do not set it to
 * `undefined` explicitly instead -- `encryptionSlice` (in `facade.ts`) only
 * ever assigns a key it has a real value for, and a hand-built `SyncDelta`
 * should follow the same rule so `Object.keys` on the result means what it
 * looks like it means.
 */
export interface SyncDelta {
  to_device_events?: unknown[]
  changed_devices?: unknown
  one_time_keys_counts?: Record<string, number>
  unused_fallback_keys?: string[]
  next_batch_token?: string
}

/**
 * What this library knew about the sender of one decrypted event, at the
 * moment it decrypted it.
 *
 * **This is not {@link TrustState}, and the difference is why there are
 * two.** `TrustState` describes a *device*, and a completed comparison
 * changes it. This describes *one event's sender at one moment*, and a
 * completed comparison does not change it. Two subjects, two vocabularies.
 * Folding them would lose the difference between an unverified identity, an
 * unsigned device and a sender mismatch, which are three different things
 * for a product to do about one event.
 *
 * **Closed**, like `TrustState` and {@link VerificationStage}: switch on
 * `state`, then on `reason`, and the compiler tells you when a later
 * version adds a case.
 *
 * ## Which of these this release produces, and why the line falls where it
 * does
 *
 * The distinction is **whose** cross-signing identity a value depends on,
 * and it is not the distinction you would guess.
 *
 * **`'unverified_identity'` is produced by this release.** It depends on
 * the *sender's* identity, not on ours: the gate underneath asks only
 * whether the sending device carries a signature from a self-signing key
 * its own owner published, and this library is not consulted. So a peer
 * whose client has cross-signing set up already produces it here, whatever
 * this library holds, and that is most peers. Handle this branch. It is
 * not a rare state and it is not a future one.
 *
 * `'verified'` and `'verification_violation'` are the two that turn on
 * **our** side rather than the sender's. `'verified'` needs this library to
 * hold a cross-signing identity and to have signed the sender's with it;
 * `'verification_violation'` needs the sender's identity to have been
 * verified by us once and to have changed since.
 *
 * **`'verified'` arrives through this surface from this release, and the
 * history of why it did not is worth one paragraph.** It was unreachable by
 * construction while this library had no way to create an identity of its
 * own, which is what this paragraph used to say. Then the Rust core could
 * create one and the TypeScript surface could not reach the call, which is
 * what it said next. Both are now over: `createCrossSigningIdentity` makes
 * the account's first identity and `bootstrapCrossSigning` publishes the one
 * this device holds. The cryptography is proved where it can be, end to end against a
 * counterparty the test process does not control, by the core's own
 * `tests/verified_sender.rs`; that every step of it can be reached, in
 * order, through the functions this package publishes is what
 * `facade.test.ts` drives. So this branch runs. `'verification_violation'` is
 * the one still waiting, and it waits on a situation rather than on a
 * missing call: it needs a sender whose chain completed and whose identity
 * then changed. Write it anyway. They are declared because the union is
 * closed, and widening a
 * closed union later is a breaking change for every consumer that switched
 * on it exhaustively, and because the alternative to a complete type is not
 * a smaller true one but a different false one: a four-value type would say
 * that four values is all this vocabulary has, which is not true of what it
 * models.
 *
 * What arrives here today, without a count over it because a count is the
 * part of a claim most likely to go stale: `'verified'`, at the end of the
 * chain and nowhere else; `'unverified_identity'`; `'unsigned_device'`, the
 * ordinary case for a peer with no cross-signing identity of their own;
 * `'no_device'` in both its forms; and `'mismatched_sender'`.
 *
 * ### This paragraph was wrong in 0.1.0, and has been rewritten twice
 *
 * It said all three of `'verified'`, `'unverified_identity'` and
 * `'verification_violation'` were "NOT PRODUCED BY THIS RELEASE".
 * `'unverified_identity'` always was produced. That claim survived review
 * because no test in the repository had a cross-signed counterparty, so
 * nothing could contradict it, and it sounded like the two true sentences
 * standing next to it. If you read it and skipped the branch, that branch
 * is reachable and this is the correction.
 *
 * The other two sentences were true when they were written, and stopped
 * being true for a different reason: the library improved. That is the
 * lesson worth carrying rather than the specific mistake. A claim about
 * what a build cannot produce is a claim about every peer it might meet
 * and about every version of itself, so it needs re-reading whenever
 * either changes, and it will not fail a test on its own when it goes
 * stale.
 *
 * ## `'verified'` in particular
 *
 * **Completing a verification with someone does not make their events read
 * `'verified'`.** It makes their *device* read `'verified'` from
 * {@link getDeviceStatuses}, which is a different question with a different
 * answer. The decrypted-event path consults cross-signing; a short-string
 * comparison sets local trust.
 *
 * That stays true now that the library can cross-sign, and the gap it
 * leaves is wider than it looks. A comparison is one step of seven. The
 * signature it produces has to be uploaded and then fetched back before
 * any event can read `'verified'`, because nothing caches the signature
 * locally and the check underneath reads the store. A chain that stops one
 * step short returns success from every call, leaves the device reading
 * `'verified'`, and leaves every event from that device reading
 * `'unverified_identity'`, which is indistinguishable from never having
 * verified the sender at all. If your product needs "did this specific
 * event come from a device we have verified", it is this field that
 * answers, and the device-level one that will mislead you. M3 design,
 * section 7, questions 3 and 6; M4 design, section 3.1.
 *
 * ## `'mismatched_sender'` in particular
 *
 * The only member here reporting an act rather than an absence of evidence:
 * the event's claimed sender is not the owner of the session that encrypted
 * it. Decryption succeeded -- the ciphertext really was encrypted with a
 * session this device holds -- and the `sender` field is still false. Treat
 * it as an impersonation signal, not as a weaker `'no_device'`.
 */
export type SenderVerification =
  // REACHABLE THROUGH THIS SURFACE, and only at the end of the whole chain.
  // The event came from a device belonging to a user this library has
  // verified, the only state in which authenticity is guaranteed. It needs a
  // cross-signing identity of OUR OWN, signed over the sender's and then
  // fetched back into our own store; completing a comparison is one step of
  // that and does not produce it on its own. Every step is now a published
  // call, starting at `createCrossSigningIdentity` and then
  // `bootstrapCrossSigning`. This said NOT YET REACHABLE
  // through two milestones and for two different reasons, the second of
  // which was a missing bridge rather than missing cryptography; both are
  // over. See the type's doc comment above.
  | { state: 'verified' }
  // The sending device is known and carries no cross-signature. The ordinary
  // case for a peer whose client has no cross-signing identity, before and
  // after a comparison alike.
  | { state: 'unverified'; reason: 'unsigned_device' }
  // PRODUCED BY THIS RELEASE. The device is cross-signed by its owner and
  // that identity is one we have not verified. Needs a published master key
  // from THE SENDER and nothing from us, so it arrives from any peer whose
  // client has cross-signing set up. Handle this branch.
  | { state: 'unverified'; reason: 'unverified_identity' }
  // NOT YET REACHABLE THROUGH THIS SURFACE. The device is cross-signed,
  // that identity was verified once, and it is not the same identity now.
  // It sits one step PAST `'verified'` rather than beside it: it needs a
  // previous verification by us, so a sender has to have been fully
  // verified once before any event of theirs can read it.
  | { state: 'unverified'; reason: 'verification_violation' }
  // The claimed sender is not the owner of the session that encrypted the
  // event. An impersonation signal; decryption succeeded regardless.
  | { state: 'unverified'; reason: 'mismatched_sender' }
  // No device could be linked to the event: `'missing'` because none is in
  // the store, `'insecure_source'` because the key came from an imported
  // session, a legacy backup or an unsafe forward.
  | {
      state: 'unverified'
      reason: 'no_device'
      problem: 'missing' | 'insecure_source'
    }

/**
 * What `decryptEvent` requires of a sender's device before it hands an
 * event to the product. The one trust decision this library hands the
 * caller instead of making for it, and the reason both exist: whether the
 * product's users carry cross-signing identities is something the product
 * knows and this library cannot.
 *
 * **Closed, deliberately**, like `SenderVerification` and `TrustState`: a
 * product branching on a requirement has to be told when a value it has
 * never seen appears, rather than handed an open type that compiles either
 * way. Widening this union is a breaking change for every consumer that
 * switched on it exhaustively.
 *
 * **What every tightened tier checks, and what none of them checks.** The
 * sending device must be signed by its owner's cross-signing identity.
 * Whether this device has verified that owner is irrelevant to the two
 * tightened tiers -- they are about the sender's device being vouched for,
 * not about our opinion of the voucher, which is what
 * `EventEnvelope.senderVerification` reports after the fact. And local
 * trust is deliberately absent from the set, exactly as it is in the layer
 * underneath: a comparison or a scan sets local trust in a device, and no
 * tier takes it, so a carefully compared peer whose device carries no
 * cross-signature is refused by every tightened tier alike. A product whose
 * users verify devices without cross-signing identities should stay on
 * `'any'` and gate on `senderVerification` instead.
 *
 * **The default is `'any'`**, and that is this library's behaviour since
 * 0.1.0: it is the layer underneath's most permissive option, the one it
 * documents as "not recommended, per the guidance of MSC4153", kept as the
 * default because refusing events from unsigned senders is the product's
 * decision to make. A call that passes nothing gets it.
 */
export type SenderTrustRequirement =
  // Decrypt events from every sender's device, signed or not. The default.
  | 'any'
  // Decrypt events from a device signed by its owner's cross-signing
  // identity, and from legacy sessions whose sender this machine could not
  // record when the session was created. The tightening a product reaching
  // for "refuse unauthenticated senders" wants when it has pre-existing
  // sessions around: events from unsigned devices are refused, but history
  // that predates trust information keeps decrypting, reading
  // 'unsigned_device' or 'no_device'/'insecure_source' on the events that
  // pass on legacy grounds alone.
  | 'identity_signed_or_legacy'
  // Decrypt events from a device signed by its owner's cross-signing
  // identity, and nothing else. The strictest tier: events from legacy
  // sessions are refused along with events from unsigned devices, so a
  // product that has never imported history can take this tier directly.
  | 'identity_signed'

/** Typed envelope for an encrypted or decrypted event. */
export interface EventEnvelope {
  scope: CryptoScopeId
  /**
   * From `encryptEvent`, the group-session algorithm this build used.
   *
   * From `decryptEvent`, spec section 7.1: this library decrypts events, it
   * does not authenticate their senders. This value is read from the
   * incoming event, not independently verified, and is **unauthenticated
   * transport metadata** — treat it accordingly, not as a claim this
   * library has confirmed. This carried a milestone twice, and both have
   * now passed without the property changing: cross-signing has landed and
   * this value is still read from the incoming event and never re-derived.
   * It is not scoped to a milestone at all, so there is no version to wait
   * for. What cross-signing adds is {@link EventEnvelope.senderVerification},
   * a separate value, and not a promotion of this one.
   */
  algorithm: CryptoAlgorithm
  eventType: string
  /**
   * **Do not trust this field's name on the decrypt path.**
   *
   * From `encryptEvent`, this is the wire ciphertext: send it as the
   * content of your `m.room.encrypted` event.
   *
   * From `decryptEvent`, this is the **plaintext** that call just
   * recovered. One type describes both directions, so the name comes from
   * the direction that produced it first and is wrong for the other. There
   * is no second field to read instead.
   *
   * The consequence is a handling rule, not a naming quibble. Everything a
   * product does to plaintext, it must do to this value on the decrypt
   * path: do not log it, do not persist it unencrypted, do not put it in a
   * crash report or an analytics event, and do not let it into a `console`
   * statement written while debugging. The Rust core hand-writes a
   * redacting `Debug` for exactly this reason, and it cannot reach across
   * this boundary to do the same for JavaScript.
   */
  ciphertext: Uint8Array
  /**
   * Fully qualified `@user:server`, verbatim. Spec section 10.
   *
   * From `encryptEvent`, this device's own identity — authenticated by
   * definition.
   *
   * From `decryptEvent`, spec section 7.1: this library decrypts events, it
   * does not authenticate their senders. This is the sender the
   * homeserver delivered on the outer, not-yet-decrypted event, not a
   * value this library independently confirmed, and it is
   * **unauthenticated transport metadata**. Verifying the sending device
   * does not change that, by string or by scanned code; cross-signing is
   * what would, and it has landed without moving this field, which is the
   * point `senderVerification` forty lines below makes at length. This said
   * "and it is M4", naming a milestone as a thing still to come. A
   * product that reads it as the cryptographic sender of a successfully
   * decrypted event has assumed something this library does not provide,
   * and that
   * assumption is the shape impersonation takes. Read it together with
   * `senderVerification` below, which is what says how much of a claim it
   * is -- and note that `'mismatched_sender'` is exactly the case where
   * this string is a lie decryption did not catch.
   */
  sender: string
  /**
   * What this library knew about the sender of this event **at the moment
   * it decrypted it** -- see {@link SenderVerification}, including which of
   * its values cannot arrive here yet and why completing a verification
   * does not change this one. That said "which three of its values" until
   * M4, and the count is the kind of detail that goes stale in silence, so
   * there is no count here now.
   *
   * **Present on every successful `decryptEvent`. Absent from
   * `encryptEvent`.** The same one-type-two-directions caveat `algorithm`
   * and `sender` above each carry, in its strongest form: those two hold a
   * real value in both directions, and this one is *discarded* on the
   * encrypt path rather than missing from it. The layer underneath does
   * receive a value when it encrypts, and that value is `'verified'` --
   * upstream reporting on this device's own keys, which is a statement
   * about a *device* and is true of a machine that has never verified
   * anything. It is dropped rather than forwarded onto the field a
   * decrypted event reads. This used to add "the one word this release
   * cannot honestly attach to an event", which stopped being true when the
   * core learned to cross-sign; the asymmetry it was pointing at is real
   * and survives the correction. On the encrypt path the word costs
   * nothing and means nothing. On the decrypt path it costs the whole
   * seven-step chain, which is why forwarding the free one would be a
   * fabrication rather than a shortcut. Absent here means "this question
   * was not asked of this event".
   *
   * **It is a snapshot, and it can go stale.** Upstream defines it as the
   * state of the sending device at the time of decryption: it "may change
   * in the future if a device gets verified or deleted", and callers who
   * persist it are told to mark it dirty when a device change is received
   * down the sync. That obligation is yours once you hold this value. The
   * trigger is already in your hands -- `device_lists.changed` on the
   * `/sync` response you pass to {@link receiveSyncChanges} -- and nothing
   * in this library re-derives a stored value for you. A record that looks
   * static is not the same as a fact that stays true.
   *
   * **Going stale is the only direction it moves. It does not improve.**
   * Verifying someone changes what their *next* messages say, not what
   * their old ones said. The value belongs to the session the event was
   * encrypted with, it is computed once when that session's key arrives,
   * and nothing recomputes it for a session whose sender was already
   * identified: so a message decrypted while its sender was merely
   * cross-signed keeps reading `'unverified_identity'` until that session
   * is replaced, however thoroughly you verify them afterwards. Design a
   * badge that says "from here on" rather than one that backfills a
   * conversation, because the backfill will not arrive. Asserted end to
   * end, not inferred: the core's
   * `tests/verified_sender.rs::history_does_not_improve_when_the_sender_is_verified_later`
   * decrypts one event before a full verification and the same event after
   * it, and then a message on a session created afterwards to show that
   * the verification really did take effect.
   */
  senderVerification?: SenderVerification
}
