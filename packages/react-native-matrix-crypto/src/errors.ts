import type { CryptoScopeId } from './types'
// Imported for the documentation below and used by nothing here, on the
// same terms `types.ts` and `signals.ts` state at length: `{@link}` resolves
// against what the file has in scope, so a name the comments send a reader
// to has to be one of them. Type-only, so it is erased.
/* eslint-disable @typescript-eslint/no-unused-vars -- The import below is
   the paragraph above put into effect: these names are in scope so that the
   `{@link}`s resolve, and `scripts/assert-doc-links.mjs` fails the build if
   one of them is missing. ESLint sees an unused binding and would have them
   deleted; the gate that owns this question wants them kept, so the rule is
   switched off for this statement and nothing else in the file. */
import type { bootstrapCrossSigning } from './facade'
/* eslint-enable @typescript-eslint/no-unused-vars */

/**
 * Deliberately open, per spec section 4bis.4: a new variant is a minor bump,
 * so every consumer must have a default branch.
 */
export type CryptoErrorKind =
  | 'missing_key'
  | 'unshared_session'
  // The policy half of the withheld-code split (G26 in the milestone's own
  // ledger): `m.blacklisted` and `m.unauthorised` are the sender's own
  // deliberate refusal, which no retry can ever change, so this kind is
  // deliberately absent from RETRIABLE below -- unlike its sibling
  // 'unshared_session', which keeps every other withheld code and stays
  // retriable.
  | 'session_refused'
  | 'unknown_device'
  // The other half of what 'unknown_device' used to fold, split out the day
  // `decryptEvent`'s sender trust requirement became the caller's to
  // choose: the device is fine and does not clear the trust bar the call
  // required. A policy gap, not a broken event -- the user fixes it by
  // verifying the device, or the product by relaxing the requirement it
  // asked for, which is the opposite of what 'unknown_device' now means
  // (provenance broken, nothing fixes it). Deliberately absent from
  // RETRIABLE below: the same call with the same requirement fails the
  // same way every time.
  | 'sender_not_trusted'
  // Forward scaffolding, not dead: nothing produces this. Device
  // verification landed and did not produce it, and neither did
  // cross-signing, which was the blocker this comment used to name and
  // which has since landed too; a second method of verifying, by a scanned
  // code, has landed since and did not produce it either. **No milestone is
  // named here on purpose**, since every one named so far came and went
  // with the comment unchanged: this kind stays declared and unproduced
  // until something produces it, and it stays in the union rather than being
  // silently dropped or silently absent -- the same treatment
  // 'not_implemented' gets in KIND_BY_NAME. If it turns out never to be
  // needed, remove it and say so; silence about which is not an option.
  | 'revoked_device'
  | 'undecryptable'
  // A payload this library was handed did not parse: `rawEvent`, a
  // `markRequestSent` response body, a sync delta. NOT a bad scope --
  // that is 'malformed_identifier' below, and telling the two apart is
  // the whole reason both exist. A malformed scope reported
  // 'malformed_payload' until the M2 final review, which sent a caller
  // whose payload was fine to go and inspect it.
  | 'malformed_payload'
  | 'unknown_request'
  // `markRequestFailed` was given a status that is not one a refused request
  // can carry. Accepted are 0, meaning nothing came back at all, and 300
  // through 599. The case this exists to catch is a **2xx**: it means
  // `markRequestFailed` and `markRequestSent` have been swapped, and since
  // reporting a refusal changes no state, saying nothing would let that
  // stand. It is the confusion this call can see in its own arguments, not
  // the only one the library catches: reporting a refused response through
  // `markRequestSent` is caught too whenever the body is not shaped like
  // that endpoint's answer. What neither can see is a refusal whose body is
  // shaped like one.
  | 'not_a_failure_status'
  | 'failed'
  // Reserved for genuine store corruption, which decryption work does not
  // currently detect; nothing maps to it yet. Kept distinct from
  // 'store_unavailable', which KIND_BY_NAME's own comment on ['Store', ...]
  // explains further.
  | 'store_corrupt'
  | 'store_unavailable'
  | 'mismatched_account'
  | 'rejected'
  // An identifier this library was handed did not parse: a `CryptoScopeId`
  // (which `asCryptoScopeId` never validates), a user id, a device id.
  | 'malformed_identifier'
  // ---- verification ------------------------------------------------------
  // The first three cross the FFI boundary; the three after them are
  // synthesised in this file's `toCryptoError` or in facade.ts, the same way
  // 'not_implemented' is, and have no Rust variant.
  //
  // A verification identifier that names no flow this process is taking
  // part in. Either it never named one, or the flow it named finished and
  // the library has since released it -- which happens the next time a flow
  // is *registered*, not on a timer. Registration is broader than starting
  // one: an inbound invitation announced down the signal channel registers,
  // and so does the first call made against a flow this process is not
  // already caching. A caller holding an id across any of those may see
  // this for a flow it watched complete.
  | 'unknown_flow'
  // The call is one this flow supports, but not at the stage it is at.
  // `getVerificationStage` says which stage that is; `startVerification-
  // Comparison` reads it for you and reports the two conditions below
  // instead where they apply.
  //
  // **On a flow proceeding by a scanned code this kind still folds two
  // conditions**, because `confirmScan` answers both "nobody has scanned
  // this yet" and "this flow is over" with it, and those want opposite
  // things done about them. The stage tells them apart, which it could not
  // when this fold was written: `'started'` is nobody has scanned yet,
  // `'code-scanned'` is the one stage that call succeeds at, and `'done'`
  // or `'cancelled'` is over. Read it before calling rather than after.
  | 'wrong_stage'
  // The keys are not exchanged, so there is no string to show yet. **Two
  // causes, and they need opposite things done about them** -- read
  // `getVerificationStage`, which is what tells them apart:
  //
  //   - stage `'started'` and *the peer* opened the comparison: their start
  //     is a question this side has not answered. Answer it with a second
  //     `acceptVerification`. Pumping never fixes this one, and a product
  //     that only pumps waits forever.
  //   - otherwise, the outbound pump was drained and never resolved: the
  //     underlying state machine advances on `markRequestSent`, so a caller
  //     that skips it parks the flow here permanently.
  //
  // Still two after verification by a scannable code arrived, and that was
  // checked rather than assumed: a flow proceeding by a code holds no
  // comparison at all, so `getVerificationMaterial` refuses it with
  // 'wrong_stage' before it can reach either cause above.
  //
  // Deliberately absent from RETRIABLE below: retrying the same call
  // changes nothing at all under either cause.
  | 'material_not_ready'
  // `startVerificationComparison` on a flow the *other* side already
  // started. Not a failure of the verification -- but not nothing to do
  // either: their start is a question, so answer it with a second
  // `acceptVerification` and then wait for the string. Split out from
  // 'wrong_stage' because the sentence a product shows for it is the
  // opposite of the one below.
  | 'comparison_already_started'
  // `startVerificationComparison` on a flow that is over, whether finished
  // or refused. Nothing to carry on with; start a new one.
  | 'verification_ended'
  // `confirmVerification` was handed material that is not the material the
  // flow currently holds. See that function's own doc comment: the argument
  // exists so a product cannot confirm a comparison it never showed.
  //
  // **That guard belongs to this one call and not to the surface.**
  // `confirmScan` is the other confirmation here and takes no material,
  // because a code flow has none to hand back: what a person recognised is
  // a device that scanned, and nothing crosses this boundary that could
  // stand for it. The obligation to ask a person first is identical; only
  // the mechanical check is absent.
  | 'material_mismatch'
  // ---- the signing identity ----------------------------------------------
  // Both cross the FFI boundary, and both are `bootstrapCrossSigning`
  // refusing rather than failing. They are kept apart because their remedies
  // are opposite: one is a round of the ordinary pump loop, the other is a
  // thing this release cannot do at all.
  //
  // This library cannot yet say what identity this account has, so it cannot
  // know whether publishing would destroy one. The call queues a key query
  // as it refuses, so the usual remedy is drain, send, report sent, call
  // again. Deliberately absent from RETRIABLE below, for
  // 'material_not_ready''s reason: calling again without pumping in between
  // returns this forever.
  //
  // **That remedy has a case where it never terminates, and
  // `getIdentityStatus` is what says so.** This kind covers two situations:
  // nobody has asked, and the query was asked and answered by a server whose
  // answer settled nothing. The second is what a homeserver sends for a user
  // it does not know, which the Matrix specification prescribes, and what a
  // real Synapse sends when the server-name half of the account id differs
  // in case from its own. Read `accountKeysAnswerUnsettled`: false means
  // pump and call again, true means stop pumping and check the account id
  // against the canonical `user_id` your login returned. Nothing is
  // destroyed while it is true.
  | 'account_keys_not_fetched'
  // The account has a signing identity whose private keys this device does
  // not hold. There is no remedy through that call and there should not be:
  // this device joins that identity, it does not replace it, and replacing
  // it would reset the trust of everyone who had verified the old one.
  | 'identity_already_exists'
  // The mirror image of the kind above, and the third refusal on this
  // surface that turns on the same question: the server has been asked and
  // named no identity for this account. Deliberately absent from RETRIABLE
  // below: calling again changes nothing until an identity exists.
  //
  // **Five calls report it and they want the same thing done, which is a
  // decision rather than a retry.** `requestSelfVerification` reports it
  // because there is no identity to join. `bootstrapCrossSigning` reports it
  // because there is none to publish; it used to create one at this point,
  // and that is what an honest server plus ordinary two-device timing turned
  // into a creation over an identity another device had just published.
  // `recoverIdentity` reports it because an import is checked against the
  // account's published identity and there is none. And
  // `getVerificationCode` and `submitScannedCode` report it because a
  // scannable code carries this account's signing keys and there are none to
  // carry. This said two, which was the whole list on the branch that wrote
  // it and not on the one it landed in. The answer to all five is
  // `createCrossSigningIdentity`, and it belongs where your product has
  // decided this account should be getting its first identity, not in the
  // handler that caught this.
  | 'identity_not_known'
  // ---- server-side recovery ----------------------------------------------
  // All five cross the FFI boundary. `recovery_key_incorrect` and
  // `recovery_data_malformed` are the pair this surface exists to keep
  // apart, and the pair a product's error message turns on. This said "all
  // four" while five stood under it, and `KIND_BY_NAME` below already knew
  // there were five: `recovery_already_exists` was appended to the block
  // and not to the sentence over it.
  //
  // `createRecovery` on a device that does not hold all three private
  // signing keys. There is nothing to write; `getIdentityStatus` says
  // whether the remedy is to create an identity or to join one.
  | 'private_keys_not_held'
  // The account data handed to `recoverIdentity` carries no complete
  // recovery. Either this account has none, or not all of it was fetched;
  // that call's own doc comment names the five events a complete one has.
  // This library sees only what it was given, so it cannot tell the two
  // apart, and says so rather than guessing.
  | 'recovery_not_set_up'
  // The passphrase or recovery key does not open the stored recovery, which
  // is otherwise intact. **The one refusal on this surface a user fixes by
  // typing again**, which is why it is not folded into the kind below.
  // Deliberately absent from RETRIABLE: retrying the same call with the same
  // secret fails the same way every time, and what resolves it is a
  // different secret rather than a repeat.
  | 'recovery_key_incorrect'
  // The stored recovery cannot be read, so no secret will open it: damaged
  // or unparseable account data, and also a recovery written for an identity
  // this account has since replaced. The remedy is to set recovery up again
  // from a device that still holds the keys.
  //
  // Folding this with 'recovery_key_incorrect' is the defect both exist to
  // prevent, and it goes wrong in both directions: a user with a typo told
  // their identity is destroyed does the one thing that destroys it, and a
  // user whose recovery really is unreadable retypes a correct passphrase
  // forever.
  | 'recovery_data_malformed'
  // `createRecovery` was handed account data that already names a recovery.
  // It will not write over one, because it cannot tell a user replacing
  // their own passphrase from a product about to invalidate the recovery key
  // another Matrix client gave this user and told them to keep. See that
  // call for the remedy, which is a deliberate clear-then-write rather than
  // a retry.
  | 'recovery_already_exists'
  // ---- verification by a scannable code ----------------------------------
  // The *other* user has no signing identity, so no code can name them.
  // Deliberately not folded with 'identity_not_known', which says the same
  // about this account: the remedies point at different people. A product
  // that showed one sentence for both would send half its users to set up
  // something that is not broken.
  | 'peer_identity_not_known'
  // This build did not offer to show a code on this flow, so there is
  // nothing for it to produce. Not a stage: no amount of waiting changes it.
  // `offerScannableCodes({ canShow: true, ... })`, before the next flow, is
  // the whole of the remedy.
  //
  // **It used to carry a second cause** as well, the far side having no
  // camera, and told a product to work out which from the switch it had set.
  // That was sound while the switch was one boolean and stopped being sound
  // the moment it became two facts: a product that answered `canShow: true,
  // canScan: false`, correctly and deliberately, is exactly the product that
  // advice sent to go and re-check whether it had asked for codes at all.
  // The far side's half is `'peer_cannot_scan'` below.
  | 'code_not_offered'
  // The other device did not say it can scan, so no code this side draws can
  // be read by it. **Nothing your product can do changes that, and waiting
  // will not**: show the short authentication string instead, which both
  // sides always announce.
  //
  // The ordinary way to meet this is two code-showing products with no
  // scanner between them, which is what two of the same product on one
  // account are. It is also what every client that speaks only the short
  // string looks like.
  //
  // Before this kind existed, such a flow reported `'code_not_offered'`
  // while its request was ready and `'wrong_stage'` once it had moved on to
  // anything else. The second is a complaint about a stage in answer to a
  // question about methods: it says wait or start again, and waiting and
  // starting again are the two things that cannot help.
  | 'peer_cannot_scan'
  // A scanned payload decoded, named this flow, and carries keys that are
  // not the ones this side holds for the device on the other end. **The
  // narrowest of the four, and the only one that can mean something is wrong
  // rather than that a camera was aimed badly**: it is what an interposed
  // party showing their own code looks like, and also what a device whose
  // keys were fetched before they were rotated looks like. Nothing here can
  // tell those apart, and the answer is the same either way: refuse, and
  // verify again from a fresh request.
  //
  // **It means only that.** It folded the three kinds below until the
  // payload gained a surface to cross on, and it folded a fourth condition
  // for longer: a peer device this side has no record of at all, which is
  // neither a mismatch nor suspicious and is fixed by the retry this kind
  // tells a product not to attempt. That one reports 'unknown_device' now.
  | 'scanned_code_refused'
  // The scanned bytes are not one of these codes at all: no header of ours,
  // or a version or mode this library does not speak. A camera pointed at
  // some other square -- a link, a network password -- or a client speaking
  // a revision of the format this release does not implement. What a product
  // says: point the camera at the code the other device is showing.
  | 'scanned_code_unrecognised'
  // The scanned bytes did not survive whatever brought them here: they ran
  // out early, or the identifier inside is not text, or the keys are not
  // keys. **The signal that a product's scanner is handing this library a
  // decoded string rather than raw bytes**, which is the most likely way
  // `submitScannedCode` is misused: the payload is binary, most scanner
  // libraries offer a `string`, and a string round trip replaces every byte
  // that is not valid text. Two sentences at once -- to a person, that code
  // did not come through; to whoever wrote the product, your scanner is
  // giving us text.
  | 'scanned_code_malformed'
  // A well-formed code, for a different verification than the one it was
  // handed to. Two flows open and the camera read the wrong screen, or a
  // code from a flow since replaced. Nothing is damaged and nothing is
  // suspicious, which is why it is not 'scanned_code_refused': a product
  // that alarmed a person here would be alarming them about their own
  // mis-aim.
  | 'scanned_code_for_another_flow'
  | 'not_implemented'
  | 'not_initialised'
  | 'already_initialised'
  | 'unknown'
  | (string & {})

export interface CryptoError extends Error {
  kind: CryptoErrorKind
  /**
   * **Always `undefined` in every release so far.** Declared, and never
   * populated: every `SessionFfiError` variant is fieldless by
   * construction, so nothing on the decryption path can carry a scope
   * across the FFI boundary for `toCryptoError` to find. See `sender` below
   * for why the fields stay.
   *
   * A product handling a failed `decryptEvent` must therefore take the
   * scope from the call it made, not from the error it caught.
   */
  scope?: CryptoScopeId
  /**
   * Fully qualified `@user:server`, verbatim. Spec section 10.
   *
   * **Always `undefined` in every release so far**, for the same reason as
   * `scope` above: `SessionFfiError` is fieldless throughout,
   * `MachineFfiError` carries only `detail` and `ProbeFfiError` only
   * `reason`, so no FFI error variant can carry a sender. Both fields are optional and both are read
   * defensively by `toCryptoError`, so a later milestone that starts
   * populating them is additive rather than breaking. That is why they are
   * declared now and said to be empty, rather than removed and re-added.
   *
   * Note that a sender would not become authoritative merely by appearing
   * here. Spec section 7.1 applies to it exactly as it applies to
   * `EventEnvelope.sender` in `types.ts`: a sender is unauthenticated transport
   * metadata, and **completing a device verification does not change
   * that.** This used to say "until device verification lands", which
   * named a condition that has since been met and is not the one that
   * matters: a verification sets *local* trust in a device, whether the two
   * people compared a short string or one of them scanned a code, and the
   * path that decides what an event says about its sender consults
   * cross-signing instead. It then said cross-signing was still to come and
   * that the README retracted the claim in the same terms. Both halves have
   * been overtaken: `bootstrapCrossSigning` publishes an identity from this
   * surface, and a second method of verifying arrived after that. Neither
   * moved this field, which is the point the paragraph was making and the
   * reason it is corrected rather than struck.
   */
  sender?: string
  /** The bridge reports transience. The product layer decides what to do. */
  retriable: boolean
}

const BRAND = Symbol.for('react-native-matrix-crypto.CryptoError')

const KIND_BY_NAME = new Map<string, CryptoErrorKind>([
  ['Rejected', 'rejected'],
  // The one entry with no Rust variant, and never will have one: synthesised
  // in TypeScript by facade.ts's `notImplemented` helper for every
  // still-stubbed function, so it never crosses the FFI boundary at all.
  // Not dead scaffolding like the `RevokedDevice`/`StoreCorrupt` entries two
  // reviews found and removed -- this one is reachable today, from the three
  // functions that still refuse in JavaScript. That set has shrunk to
  // `exportSecrets`, `importSecrets` and `restoreCryptoMachine`, and the
  // first two are refused on purpose rather than pending, so calling them
  // "deferred" would say the wrong thing about why.
  ['NotImplemented', 'not_implemented'],
  ['MissingKey', 'missing_key'],
  ['UnsharedSession', 'unshared_session'],
  ['SessionRefused', 'session_refused'],
  // Reached from two enums, like `MalformedIdentifier` below.
  // `SessionFfiError::UnknownDevice` is a device that did not meet the trust
  // level a decryption required; `MachineFfiError::UnknownDevice` is a
  // well-formed pair of identifiers naming a device this machine has never
  // been told about, which `requestVerification` reports. One entry serves
  // both because this map is keyed on the variant name alone, and what a
  // caller does about either is the same: query that user's devices through
  // the pump and try again.
  ['UnknownDevice', 'unknown_device'],
  // The split half, and what its presence here is worth: without this
  // entry the newly-reachable `SessionFfiError::SenderNotTrusted` arrives
  // as kind 'unknown' with the message "crypto error: unknown", which is
  // the failure mode this map exists to prevent and which no test on the
  // Rust side can see. It matters most here because the split exists so a
  // product can tell "verify this person to read this" from "this event's
  // provenance is broken", and this map is the only thing that decides
  // whether it can.
  ['SenderNotTrusted', 'sender_not_trusted'],
  ['Undecryptable', 'undecryptable'],
  // The remaining three `SessionFfiError` variants (Task 7): `raw_json`
  // that did not parse, an upstream crypto operation that failed for a
  // reason spec section 7 forbids echoing, and a `mark_request_sent` id
  // that does not match anything `take_outgoing_requests` handed out.
  ['MalformedPayload', 'malformed_payload'],
  ['Failed', 'failed'],
  ['UnknownRequest', 'unknown_request'],
  // `markRequestFailed` handed a status that is not a refusal. See the
  // kind's own comment in the union above for why a 2xx is the case that
  // matters.
  ['NotAFailureStatus', 'not_a_failure_status'],
  // `MachineError::Store` means the store could not be opened -- often a
  // wrong passphrase or a permissions problem, not damaged data. Mapping it
  // to 'store_corrupt' would send a product down a destructive recovery path
  // over what might just be a typo'd passphrase. 'store_corrupt' stays in
  // the CryptoErrorKind union for genuine corruption, which decryption work
  // could detect; nothing maps to it yet, and nothing in M2 or M3 came to.
  // It stays declared rather than removed, on the same rule as
  // 'revoked_device' above.
  ['Store', 'store_unavailable'],
  // A parked finding from Task 2's review: opening a store that belongs to
  // a different account (a different user id, device id, or both) is a
  // recoverable configuration mistake -- point this config at the right
  // store, or the right account -- not a storage failure like a full disk,
  // which reconfiguring cannot fix. Kept out of 'store_unavailable' so a
  // product can tell the two apart, matching Task 6's own decryption kinds:
  // being able to run this classification once is not a reason to leave a
  // distinguishable condition unclassified. Not in RETRIABLE: retrying with
  // the same mismatched config fails the same way every time.
  ['MismatchedAccount', 'mismatched_account'],
  // Reached from two enums, not one. `MachineFfiError::MalformedIdentifier`
  // carries a `detail` and covers a bad user or device id at machine
  // creation; `SessionFfiError::MalformedIdentifier` is fieldless and
  // covers a `scope` (or a user id given to `shareScopeKey`) that does not
  // parse. This map is keyed on the variant name alone, so one entry
  // already served both the moment the second existed -- which is
  // convenient and easy to miss, since nothing in this file names either
  // enum. errors.test.ts asserts both, and asserts they agree.
  ['MalformedIdentifier', 'malformed_identifier'],
  ['NotInitialised', 'not_initialised'],
  ['AlreadyInitialised', 'already_initialised'],
  // The three `MachineFfiError` variants the verification surface added.
  // Without these entries every one of them arrives as kind 'unknown' with
  // the message "crypto error: unknown", which is the failure mode this map
  // exists to prevent and which no test on the Rust side can see: the core
  // proves the *right error* is produced, and this map is the only thing
  // that decides whether a product can tell it apart from any other. That
  // matters most for 'material_not_ready', which is the loud form of the one
  // way this flow can otherwise fail silently.
  ['UnknownFlow', 'unknown_flow'],
  ['WrongStage', 'wrong_stage'],
  ['MaterialNotReady', 'material_not_ready'],
  // Three more entries with no Rust variant, like 'NotImplemented' above,
  // synthesised in facade.ts. The first two are what
  // `startVerificationComparison` reports in place of the single
  // `WrongStage` the layer underneath can produce for three different
  // situations; the third is `confirmVerification` refusing material that
  // is not what the flow is showing. Named here rather than built inline so
  // there is one list of every kind this library can produce.
  ['ComparisonAlreadyStarted', 'comparison_already_started'],
  ['VerificationEnded', 'verification_ended'],
  ['MaterialMismatch', 'material_mismatch'],
  // The two `MachineFfiError` variants the signing identity added. They were
  // declared on the Rust side one task before anything returned them, so
  // until `bootstrapCrossSigning` was bridged there was no way to notice
  // they were missing here -- and the symptom would have been the one this
  // map exists to prevent: both refusals arriving as kind 'unknown' with the
  // message "crypto error: unknown", indistinguishable from each other and
  // from every unmapped failure, on the one call whose two refusals need
  // opposite things done about them.
  ['AccountKeysNotFetched', 'account_keys_not_fetched'],
  ['IdentityAlreadyExists', 'identity_already_exists'],
  // The third of that group, added with self-verification. It completes a
  // triangle rather than a pair: `identity_already_exists` says the account
  // has an identity this device is not part of, and this says the account has
  // none at all. A product told the wrong one either waits for an identity
  // that does not exist or refuses to create the one that is missing.
  ['IdentityNotKnown', 'identity_not_known'],
  // The four `MachineFfiError` variants server-side recovery added. Without
  // these entries every one of them arrives as kind 'unknown' with the
  // message "crypto error: unknown", which is the failure mode this map
  // exists to prevent and which no test on the Rust side can see. It matters
  // most for the middle pair: the Rust side proves a wrong passphrase and an
  // unreadable recovery are told apart, and this map is the only thing that
  // decides whether a product can act on the difference.
  ['PrivateKeysNotHeld', 'private_keys_not_held'],
  ['RecoveryNotSetUp', 'recovery_not_set_up'],
  ['RecoveryKeyIncorrect', 'recovery_key_incorrect'],
  ['RecoveryDataMalformed', 'recovery_data_malformed'],
  // The fifth, added when `createRecovery` stopped writing over a recovery
  // the account already had. Without this entry a product would be told
  // 'unknown' on the one refusal whose whole purpose is to make it stop and
  // look.
  ['RecoveryAlreadyExists', 'recovery_already_exists'],
  // The first three `MachineFfiError` variants verification by a scannable
  // code added. This said the core produced all three and that nothing on
  // this side called the functions that return them yet, which was true for
  // as long as it took the facade to catch up: `getVerificationCode`,
  // `submitScannedCode` and `confirmScan` are exported now and every one of
  // these arrives from a real call. They were mapped ahead of that for the
  // reason the recovery block above gives, and the reason still holds for
  // whatever is mapped ahead of its caller next. An entry missing here is
  // not a compile error and no test on the Rust side can see it -- the type
  // test in `errors.test.ts` that walks every generated variant is the only
  // thing that can, and it is what caught these.
  ['PeerIdentityNotKnown', 'peer_identity_not_known'],
  ['CodeNotOffered', 'code_not_offered'],
  // The half that left `CodeNotOffered` when the code switch became two
  // facts rather than one boolean. Without this entry it arrives as kind
  // 'unknown' with the message "crypto error: unknown", which is exactly the
  // failure this map exists to prevent and which no test on the Rust side
  // can see: the core proves the right error is produced, and this map is
  // the only thing that decides whether a product can act on it. It matters
  // here as much as anywhere in this file, because the whole reason the
  // variant was split out is that a product has to be able to stop offering
  // a code and offer a string instead.
  ['PeerCannotScan', 'peer_cannot_scan'],
  ['ScannedCodeRefused', 'scanned_code_refused'],
  // The three that split `ScannedCodeRefused` apart, and the reason this
  // block is where the split is worth anything: the design's section 4
  // requires a product to be able to tell "this is not one of our codes"
  // from "this code is for a different flow" from "the bytes were mangled",
  // and nothing in Rust can decide whether it can. Four distinct kinds here
  // is what makes those four Rust variants four different sentences on a
  // screen; three entries missing would have made all three arrive as
  // 'unknown' on the one call whose refusals a product most needs to word
  // differently.
  ['ScannedCodeUnrecognised', 'scanned_code_unrecognised'],
  ['ScannedCodeMalformed', 'scanned_code_malformed'],
  ['ScannedCodeForAnotherFlow', 'scanned_code_for_another_flow'],
])

// 'session_refused' is deliberately not here: see its own doc comment on
// CryptoErrorKind above. It is the one kind this set must never gain by a
// well-meaning edit that assumes every withheld-session kind belongs next
// to 'unshared_session'.
//
// 'material_not_ready' is deliberately not here either, and for the sharper
// version of the same reason. It reads transient -- "not ready *yet*" -- and
// a retry loop is the obvious thing to reach for. But the state it names
// does not resolve on its own: the flow advances when the caller resolves
// what it drained from the pump, so a caller that retries without doing that
// spins forever against a machine that will never move. Reporting it
// non-retriable is what sends a reader to the doc comment that says which
// call is missing.
const RETRIABLE: ReadonlySet<CryptoErrorKind> = new Set([
  'missing_key',
  'unshared_session',
])

export function isCryptoError(e: unknown): e is CryptoError {
  return e instanceof Error && BRAND in e
}

/**
 * `@ubjs/core`'s `UniffiError` (the base class every generated error variant
 * extends) never sets `.name` -- confirmed by reading its source, and by a
 * real device run throwing a real `ProbeFfiError.Rejected` instance whose
 * `.name` is the inherited, useless `"Error"`. What it does set, always, is
 * `.message`, to exactly `"<EnumTypeName>.<VariantName>"` (optionally
 * followed by `": <message>"`) -- its own comment explains why: it cannot
 * rely on an overridden `toString()` being called. That format is the one
 * stable, codegen-version-independent way to recover the variant name
 * without importing a specific enum shape from ./generated, which would
 * couple this file to one Rust error type and need editing for every future
 * variant. `interop/reference.ts` and this file's own tests construct plain
 * `{ name: 'Rejected', ... }` objects instead, which is why this bug was
 * invisible until a real UniFFI error crossed the bridge for the first time
 * on a real build (Task 11) -- so `.name` is still checked first, both for
 * those and for any future binding that does set it directly.
 */
function variantNameFromMessage(message: unknown): string | undefined {
  if (typeof message !== 'string') return undefined
  const dot = message.indexOf('.')
  if (dot === -1) return undefined
  const afterDot = message.slice(dot + 1)
  const colon = afterDot.indexOf(': ')
  return colon === -1 ? afterDot : afterDot.slice(0, colon)
}

/**
 * A generated error's payload (`reason`, and per spec section 10 eventually
 * `sender`/`scope`) is nested under `.inner`, not on the error itself --
 * confirmed the same way as the `.name` gap above. Checked second, so a
 * hand-built fixture with the field at the top level still works.
 */
function stringField(
  source: Record<string, unknown>,
  field: string,
): string | undefined {
  if (typeof source[field] === 'string') return source[field] as string
  const inner = source.inner
  if (typeof inner === 'object' && inner !== null) {
    const value = (inner as Record<string, unknown>)[field]
    if (typeof value === 'string') return value
  }
  return undefined
}

/**
 * Normalizes anything thrown by the generated layer into a CryptoError.
 *
 * Only `reason` (falling back to `detail`, e.g. `IdentityFfiError.
 * MalformedIdentifier`'s field) is ever copied into the message. Both are
 * fixed diagnostics the Rust side deliberately chose to expose, never
 * caller-supplied payload or ciphertext content, so this stays safe to
 * surface without reaching a crash report.
 */
/**
 * What a fieldless refusal says when it reaches a developer.
 *
 * **The message is the only prose most of these ever get.** The Rust
 * `#[error(...)]` string does not cross the FFI boundary, and a fieldless
 * variant arrives carrying no `reason` and no `detail`, so without this map
 * `toCryptoError` produces `crypto error: identity_not_known` and nothing
 * else. A developer debugging at speed sees that string, in a stack trace or
 * a log line, and nowhere near it any of the six places this repository
 * explains what to do.
 *
 * That mattered enough to fix rather than document. The gate refusals below
 * are decisions rather than failures, and the decision is what the message
 * has to carry: `'identity_not_known'` in particular is the one whose
 * obvious-looking remedy is the destructive call, and wiring
 * `createCrossSigningIdentity` to it is how a product mints an identity on a
 * launch-path error handler, on devices that are frequently killed and
 * frequently offline.
 *
 * Only the refusals whose remedy is a choice are listed. A kind that already
 * carries a `reason` from the Rust side keeps it: the map is consulted only
 * when there is nothing better.
 */
const MESSAGE_BY_KIND: ReadonlyMap<CryptoErrorKind, string> = new Map([
  [
    'account_keys_not_fetched',
    'this library cannot yet say what identity this account has, so it will not publish or ' +
      'create one. The key query that lifts this has already been queued: drain ' +
      'takeOutgoingRequests, send it, report it with markRequestSent, and call again. If ' +
      'getIdentityStatus().accountKeysAnswerUnsettled is true, calling again will do exactly ' +
      'this again: stop looping and check the userId you passed to createCryptoMachine against ' +
      'the canonical user_id your login returned.',
  ],
  [
    'identity_not_known',
    'this library cannot show the homeserver an identity for this account: either it has ' +
      'none, or this device holds one no homeserver has ever accepted, which ' +
      'getIdentityStatus().identityPublicationPending tells apart. Either way the call is ' +
      'createCrossSigningIdentity, and it is destructive if the account turns out to have ' +
      'an identity after all: do not call it from this handler. It belongs where your ' +
      'product has decided this account should be getting its first identity, having ' +
      'checked something it knows and this library cannot, such as that no other session ' +
      'is listed on the account.',
  ],
  [
    'identity_already_exists',
    'this account already has a cross-signing identity and this device does not hold its ' +
      'private keys. Join it with requestSelfVerification, or restore it with ' +
      'recoverIdentity. Replacing it would reset the trust of everyone who has verified this ' +
      'account, and no call on this surface will do it.',
  ],
  [
    'private_keys_not_held',
    'this device does not hold this account\u2019s private signing keys, so there is nothing ' +
      'for it to write into server-side storage. getIdentityStatus says whether the remedy is ' +
      'to join the account\u2019s identity or to create one.',
  ],
])

export function toCryptoError(raw: unknown): CryptoError {
  const source = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<
    string,
    unknown
  >
  const name = typeof source.name === 'string' ? source.name : ''
  const kind =
    KIND_BY_NAME.get(name) ??
    KIND_BY_NAME.get(variantNameFromMessage(source.message) ?? '') ??
    'unknown'
  const reason = stringField(source, 'reason') ?? stringField(source, 'detail')

  const err = new Error(
    reason ?? MESSAGE_BY_KIND.get(kind) ?? `crypto error: ${kind}`,
  ) as CryptoError
  err.name = 'CryptoError'
  err.kind = kind
  err.retriable = RETRIABLE.has(kind)
  const sender = stringField(source, 'sender')
  const scope = stringField(source, 'scope')
  if (sender !== undefined) err.sender = sender
  if (scope !== undefined) err.scope = scope as CryptoScopeId
  Object.defineProperty(err, BRAND, { value: true, enumerable: false })
  return err
}
