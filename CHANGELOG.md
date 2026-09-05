# Changelog

What each release changes for somebody who depends on this package.

Scope, and it is narrower than the commit log on purpose: this file records
what reaches a consumer of `react-native-matrix-crypto` — the public API, the
behaviour behind it, and anything shipped in the published tarball. Work on
continuous integration, the example app, the measurement rigs and the
documentation is deliberately absent; it never leaves the repository, and a
changelog that lists it buries the two lines that matter.

No dates here. A release is a git tag, and the tag carries the date the
release actually happened, which is a fact rather than an intention. Versions
follow [semantic versioning](https://semver.org/); until 1.0, as the README's
stability section states, a minor release may still change the surface.

Versions 0.1.0 through 0.3.0 predate this file.

## 0.5.0

History sharing. A person invited into a conversation could not read a word
of what was said before they arrived; this release gives a product the means
to hand them the past deliberately, and refuses to let it happen by accident.

### Added

- **Four calls implementing [MSC4268] room key bundles**: `buildHistoryBundle`
  assembles every session this account holds for a scope and encrypts it,
  `shareHistoryBundle` announces an uploaded bundle's location and the secret
  that opens it to one recipient's devices, `offeredHistoryBundle` reports
  whether somebody has offered this device one, and `receiveHistoryBundle`
  decrypts and imports it. The bundle travels through your media repository
  rather than through this library, which still performs no request: build,
  upload it yourself, then announce. The README's "Sharing history with
  somebody you invite" section walks both halves.

- **The encryption is this library's, not the product's.** A React Native
  product has no AES and no SHA-256 to hand, so an API that returned the
  bundle in clear would be an instruction to implement Matrix's attachment
  encryption in JavaScript in order to protect every room key an account
  holds. What crosses the boundary is ciphertext. On the sending side a
  product handles an opaque secret it passes back and drops; on the receiving
  side it handles no key material at all, because the key arrived in the
  announcement this library already recorded.

- **`buildHistoryBundle` reports the size of the gift before anything leaves
  the device.** It returns `shared` and `withheld` counts alongside the
  ciphertext, and has no side effect, so a product can build one purely to
  put a number in front of a person. This is the surface's answer to an act
  that cannot be undone: a key handed over is a key the other device keeps,
  there is no revocation and no expiry, and it names one recipient rather
  than a room.

- **Three error kinds.** `no_offer` says no announcement has been recorded for
  that sender and scope — wait for a sync rather than retry, since the
  announcement is a to-device event. `bundle_unreadable` says the downloaded
  file is not the one that was announced: it will not decrypt under the
  announcement's key, or its hash is not the promised one — the caller's
  arguments were fine and the file was not. `sender_not_trusted` is now
  reachable from a second call: `receiveHistoryBundle` refuses a bundle whose
  sender this device cannot vouch for. That refusal exists because
  `matrix-sdk-crypto`'s own answer there is to drop the bundle and return
  success, which from inside a product is indistinguishable from an import
  that worked.

### Changed

- **Nothing on the existing surface.** Every call, argument, return shape and
  error kind that 0.4.0 shipped behaves exactly as it did. The one internal
  change worth recording is that the rule deciding which of a user's devices
  may receive this account's keys is now written once and consulted by both
  the live-key path and the history path, so the two cannot come to disagree:
  a bundle shared more widely than the live key would hand the past to devices
  the present is withheld from.

[MSC4268]: https://github.com/matrix-org/matrix-spec-proposals/pull/4268

## 0.4.0

The two trust decisions that bound this library's cryptographic behaviour
were pinned to the most permissive settings the layer underneath offers, both
of which upstream marks "not recommended". Both move in this release: one
becomes the caller's to choose, the other follows from the machine's own
state.

### Added

- **`decryptEvent` takes a third argument, `senderTrustRequirement`.** What a
  sender's device must satisfy before the plaintext is handed over: `'any'`,
  `'identity_signed_or_legacy'` or `'identity_signed'`. It defaults to
  `'any'`, which is what every caller got before the parameter existed, so a
  call that passes nothing behaves exactly as it did in 0.3.0.
- **`SenderTrustRequirement`** is exported from the package root. The union is
  closed, deliberately: a product branching on it exhaustively is told at
  compile time when a value it has never seen appears. Widening it later is a
  breaking change.
- **`'sender_not_trusted'` joins `CryptoErrorKind`**, split out of
  `'unknown_device'` because the two want opposite things done about them —
  the first is a policy gap a user closes by verifying the device, the second
  means the event's provenance is broken and nothing closes it. It is
  reachable only under one of the two tightened requirements, so a caller on
  the default never sees it. `CryptoErrorKind` is an open union, and this is
  the minor bump its documentation describes.

### Changed

- **Room keys are now shared by identity when the machine holds a verified
  cross-signing identity of its own.** `shareScopeKey` collects recipients
  with the identity-based strategy (MSC4153) instead of sharing with every
  unblacklisted device: a device signed by its owner receives the key, and a
  user with no published identity receives none, withheld as `m.unverified`.

  **This one changes behaviour without a caller opting in, and it is the
  entry to read before upgrading.** If your users have bootstrapped
  cross-signing, devices that no identity vouches for — including a user's own
  device that has not been verified yet — stop receiving room keys and stop
  decrypting messages sent after the upgrade. That is the recommended posture
  and what mainstream Matrix clients do, but it is a visible change in what an
  app does.

  A machine that has never bootstrapped an identity keeps the previous
  strategy and is unaffected. The choice is not a parameter because it cannot
  be one: the identity-based strategy refuses outright for a machine with no
  identity of its own, before it looks at a single recipient, so the strategy
  has to follow from the machine's state.

- `receiveSyncChanges` deliberately keeps the permissive requirement on its
  ingest path. Tightening what to-device traffic is accepted would refuse room
  keys from the user's own unverified devices and stop every event those keys
  protect from decrypting.

### Security

- **The recovery types no longer derive `Debug`.** `AccountDataEntry` carries
  the account's encrypted private signing keys, and `RecoverySetup` carries
  the recovery key itself; a derived `Debug` left either a single `{:?}` away
  from a log. The derive is gone and a
  `compile_fail` doctest holds it gone, because a prose rule does not fail CI.
  Rust-side hardening: `Debug` never crossed the FFI boundary, so no
  TypeScript caller could reach it.

### Unchanged, and worth saying

- No breaking change. Every addition above is additive, and code written
  against 0.3.0 compiles and behaves the same, with the one exception named
  under **Changed**.
