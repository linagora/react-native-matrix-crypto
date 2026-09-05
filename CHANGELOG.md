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

### Added

- **`discardScopeKey`**, which is what makes removing somebody from a
  conversation mean anything. Removing them removes their right to write and
  takes back no key, and Megolm keys do not expire, so without a rotation the
  departed party goes on reading everything sent afterwards and nothing
  reports it. Remove first and rotate second: no new key is made by this
  call, the replacement is created at the next `shareScopeKey`, and that call
  shares it with the users it names — so rotating first and sharing before
  the removal has landed hands the fresh key to the very person it was
  rotated away from.

  It rotates only this device's key, and it takes nothing back: everything
  the other party already received, they keep. The returned boolean says
  whether a key of this device's existed to rotate at all, and `false` is not
  a failure — it is reported because "the key was rotated" and "there was no
  key of ours to rotate" are different facts about a conversation.

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
