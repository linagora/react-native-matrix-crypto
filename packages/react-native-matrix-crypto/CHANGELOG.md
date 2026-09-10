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

## 0.7.0

### Added

- Key backup, so that losing a telephone stops costing every message it had
  already received. `createKeyBackup` generates the key and describes the
  version to publish, `enableKeyBackup` starts backing up to a version the
  homeserver named, `getKeyBackupState` reports how far along it is,
  `restoreKeyMatches` says whether a key opens a backup before it is
  downloaded, `restoreKeyBackup` decrypts and imports one, and
  `disableKeyBackup` stops. The records `BackupSetup`, `BackupState` and
  `BackupImport` come with them.

  Nothing happens until a product asks: `createKeyBackup` makes no request and
  changes no state, so its result can be shown and refused before anything is
  published.

  `restoreKeyBackup` tells a damaged download apart from a wrong key. A body
  whose entries cannot be read at all is `malformed_payload`, because those
  entries never reached the key and so cannot be evidence about it;
  `wrong_key` is reserved for a key that was given something to open and did
  not open it.

- An eighth outgoing request kind, `room_key_backup`, for
  `PUT /_matrix/client/v3/room_keys/keys`. It appears only after
  `enableKeyBackup`, so a product that never sets a backup up sees no change
  in its pump at all. The `version` that belongs in the query string travels
  inside `body`, the third of the pump's disclosed exceptions; its response
  must carry `etag` and `count`.

- Two error kinds. `wrong_key` is a well-formed restore key that opens a
  different backup — a different secret rather than a typo, which is a
  distinction a product has to word differently. `not_what_was_announced` is
  a downloaded attachment failing the SHA-256 its secret carried.

### Fixed

- **`encryptAttachment` and `decryptAttachment` errors reached products as
  kind `'unknown'`.** `AttachmentFfiError` was generated and never listed in
  the test that walks every error enum, so its three variants had no mapping
  and arrived with the message "crypto error: unknown" — including the one
  that says a downloaded file is not the file that was announced, which the
  Rust core is careful to tell apart from every other failure. `MalformedSecret`
  now reports `malformed_payload` and `NotWhatWasAnnounced` reports
  `not_what_was_announced`.

  It was found by listing every generated error enum in that walk, which the
  key-backup work did because its own enum needed covering. `HistoryFfiError`
  was unlisted too and had, by luck rather than design, a complete mapping
  already.

### Changed

- **`enableKeyBackup` on a different version drops the batch already in
  flight.** Nothing upstream does it: `enable_backup_v1` writes the key and
  never touches the pending request, and the backup machine hands an existing
  one back without comparing its version. So replacing a recovery key while a
  batch was unacknowledged would have re-emitted the _retired_ version on
  every drain for ever — the homeserver answering `M_WRONG_ROOM_KEYS_VERSION`
  and the pump never moving again, through the one path that exists to help
  somebody who wrote their key down badly. Re-enabling the _same_ version, which
  is what every launch does, is untouched.

- **The private half of a backup key is never written to the crypto store.**
  Upstream offers to keep it there for gossiping between devices and this
  library does not call that: what a device needs to keep writing is the
  public half, which `createKeyBackup` hands back for a product to keep. The
  cost is stated rather than discovered — a device cannot pass the key to
  another device of the same account, and a second device restores from the
  restore key like any other.

### Worth knowing before you ship it

- **`m.megolm_backup.v1.curve25519-aes-sha2` does not authenticate its
  ciphertext.** Whoever can write to a backup can substitute keys in it
  undetectably, and a device restoring would decrypt what they chose;
  `vodozemac` gates the algorithm behind a feature named
  `insecure-pk-encryption`. It is the only server-side backup Matrix has, so
  the choice is this or none, and the obligation it creates is that a product
  says so rather than letting "end-to-end encrypted" imply more than the
  mechanism delivers.

- **There are now two secrets in this library that look alike.**
  `createRecovery`'s `recoveryKey` opens the account's private signing keys;
  `createKeyBackup`'s `restoreKey` opens this backup's message keys. Both are
  32 random bytes in base58 and neither opens what the other opens. A product
  offering both must not call them the same thing.

## 0.6.1

### Added

- `CHANGELOG.md` now ships inside the published tarball. Until this release it
  existed only in the repository, so somebody reading the package they had
  actually installed could not see what any version changed without going to
  GitHub for it.

### Unchanged, and worth saying

- **No code changed.** The TypeScript surface, the Rust core and the native
  binaries in this tarball are built from the same sources as 0.6.0. Nothing
  here fixes a bug or adds behaviour, and somebody already on 0.6.0 gains
  nothing but the file named above. It is a packaging release, said plainly
  rather than dressed up as more.

## 0.6.0

### Added

- `encryptAttachment` and `decryptAttachment`, and the `SealedAttachment`
  record they hand back. A product encrypts a file, uploads the ciphertext
  itself, and keeps an opaque secret; on the other side it downloads and
  decrypts. The same primitives the history bundle already used internally,
  now available for arbitrary files, so a React Native product never
  implements Matrix's attachment encryption — it has no AES and no SHA-256,
  and that lesson cost a redesign during the bundle work.

  Two failures are told apart, and the difference is worth acting on:
  `malformed_secret` is a statement about the secret and retrying will not
  help, while `not_what_was_announced` is the SHA-256 check failing against
  the downloaded bytes, which is a download worth making again. Neither ever
  returns a partial file.

  No upload and no download happen in this library. The media repository
  stays the product's, on the same boundary `shareHistoryBundle` draws.

## 0.5.0

History sharing, and the rotation that makes a removal mean something.
A person invited into a conversation could not read a word of what was said
before they arrived; this release gives a product the means to hand them the
past deliberately, and refuses to let it happen by accident. It also closes
the other direction: removing somebody takes back no key, and until now
nothing here could stop them reading on.

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
