# react-native-matrix-crypto

[![npm version](https://img.shields.io/npm/v/react-native-matrix-crypto)](https://www.npmjs.com/package/react-native-matrix-crypto)
[![CI](https://github.com/linagora/react-native-matrix-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/linagora/react-native-matrix-crypto/actions/workflows/ci.yml)
[![License](https://img.shields.io/npm/l/react-native-matrix-crypto)](LICENSE)

A React Native bridge for Matrix end-to-end encryption.

It exposes [`matrix-sdk-crypto`](https://github.com/matrix-org/matrix-rust-sdk/tree/main/crates/matrix-sdk-crypto), the same Rust implementation Element uses, to a React Native application through a small, typed TypeScript surface. You hand it an event, it hands you back an encrypted one, and the reverse.

**It does not talk to a homeserver.** There is no login, no `/sync`, no sending, no room state, no timeline. Transport is your application's job. That boundary is deliberate, and it is the same one upstream draws between `matrix-sdk-crypto` and the full `matrix-sdk`, for the same reason: a crypto engine that also owns networking is far harder to audit, reuse and reason about. So this is not a Matrix client SDK (see [`matrix-js-sdk`](https://github.com/matrix-org/matrix-js-sdk) for that), not a replacement for a homeserver connection, and not tied to any product, backend or deployment. Any React Native project can consume it without carrying configuration that belongs to someone else's product.

## Contents

* [Why adopt it](#why-adopt-it)
* [Requirements](#requirements)
* [Install](#install)
* [Getting started](#getting-started)
* [The pump](#the-pump)
* [Creating this account's signing identity](#creating-this-accounts-signing-identity)
* [Joining an identity from a second device](#joining-an-identity-from-a-second-device)
* [Verifying a device](#verifying-a-device)
* [Limits you must design around](#limits-you-must-design-around)
* [What works today](#what-works-today)
* [Design notes and history](#design-notes-and-history)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [Security](#security)
* [License](#license)

## Why adopt it

**No Rust toolchain is required.** The published package ships prebuilt binaries: an `.xcframework` for iOS, and for Android a prebuilt Rust library per ABI under `android/src/main/jniLibs/`, which this module's `CMakeLists.txt` links when your app autolinks it and builds its C++ from source. `yarn add` is all you need.

Two checks stand behind that. On every pull request, a job packs this repository, installs the result on a machine with every directory carrying `cargo` or `rustc` scrubbed out of `PATH`, and asserts the installed package declares no `preinstall`, `install`, `postinstall` or `prepare` script and ships no `binding.gyp`, so nothing in it can reach for a compiler on your machine either. It cannot check the binaries: they are build outputs, ignored by git, so the tarball a pull request can pack contains none of them. At publication the release workflow does check them. It builds both platforms in full, packs one tarball, then opens that tarball and reads what is inside: every slice the `.xcframework` advertises and a prebuilt Rust library for every ABI `android/build.gradle` declares, each large enough and with the right magic number to be real compiled code rather than a placeholder. Only then does it install those exact bytes with `cargo` and `rustc` unreachable, load the module out of the installed package the way your bundler would, and publish the tarball it checked, with [npm provenance](https://docs.npmjs.com/generating-provenance-statements). Neither check runs the cryptography: a JSI turbo module needs a React Native runtime, so loading the module in a plain Node process stops where it calls into the native library.

**A third-party Matrix client decrypts what this library encrypts.** [`matrix-nio`](https://github.com/matrix-nio/matrix-nio) is a Matrix client written in Python by people who have never seen this code. It decrypts an event this library encrypted, this library decrypts an event it encrypted, and each test flips a single character of each ciphertext to watch both refusals happen. Both run over a real homeserver, and anyone can run them: one drives the Rust core, one drives the published TypeScript API on an emulator with a second Matrix user as the counterparty. Two of our own crypto machines agreeing would prove only that the implementation is self consistent, because a consistent misreading of the protocol passes that cleanly on both sides. See [running the proofs](#running-the-proofs), and read the floor under [limits](#limits-you-must-design-around) before you weigh it.

**Every build gate has been watched rejecting a real violation**, not merely passing. There are thirteen, they all run in CI, and a gate nobody has watched fail is not known to work. This sentence said ten while the table below listed eleven and `package.json` declared eleven. `gate:readme` held the rows, the scripts and the workflow to each other and counted nothing, so nothing failed; it counts now, and reads this sentence to do it.

**There is a working application to start from.** `packages/example-app` is a neutral React Native app that drives the encryption chain live on a device: it creates a machine, drains the outbound queue, encrypts and decrypts a real event, reads identity keys, and shows for each step the exact TypeScript a consumer would write next to what it got back. It imports from `react-native-matrix-crypto` and from nothing else, so what you read there is what you can write, with no private entry point doing the interesting part off screen. Copying from it is a reasonable way to start. It does not cover device verification, by either method, and `packages/example-app/README.md` says what else only a person holding a phone reaches.

## Requirements

* React Native 0.87 or later, with the **New Architecture enabled**. This is a JSI Turbo Module; it does not run on the old architecture.
* React 19.2 or later
* iOS 13 or later, Android API 24 or later

| Platform | Architectures |
|---|---|
| iOS | `arm64` device, `arm64` simulator, `x86_64` simulator |
| Android | `arm64-v8a`, `armeabi-v7a`, `x86_64`, `x86` |

**Expo.** This package contains native code, so it cannot load in Expo Go. A development build (`expo prebuild` + `expo run`) is the expected path; it is not exercised by this repository's CI, which builds with the plain React Native toolchain.

## Install

```sh
yarn add react-native-matrix-crypto
```

A plain `yarn add` resolves npm's `latest` tag, and a prerelease is published under its own tag, so `yarn add react-native-matrix-crypto@rc` is how you ask for one on purpose. Which state the registry is in as you read this is not something this file can tell you: `scripts/assert-published-tags.sh` reads the tags back off the registry after every publish, or run `npm dist-tag ls react-native-matrix-crypto` yourself. The publication history behind that check is in [the design notes](DESIGN-NOTES.md).

## Getting started

This library performs no network requests. It hands you a list of requests to send and expects you to tell it when you have sent them. That is not a detail: **a key reaches another device only through requests you send**, so a product that never drains the queue encrypts to nobody, silently and with no error.

```ts
import {
  createCryptoMachine, shareScopeKey, takeOutgoingRequests,
  markRequestSent, markRequestFailed,
  encryptEvent, decryptEvent, asCryptoScopeId,
} from 'react-native-matrix-crypto'

await createCryptoMachine({
  userId: '@alice:example.org',
  deviceId: 'DEVICE1',
  storePath: `${documentsDir}/crypto`,
  storePassphrase: secret,   // null is allowed, and means unencrypted at rest
})

const scope = asCryptoScopeId('!s:example.org')

// Drain and send after every call that changes crypto state. Send in the
// order given, one at a time, and never overlap two drains: see The pump.
async function pump() {
  for (const request of await takeOutgoingRequests()) {
    const { ok, status, body } = await yourHomeserverClient.send(request)  // your transport
    if (ok) await markRequestSent(request.id, body)
    else await markRequestFailed(request.id, status)
  }
}

await pump()                                   // publishes this device's keys
await shareScopeKey(scope, ['@bob:example.org'])
await pump()                                   // asks the server about Bob's devices
await shareScopeKey(scope, ['@bob:example.org'])
await pump()                                   // now the key actually travels

const envelope = await encryptEvent(scope, 'm.room.message', { body: 'hi' })
// send envelope.ciphertext as the content of an m.room.encrypted event

const recovered = await decryptEvent(scope, incomingEvent)
// recovered.ciphertext is the PLAINTEXT. See Limits.
```

**The first `shareScopeKey` for a user you have never encrypted to delivers nothing, and that is correct.** It starts tracking them and queues a query about their devices. That query only reaches your homeserver when you drain the queue, so nobody is known to share with yet. Call it again after pumping. The library cannot collapse these steps, because it sends nothing itself and therefore cannot wait for a reply.

## The pump

Everything this library needs from the network leaves through `takeOutgoingRequests`, and the rules below apply to every drain you write.

### Reporting a request that failed

**`markRequestSent` means the homeserver accepted the request.** Reporting
anything else through it tells the library a falsehood, and the shape of that
falsehood is the reason `markRequestFailed` exists: pass it the HTTP status you
received, or `0` if nothing came back at all.

The library rejects a body it can show is not a response, which covers a Matrix
error, an authentication challenge, a gateway page and a bare
`{"message":"Internal server error"}`. What it accepts is any body shaped like
that endpoint's answer, and the one that matters is an empty object: `{}` is the
whole success response of the signing-keys upload, and a 503 that carried no
body arrives as the same bytes. No HTTP status crosses this boundary on
`markRequestSent`, so only your branch can tell them apart.

A key query answer is held to one thing more, because the gate it lifts is the
one that decides whether an identity is minted over an account that already has
one. It must **name your account**, in `device_keys`, `master_keys`,
`self_signing_keys` or `user_signing_keys`. Synapse, Dendrite and continuwuity
were each measured over HTTP, on accounts with no signing identity and no
uploaded device keys, and all three name the queried account even when they
hold nothing for it. So an answer about other users, an answer whose only
substance is a `failures` map, and an empty body are all accepted and none of
them satisfies the gate. That closes the collision above for the key query;
reporting the status still closes it for the signing-keys upload, and is still
what keeps a refused request retriable.

Reporting nothing at all is as safe as reporting a failure. Both leave the
request outstanding and nothing recorded as answered, so a retry is an ordinary
second send of the same id. `markRequestFailed`'s own doc comment carries the
full division.

### Ordering, overlap, and which ids a later drain retires

**Send the requests within one batch in the order you were given them**, one at a time. *Marking* is a different matter and is not ordered at all, because `markRequestSent` is a lookup by id, so you may mark them in whatever order the responses come back. The order is load-bearing because a verification ends with a confirmation followed by an acknowledgement, and the other device **silently discards** an acknowledgement that reaches it before the confirmation it acknowledges; the library orders the batch it hands you correctly but never sees your requests leave, so preserving that order is yours to do.

**Do not let a second drain overlap an unfinished one.** `takeOutgoingRequests` hands out three kinds that describe a standing need rather than one message, `keys_upload`, `keys_query` and `keys_claim`, and a later call that hands out a fresh request of one of those kinds usually retires the older id: `markRequestSent` then rejects it with `unknown_request`. Two `keys_query` requests are exceptions, and the next paragraph is about them. That is deliberate, because the machine mints a new id for the same need each time and forgets the old one, but it means two pumps racing, or a pump on a timer alongside a pump after a write, will fail on ids you are legitimately holding. If you do see `unknown_request` for an id from an earlier batch, discard that response and pump again rather than retrying it; nothing is lost, because the need was re-derived rather than dropped. `takeOutgoingRequests`' own doc comment carries the full rule.

**Two of the `keys_query` requests this library sends are never retired by an ordinary one, and nothing on the outside tells them apart.** All four arrive with `kind` `keys_query`, because that is the endpoint they call. The first is the query about your own account that this library sends when a bootstrap was refused and the machine would otherwise never ask; only another query of that same kind retires it, and an ordinary `keys_query` leaves it alone. The second is the query queued by a verification that finished by scanning a code, and nothing retires it at all: its answer is the entire product of that verification, so an ordinary `keys_query` handed out for an unrelated user must not evict it while it is still in flight. **So you can hold two live `keys_query` ids at once, and a new one arriving is not evidence that an older one is dead.** The rule in the previous paragraph is still the one to follow, and it is why that rule is written as "discard the response and pump again" rather than as "the older id is gone": pumping again re-derives whatever is genuinely still needed, and leaves alone whatever was never retired.

A fourth kind, `signing_keys_upload`, is retired the same way and on a narrower trigger: a fresh one exists only after another `bootstrapCrossSigning`, so an ordinary second drain leaves it alone. It matters more than the other three because it is the one id you are meant to hold for a while, across an authentication loop with your user in the middle of it. Refused attempts never retire it; a second bootstrap followed by a drain does. `to_device`, `signature_upload` and `room_message` ids are never retired this way at all, and neither is the `keys_query` a scanned-code verification queues.

## Creating this account's signing identity

A signing identity is what lets one device vouch for another without a person comparing anything, and what lets a decrypted event say who sent it rather than only which key it arrived under. Without one, `senderVerification` can never read `verified`, however many strings your users compare.

**Two calls, and only one of them is safe to run unattended.** `bootstrapCrossSigning` publishes the identity this device already holds. `createCrossSigningIdentity` makes the account's first one, and making one over an identity the account already has resets the trust of every device and every person who ever verified it. The second is a decision your product makes, not a fallback your error handler runs. The section below this one says why.

```ts
import {
  bootstrapCrossSigning,
  createCrossSigningIdentity,
  getIdentityStatus,
} from 'react-native-matrix-crypto'

try {
  await bootstrapCrossSigning()
} catch (e) {
  // The first call in a process is normally refused with
  // 'account_keys_not_fetched'. The key query that lifts it has already been
  // queued by the refusal, so: pump, then call this again.
  if (e.kind !== 'account_keys_not_fetched') throw e
  await pump()
  const { accountKeysAnswerUnsettled } = await getIdentityStatus()
  // The server answered and the answer settled nothing, so calling again
  // does exactly this again. Check the user id you passed to createCryptoMachine
  // against the canonical user_id your login returned. See below.
  if (accountKeysAnswerUnsettled) throw new Error('the homeserver said nothing about this account')
  await bootstrapCrossSigning()
}
// 'identity_not_known' from either call means the server was asked and this
// account has no identity. Do NOT handle it by calling
// createCrossSigningIdentity here: that is the decision, and an error handler
// is not where it belongs. See the next section.

for (const request of await takeOutgoingRequests()) {
  // In the order you were handed them: device keys, then signing_keys_upload,
  // then signature_upload. A signature may reference a key that is not
  // published yet.
  const res = await send(request)
  if (res.ok) await markRequestSent(request.id, await res.text())
  else await markRequestFailed(request.id, res.status)
}
```

### When to create the first identity, and why this library will not decide it for you

`createCrossSigningIdentity` is the one destructive call on this surface. Creating an identity over one the account already has replaces it on the server, and every device and every person who had verified the old one silently loses that. There is no undo and nothing afterwards can detect it.

The library refuses to create one until it has asked the server and been told the account has none. **That is necessary and it is not sufficient**, and the reason is timing rather than trust. A `/keys/query` answer is true of the instant the server sent it and of nothing later. Measured against a live homeserver with every party behaving correctly: a device asked about its own fresh account, the server honestly answered "no identity" because at that instant there was none, another device of the same account published one in the window, and the answer was then reported. Nothing in that answer could say so.

That used to be enough to lose an identity, because creating was part of the call you make on every launch. It no longer is. What you supply instead is the fact the library cannot have: **that this account is meant to be getting its first identity now.** Anything you know is a better basis than the answer alone:

* the user has just created the account, and this is the sign-up flow rather than a relaunch;
* `GET /_matrix/client/v3/devices` lists no other session for the account;
* a person was asked and said yes.

Whatever you use, do not call this on every launch and do not make it the automatic handler for `'identity_not_known'`. Both put the decision back where it was.

**What the library does about the window it cannot close.** The batch `createCrossSigningIdentity` queues carries a `'keys_query'` for your own account after the publication, so your ordinary send-and-report loop asks the server once more straight after. That does not prevent the race: the publication is handed to you first, and if you send it you have sent it. It prevents the state the race otherwise leaves behind, which was also measured. A device that lost the race held an identity the account did not have, reported `identityKnown` and `privateKeysHeld` like a healthy device, and asked the server nothing ever again. With that query in the batch, the next answer carries the identity the account really has, the keys that disagree with it are dropped, and `getIdentityStatus` reports the truth.

**If the publication does not land, nothing is lost, but finishing it is a decision and not a retry.** `createCrossSigningIdentity` writes the identity to the store and then hands you the upload. Between those two moments the store holds an identity your account does not have, and a killed process, an offline device or a timed-out request leaves exactly that on disk. `getIdentityStatus().identityPublicationPending` is `true` while that is the case, and **finishing it is `createCrossSigningIdentity` again**, deliberately, on the same grounds you decided the first time.

An earlier version of this paragraph advised `bootstrapCrossSigning` for that state, and that was wrong: measured on two homeservers, a device in it published over an identity a second device of the same account had legitimately created in the gap before its own answer was reported. `bootstrapCrossSigning` now refuses here with `identity_not_known`, the same refusal a brand-new account gets, with the same remedy, so one branch in your product handles both. The full account of the correction is in [the design notes](DESIGN-NOTES.md).

Why it has to be a decision: from inside a device, **an identity it holds and has never seen a homeserver accept is indistinguishable from one the account has since replaced.** No answer settles it, because an answer describes the instant the server computed it and nothing later. What you know and this library does not is whether this account is still in sign-up.

This matters more than it sounds, because it is the one state where `identityKnown` is `true` and your account still has no identity. A product that shows "encryption is set up" on `identityKnown` alone is wrong here, and `identityPublicationPending` is how it can tell.

**And report the upload honestly.** `markRequestSent` on a `signing_keys_upload` that the server did not accept used to mark the identity published, and the two bodies this library cannot tell from a success are `""` and `{}`, which is what a dropped connection produces. It no longer marks anything: only a `keys_query` answer that carries the identity back does. So a wrong report now costs you one more round trip instead of the account.

**Do not count on the server's authentication challenge to stop you.** It was measured and it does not. The homeserver refused the replacement upload with a `401` and a password challenge; answering it with the password the product already had, which is exactly what the paragraph above tells you to do for an ordinary first publication, returned `200` and completed the overwrite.

**The `signing_keys_upload` request needs user-interactive authentication, and this library will not do it for you.** Send it. If it comes back `401`, that body is a challenge: read the session out of it, ask your user, merge an `auth` object into `request.body`, which is opaque JSON this library never interprets, and send the same body again. The id survives any number of refused attempts, because only a success consumes it.

**A first publication is normally not challenged, and that is not a bug in your code.** Both mainstream homeservers decide it the same way: the upload is accepted outright when the account holds no cross-signing key yet, and challenged only when it would replace one. Measured on continuwuity v26.7.2, and read off Synapse 1.159.0's own handler, which allows first-time setup without authentication per MSC3967. So a fresh account's first publication normally answers `200` with no challenge at all, and the challenge is what you meet when an identity is already there. Write both branches: a loop that only handles `401` never finishes on a fresh account, and one that only handles `200` fails the first time it matters.

Here is the whole loop, both branches. It is the code `rust/matrix-crypto-core/tests/level_two_identity_challenge.rs` runs against a real homeserver's real refusal, step for step; `gate:uia-example` holds this block and that test to the same ordered steps, so it cannot drift from what is actually proven.

<!-- uia-example:begin -->
```ts
for (const request of await takeOutgoingRequests()) {
  if (request.kind !== 'signing_keys_upload') {
    const res = await send(request)
    if (res.ok) await markRequestSent(request.id, await res.text())
    else await markRequestFailed(request.id, res.status)
    continue
  }

  // uia-step: send
  let res = await post('/_matrix/client/v3/keys/device_signing/upload', request.body)

  // uia-step: accepted
  // The ordinary answer on an account that has no identity yet. Nothing to
  // ask your user, nothing to retry.
  if (res.ok) {
    await markRequestSent(request.id, await res.text())
    continue
  }

  // uia-step: refusal
  if (res.status !== 401) throw new Error(`signing keys refused with ${res.status}`)
  await markRequestFailed(request.id, res.status)

  // uia-step: challenge
  // The session is the homeserver's, and knowable only from here. That is
  // why bootstrapCrossSigning has no auth parameter to pass one in through.
  const challenge = await res.json()
  const flows = challenge.flows ?? []
  if (!flows.some((flow) => flow.stages?.includes('m.login.password'))) {
    throw new Error('this homeserver asked for a flow this code cannot answer')
  }
  const password = await askYourUserForTheirPassword()

  // uia-step: merge
  // request.body is opaque. Parse it, add one member, serialise it back. Do
  // not rebuild it: the keys in it are the ones already minted, and a body
  // you construct yourself is a different identity.
  const body = JSON.parse(request.body)
  body.auth = {
    type: 'm.login.password',
    identifier: { type: 'm.id.user', user: myUserId },
    password,
    session: challenge.session,
  }

  // uia-step: resend
  // The same id and the same keys. markRequestFailed left the request
  // pending, so this is a second send of it rather than a new request.
  res = await post('/_matrix/client/v3/keys/device_signing/upload', JSON.stringify(body))
  if (!res.ok) throw new Error(`challenge answered and still refused: ${res.status}`)

  // uia-step: sent
  await markRequestSent(request.id, await res.text())
}
```
<!-- uia-example:end -->

**A `200` from the second send is the only evidence you get.** `getIdentityStatus` reads the same before and after: holding the account's private signing keys is a local fact, and publishing nothing does not change it. A run of the test above with the retry deleted still reports `identityKnown` and `privateKeysHeld`, and the homeserver still serves somebody else's identity. If you need to know the identity is really on the server, ask the server.

**There is no `auth` parameter, and there will not be one.** The challenge is only known after the first request has been refused, so an argument on `bootstrapCrossSigning` would have to be guessed before the server had said what it wants. The cost is stated rather than hidden: you cannot complete this step without implementing an authentication flow this library gives you no help with. What you get for it is that this library has never touched an account credential.

**Call `bootstrapCrossSigning` on every launch.** It re-uploads this device's keys and its signature into the account's identity, and it **never uploads the cross-signing keys themselves**, so there is no state in which running it unattended can change what identity your account has. On an account whose identity this device does not hold it is refused with `identity_already_exists`, which is where a second login belongs and the next section is what it does instead; on an account with no identity at all it is refused with `identity_not_known`, which is the decision described above.

`getIdentityStatus` reports five separate facts, and two of them have to be read together: `identityKnown === false` means "nobody has asked" while `accountKeysFetched` is false, and "the server says there is none" once it is true. Only the second is a basis for creating one, and only alongside something your product knows: see the decision above.

**`accountKeysAnswerUnsettled` is the field to read when a refusal will not go away.** `account_keys_not_fetched` covers two situations, and the pump loop above only fixes one of them. With this field false, nobody has asked and pumping is the whole remedy. With it true, the query was sent, the server answered, the answer was accepted, and this library still cannot say whether the account has an identity, so the next round of the loop does what the last one did.

The reachable cause is the account id. A homeserver compares the server name half of a user id against its own case-sensitively, so `@you:Example.org` where the server calls itself `example.org` is treated as a remote account: the server federates to itself, fails, and answers about nobody. A sign-in form where the user types their own address produces exactly that. Compare the `userId` you passed to `createCryptoMachine` against the canonical `user_id` your `/login` returned. The Matrix specification also prescribes omitting a user a reachable server does not know, so a conformant server can answer this way about an account that genuinely does not exist.

Nothing is destroyed while this field is true and nothing will be. Refusing to create a second identity is the safe direction; this field is what stops the refusal from also being silent.

## Joining an identity from a second device

A second login holds none of the account's private signing keys, so `bootstrapCrossSigning` refuses it with `identity_already_exists`. That refusal is the point rather than a gap: creating a second identity over the first would reset the trust of every device and every person who had verified the one the account already has. The new device **joins** that identity, by verifying itself against a device that already holds it.

```ts
import { getIdentityStatus, onCryptoSignal, requestSelfVerification } from 'react-native-matrix-crypto'

onCryptoSignal(async (signal) => {
  if (signal.kind !== 'trust_changed' || signal.user !== myUserId) return
  const { privateKeysHeld } = await getIdentityStatus()
  if (privateKeysHeld) thisDeviceCanNowSign()
})

const id = await requestSelfVerification()
// From here it is the flow in the next section, unchanged: pump, wait for
// 'ready', startVerificationComparison, read the string, show it, confirm.
```

**`requestSelfVerification` takes no arguments, and that is the difference that matters.** The invitation goes to every other device of yours that the account's identity has signed, and whichever one is in front of a person answers first; the rest are told the flow was taken. A device of yours the identity has never signed is not invited, deliberately: it is a login this account has never vouched for. The person compares two of their own screens instead of talking to somebody else, and nothing else about the flow changes.

**The seeds arrive after the comparison, on a later sync, and nothing returns to you when they do.** Once both sides have confirmed, this library asks your other devices for the cross-signing seeds this one lacks. They go out as ordinary entries in `takeOutgoingRequests`, and the encrypted answer comes back in a `receiveSyncChanges` you feed it. `getIdentityStatus().privateKeysHeld` then reads `true`, which is the moment this device can sign with the account's identity rather than only recognise it. `trust_changed` for your own user id is what tells you to look; do not poll for it. It is the same signal a completed comparison produces, which is why the handler above reads the status rather than counting signals.

**After the join, `bootstrapCrossSigning` stops being refused and starts being served.** This device now holds the account's private keys, so it republishes the identity it holds rather than creating a second one, which is correct and is what "call it on every launch" is for. What it also means is that the batch carries a `signing_keys_upload` again, and you still send it through the loop above. It will normally be accepted without a challenge, because the keys in it are the ones the account already has and neither continuwuity nor Synapse challenges an upload that changes nothing: Synapse short-circuits an identical re-upload to `200` before it considers authentication at all. Do not treat that as the request having been skipped, and do not assume the challenge either. Send it and handle both answers.

Two refusals, and they want opposite things done about them. `account_keys_not_fetched` means this library cannot yet say what identity this account has, and this call queues that key query as it refuses: drain the pump, send, report sent, and call again, checking `accountKeysAnswerUnsettled` as above before you loop. `identity_not_known` means one of two things, and `identityPublicationPending` tells them apart: the server answered and this account has no identity at all, so there is nothing to join; or this device holds an identity it minted that no homeserver has ever asserted back, so there is nothing yet for another device to join it to. `createCrossSigningIdentity` is the call for both, because creating a first identity and finishing an interrupted publication are the same decision, and it is a decision your product makes rather than something this handler calls: see the section above for what to decide it on and why answering this error with that call is the shape that goes wrong.

## Verifying a device

Two people compare a seven-symbol string, read off their two screens, over a channel this library did not establish, in person or on a call they already trust — or one of them points a camera at a code on the other's screen. Both end in the same place, and a product may ship either or both. This section is the string, and [verifying by a scannable code](#verifying-by-a-scannable-code) is the other. If the string matches, each side records the other's device as verified; if it does not, the flow is cancelled and nothing is recorded. That refusal is the point: a comparison that can only ever agree proves nothing. A flow is named by an opaque id; hand it back verbatim and parse nothing out of it.

**Both sides must already know each other's devices before any of this.** Track the user, drain the `keys_query` and report it with `markRequestSent`, and check that `getDeviceStatuses` for that user answers non-empty.

```ts
// The side that asks.
const id = await requestVerification('@bob:example.org', 'BOBDEVICE')
// pump, then wait for their answer to arrive in a later /sync you feed to
// receiveSyncChanges; getVerificationStage(id) then reads 'ready'.
await startVerificationComparison(id) // either side may; pump again
const material = await getVerificationMaterial(id)
// Show material.emoji (or material.decimals) to a person and ask.
await confirmVerification(id, material) // or cancelVerification(id)
// Pump once more. The stage reaches 'done', and only then:
await getDeviceStatuses('@bob:example.org') // BOBDEVICE reads 'verified'

// The side that is asked is a different application, in a different process,
// and the signal channel is what hands it an id.
onCryptoSignal((signal) => {
  if (signal.kind !== 'verification_requested') return
  acceptVerification(signal.verificationId) // or cancelVerification to refuse
  // pump, and carry on from startVerificationComparison above.
})
await receiveSyncChanges(encryptionSlice(sync))
```

* **Subscribe before your first sync, and keep the subscription.** Every producer runs inside `receiveSyncChanges`, and nothing is consumed while nobody is subscribed, so an invitation that arrives while you are away is announced on the first sync after you come back and the ordinary `useEffect(() => onCryptoSignal(h), [])` does not lose invitations. A `trust_changed` is not re-offered that way; `getDeviceStatuses`, and `getIdentityStatus` for the private-keys one, are the durable answers to those questions.
* **A subscribe that cannot reach the native module throws, and every subscribe does.** `onCryptoSignal` installs the observer on the first subscription, and returning normally means that worked. If it does not, the exception comes out of `onCryptoSignal` itself rather than being reported as an unsubscribe function for a channel that will never deliver, no listener is registered, and the next subscribe tries again. Subscribing inside an effect sends that throw to your nearest error boundary, which is the intent: the alternative is a screen waiting for an invitation that expires in ten minutes.
* **Some clients do not ask first, and it makes no difference to your code.** The protocol still carries an older shape in which a peer opens the comparison directly, with no invitation before it. It is what `matrix-nio` implements, and all it implements. It arrives as the same `verification_requested` signal and `acceptVerification` still agrees to it. Two things differ, neither needing a branch: the stage never reads `ready`, so `startVerificationComparison` answers `comparison_already_started`, which means carry on and wait for the string; and `confirmVerification` can finish the flow outright, so the device is verified when that call resolves, though its `trust_changed` still waits for your next `receiveSyncChanges`. This is the one shape that cannot be re-offered after an unsubscribe, because it leaves nothing behind that a later sync can enumerate.
* **An invitation from a device you have never been told about is discarded on arrival, and is not announced.** The layer underneath needs the sender's device keys to build the flow. `receiveSyncChanges` still resolves successfully, no flow exists, and `acceptVerification` would reject that transaction id with `unknown_flow`. The silence is the channel refusing to hand you an identifier no call here answers to.
* **Keep the to-device events you could not act on, and the ones you did, until their flow finishes.** Feeding the same event to `receiveSyncChanges` again once you have queried the sender's devices does create the flow and announces it exactly as a first arrival would; you never open the event, you keep an opaque blob and get back the announcement. Flows also live in memory on both sides of this boundary, so a process that restarts mid-verification holds a `verificationId` that now rejects with `unknown_flow`, and the recovery is the same one. Promptly, though: an invitation expires ten minutes after it was sent.
* **Every step goes through the queue.** Skipping `markRequestSent` is the one way this flow could fail silently, because the state machine advances on that report and on nothing else. It is reported instead: `getVerificationMaterial` rejects with kind `material_not_ready` rather than resolving empty or hanging, and that kind is deliberately **not** retriable. Retrying never resolves it; pumping does.
* **`getDeviceStatuses` is the only place a verification becomes visible.** Your own device reads `verified` from the moment it exists, because this process holds its private keys, so "some device in this list reads verified" says nothing. What carries a claim is another user's device changing.
* **`verified` means "trusted", not "a person compared a string with this particular device".** The value maps from one boolean underneath: locally trusted, or signed by an identity you have verified. Once you hold a signing identity, verifying one device of a user moves *every* device of that user to `verified` at once, including devices that appear later, with nobody comparing or scanning anything on any of them. That is correct rather than a defect and it is the point of cross-signing, but a product that reads this value as "a human checked this exact device" is wrong. Read it as "trusted", and ask `senderVerification` if what you need is what one event can be said to prove.
* **`startVerificationComparison` reports three different things.** `comparison_already_started` means the other side got there first, which is not a failure but does leave you something to do: call `acceptVerification` again, because their start is a question and the flow waits at `started` until you answer it. `verification_ended` means the flow is over and you need a new one. `wrong_stage` means it has not been agreed to yet, or that it went to a scannable code instead, which is a comparison that will never exist rather than one that has not started. `getVerificationStage` is free to call and tells you which at any point.

### Verifying by a scannable code

A person points one phone's camera at a code on the other's screen, and nobody reads seven symbols off anything. The code carries two signing keys and a random shared secret in about 126 bytes: one side draws them, the other reads them, and the flow finishes with no string for anybody to compare. It ends where the string method ends, with a `signature_upload` in the queue and `getDeviceStatuses` reading `verified` for the other device once you have fetched their keys again. Everything before the two methods diverge is the flow in the section above, with the same calls and the same opaque id.

**This library never sees a camera.** It has no image decoder, asks for no permission and contains no scanner. Your product owns all three, the same way it owns the network. What crosses this boundary is a byte array in each direction, plus a grid of squares for you to draw.

#### Say what your product can do, because nothing happens until you do

```ts
import { offerScannableCodes } from 'react-native-matrix-crypto'

// Once at start-up, next to createCryptoMachine. Most products have a
// screen and no scanner, and this is what that says.
offerScannableCodes({ canShow: true, canScan: false })
```

**Two questions and not one, and neither has a default.** `canShow` is true if you can draw the grid this library hands you; `canScan` is true if you have a scanner, have the camera permission, and can hand the raw bytes it reads to `submitScannedCode`. Both start false, both stay false until you answer, and leaving a field out is a type error rather than a yes you never said.

**`canScan: true` when your product cannot really scan** tells the other side's client that this one can, so it may answer by showing its user a code and asking them to point a camera at it. Nothing here can read it, and **no error reaches either product**, because nothing was asked of this library. The flow stalls until the protocol's own ten-minute timeout, the person who pays is a user who did nothing wrong, and neither product can see it happen. That is not a hypothetical: it is what a real Element Web client chose, correctly, against a build whose only way to ask for codes was to claim both halves.

**`canShow: false` when you meant true** refuses `getVerificationCode` with `code_not_offered` on the first flow you try it on: a named error, at integration time, in front of the person who can fix it in one line. That asymmetry is the whole argument for the default.

**Answering `canShow: true, canScan: false` removes a choice from the far side**, which is what makes it worth saying rather than merely honest. A peer told this side has no camera cannot decide to show: its own code builder tests your announced list for the scanning half before it produces anything, so it scans, or the two of you fall back to the short string. `rust/matrix-crypto-core/tests/qr_announcement.rs` watches a counterparty that answered with every method it has be left with no code to show, and `qr_show_only.rs` watches a whole flow finish this way against a peer that announced the scanning half alone.

**A build that never calls this announces on the wire exactly what it announced before codes existed here**, entire, rather than merely still including the short string. That is a test rather than a sentence. `rust/matrix-crypto-core/tests/qr_announcement.rs` reads the method list back off the request bodies the pump actually hands out, and asserts the untouched default equals the list every release up to `0.1.1` sent. It covers two of the three places this library announces one, including the one where the other side opened the flow; `qr_self_new_login_shows.rs` covers the third. All three read the wire rather than the constant behind it, so a call site left pinned to the wider list fails rather than passing on a shared reading.

Off also makes a code unavailable rather than merely unadvertised, in both directions, and that is the protocol's doing rather than this library's: a code exists only if both sides announced their half, so with this off the peer's own client produces none either and falls through to the short string.

It applies to the whole process rather than to one flow, because it describes your product, and a product does not have a camera on some of its verifications and not others. What a flow announces is fixed when that flow is created or agreed to, so calling this afterwards changes nothing about a verification already under way. It is one of six calls on this surface that are not asynchronous, and the only one of the six that changes anything: it sets a flag and cannot fail, and an awaitable call somebody forgot to await could land after the flow it was meant to affect had already said what it can do. The other five, `asCryptoScopeId`, `encryptionSlice`, `getSupportedAlgorithms`, `isCryptoError` and `onCryptoSignal`, either shape a value or install a listener.

#### Showing a code

```ts
import { getVerificationCode, confirmScan } from 'react-native-matrix-crypto'

const code = await getVerificationCode(id)
// Draw code.modules: width rows of width squares, row-major, true is dark.
// Leave the usual quiet margin. Then ask a person whether it was scanned.
await confirmScan(id)   // or cancelVerification(id)
// Pump once more. The stage reaches 'done'.
```

**Draw `modules`, not `payload`, and that is not a convenience.** The payload is binary and is not text: it carries two raw signing keys and a random shared secret, and there is no string it can honestly be turned into, so a JavaScript code-drawing component, which nearly always takes a string, cannot be given it. `modules` is the symbol this protocol's own encoder built, at a version and error-correction level it fixes deliberately, in its own words because mobile clients have trouble decoding otherwise. Draw `width` rows of `width` squares from it and a camera reads what the protocol meant; re-encode the payload yourself and you get a code this library's own scanner reads back and another client may refuse. The payload is there so a product can move it, to a component of its own or to a test, not so it can be turned into a picture by hand.

**`confirmScan` is where this method's security actually rests**, and it is the same act `confirmVerification` asks for on a string: *that was my other phone, and not somebody's screenshot*. Ask before you call it. Nothing inside this process can observe whether a person recognised the device that scanned, so a product that confirms on its own has verified nothing however well formed its arguments were. Skipping it does not fail loudly, but it does fail: the flow sits open until the ten-minute timeout retires it.

#### Reading one

```ts
import { submitScannedCode } from 'react-native-matrix-crypto'

await submitScannedCode(id, rawBytesFromYourScanner)
// Pump. Nothing is verified when this resolves: the other side has still
// to confirm, and messages have to cross.
```

**The bytes must be the raw bytes the code carried, not a decoded string, and this is the sharp edge of the whole method.** React Native's popular scanners, vision camera's code scanner and expo's barcode handler among them, surface a decoded `value: string`, and that string cannot carry this payload: it is binary, it is not valid text, and a string round trip replaces every byte that could not be represented. Reach for the raw byte output your scanner offers, and if it offers none, that scanner cannot be used for this. This library cannot undo the damage; what it can do is name it, and a payload that went through a string arrives as `scanned_code_malformed`, which is the one signal you get that the scanner is the problem rather than the person holding the phone.

It is one call and two protocol steps: the scan is registered, and the message telling the other side the code was read is queued for the pump. Drain it. A scan nobody hears about leaves both sides waiting.

#### Which device shows, and which one scans

There are three modes and all three work here. Which one a flow uses is decided by **which phone is held up**, not by anything you pass.

* **Verifying another user.** Both master signing keys travel in the code, so this device needs its own private signing keys and the other user needs a published identity.
* **Verifying your own new login, established device showing.** The code carries the account's master key, which the device showing it already trusts.
* **Verifying your own new login, new login showing.** The same flow with the screens the other way round, and the code says so, because the device showing it holds none of the account's private keys yet.

Both self modes are here because a product that shipped one of them would work exactly half the time, and which half would be chosen by whichever phone its user picked up rather than by the product.

#### Refusals

Every one of them is a sentence you can put on a screen, which is the point: underneath, seven different conditions answer an empty code with a warning nobody reads.

`getVerificationCode` refuses with:

| Kind | What it means | What to do |
|---|---|---|
| `code_not_offered` | this build did not offer to show a code on this flow, so there is nothing for it to produce | one line before the next flow: `offerScannableCodes({ canShow: true, ... })`. It used to fold the row below in with this one and ask you to work out which from the switch you had set, which stopped being sound the moment the switch became two facts |
| `peer_cannot_scan` | the other device did not say it can scan, so no code you draw can be read by it | nothing you can do, and waiting will not help: show the short authentication string instead. Two code-showing products with no scanner between them is the ordinary way to meet this, and so is any client that speaks only the short string |
| `identity_not_known` | this account has no signing identity for the code to carry | `createCrossSigningIdentity`, which is the call that makes one. Not `bootstrapCrossSigning`, which publishes an identity this device already holds and answers this same refusal |
| `peer_identity_not_known` | the other user has none, and nothing this device does will produce one | compare a short string instead. Deliberately not folded with the row above: the two remedies point at different people |
| `private_keys_not_held` | verifying another user puts this account's own key in the code, and this device cannot prove it holds one | `requestSelfVerification`, `recoverIdentity`, or `createCrossSigningIdentity` on an account with no identity at all. Verifying your own new login does not need them |
| `wrong_stage` | nobody has agreed to this flow yet, or it is over | |
| `unknown_flow` | no flow of that id | |
| `malformed_identifier` | the flow's own identifier is too long to fit in a code | only reachable from a peer that chose the identifier, and nothing you do will help. Offer a short-string comparison |

`submitScannedCode` refuses with four, because a product has four different things to say:

| Kind | What it means | What to do |
|---|---|---|
| `scanned_code_unrecognised` | not one of these codes at all: some other square, or a revision of the format this release does not speak | point the camera at the code the other device is showing |
| `scanned_code_malformed` | the bytes did not survive whatever brought them here | scan again, and check that your scanner yields bytes rather than text |
| `scanned_code_for_another_flow` | a real code, for a different verification. Nothing is damaged and nothing is suspicious | the wrong screen was read. Do not alarm anybody about their own mis-aim |
| `scanned_code_refused` | a code for this flow carrying keys this flow does not expect. **The only one of the four that can mean something is wrong** rather than that somebody aimed badly | refuse, and start again from a fresh request. Do not invite a retry of the same code |

`scanned_code_refused` covered all four conditions while the core had them and the boundary did not, and it keeps its name and its wire position while meaning only the narrowest of them. That happened inside this release rather than across two, so no published version ever carried the wide meaning; the narrowing is recorded because the name still reads wider than it is, and a reader who finds it in the source deserves to know it was once the whole set. `CryptoErrorKind` is open in any case, so a kind arriving that your code has never seen is a widening rather than a break, and the `default` branch you already have catches it.

Scanning needs a signing identity on both sides too, so `identity_not_known` and `peer_identity_not_known` are reachable here as well and name which side is missing one.

#### Seven more things to design around

* **Treat the code as secret while the flow is open**, on exactly the terms `SasMaterial` is treated on. The payload carries the shared secret the whole method rests on, and the grid is that same secret drawn as squares, so anything that learns either learns what an interposed party would need to answer the flow as though it had read the screen. No logging, no unencrypted persistence, no crash report. The Rust core redacts its own copy and cannot reach across this boundary to do the same for yours.
* **A flow can halt where only you can end it, and ending it is not optional.** A peer that declares itself finished the moment it has scanned, rather than after you confirm, spends the message that would have completed the flow. That is a deviation from the specification on their side and it has been measured against a real client, not inferred; nothing here can make such a flow finish. What it leaves behind matters more than the failed verification: the layer underneath allows one live verification per person, and a flow that is neither done nor cancelled stays in its cache and takes the **next two** attempts with that person down with it, silently, with no error attached to either. `cancelVerification` is what frees them. A product that shows a code needs a way off that screen and not only a way forward.
* **Call `receiveSyncChanges` at least once between two verifications with the same person**, including two with your own account. Without it the second comes back already cancelled: nothing was refused and nothing failed, `getVerificationStage` simply reads `cancelled` from the start. The sweep that empties that cache runs at the top of every sync, and any sync will do, empty included. A product that syncs continuously never meets this; one that drives two verifications from one screen, or from a test, walks straight into it.
* **A code and a string race, and the code can lose.** On a flow where both were announced, both are live at once and either side may move first. A displayed code may still give way to a short-string comparison, and once either side has scanned it is too late. A code that loses that race is cancelled with nobody refusing it and no error returned to anybody, because nothing was asked. A product showing a square has to be able to take it off the screen.
* **Scanning is not verifying.** When `submitScannedCode` resolves, nothing is verified: the other side has still to confirm and messages have to cross. What the flow produces at the end is the same `signature_upload` a string comparison produces. **The key query that turns that signature into a `verified` answer is queued for you** on the sync that finishes a flow with another person, so the step everyone omits after a string comparison is not one you have to go and find here. Queued is not answered: it leaves through `takeOutgoingRequests` like anything else, so drain the pump once more when `verification_completed` arrives and expect `unverified` from `getDeviceStatuses` if you read it in between. A flow with one of your own devices needs none of that and reads `verified` the moment it finishes.
* **A code flow finishing announces `verification_completed`, never `trust_changed`.** The `trust_changed` producer reads the short-string comparison's own final state and a code flow never has one, so a product that waits on that signal after `confirmScan` waits forever. `verification_completed` is what arrives instead, on both screens, and it names the flow rather than the user. Read `getDeviceStatuses` when you get it, which is what both signals tell you to do anyway, and expect another user's devices to turn verified a sync or two later rather than at that instant.
* **`getVerificationStage` names a code flow's own moment, and two of its answers are still shared.** `code-scanned` is the one stage only a code flow reaches, and reading it is what tells `confirmScan`'s two `wrong_stage` causes apart: nobody has scanned yet, versus the flow is over. This paragraph said that could not be read at all, and adding `code-scanned` is what changed it. What is still shared is `started` and `confirmed`: both flow shapes reach both, so `startVerificationComparison` on a code flow that nobody has scanned yet still answers `comparison_already_started`, whose advice is written for a comparison. Your own state is what tells those apart, because a build that never answered `offerScannableCodes` cannot be in a code flow. **`getVerificationCode` no longer answers `wrong_stage` for a flow that negotiated no code mode**, which it used to do once such a flow had moved on to anything else: the two method lists live on the ready state and nowhere afterwards, so a stage complaint stood in for an answer about methods. It says `peer_cannot_scan`.

## What works today

| Capability | State |
|---|---|
| Rust to UniFFI to JSI to TypeScript chain | working, verified on an iOS simulator and an Android emulator |
| Byte accurate marshalling, typed errors and Rust to JavaScript callbacks across the boundary | verified |
| Real `OlmMachine` identity keys, and a persistent encrypted store surviving restart | working, storage through `matrix-sdk-sqlite` |
| `encryptEvent`, `decryptEvent` | working, group sessions backed by `matrix-sdk-crypto`, proven between two crypto machines with the key travelling through the queue rather than handed over in test code |
| `receiveSyncChanges`, `shareScopeKey`, `takeOutgoingRequests`, `markRequestSent` | working, over a typed `SyncDelta` and one shared mapping |
| Interoperability with a third-party Matrix client | proven both directions against `matrix-nio` over a real homeserver, through the Rust core and through the published TypeScript surface on an emulator |
| Device verification by short string comparison (SAS) | working, in both flow shapes and whichever side opens the comparison, proven against a bare `matrix-sdk-crypto` machine driven directly: an agreement completing, and a genuine disagreement refusing |
| Device verification by a scannable code | working, and **claiming nothing until a product answers `offerScannableCodes`**, showing and scanning separately. All three modes the protocol defines. Proven against a bare `matrix-sdk-crypto` machine driven directly, and against mautrix-go over a real homeserver in both directions — an implementation sharing neither protocol code nor Olm with this one. Read by a real camera once, in one mode and one direction, recorded in full in the [design notes](DESIGN-NOTES.md). The library sees no camera and draws no picture: it hands over the bytes and the grid of squares, and the product owns the scanner and the screen |
| A third-party client taking part in a verification | proven over a real homeserver, and it stops short of *completing* one for a reason in the counterparty, described in the [design notes](DESIGN-NOTES.md) |
| Crypto signal channel (`onCryptoSignal`) | working for verification and for the signing identity. `verification_requested` carries the `verificationId` that `acceptVerification` takes, and is the only way this library hands a receiving side that identifier; `trust_changed` names a user, and the rule is to read status rather than count signals; `verification_completed` names the flow a scanned code finished, on both screens, and carries no trust, so read `getDeviceStatuses` or `getIdentityStatus` when it arrives. The asymmetry between the signals is named on `onCryptoSignal` itself. `unexpected_device` and `key_missing` still have no producer: a missing key arrives as a rejected `decryptEvent` with kind `missing_key` |
| Creating and publishing this account's cross-signing identity | working, through `createCrossSigningIdentity` for the account's first identity and `bootstrapCrossSigning` for publishing the one this device holds, read with `getIdentityStatus`, with the user-interactive authentication loop left to your product because this library never sees a credential |
| Joining that identity from a second login | working, through `requestSelfVerification`: the new device verifies itself against one that already holds the identity, the private keys arrive by encrypted gossip on a later sync, and `getIdentityStatus` then reports `privateKeysHeld`. Proven between two crypto machines with everything travelling through the queue. When no second device is to hand, `recoverIdentity` is the other way in |
| `EventEnvelope.senderVerification` on a decrypted event | working, and it reads `verified` once the whole chain has been driven, which it can be from TypeScript since this release |
| Sender authenticity, per event | **provided at the end of a chain, not by a call.** Seven steps: hold a signing identity, publish it, have the sender publish and sign theirs, fetch their keys, complete a comparison, upload the signature it produces, and fetch their keys again. Omitting the last step is silent and leaves every event reading `unverified_identity` |
| Surviving a reinstall | working, through `createRecovery` and `recoverIdentity`: the account's private signing keys are stored encrypted in its own account data under a passphrase, and a device that has lost its store restores them and is the same identity it was. Proven end to end against a real store. `createRecovery` refuses to write over a recovery the account already has, including one another Matrix client wrote. The two account data requests are your product's, because this library performs none |
| Secret export and import | **not implemented, and not coming.** `exportSecrets` and `importSecrets` would need a `Uint8Array` container that Matrix does not define, so it would be a format this library invented and no other client could read. `createRecovery` delivers the interoperable form instead; the [design notes](DESIGN-NOTES.md) say more |

The unimplemented functions exist today as final types that compile, and reject at runtime with a typed `not_implemented` error. That is intentional: a consuming team can build against the real shape while the cryptography underneath is written.

## Limits you must design around

**A verified device is not a verified sender.** `EventEnvelope.sender` is the value the homeserver delivered, and a successfully decrypted event does not prove who sent it. **Verifying a device does not change this.** A verification establishes *local* trust in a device, whether the two people compared a string or one of them scanned a code, and the path that decides what a decrypted event says about its sender consults *cross-signing*: upstream's `SenderData::from_device` branches on whether the sending device is cross-signed and then on whether that signature is trusted, and never consults local trust. Only the second of those two questions needs a key of ours. So a device can read `verified` from `getDeviceStatuses` while an event from that same device still carries an unauthenticated sender. Treat `sender` and `algorithm` as unauthenticated transport metadata, and not until any particular version: this said "until cross-signing lands in M4", cross-signing has landed, and neither field moved. Both are read from the incoming event and never re-derived. What cross-signing adds is `senderVerification`, a separate value rather than a promotion of those two.

`EventEnvelope.senderVerification` reports what this library knew about the sender at the moment it decrypted, in its own vocabulary rather than folded into `TrustState`, because they are two subjects. What each value costs to reach is documented at the type and at each member rather than left for you to discover.

**Which two, and the surprising one that is not among them.** The line falls on *whose* cross-signing identity a value depends on. `verified` and `verification_violation` both need an identity of **ours**. `unverified_identity` needs one from **the sender** and nothing from us: the check underneath asks only whether the sending device carries a signature from a self-signing key its own owner published. So this release does produce it, from any peer whose client has cross-signing set up, which is most of them. Handle that branch.

**The other two were right when they were written, and one of them is out.** `verified` arrives through this surface from this release. Reaching the value is still a chain of seven steps rather than a setting, and the step everyone omits is the last one, but every step of it can now be driven from your product. `verification_violation` is the one still waiting, and it waits on a situation rather than on a missing call: it needs a sender whose chain completed and whose identity then changed. Write both branches.

**When `verified` does arrive, it does not arrive retroactively.** Verifying someone changes what their next messages report, not what their old ones reported. The value belongs to the Megolm session an event was encrypted with, it is computed once when that session's key arrives, and it is never recomputed for a session whose sender had already been identified. A message decrypted while its sender was merely cross-signed keeps reading `unverified_identity` until that session is replaced, however thoroughly you verify them afterwards. Design for "from here on" and not for a badge that backfills a conversation.

What `senderVerification` can also do is tell an ordinary unsigned device apart from `mismatched_sender`, which says the sender the event claims is not the owner of the session that encrypted it. Decryption succeeded and the `sender` field is still false. That is an impersonation signal and the one value here worth reacting to on its own. It is also a **snapshot taken at decryption time**: upstream defines it as the state of the sending device then, and tells callers who persist it to mark it dirty when `device_lists.changed` arrives down the sync, which you are already passing to `receiveSyncChanges`. Nothing re-derives a stored value for you.

**The recovery key is shown once and cannot be produced again.** `createRecovery` returns it, nothing stores it, and no call brings it back. If your user loses it and forgets the passphrase, the account's identity is gone: nothing on the server can open the stored keys without one of the two, this library keeps no second copy, and the consequence is not only theirs. Every device they own has to be verified again, and so does every person who had verified them. That is the whole security value of the mechanism and the whole support burden of it, and a screen the user taps past is where the burden starts.

**A wrong passphrase and an unreadable recovery are different answers, and your product has to word them differently.** `recoverIdentity` reports `recovery_key_incorrect` when the stored recovery is intact and the secret was wrong, which is the one refusal here a user fixes by typing again, and `recovery_data_malformed` when no secret will ever open it. Telling a user with a typo that their recovery is destroyed sends them to set it up again, which is the one action that actually destroys the old one; telling a user whose recovery really is unreadable that their passphrase is wrong leaves them retyping something that was already right. The library never folds the two, and that holds for a mistyped **recovery key** as much as a mistyped passphrase, including against a recovery another client wrote that describes no passphrase at all. The third refusal, `recovery_not_set_up`, means the account data you handed over carries no complete recovery: this account has none, or you did not fetch all five events, or its `m.secret_storage.default_key` has been cleared and points at nothing. That last one is the state a half-finished replacement leaves, and it is deliberately not `recovery_data_malformed`: the key description and every ciphertext are still on the server, writing the pointer back makes the same passphrase work again, and telling that user their recovery is destroyed would send them to do the one thing that destroys it.

**`createRecovery` will not write over a recovery this account already has, and it needs the account data to know.** It takes the account's existing global account data alongside the passphrase, and refuses with `recovery_already_exists` when that names a recovery. It cannot tell your two callers apart: a user replacing their own passphrase, where the old recovery key is meant to stop working, and a product writing what it believes is a first recovery for a user who already set one up in Element, where the key that stops working is one somebody wrote down and was told to keep forever. **To add one deliberately, call again with the same account data minus the `m.secret_storage.default_key` entry.** Filter that one entry out of the array; write nothing to your homeserver to arrange it. The refusal lifts, the ciphertexts still merge, and the recovery the account has keeps working until your last `PUT`, of the new pointer, switches it over, so there is no window and nothing to undo if you stop halfway. Clearing the pointer on the server also works and keeps the merge, at the cost of a window in which the account resolves no recovery. Passing `[]` also works and costs the merge instead: this call merges into what you hand it, so handed nothing it drops every other key's ciphertext, including another client's. All three are possible because the call believes what you hand it, the same way the cross-signing gate believes a key query you reported as answered. What the refusal buys is not that destruction is impossible, but that you have to have looked, and that the cheapest way past it destroys nothing.

**Adding a key is not revoking one, and the difference matters most to the user you are most likely to be helping.** The route above re-points the account. It leaves the old key description on your homeserver and the old key's ciphertext in every `encrypted` map, because keeping them is what the merge is for, so anyone holding the old passphrase who can read that account data still opens the account's private signing keys by reading the old description directly rather than following the pointer. `recoverIdentity` follows the pointer; a homeserver operator, anyone with a live access token and any client that remembers the old key id do not have to. If your user is replacing a passphrase they no longer trust, you must additionally remove the old key id from each `m.cross_signing.*` entry before you write it, and clear `m.secret_storage.key.<old id>` **after** the new pointer is live. Never before: a key whose description is gone can never be reconstructed from any secret, so clearing it while it is still the account's default is a loss rather than a rotation. This library cannot do the removal for you, for the same reason it refuses in the first place, which is that the entry it would drop is indistinguishable from another client's.

**The passphrase is the weak half, and this library imposes no rule on it.** The encrypted keys sit on your homeserver, so the passphrase is what stands between anyone who can read that account data and the account's private signing keys. `createRecovery('')` is accepted, and so is anything else: no minimum length, no strength estimate, no refusal. That is a decision, not an omission, and the reason is that any threshold picked here would be arbitrary, wrong for somebody, and unadjustable from your side. Choose a policy and apply it before you call. A strong recovery key does not make up for a weak passphrase: secret storage opens on either credential, so anyone who can read the account data has to beat only the weaker of the two, and thirty-two random bytes are no help while an empty passphrase opens the same ciphertext. What the recovery key protects is your user's own access, which is the reason to make them record it.

**Write the account data in the order you were given it, with the default-key pointer last.** Everything before it adds to the account without changing what any client resolves, so an interrupted write leaves whatever recovery the account had still working. Writing the pointer earlier repoints the account at a key whose secrets do not exist yet, and in that window neither the old recovery nor the new one opens anything.

**Server-side recovery is Matrix's format, not this library's.** What `createRecovery` writes is secret storage as the specification defines it, produced by `matrix-sdk-crypto`'s own implementation, so another Matrix client signed into the same account reads it with the same passphrase and a recovery another client wrote is one `recoverIdentity` restores. The two requests are yours: this library performs none, so you `PUT` the five events it hands back and `GET` them again when you need them. The key description's event type ends in the key's own id, so read `m.secret_storage.default_key` first, or take the whole of your global account data out of a sync you already perform.

**`EventEnvelope.ciphertext` holds the plaintext on the decrypt path.** One type serves both directions, so the field name describes the encrypt path and is wrong on the other one. Handle what `decryptEvent` returns as plaintext: no logging, no unencrypted persistence, no crash report.

**The interoperability proof has a floor, and it is the ratchet.** `matrix-nio` 0.26 and this library both call `vodozemac` 0.10.0, so a defect inside that crate, or a misreading shared below the protocol line, would pass both sides. What is genuinely tested by two independent implementations is everything above it: event shapes, the `/keys/*` payloads a real homeserver accepts and answers, to-device routing, and the order a session key has to travel in. That is where this library's own code lives. **The same floor applies to the verification proof, and for the same crate**: nio's short string key agreement and MAC derivation go through `vodozemac` too, so what that proof establishes is the protocol layer, which is the event vocabulary, the flow shape, and the commitment computation, which is where the defect it found actually was.

**A signal that has not arrived may still be coming, and nothing bounds how late.** A crypto signal was observed missing a 2000 ms budget once in eight launches on an emulator, and that observation **remains unexplained**. The measurement that followed removed a candidate rather than finding a cause: emission was measured before and after the change that replaced one operating system thread per signal with a reusable pool, under three host conditions including deliberate saturation, and both arms delivered in milliseconds, so emission is not what those seconds were paying for. The original check had no instrument and so cannot tell a late callback from a lost one. The interop suite's 10000 ms wait is interpolated between the one budget watched failing and the one watched passing, not derived from the clean distribution, and nothing has ever been observed at 10000 itself. Design for a signal that is late, not for one that cannot be. The full measurement record, with the raw samples, is kept outside this repository.

**iOS signal delivery has been measured on a simulator, and on nothing else.** Forty launches on a booted iOS 26.5 simulator, interleaved between two builds of the emission path so that host drift falls on both arms equally: every launch delivered its callback and reported every check passing, no signal was lost, and the whole distribution is milliseconds, the worst first delivery anywhere in the run being 29 ms. The callback never lost the race to the promise, in any of the 40, where on Android it lost it in half of them. So the 10000 ms budget is generous here too, and for the first time that is an observation rather than an assumption. **A simulator is not a device, and the gap is not a detail.** It runs on the development machine's own processor, scheduled by that machine's kernel, with no thermal throttling, no app lifecycle, no memory pressure from other applications and no radio, and it runs the simulator slice rather than the device slice of the Rust. What the run establishes is that the callback path works on iOS, that it delivers rather than dropping, and roughly what it costs when nothing is in its way. **iOS hardware remains unmeasured**, and `ci.yml` still runs no iOS end to end leg, so no job exercises this path on a pull request. The full record, with the method and the raw samples, is kept outside this repository.

## Design notes and history

How this library was built, what the measurements do and do not establish, and the corrections this file has made along the way, live in [DESIGN-NOTES.md](DESIGN-NOTES.md). None of it is needed to use the library.

## Roadmap

**Everything this library set out to do is built.** Encryption and decryption, device verification by comparing a short string, verification by scanning a code in all three modes the protocol defines, cross-signing identities, and recovery through server-side secret storage. The table above is the authority on what each of those does and does not promise; the design notes are the history behind it, and you do not need either to use the library.

What remains open:

* a scannable code read by an ordinary phone camera, as something a run can assert rather than something a person confirms
* multi participant scenarios and federation neutral test coverage
* cross implementation testing against both Synapse and Continuwuity
* a stabilised API, published documentation and multi platform CI for 1.0

## Contributing

```sh
yarn install
cargo test --manifest-path rust/Cargo.toml            # Rust
yarn --cwd packages/react-native-matrix-crypto test   # TypeScript
yarn --cwd packages/example-app test                  # the example app
```

`packages/example-app` is a neutral React Native application that runs the full chain and explains it, walking from a trivial call through to real cryptographic keys and showing at each step the exact TypeScript a consumer would write, what crosses the native boundary, and the result. It counts its own steps on screen rather than stating a number here, because the number was wrong in both copies of this file at once and the check that compares them could not see it. Its tests drive the walkthrough's real step functions, and what they cannot reach is the JSI turbo module, which no Node process can load; `packages/example-app/README.md` lists exactly which behaviour is still exercised only on a device.

The layers, top to bottom: the TypeScript facade in `src/*.ts` holds the branded types, error normalisation and the public API; `src/generated/` and `cpp/generated/` are emitted by [`uniffi-bindgen-react-native`](https://github.com/jhugman/uniffi-bindgen-react-native) and are never edited by hand; `rust/matrix-crypto-ffi` is the `#[uniffi::export]` surface and does type mirroring, conversion and delegation only; `rust/matrix-crypto-core` holds all the logic, knows nothing about UniFFI, JSI or React Native, and is testable with plain `cargo test`. Change the Rust and regenerate with `yarn --cwd packages/react-native-matrix-crypto codegen`; `gate:drift` regenerates and fails on any difference, and `gate:boundary` asserts the core never gains a direct `uniffi` dependency.

### Running the proofs

```sh
./scripts/run-level-two-interop.sh                       # the Rust core
python3 packages/example-app/level-two/run_level_two.py  # the published TypeScript API
```

The first starts a throwaway [Continuwuity](https://continuwuity.org) homeserver in a container, creates the five accounts the tests need with a password generated for that run, installs a pinned `matrix-nio[e2e]` into a temporary virtualenv, builds the mautrix-go counterparty from the version its own `go.mod` declares, runs the five level 2 proofs, and destroys all of it. It needs Docker, a Rust toolchain, a Python 3 and a Go toolchain, and nothing else, and it demands all four before it starts anything. No credential is read from anywhere and none is left behind. CI runs the same script, so what you run and what stands behind the claim are the same code path. A run that never reaches the assertions fails: the script requires cargo's own output to name each test as passed, because `cargo test` exits successfully when it matches no test at all. The five are encryption against a third-party client, device verification against one, a signing identity published to a real homeserver, the authentication loop that publishing one needs, driven against a refusal the homeserver wrote, and all three modes of verification by a scannable code against a counterparty that shares no protocol code and no Olm implementation with this one. To point it at a homeserver you already have accounts on, set `MATRIX_INTEROP_HOMESERVER`, `MATRIX_INTEROP_USER`, `MATRIX_INTEROP_PASSWORD`, `MATRIX_INTEROP_CHALLENGE_USER`, `MATRIX_INTEROP_CHALLENGE_PASSWORD` and `MATRIX_INTEROP_NIOSTORE` in the environment. The Python leg takes the same variables.

The second drives the same exchange through the UniFFI scaffolding, the JSI binding, the generated TypeScript and the facade, on an Android emulator. It needs Docker, an emulator `adb` can see, a release APK already built, and a Python with `matrix-nio[e2e]`, and no Rust toolchain. It stands up its own homeserver, creates two accounts and an encrypted room, drives `matrix-nio` as the counterparty, installs and launches the example app, and reads the app's own `LEVEL2_SUMMARY 13/13` back out of the system log. Every call the app makes is the published API and nothing else. Everything it creates lives inside the container, which is destroyed from a `finally`, an `atexit` hook and a signal handler. `--mutation <name>` sabotages exactly one assertion to check that assertion can fail, and a mutated run prints a different summary line, so it can never be read as a clean one.

### Build gates

Every one of these runs in CI. Each has been observed rejecting a real violation, not merely passing.

| Gate | Enforces |
|---|---|
| `gate:workspaces` | the Cargo and yarn workspaces resolve |
| `gate:boundary` | the core takes no direct `uniffi` dependency |
| `gate:drift` | committed bindings match the Rust source |
| `gate:logger` | the bridge contains no logger, in every language it ships: Rust, TypeScript, C/C++/Objective-C, Kotlin, Swift and the podspec |
| `gate:agility` | no Megolm, Olm, room or Matrix specific identifier reaches the public API |
| `gate:stubs` | the committed turbo module is really wired up, not an empty shell |
| `gate:surface` | every name a public module exports reaches `src/index.ts`, so nothing ships unreachable |
| `gate:doc-links` | every doc link, in Rust and in TypeScript, points at something that exists |
| `gate:readme` | the README npm shows is the README GitHub shows, and every gate here runs in CI |
| `gate:uia-example` | the worked example for the signing-keys authentication loop runs the same steps as the test that proves it |
| `gate:measure-guards` | the B2 measurement harness still refuses the runs it documents refusing |
| `gate:measure-guards-ios` | the same, for the iOS harness, including its refusal to launch into a log stream it cannot show was already attached |
| `gate:artifact-provenance` | an artifact size is only ever recorded from a binary this tree built |

`gate:stubs` exists because of a specific near miss: `ubrn build --and-generate` can emit a turbo module that exports nothing, with exit code zero and no warning, when it reads an Android shared library whose symbol table was stripped. Nothing downstream noticed and the build went green. `gate:drift` cannot catch that either, because two equally empty generations agree with each other perfectly. If you add a gate, add the step that proves it fails on a real violation.

### Releasing

A release is a git tag. Pushing a tag matching `v*` — for example `v0.3.0` — runs `.github/workflows/release.yml`, which calls the entire pull request workflow first, then builds the full cross compile matrix for both platforms, checks that the binaries really landed in the tree it is about to pack from and that npm's own file list names them, packs one tarball, asserts that tarball really contains the prebuilt binaries, installs those same bytes with `cargo` and `rustc` scrubbed out of `PATH` and loads the module out of them, and only then publishes, with provenance and under the correct distribution tag. It publishes the exact tarball it checked rather than repacking. Afterwards `scripts/assert-published-tags.sh` reads the tags back off the registry. Four things stop the run before anything is built, each saying so by name: a tag that disagrees with the version in `packages/react-native-matrix-crypto/package.json`, a distribution tag that disagrees with what that version implies, a version already on the registry, and a missing `NPM_TOKEN`.

`./scripts/rehearse-publish.sh` runs the same tree check, packs exactly as the release workflow packs, runs the same assertion on the packed bytes, and finishes with `npm publish --dry-run --tag <tag>`, uploading nothing. It needs the binaries on disk and names precisely which are missing. `./scripts/assert-release-ready.sh v0.3.0 latest` rehearses the other half against the current version; pass the version you are about to tag. Neither is a `gate:*` script, because `gate:readme` requires every `gate:*` to run as a step in `ci.yml` and these need an artifact with binaries in it, which a pull request never has.

### Conventions

* Conventional Commits, imperative mood, one subject per commit.
* A manifest change and its lockfile update belong in the same commit.
* Every core to FFI type conversion destructures its source, so a field added later fails the build instead of being silently dropped.
* Tests assert, they do not print, and `gate:logger` reads `rust/*/tests` to make sure of it. The one thing a test may do that the library may not is write a file: the level 2 proof passes a marker through the filesystem to a spawned child process, which is how the cross-process restore is proved at all.

## Security

This library has not been independently audited. It wraps `matrix-sdk-crypto`, which is widely deployed, but the bridge layer around it is new.

If you believe you have found a security issue, please report it privately through GitHub's security advisory feature on this repository rather than opening a public issue.

## License

Apache-2.0. The same license as `matrix-sdk-crypto`, which this library is built on, and which carries the patent grant that matters for cryptographic work.
