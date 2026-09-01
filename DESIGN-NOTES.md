# Design notes

The history, measurements and corrected mistakes behind the claims the README
makes. None of this is needed to use the library; it is kept because a claim
you cannot interrogate is worth less than one you can. The README states what
is true now and points here for how it came to be known.

## Publication history

A plain `yarn add` resolves npm's `latest` tag, and a prerelease is published under its own tag, so `yarn add react-native-matrix-crypto@rc` is how you ask for one on purpose. That was not always enough to keep a prerelease away by accident: npm assigns `latest` to the *first* version published to a new package whatever `--tag` says, because a package must always have a `latest`, and `0.1.0-rc.2` was that first version. Until a stable version took `latest` over, `latest` and `rc` pointed at the same prerelease and a bare `yarn add` got it. npm does not allow the `latest` tag to be deleted, so a stable publish is the only thing that moves it. `0.1.0` is that publish.

**Which state the registry is in as you read this is not something this file can tell you.** A file shipped inside an artifact cannot report on the state its own publication creates. `scripts/assert-published-tags.sh` reads the tags back off the registry after every publish and says which state you are in, because every check before a publish can only verify the tag npm was *told*, never the one npm *applied*. Run it, or read the tags yourself with `npm dist-tag ls react-native-matrix-crypto`.

## How it was built

The work ran as five milestones, and their numbers appear in commit messages and in tests. M2 was the encryption core, M3 device verification by short string, M4 cross-signing and recovery, M5 verification by a scannable code. This paragraph named M2 and M3 alone for two milestones after that stopped being the whole list, while the table under it grew rows neither of them produced, and a reader could reasonably read the stale half and stop. Two things are worth recording about the first two. A tokio runtime became mandatory, because group key sharing reaches `tokio::task::spawn`; the core owns one, and signal delivery is non blocking, so no callback holds a lock or waits on JavaScript. And binary size went the other way from expected: linking the Rust as a shared library instead of a static archive cut the published tarball by 74 percent, from 263 MB to 68 MB, which is 44 percent of its budget, so splitting into per platform packages was not needed.

The third-party verification proof is where M3 stopped short. `matrix-nio` opens a verification, this library announces it with a usable identifier and agrees to it, and this library carries its own half of the key exchange to a short authentication string, over a real homeserver. That is participation, not completion, and the reason is in the counterparty: matrix-nio 0.26.0 writes the SAS commitment as hexadecimal where the specification requires unpadded base64, which no spec-compliant client can accept in either direction. It was compliant in 0.25.2, and nio's own tests pair two nio objects, so nothing there could notice. The test is written so a corrected nio makes it fail rather than pass silently: it waits for a refusal that no longer comes, and says so in the message it times out with.

**Verification by a scannable code was deferred twice and has now landed**, and what became of the three costs recorded against it is worth reading, because two of them turned out to be small and the third was already false when it was written. It would add a dependency absent from `rust/Cargo.lock`: it added exactly two entries, `matrix-sdk-qrcode` and `qrcode`, the second of which has no dependencies of its own and every dependency of the first of which was already in the tree. It would add an off-by-default Cargo feature: that feature is on now, and a consumer who never scans is unchanged on the wire anyway, because announcing a code is a runtime switch this library leaves off. And it would put pressure on a size budget already tripped once: two full release builds per platform, identical but for that one feature line, put the Rust up by 250,168 bytes on the `aarch64-apple-ios` archive the `.xcframework` ships and by 50,144 bytes on the `aarch64-linux-android` library that ships in `jniLibs/`, which is half a percent of each. The third recorded cost was that the bridge had never carried a scanned payload across the boundary, and a byte vector had in fact crossed outward since M2 and inward since M1, both proven on a device.

**That size figure was a measurement of two architectures and a projection to the other five, and a release build has since replaced it.** Seven ship: three iOS targets and four Android ABIs, and the projection scaled the two over all seven to roughly 299 KB on the packed tarball. The measurement disagrees. `artifact-sizes.json` carries it as `m5-scanned-code`, from a release build of both legs with the provenance check satisfied on each: the tarball goes from 66,226 KB to 67,851 KB, which is plus 1,625 KB, and from 43.12 percent of its 150 MB gate to 44.17 percent. Unpacked that is plus 4,541 KB against a 193,565 KB tree, of which 2,328 KB is the `.xcframework` over three slices and 2,009 KB is `android` over four ABIs. **The projection was wrong by about five times**, and it is corrected here rather than defended. Two things the measured number is not. It is not all of M5: the baseline row was built on a hosted macOS runner and this one on a developer machine, so a toolchain difference falls inside it. And it is not a gate failure, at 44 percent of the budget against 43 before. The gate refused the first attempt at the row, correctly: the iOS framework carried a stamp naming a commit two behind the tree, and it declined rather than attributing this tree's Rust to bytes that never contained it. A number taken from whatever binary happened to be lying around would be a real measurement of the wrong artifact and would read exactly like a real measurement of the right one, so `scripts/measure-artifacts.sh` refuses that case rather than recording it.

**A camera has read one, once.** On 2026-08-31 the repository owner held a phone running `packages/example-app`, showing a code this library drew, in front of a Logitech webcam serving as the back camera of an Android emulator running **Element Classic 1.6.62**. Element scanned the square, the person confirmed on the phone, and both sides finished. The phone's own log carried the stages in order: `ready`, then `code-scanned` when Element said it had read the code, then `code-scanned` again after the confirmation, then `done`. That run was also the first time a real payload byte crossed the published TypeScript surface, because every other test of that surface talks to a mock.

**What that run does not establish, said here rather than left to be reconstructed.** It was **one run**. It was **one mode**: self verification between two logins of one account, with the phone, which held no cross-signing private keys of its own, showing the code. It was **one direction**: this library drew and Element read. No camera has read a code in the other direction, and no client other than that one has been tried. The far side was confirmed by **a person looking at Element's verified shield**, not by a program reading a result, so the far half of "both sides finished" is a human observation. It ran on a tree containing `3e9c5be`, the commit that let a product announce showing without scanning, which this branch contains; the same attempt before that commit failed, because this library told Element that a product with no scanner could scan and Element reasonably chose the mode that product could not perform. **Nothing in this repository re-checks any of it.** `packages/example-app/level-two/run_camera_proof.py` arranges the setup, prints what to do, and then stops and asserts nothing on purpose, because a program claiming to have checked a person looking at two screens would be claiming something it did not see. Everything in this paragraph is one person's report of one thing they saw once, and it is worth exactly that.

A foreign implementation has done the rest under test: `rust/matrix-crypto-core/tests/level_two_scanned.rs` drives all three modes against a mautrix-go counterparty over a real homeserver, in both directions, and that counterparty shares no protocol code and no Olm implementation with this one. That is the claim with a machine behind it. The camera is the claim with a person behind it, and the two are not interchangeable. This roadmap entry named three things, and all three have now landed. The other two were the same piece of work, the stage vocabulary growing to carry a scanned flow: `getVerificationStage` answers `code-scanned`, and a flow that finishes by a scan announces `verification_completed` rather than the `trust_changed` it produces no producer for.

**Secret export and import have been decided against rather than deferred, and the roadmap no longer lists them.** `exportSecrets` and `importSecrets` are frozen with a passphrase in and a `Uint8Array` out, and `matrix-sdk-crypto` gives the payload for that but not the container: the three signing seeds come out as plain JSON, neither encrypted nor derived from a passphrase, and neither of its two passphrase primitives is the right shape to wrap them. So the byte array would be a format this library invented, readable by nothing else. That is defensible for moving an identity between two phones you own and wrong for anything a user would call a recovery key, and since `createRecovery` now delivers the interoperable form, shipping a private one beside it would invite exactly that confusion. Both calls stay, rejecting with `not_implemented`, and their documentation says why rather than reading as unfinished work.

### What remains open

Next, in order:

* a scannable code read by an ordinary phone camera, as something a run can assert rather than something a person confirms. The method itself has landed and the two paragraphs above say what it cost and what it still owes; this line used to say the method was next, then that a code flow's own stages were still unreadable, which `getVerificationStage`'s `code-scanned` closed, and then that no foreign implementation had read a code, which mautrix-go closed
* multi participant scenarios and federation neutral test coverage
* cross implementation testing against both Synapse and Continuwuity
* a stabilised API, published documentation and multi platform CI for 1.0

## Assembling a milestone from parallel branches

M5 was built as five task branches merged into one consolidation branch, and
**the documentation sweep merged third of five**. Three merges landed after it.
Nothing re-read the prose against them, and the request-lifecycle paragraphs
near the top of the README went false in exactly that window: they described
every `keys_query` as retired by a later drain, which stopped being true when
the branch that queues a key query behind a scanned code's signature landed
after the sweep had already run. The sentence was still fluent, still identical
in both copies of this file, and still linked to real names.

**No gate here catches that, and none can.** `gate:drift` compares generated
code against the source it was generated from, `gate:readme` compares two copies
of one file against each other, and `gate:doc-links` checks that a name a link
points at exists. Every one of them checks a relationship between two artifacts
of the same age. What goes stale when branches land in parallel is the
relationship between prose and code, and a paragraph can be perfectly consistent
with everything a gate compares it to while describing behaviour the tree no
longer has.

So, when a milestone is assembled from parallel branches:

* **Merge the documentation sweep last, or run it twice.** A sweep that cannot
  see three of the branches it is sweeping for has swept a different tree.
* **Re-read the prose the last merge's code touches, specifically.** A branch
  that changes a lifecycle, an enumeration, a count or a refusal has probably
  falsified a sentence somewhere, and that sentence will not appear in its diff.
* **Re-measure at the tip anything stated as a number.** A correct measurement
  of an earlier tree reads exactly like a correct measurement of this one, which
  is the argument `gate:artifact-provenance` already makes about build stamps;
  it applies to the tree being published as well as to the artifact being
  measured.

## Corrections this documentation has made

The README records its own past errors where the correction matters to a
reader weighing a claim. The ones that no longer bear on any current
sentence live here instead.

**This paragraph told you to use `bootstrapCrossSigning` for one release and that was wrong.** Measured on two homeservers: a device in this state, answered honestly that the account has no identity, published over an identity a second device of the same account had legitimately created in the gap before that answer was reported. The launch-time call did it, while `createCrossSigningIdentity` refused correctly throughout. So `bootstrapCrossSigning` now refuses here with `identity_not_known`, and that refusal is the same one a brand-new account gets, with the same remedy, so one branch in your product handles both.
