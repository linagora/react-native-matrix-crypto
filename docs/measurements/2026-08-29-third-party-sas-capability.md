# Can a third-party client complete a SAS verification against this library? (spec §8)

*What matrix-nio 0.26.0 can and cannot do, which of it was read and which was watched
running, and exactly whose code would have to change.*

`docs/superpowers/specs/2026-08-28-m3-design.md` §8 requires, as an M3 exit criterion,
that **a third-party client participates in at least one SAS flow over a real
homeserver** — *"or an explicit written finding that no available third-party
counterparty implements SAS in a form this can drive, with the evidence for that
finding. The second outcome is acceptable; silence is not."*

This file is that finding. It is written **before** any test, deliberately: the criterion
permits a negative answer, and the way to get a dishonest positive is to decide the answer
is yes and then build a counterparty that only appears to be one.

**The answer is neither of the two the criterion anticipated.** It is not "a third-party
client can do this today" and it is not "no available counterparty implements SAS".
matrix-nio implements SAS completely, and every byte of it is wire-compatible with what
this library's own crypto core produces — but in a **flow shape this library neither
sends nor can receive.** The obstacle is not in nio. It is two named, small gaps in
`rust/matrix-crypto-core/src/verification.rs`, and this file says exactly what they are.

---

## 1. What was examined, and at which version

| Component | Version | Where it is pinned |
| --- | --- | --- |
| `matrix-nio` | **0.26.0** | `rust/matrix-crypto-core/tests/interop/requirements.txt` |
| `vodozemac` (nio's ratchet) | 0.10.0 | same file |
| `matrix-sdk-crypto` (this library's core) | 0.18.0 | `rust/Cargo.lock` |
| `ruma-events` | 0.34.0 | `rust/Cargo.lock` |

The existing level-2 harness is `scripts/run-level-two-interop.sh`, which builds a
throwaway virtualenv, installs that requirements file with `--no-deps`, and drives
`rust/matrix-crypto-core/tests/interop/nio_party.py` as a subprocess of
`rust/matrix-crypto-core/tests/level_two_interop.rs`. That pin is what this file examined:
the same file, installed the same way, into a scratch virtualenv that has since been
removed.

**0.26.0 is the newest matrix-nio in existence.** *Observed*: PyPI's own metadata reports
`info.version == "0.26.0"`, uploaded 2026-07-23. There is no later release to upgrade to,
so nothing below can be answered with "a newer nio fixes it".

A note the requirements file already makes and this one inherits: nio 0.26 moved its
ratchet to `vodozemac`, the same crate `matrix-sdk-crypto` uses. The independence is at
the protocol level — event shapes, negotiation, state machine — not all the way down.
For verification that distinction is *more* favourable than it is for encryption: nio's
SAS state machine (`nio/crypto/sas.py`) is 700 lines of Python that upstream's Rust does
not share. Only the underlying `vodozemac.Sas` Diffie-Hellman and HKDF are common.

### 1.1 How to read the claims below

Every claim in this file is marked. **Read** means the assertion rests on reading the
source. **Observed** means something was executed and its output is reproduced here. The
distinction is load-bearing: three times during this milestone, reading upstream produced
a confident belief that a test then refuted, so the claims that carry the answer were all
promoted to *observed* before this file was written.

---

## 2. Does matrix-nio 0.26.0 implement SAS? Yes, completely.

*Read.* The implementation is `nio/crypto/sas.py`: a `Sas` class and a `SasState` enum
(`created`, `started`, `accepted`, `key_received`, `mac_received`, `canceled`). The
client-facing half is `nio/client/base_client.py` (`key_verifications`, `get_active_sas`,
`create_key_verification`, `confirm_key_verification`) and
`nio/client/async_client.py` (`start_key_verification`, `accept_key_verification`,
`confirm_short_auth_string`, `cancel_key_verification`, `to_device`,
`send_to_device_messages`). Event dispatch is `nio/crypto/olm_machine.py`'s
`handle_key_verification`.

*Observed.* Two nio `Sas` objects were paired against each other offline — no homeserver,
no credentials, the to-device messages hand-carried between them — to watch the whole flow
rather than infer it. The transcript:

```
matrix-nio 0.26.0 / vodozemac 0.10.0

[1] alice.start_verification() -> type='m.key.verification.start' method='m.sas.v1'
    sas methods offered: ['emoji', 'decimal']
[2] bob responded via from_key_verification_start; we_started_it=False
[3] accept exchanged; alice.state=accepted chosen_key_agreement='curve25519-hkdf-sha256'
[4] keys exchanged; alice.state=key_received bob.state=key_received
[5] alice emoji: ['Lion', 'Wrench', 'Gift', 'Glasses', 'Rooster', 'Flag', 'Dog']
    bob   emoji: ['Lion', 'Wrench', 'Gift', 'Glasses', 'Rooster', 'Flag', 'Dog']
    emoji agree: True   decimals agree: True  (alice decimals (2365, 1414, 1227))
[6] accept_sas() on both; alice.sas_accepted=True
[7] MACs exchanged; alice.state=mac_received bob.state=mac_received
    alice.verified=True bob.verified=True
    alice.verified_devices=['BBBBBB'] bob.verified_devices=['AAAAAA']

[8] reject_sas() -> canceled=True code='m.mismatched_sas'
    reason='Mismatched short authentication string'
    cancellation to-device message type='m.key.verification.cancel'
```

That answers the five sub-questions §8's task asked, in order:

| Question | Answer | Evidence |
| --- | --- | --- |
| Can it **initiate**? | Yes — `Sas.start_verification()` / `AsyncClient.start_key_verification(device)` | *Observed*, step [1] |
| Can it **respond**? | Yes — `Sas.from_key_verification_start()`, driven by `handle_key_verification` | *Observed*, step [2] |
| Does it expose the **short authentication string**? | Yes — **both** `get_emoji()` (7 emoji with names) and `get_decimals()` (3 integers) | *Observed*, step [5] |
| Can a caller **confirm and cancel** without a UI? | Yes — `accept_sas()` / `reject_sas()` / `cancel()` are plain method calls returning to-device messages | *Observed*, steps [6] and [8] |
| Does it complete the **MAC exchange** and **mark the peer verified**? | Yes — `verified=True`, `verified_devices` populated | *Observed*, step [7] |

*Read*, for the last one at the client layer: on a successful MAC,
`olm_machine.py`'s `handle_key_verification` calls `self.verify_device(device)`, so the
trust state is persisted in nio's own store rather than only living on the `Sas` object.

**There is no terminal-UI dependency anywhere in this path.** Everything above is a method
call returning a `ToDeviceMessage`. nio's shipped `matrix-nio` examples wrap these in a
prompt; nothing in the library requires it.

---

## 3. Which flow shapes does it support? To-device only, and only the deprecated one.

This is where the answer turns.

*Observed.* Every `m.key.verification.*` string that appears anywhere in the installed
package:

```
nio/events/to_device.py:  start, accept, key, mac, cancel   (the parse dispatch)
nio/crypto/sas.py:        start, accept, key, mac, cancel   (the messages it builds)
```

Five event types. **`m.key.verification.request`, `m.key.verification.ready` and
`m.key.verification.done` do not appear in matrix-nio 0.26.0 at all** — not as strings,
not as classes, not in any schema.

So nio implements the **deprecated direct-start** to-device flow:

```
start → accept → key → key → mac → mac
```

and not the modern request-first flow that the Matrix spec has carried since v1.1
(MSC2241 / MSC3122):

```
request → ready → start → accept → key → key → mac → mac → done
```

*Read.* There is **no in-room verification** either: `nio/events/room_events.py` has no
key-verification handling, so the `m.key.verification.*` events that a modern client
exchanges as room messages are not parsed at all. nio's verification is to-device only.

### 3.1 What this library sends, and what nio makes of it

`rust/matrix-crypto-core/src/verification.rs:451` calls
`device.request_verification_with_methods(vec![VerificationMethod::SasV1])`, which is the
modern flow. So `request_flow` puts an `m.key.verification.request` on the wire.

*Observed.* The exact body this library's own outbound pump produced, captured from a real
run of the level-1 harness:

```json
{"event_type":"m.key.verification.request",
 "messages":{"@capture:example.org":{"CAPTUREONE":{
   "from_device":"ALICEDEVICE",
   "transaction_id":"0abf13c203cb47ef8216ba1bd71ba9ee",
   "methods":["m.sas.v1"],
   "timestamp":1788000819415}}}}
```

*Observed.* That body, and a `m.key.verification.done`, fed verbatim to nio's own
`ToDeviceEvent.parse_event`:

```
m.key.verification.request (what request_flow sends) -> UnknownToDeviceEvent
m.key.verification.done    (end of a request flow)   -> UnknownToDeviceEvent
m.key.verification.start   (deprecated bare start)   -> KeyVerificationStart
     from_device='ALICEDEVICE' method='m.sas.v1'
     sas methods=['decimal', 'emoji']
     macs       =['hkdf-hmac-sha256', 'hkdf-hmac-sha256.v2',
                  'org.matrix.msc3783.hkdf-hmac-sha256']
```

**The direction in which this library initiates is dead at the first message.** nio
classifies the request as an unknown to-device event and drops it. It never replies
`ready`, so the flow never leaves `FlowStage::Requested`. Nothing times out loudly; it
simply never advances.

---

## 4. But the *other* direction is wire-compatible, all the way down

The deprecated shape is not merely something nio speaks. It is something **upstream still
speaks too**, and the compatibility is exact.

*Read.* `matrix-sdk-crypto` 0.18.0's `verification/machine.rs`, in the `Start` branch of
`receive_any_event`, has an explicit fallback for a `.start` that belongs to no known
request:

> `} else if let FlowId::ToDevice(_) = flow_id {`
> `    // TODO remove this soon, this has been deprecated by MSC3122`
> …  `Sas::from_start_event(flow_id, c, identities, None, false)` → `self.verifications.insert_sas(sas)`

*Read.* And `identities/device.rs:157` still offers the initiating half:
`Device::start_verification() -> StoreResult<(Sas, ToDeviceRequest)>`, documented as
"deprecated in the spec", which emits a bare `m.key.verification.start`.

Three compatibility details that could each have killed this and do not:

- **MAC method.** nio offers only the legacy `hkdf-hmac-sha256`
  (`Sas._mac_v1 = ["hkdf-hmac-sha256"]`). *Read*: `verification/sas/sas_state.rs` lists
  `HkdfHmacSha256`, `HkdfHmacSha256V2` and the MSC3783 name as supported, so the legacy
  one still negotiates.
- **Key agreement.** *Observed*: negotiated to `curve25519-hkdf-sha256` by both.
- **Termination.** *Read*: `verification/sas/inner_sas.rs` forks on `started_from_request`
  in both `confirm()` and the MAC branch of `receive_any_event`. When it is **true**, the
  SAS moves to `WaitingForDone` and waits for the peer's `m.key.verification.done` — which
  nio can never send. When it is **false** — the bare-start path — it goes **straight to
  `Done`** with no `.done` required. *Observed*: nio likewise reaches `verified=True` on
  the MAC alone, with no `.done` (§2, step [7]). **The two implementations terminate the
  same way, and only in this shape.**

*Observed.* The decisive check: matrix-sdk-crypto's real bare-start body, fed to nio.

```
nio state after receiving the library's bare start: started
canceled=False code='' reason=''
nio replies with: m.key.verification.accept
  key_agreement_protocol      = 'curve25519-hkdf-sha256'
  message_authentication_code = 'hkdf-hmac-sha256'
  short_authentication_string = ['emoji', 'decimal']
  commitment present          = True
```

nio does not cancel. It negotiates and replies. **The protocol is compatible; only this
library's surface is not.**

---

## 5. The two gaps, both in this repository

### 5.1 An incoming bare start is invisible to the public surface

*Observed.* A throwaway test was built on `tests/sas_two_party.rs`'s existing level-1
harness: a bare `OlmMachine` counterparty calls the deprecated
`Device::start_verification()`, and the resulting `m.key.verification.start` is relayed
into the library through its own `receive_sync_changes`. Then every public entry point is
asked about the flow:

```
PROBE: bare start event_type = m.key.verification.start
PROBE: flow id = 00b1b80a7654479c9bbdcd6b8fb4e6b6
PROBE: pump after the bare start = [("keys_query", "<no event_type in body>")]
PROBE: flow_stage      = Err(UnknownFlow)
PROBE: read_material   = Err(UnknownFlow)
PROBE: accept_flow     = Err(UnknownFlow)
PROBE: begin_comparison= Err(UnknownFlow)
PROBE: upstream (get_verification, get_verification_request) = Ok(Ok((true, false)))
```

The last line is the whole finding in one measurement. **Inside the library's own machine
the SAS exists** — `get_verification` returns it — **and the library's public surface
cannot reach it**, because `get_verification_request` returns nothing. The library also
does not refuse it: no cancellation was queued, only an unrelated keys query. The flow sits
there, live and unreachable, until it times out.

*Read*, for the cause. `verification.rs`'s `handles()` resolves an unknown flow with
exactly one upstream call:

```rust
Ok(tracked.iter().find_map(|user| machine.get_verification_request(user, &flow_id)))
```

and `FlowRecord`/`Handles` are both declared with a non-optional
`request: VerificationRequest`. A bare SAS has no request, so it cannot be represented,
let alone found. This is a deliberate shape — the module's own comment explains that the
comparison handle is read *from the request* rather than from upstream's map, because the
map is garbage-collected — and it is precisely what excludes the deprecated flow.

### 5.2 There is no way to *send* a bare start

*Observed*, §3.1: `request_flow` emits `m.key.verification.request`. *Read*: no code path
in `rust/matrix-crypto-core/src/` calls `Device::start_verification()`. So this library
cannot initiate in the only shape nio understands.

---

## 6. The answer

**Partial, and the obstacle is in this repository rather than in nio.**

- matrix-nio 0.26.0 **does** implement SAS, completely, headlessly, in both roles, with
  emoji and decimals exposed and confirm/reject as ordinary method calls. *Observed.*
- It implements **only the deprecated to-device direct-start flow**, and **no** in-room
  verification. *Observed* for the absent event types, *read* for in-room.
- That flow is **fully wire-compatible** with `matrix-sdk-crypto` 0.18.0, including the
  MAC method, the key agreement, and — the detail that could most easily have been fatal —
  the termination rule, which requires no `m.key.verification.done` in exactly this shape.
  *Observed* for the negotiation, *read* for the termination fork.
- This library **cannot drive it in either direction today**: it sends a `request` nio
  drops, and it cannot see a bare `start` nio sends even though its own core accepts one.
  *Observed*, both.

So the honest sentence for §8 is **not** "no available third-party counterparty implements
SAS in a form this can drive". It is: *a third-party counterparty implements SAS in a form
this library's core already speaks, and this library's public surface does not expose it.*

### 6.1 The other counterparties, and why they are worse

Checked, not recalled. Nothing is listed here that was not examined.

- **`matrix-js-sdk`** (latest, 42.2.0). *Observed* via the npm registry's own metadata: its
  dependencies include **`@matrix-org/matrix-sdk-crypto-wasm ^18.4.0`** — that is
  `matrix-sdk-crypto`, the same crate in `rust/Cargo.lock`, compiled to WebAssembly. It
  would speak the modern request-first flow and would therefore "work" immediately, which
  is exactly the trap. It is not an independent implementation of the verification state
  machine; it is *the same state machine*. A test against it would be level 1 wearing a
  level 2 costume, and would prove strictly less than the M2 nio test already proved. The
  design doc's own warning about vodozemac applies here an order of magnitude harder.
- **`mautrix` (mautrix-python, 0.21.1).** Genuinely independent — *observed* from its PyPI
  metadata that its `encryption` extra uses `python-olm`, i.e. libolm, not vodozemac. But
  *observed* from the package source: the string `m.key.verification` **does not occur
  anywhere in it**, and its to-device event-type table
  (`mautrix/types/event/type.py`) lists only `m.room_key_request`,
  `m.forwarded_room_key`, `m.dummy` and `com.beeper.room_key.ack`. It has cross-signing
  key handling; it has no interactive verification. Not a candidate.
- **A newer matrix-nio.** *Observed*: 0.26.0 is the latest release. Not an option.

matrix-nio remains the best available counterparty, for verification as for encryption.

---

## 7. What would have to change, and in whose code

**Nothing in matrix-nio. Nothing upstream.** Both halves are in
`rust/matrix-crypto-core/src/verification.rs`, and upstream already provides everything
they need.

1. **Represent a flow that has no request.** `FlowRecord` and `Handles` become
   `request: Option<VerificationRequest>` (or a two-variant enum). Most of the work is
   already done: `stage_of_comparison(comparison: &Sas)` exists at
   `verification.rs:273` and derives a `FlowStage` from a bare `Sas` alone.
2. **Look one more place.** `handles()` falls back from
   `machine.get_verification_request(user, &flow_id)` to
   `machine.get_verification(user, &flow_id)` and takes its `sas_v1()`. *Observed* in §5.1
   that this call already returns the SAS a nio-shaped start creates.
3. **Decide what `accept_flow` means for a bare flow.** There is no request to accept; the
   equivalent step is upstream's `Sas::accept()`. Either map it, or refuse it with a
   distinct error and require `begin_comparison`-free entry.
4. **Optionally, to initiate:** an entry point that calls
   `Device::start_verification()` (`matrix-sdk-crypto` `identities/device.rs:157`) instead
   of `request_verification_with_methods`. Only needed if the test is to drive the flow
   from this library's side; the nio-initiates direction needs 1–3 alone.

Whether any of that is M3's work is a scope decision this file does not make. The point of
the finding is that it is a **contained, named change in code this repository owns**, not
an upstream gap and not an impossibility.

---

## 8. What the test would do, if the change is made

The shape is already built. `scripts/run-level-two-interop.sh` stands up the virtualenv and
the credentials; `nio_party.py` is a newline-delimited-JSON subprocess with the Rust side
owning every step; `level_two_interop.rs` drives it. A SAS flow adds operations to that
same protocol, and nothing structural.

**The synchronisation question §8's task asked about has a good answer.** nio's sync loop
**does not have to run continuously.** *Read*: `AsyncClient.send_to_device_messages()` is a
public method whose own docstring says it is "automatically called by `sync_forever()`" —
so a step-by-step driver calls it explicitly, exactly as `nio_party.py`'s existing
`settle()` already calls `keys_upload()` and `keys_query()` by hand rather than letting a
loop do it. A verification-aware `settle()` is one line longer.

New ops on `nio_party.py`, with the nio calls each makes:

| Op | nio calls | Note |
| --- | --- | --- |
| `sas_start` | `client.device_store[user][device]`, `client.start_key_verification(device)` | Sends the bare `.start`. Returns the transaction id. |
| `sas_await` | `client.sync(...)`, `client.send_to_device_messages()` | Pumps until `txn_id in client.key_verifications`, then until the SAS reaches a named state. `.accept` and `.key` replies are queued **automatically** by `handle_key_verification` — *read* — so this op is mostly draining. |
| `sas_accept` | `client.accept_key_verification(txn_id)` | Only for the direction where nio responds. |
| `sas_read` | `client.key_verifications[txn_id].get_emoji()` / `.get_decimals()` | Returns the SAS for the Rust side to compare against its own `read_material`. |
| `sas_confirm` | `client.confirm_short_auth_string(txn_id)` | Sends `.mac`. |
| `sas_reject` | `client.cancel_key_verification(txn_id, reject=True)` | The negative run: produces `m.mismatched_sas`, *observed* in §2 step [8]. |
| `sas_status` | `sas.verified`, `sas.verified_devices`, `client.device_store[...].trust_state` | The assertion: nio's own store says the device is verified. |

One precondition, *read* from `handle_key_verification`: nio drops a `.start` from a device
it does not know, adding the sender to `users_for_key_query` instead. So the existing
`settle()` must have run a `keys_query` covering this library's device before the start
arrives — which the current harness already does, and which the flow shape makes natural
because both sides must be in each other's device store to verify at all.

The two runs the criterion needs are the agreeing one and the disagreeing one. The second
is genuinely available rather than simulated: `sas_reject` drives nio's real `reject_sas()`
and produces a real `m.key.verification.cancel` with code `m.mismatched_sas`, which is what
§8 means by a flow proven able to fail.

**Cost, honestly.** The nio side is roughly 80 lines added to `nio_party.py`. The Rust side
is a new test file in the shape of `level_two_interop.rs`. Neither is the expensive part.
**The expensive part is §7 items 1–3** — making the verification registry able to hold a
flow that has no request — and that is a change to shipped library code with its own
review, its own tests, and its own risk of regressing the request-first flow that M3
actually shipped. That is the trade this finding puts in front of the milestone, and it is
a scope decision rather than an engineering unknown.

---

## 9. Reproducing this

Everything above came from the pinned requirements file and the crates already in
`rust/Cargo.lock`. Nothing needed a homeserver, and no credentials were used.

- The nio-side observations: a virtualenv built from
  `rust/matrix-crypto-core/tests/interop/requirements.txt` with `--no-deps`, then two
  `nio.crypto.sas.Sas` objects paired by hand, and `nio.events.to_device.ToDeviceEvent`
  `parse_event` called on bodies captured from this library's own pump.
- The library-side observations: a throwaway test built from the first 502 lines of
  `rust/matrix-crypto-core/tests/sas_two_party.rs` — its helpers unchanged — with a single
  test appended that relays a bare `Device::start_verification()` into
  `receive_sync_changes` and then queries every public entry point.

Both scratch artefacts were deliberately **not** committed: the probe would be a test that
asserts nothing, and the virtualenv is rebuilt by `run-level-two-interop.sh` on demand.
Their outputs are reproduced above in full so the finding does not depend on rerunning
them.
