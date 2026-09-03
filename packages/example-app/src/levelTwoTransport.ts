/**
 * Transport for the level 2 facade run: HTTP the app performs itself, the
 * run plan it is handed, and the one mapping a product still has to write
 * for itself -- `receiveSyncChanges`'s own five-field rename moved into
 * `react-native-matrix-crypto` as `encryptionSlice` in Task 1 (M3); see the
 * "one mapping" section below for what remains here.
 *
 * # Why this file exists at all
 *
 * Design doc section 8's level 2 -- "does a real Matrix client decrypt what
 * we encrypt, and can we decrypt what it sends" -- was proven once, against
 * a real homeserver, by `rust/matrix-crypto-core/tests/level_two_interop.rs`.
 * That test drives the **Rust core**. Nothing in the TypeScript facade, the
 * UniFFI bindings or the JSI layer had ever faced a homeserver, and the one
 * defect a person found by reading this milestone's code -- `facade.ts`
 * documenting a `receiveSyncChanges` call its own guard provably rejects --
 * lived precisely in the layer that proof skips.
 *
 * So this run drives the published TypeScript surface and nothing else:
 * `createCryptoMachine`, `shareScopeKey`, `takeOutgoingRequests`,
 * `markRequestSent`, `receiveSyncChanges`, `encryptEvent`, `decryptEvent`.
 * The library gained nothing to make it possible; every helper below is
 * something a product writes for itself, which is the point.
 *
 * # Why the app does the HTTP
 *
 * The bridge performs no request, by design (spec section 6, design doc
 * section 3bis): it hands the product a description of what to send and the
 * product, which already owns transport, sends it. This file is that
 * product. If a `kind` ever appeared that could not be routed to an
 * endpoint, that would be a finding about the surface rather than something
 * to work around, and {@link sendOutgoing} throws instead of skipping it --
 * silently skipping is how section 3bis was got wrong the first time.
 */

import type { OutgoingRequest } from 'react-native-matrix-crypto'

/**
 * Where the run plan comes from, in the order they are tried, per platform.
 *
 * Not configuration and not a secret: `10.0.2.2` is the standard Android
 * emulator's alias for the host's loopback interface, and `127.0.0.1` is
 * what an iOS simulator sees of the same host. A conductor that is not
 * running answers neither, the connection is refused in milliseconds, and
 * this app runs its ordinary probe instead -- see `App.tsx`.
 *
 * The platform split is not cosmetic, and the weighing is the same one
 * `android/.../res/xml/network_security_config.xml` records for its own
 * three names. On the Android emulator `10.0.2.2` is a magic alias for the
 * host's loopback; on iOS it is not magic at all, it is an ordinary RFC1918
 * address in 10/8, and on a physical iPhone attached to a 10/8 or LAN
 * network it routes to whichever host holds it -- a host that could answer
 * the probe below with a homeserver address and an access token. Nothing of
 * the user's is at risk, because this app holds nothing of the user's, but
 * the probe exists for exactly one host and iOS has no use for the address
 * that names it anywhere but Android: the iOS simulator sees the developer's
 * machine at `127.0.0.1`, so that is the only address the iOS side probes.
 * The Android side keeps trying both, because the emulator's alias and the
 * host's own loopback are the same conductor and the alias is tried first.
 *
 * The port is fixed rather than discovered because the app has to know it
 * before it can ask anything. Nothing sensitive travels on the way *out*;
 * everything sensitive travels in the reply, over the host's own loopback.
 */
const PLAN_URLS: Record<'ios' | 'android', string[]> = {
  android: ['http://10.0.2.2:8449/plan', 'http://127.0.0.1:8449/plan'],
  ios: ['http://127.0.0.1:8449/plan'],
}

/** How long to wait for a conductor that is probably not there. */
const PLAN_TIMEOUT_MS = 2500

/**
 * Everything the run needs, minted by the conductor for this run alone.
 *
 * **`accessToken` is the one credential in this file, and it is deliberately
 * the weakest one that can work.** It names a single device on a homeserver
 * that exists only inside a container the runner destroys when it exits, it
 * is never written to any file, it never travels as an initial property (see
 * the rule in `MainActivity.kt`), and it is never printed: the run's output
 * is step names, PASS or FAIL, and details that carry counts and event types
 * and never a value. The run also revokes it itself, as an asserted step,
 * rather than trusting the container teardown to be the only thing that
 * ends it.
 */
export interface LevelTwoPlan {
  /**
   * Which run this launch is.
   *
   * Absent means `'level-two'`, which is what the conductor that predates
   * this field serves, so an older plan keeps working unchanged.
   *
   * `'scanned-code'` is a run for a **person** rather than for CI: it draws
   * a real code and waits for a human to hold another client's camera up to
   * it. Nothing automated can make that claim, which is why it is a separate
   * mode rather than one more step in the suite.
   *
   * `'camera-proof'` is that same drawing side with the person replaced by
   * a fixed rig: an emulator shows the code fullscreen while a phone on a
   * mount, running an unmodified Element, scans it (issue #6). The plan is
   * identical in shape -- the conductor mechanism is deliberately reused --
   * and only the app's mode branch and the host-side driver differ.
   */
  mode?: 'level-two' | 'scanned-code' | 'camera-proof'
  /** Base URL of the throwaway homeserver, as the emulator can reach it. */
  homeserver: string
  /** Base URL of the conductor, for {@link counterpartyOp}. */
  conductor: string
  /** This device's account, and the device the `accessToken` names. */
  userId: string
  deviceId: string
  accessToken: string
  /** The room both parties are in; the scope every step shares under. */
  roomId: string
  /** The counterparty. A **different Matrix user**, deliberately -- see the suite. */
  nioUserId: string
  /**
   * Which assertion to sabotage, or `'none'`.
   *
   * A control that has never been seen to fail proves nothing, and this
   * milestone has already shipped one that could not (task 12's replay
   * trap). Rather than editing the suite to mutate it and editing it back,
   * the mutations live in the suite permanently and the conductor names the
   * one to apply. A run with a mutation reports under a **different summary
   * line**, so a sabotaged run can never be read as a clean one.
   */
  mutation: string
}

export interface HttpResult {
  status: number
  /** The raw response body. Never logged; see this file's header. */
  text: string
}

/**
 * One HTTP request, on `XMLHttpRequest` rather than `fetch`.
 *
 * `fetch` in React Native has no timeout of its own and needs an
 * `AbortController` plus a timer to get one; `XMLHttpRequest.timeout` is a
 * single property that has behaved the same way for the whole life of the
 * platform. This run long-polls `/sync`, so a request that hangs forever is
 * the difference between a red step and a run that never reports anything.
 *
 * Never rejects with a message carrying a header, a token or a response
 * body: it names the method and the path and nothing else. A crypto run's
 * failure text is read in logcat.
 */
export function httpJson(
  method: string,
  url: string,
  options: { token?: string; body?: string; timeoutMs?: number } = {},
): Promise<HttpResult> {
  const { token, body, timeoutMs = 30_000 } = options
  return new Promise<HttpResult>((resolve, reject) => {
    const request = new XMLHttpRequest()
    request.open(method, url)
    request.timeout = timeoutMs
    request.setRequestHeader('Content-Type', 'application/json')
    if (token !== undefined)
      request.setRequestHeader('Authorization', `Bearer ${token}`)
    // `redactPath` rather than `url`: a `/sendToDevice/{type}/{txn}` URL
    // carries a transaction id, and a homeserver base URL is not something
    // this run's output has any business repeating either.
    const where = `${method} ${redactPath(url)}`
    request.onload = () =>
      resolve({ status: request.status, text: request.responseText })
    request.onerror = () =>
      reject(new Error(`${where} failed to reach the homeserver`))
    request.ontimeout = () =>
      reject(new Error(`${where} timed out after ${timeoutMs}ms`))
    request.onabort = () => reject(new Error(`${where} was aborted`))
    request.send(body)
  })
}

/**
 * The endpoint family a URL belongs to, with every identifier removed.
 *
 * Used in every message this file can produce. `/_matrix/client/v3/rooms/
 * !abc:server/send/m.room.encrypted/txn-4` becomes
 * `/_matrix/client/v3/rooms/*` -- enough to say which call failed, carrying
 * no room id, no transaction id and no user id.
 */
function redactPath(url: string): string {
  const withoutOrigin = url
    .replace(/^https?:\/\/[^/]+/, '')
    .replace(/\?.*$/, '')
  const match = withoutOrigin.match(/^\/_matrix\/client\/v3\/[a-zA-Z_]+/)
  if (match === null) return '<a path>'
  return match[0] === withoutOrigin ? match[0] : `${match[0]}/*`
}

/**
 * Asks the conductor for a run plan, or reports that there is none.
 *
 * `os` selects which hosts the probe may ask, per `PLAN_URLS`' own
 * weighing: the address list is platform-scoped so that an iOS build never
 * probes the Android emulator's `10.0.2.2` alias, which on a physical
 * iPhone is an ordinary routable RFC1918 address.
 *
 * Returns `null` for every failure, deliberately: "no conductor is running"
 * is the ordinary case (a plain app launch, and every CI run of the probe),
 * and it must be indistinguishable to this app from "the conductor is
 * broken". The runner on the other side is what turns a missing summary
 * into a failed run -- it asserts that it *found* one, exactly as
 * `scripts/run-probe-on-emulator.sh` does for `PROBE_SUMMARY`.
 */
export async function fetchLevelTwoPlan(
  os: 'ios' | 'android',
): Promise<LevelTwoPlan | null> {
  for (const url of PLAN_URLS[os]) {
    try {
      const { status, text } = await httpJson('GET', url, {
        timeoutMs: PLAN_TIMEOUT_MS,
      })
      if (status !== 200) continue
      const plan = JSON.parse(text) as LevelTwoPlan
      if (
        typeof plan.homeserver !== 'string' ||
        typeof plan.accessToken !== 'string'
      )
        continue
      return plan
    } catch {
      // Refused, timed out, or answered something that is not a plan. Try
      // the next address, then give up quietly.
    }
  }
  return null
}

/**
 * One operation on the counterparty, which runs on the host because
 * `matrix-nio` is Python.
 *
 * The reply shape mirrors `rust/matrix-crypto-core/tests/interop/nio_party.py`
 * on purpose -- `{ ok, ... }`, one op per call, the caller owning every
 * assertion -- so the two level 2 proofs describe the counterparty the same
 * way. **The counterparty is never told what it is supposed to find.** It is
 * given a room and a list of event ids and reports what it made of each; the
 * plaintext this suite compares against never crosses to it, so a harness
 * that lied would have to guess the string.
 */
export async function counterpartyOp(
  plan: LevelTwoPlan,
  op: Record<string, unknown>,
  timeoutMs = 120_000,
): Promise<Record<string, unknown>> {
  const { status, text } = await httpJson('POST', `${plan.conductor}/op`, {
    body: JSON.stringify(op),
    timeoutMs,
  })
  if (status !== 200) {
    throw new Error(
      `the counterparty returned HTTP ${status} for op "${String(op.op)}"`,
    )
  }
  const reply = JSON.parse(text) as Record<string, unknown>
  if (reply.ok !== true) {
    // `error` is the counterparty's own traceback text. It is a local
    // Python process talking about a container, so it carries no secret --
    // but it can be long, and the run's output is read in logcat, so only
    // its first line travels.
    const first = String(reply.error ?? 'no reason given').split('\n')[0]
    throw new Error(`the counterparty refused op "${String(op.op)}": ${first}`)
  }
  return reply
}

// ---------------------------------------------------------------------------
// The one mapping a product still writes for itself
// ---------------------------------------------------------------------------
//
// `encryptionSlice` used to live here too -- the mapping the facade's own
// documentation got wrong, and the reason this run exists in this layer at
// all. It is now `react-native-matrix-crypto`'s own `encryptionSlice`
// (Task 1, M3): callers (`levelTwoSuite.ts`) import it from the library
// directly rather than from this file, so it is not re-exported here as a
// second hand-written copy. `sendOutgoing` below is what remains: the
// `kind` -> endpoint mapping `OutgoingRequest`'s own doc comment tables,
// which nothing generates.

/**
 * Sends one request the pump handed out to the endpoint its `kind` names,
 * and returns the homeserver's own response body for `markRequestSent`.
 *
 * The response is handed back **unwrapped and verbatim**, which is the
 * contract `OutgoingRequest`'s own documentation states. Nothing in this
 * function synthesises a body: a run that fed the machine bodies of its own
 * making would prove nothing about whether a real homeserver's answers are
 * accepted.
 */
export async function sendOutgoing(
  plan: LevelTwoPlan,
  request: OutgoingRequest,
): Promise<HttpResult> {
  let method = 'POST'
  let path: string
  let body = request.body

  switch (request.kind) {
    case 'keys_upload':
      path = '/_matrix/client/v3/keys/upload'
      break
    case 'keys_query':
      path = '/_matrix/client/v3/keys/query'
      break
    case 'keys_claim':
      path = '/_matrix/client/v3/keys/claim'
      break
    case 'to_device': {
      // The endpoint carries the event type and the transaction id in its
      // URL and takes only `messages` as its body. The pump's body
      // additionally carries both, which is the only reason this URL can be
      // built at all -- see `describe_outgoing`'s two disclosed exceptions
      // in the core.
      const parsed = JSON.parse(request.body) as Record<string, unknown>
      const eventType = parsed.event_type
      const txnId = parsed.txn_id
      if (typeof eventType !== 'string' || typeof txnId !== 'string') {
        throw new Error(
          'a to-device request must name its event type and transaction id',
        )
      }
      method = 'PUT'
      path =
        `/_matrix/client/v3/sendToDevice/${encodeURIComponent(eventType)}` +
        `/${encodeURIComponent(txnId)}`
      body = JSON.stringify({ messages: parsed.messages })
      break
    }
    default:
      // Not skipped. `kind` is an open tag, so a value this product cannot
      // route is a finding about the surface -- either section 3bis's
      // mapping is missing an endpoint, or this app is behind it.
      throw new Error(
        `the pump handed out a request of kind "${request.kind}", which this run cannot route`,
      )
  }

  const result = await httpJson(method, `${plan.homeserver}${path}`, {
    token: plan.accessToken,
    body,
    timeoutMs: 60_000,
  })
  if (result.status < 200 || result.status >= 300) {
    throw new Error(
      `${method} ${path.replace(/\/[^/]*$/, '/*')} for a "${request.kind}" request ` +
        `returned HTTP ${result.status}`,
    )
  }
  return result
}

/** One `/sync`, returning the parsed body. */
export async function syncOnce(
  plan: LevelTwoPlan,
  since: string | null,
  timeoutMs: number,
): Promise<Record<string, unknown>> {
  const query =
    since === null
      ? `timeout=${timeoutMs}`
      : `timeout=${timeoutMs}&since=${encodeURIComponent(since)}`
  const { status, text } = await httpJson(
    'GET',
    `${plan.homeserver}/_matrix/client/v3/sync?${query}`,
    {
      token: plan.accessToken,
      timeoutMs: timeoutMs + 30_000,
    },
  )
  if (status !== 200)
    throw new Error(`GET /_matrix/client/v3/sync returned HTTP ${status}`)
  return JSON.parse(text) as Record<string, unknown>
}

/**
 * Flips one character of a base64 ciphertext.
 *
 * The control this whole run needs: an event that differs from a valid one
 * by a single character must not decrypt anywhere. Without it a green run
 * says nothing about whether any cryptography was checked.
 *
 * **It must be applied to a freshly encrypted event, never to a copy of one
 * already delivered.** A corrupted copy carries a megolm message index the
 * recipient has already seen, so the recipient refuses it as a replay
 * whatever the ciphertext says -- which is how task 12's first corruption
 * control passed while proving nothing.
 */
export function corruptOneCharacter(text: string): string {
  if (text.length <= 8) {
    throw new Error(
      'a megolm ciphertext is never this short; refusing to corrupt it',
    )
  }
  const index = Math.floor(text.length / 2)
  const replacement = text[index] === 'A' ? 'B' : 'A'
  return text.slice(0, index) + replacement + text.slice(index + 1)
}
