import React, { useEffect, useState } from 'react'
import { Text, View } from 'react-native'
import {
  asCryptoScopeId,
  createCryptoMachine,
  decryptEvent,
  encryptEvent,
  getDeviceIdentityKeys,
  isCryptoError,
  markRequestSent,
  runProbe,
  shareScopeKey,
  takeOutgoingRequests,
} from 'react-native-matrix-crypto'
import {
  runInteropSuite,
  type BridgeBinding,
  type InteropCheck,
} from 'react-native-matrix-crypto/interop/suite'
import {
  CRYPTO_SUITE_STEPS,
  runCryptoSuite,
  type CryptoBinding,
} from 'react-native-matrix-crypto/interop/crypto-suite'
import {
  DEMO_DEVICE_ID,
  DEMO_SCOPE,
  DEMO_USER_ID,
  demoMachineConfig,
} from './cryptoConfig'
import { timeOprfMasking } from './oprfTiming'
import { nthSignal } from './signalOrder'

/**
 * Adapts the shipped JSI binding to the shared contract from Task 9b.
 * The checks themselves live in the suite, so the device run and the Node
 * run cannot drift apart.
 *
 * `runProbe`'s own signal callback is forwarded directly -- not read via
 * `onCryptoSignal` -- so this harness's 'signal' check only ever sees the
 * signal from its own call, never `GuidedFlow`'s. Both mount as siblings
 * in App.tsx and both call `runProbe`; before this, the shared global
 * channel meant one's probe call showed up in the other's check too.
 *
 * FOUR PROBE LINES, AND WHY THEY ARE HERE RATHER THAN IN THE SUITE
 *
 * `interop/suite.ts`'s `signal` check answers "did the callback arrive at
 * all", bounded by `SIGNAL_WAIT_MS`. That constant is a measured number, and
 * a measured number nobody can re-measure decays into a guess: it was sized
 * from a release build on an emulator because the Rust-to-JavaScript
 * callback lost a race to the promise there and nowhere else (spec section
 * 5.1, B2). These two lines are the instrument that produced it, kept in the
 * tree so the next person to touch the delivery mechanism re-derives the
 * budget instead of inheriting it.
 *
 * - `PROBE_SIGNAL_MS n` -- milliseconds from calling `runProbe` to the
 *   observer callback landing on the JavaScript thread. This is the whole
 *   chain a product waits on: Rust's `emit`, the UniFFI callback, the JSI
 *   hop, and the JavaScript thread getting round to it.
 * - `PROBE_PROMISE_MS n` -- the same clock, stopped when `runProbe`'s
 *   promise resolves. The two together say which won, which is the race
 *   itself rather than a proxy for it.
 * - `PROBE_EMIT_BUILD v` -- `coreVersion`, which now carries a fingerprint
 *   of the emission path compiled into the `.so` this launch is running
 *   (`observer.rs`'s `EMIT_BUILD`). A latency number is worth nothing
 *   without it. Android imports the Rust library as a prebuilt from a
 *   gitignored `jniLibs/` with no Gradle edge back to the crate, so a build
 *   that forgot to re-run `ubrn build android` produces an APK that looks
 *   new and runs the old `emit` -- and the first measurement of this path
 *   reported two indistinguishable distributions, which is exactly what
 *   that mistake would have produced. This line is how a reader of a probe
 *   log decides which emission path produced the numbers above it, instead
 *   of trusting whoever ran the build.
 * - `PROBE_SIGNAL_NTH n` -- which observer callback of this process the
 *   timed one turned out to be. Not decoration. Three review rounds
 *   described the line above as timing "the first signal of a cold process",
 *   arguing from the true fact that the interop suite issues exactly one
 *   observed call. That fact establishes something else: that this harness
 *   times only its *own* call, which is what the direct-callback forwarding
 *   described above is for. It does not establish that this call is the
 *   process's first emission, and the paragraph forty lines above -- "both
 *   mount as siblings in App.tsx and both call `runProbe`" -- says why not.
 *   `GuidedFlow` renders first and calls `runProbe` on mount with a
 *   non-empty input, so two emitting calls race on every cold launch.
 *
 *   Rather than reason about which one wins, every emitting call site in
 *   this app draws a number from `signalOrder.ts` as its signal lands and
 *   this line reports the one the timed callback drew. A row then carries
 *   which delivery it measured instead of a comment asserting it.
 * - `PROBE_SIGNAL2_MS n` -- the same measurement again, for a second signal
 *   in the same process, issued after both suites have finished. This one
 *   exists to settle a question the others cannot: whether a difference
 *   between two emission implementations is a start-up cost or one the
 *   process keeps paying.
 *
 *   Whatever `PROBE_SIGNAL_MS` times is early in a cold process, so it
 *   carries whatever the emission path builds on first use -- for the
 *   blocking pool, this library's entire tokio runtime -- and no single
 *   sample can tell that apart from a per-signal cost. This line is the
 *   comparison that can. **It has been run:** across 22 launches the gap
 *   between the two emission paths was 22 ms at the median on the timed
 *   early signal under CPU saturation and 0 ms on this one, so the excess is
 *   a start-up cost and not one paid per signal. That does not identify
 *   *which* start-up cost. Building the runtime is one candidate among
 *   several -- creating the first pool thread and simply having more
 *   handoffs to be descheduled between are others -- and nothing measured
 *   separates them. `observer::emit` and
 *   `docs/measurements/2026-08-29-signal-delivery-latency.md` carry the
 *   detail and the samples.
 *
 * - `PROBE_OPRF_BLIND_MS`, `PROBE_OPRF_FINALIZE_MS`, `PROBE_OPRF_OUTPUTS`
 *   -- the OPRF client on two thousand inputs, timed after the second
 *   signal. `oprfTiming.ts` says what each line measures and why
 *   finalising reads a fixture.
 *
 * They are not checks: nothing passes or fails on them, the summary's
 * denominator does not move, and `scripts/run-probe-on-emulator.sh` prints
 * them with the rest of the `PROBE_` output because it greps the prefix. The
 * suite stays free of them deliberately -- it is the shipped contract every
 * binding must satisfy, and a latency number is a measurement of one
 * binding on one machine, not a property a binding must have. The example
 * app is not the bridge and may log; these carry four integers and a build
 * identifier -- no user identifier, no payload and no key material.
 */
function jsiBinding(): BridgeBinding {
  return {
    runProbe(input, payload, onSignal) {
      const calledAt = Date.now()
      const call = runProbe(
        input,
        payload,
        onSignal &&
          (signal => {
            console.log(`PROBE_SIGNAL_MS ${Date.now() - calledAt}`)
            console.log(`PROBE_SIGNAL_NTH ${nthSignal()}`)
            onSignal(signal.kind)
          }),
      )
      // Only the observing call is timed: the suite's second `runProbe` is
      // the rejection check and passes no observer, so there is no delivery
      // to time and no promise worth a second line.
      //
      // The rejection handler is not a swallowed error. The suite awaits
      // this same promise and reports whatever it does; this `then` is a
      // second, independent consumer, and without an `onRejected` a
      // rejection here would surface as an unhandled promise rejection from
      // a branch that exists only to print diagnostics.
      if (onSignal) {
        void call.then(
          report => {
            console.log(`PROBE_PROMISE_MS ${Date.now() - calledAt}`)
            console.log(`PROBE_EMIT_BUILD ${report.coreVersion}`)
          },
          () => {},
        )
      }
      return call
    },
    isCryptoError,
    errorKind: e => (isCryptoError(e) ? e.kind : undefined),
  }
}

/**
 * The same adaptation for the crypto half of the contract (Task 10). Every
 * member below is the public facade, unwrapped: no test helper, nothing from
 * `./generated`, nothing this library does not ship to a product. The only
 * work done here is branding the scope, which is exactly what a product
 * writes too.
 */
function jsiCryptoBinding(): CryptoBinding {
  return {
    createCryptoMachine,
    takeOutgoingRequests,
    markRequestSent,
    shareScopeKey: (scope, userIds) =>
      shareScopeKey(asCryptoScopeId(scope), userIds),
    encryptEvent: (scope, eventType, payload) =>
      encryptEvent(asCryptoScopeId(scope), eventType, payload),
    decryptEvent: (scope, rawEvent) =>
      decryptEvent(asCryptoScopeId(scope), rawEvent),
    errorKind: e => (isCryptoError(e) ? e.kind : undefined),
  }
}

/**
 * Times a second observed signal in this same process, and reports it as
 * `PROBE_SIGNAL2_MS`.
 *
 * Not a check: it adds nothing to `PROBE_SUMMARY`'s numerator or denominator,
 * and a failure here is swallowed deliberately -- an instrument that can turn
 * the probe red is worse than no instrument, and `scripts/run-probe-on-emulator.sh`
 * gates on the summary line.
 *
 * Placed last, after both suites, for two reasons. It must not perturb what
 * the suites measure, and by the time it runs the process is as warm as this
 * app ever gets -- runtime built, pool threads created, store open. That is
 * the comparison worth having against `PROBE_SIGNAL_MS`, which every launch
 * measured so far reports as the process's first delivery -- read off
 * `PROBE_SIGNAL_NTH`, not assumed. This sentence said "always the first
 * signal of a cold process" for four rounds, including one round after the
 * bullet a hundred lines above had that same claim removed and replaced with
 * the measured account. There were two copies; one was fixed.
 *
 * The observer is a fresh inline closure, so this call's signal is its own
 * and reaches nothing else.
 */
async function timeASecondSignal(): Promise<void> {
  try {
    const calledAt = Date.now()
    await runProbe('second', new Uint8Array([1]), () => {
      console.log(`PROBE_SIGNAL2_MS ${Date.now() - calledAt}`)
      console.log(`PROBE_SIGNAL2_NTH ${nthSignal()}`)
    })
  } catch {
    // Deliberately silent. See above: this is an instrument, not a check.
  }
}

/**
 * Every check this harness is responsible for producing itself, beyond the
 * probe suite's own. Reconciled against what actually came back before
 * anything is printed: a step that could not run must report FAIL, never
 * disappear. A summary counting eleven of twelve steps and calling it
 * 11/11 is the failure this file exists to make impossible.
 *
 * The probe suite's five checks are not listed: it legitimately collapses
 * to a single 'fatal' check when the binding itself is unusable, so there
 * is no fixed set of names to reconcile against for that half.
 */
const HARNESS_OWNED_CHECKS: readonly string[] = [
  ...CRYPTO_SUITE_STEPS,
  'real_crypto',
]

/**
 * The one genuine cryptographic value M1b proved crossed the chain, kept as
 * its own check.
 *
 * It runs *after* the crypto suite, and with the suite's own identifiers,
 * because M2 changed what it reads: `getDeviceIdentityKeys` now reports the
 * live machine's keys rather than minting a throwaway machine per call, and
 * refuses a caller who names a different user or device than the machine
 * holds. Called before `createCryptoMachine`, or with any other identity,
 * it rejects -- which is why this is no longer a check that can stand on
 * its own at the top of the run.
 */
async function realCryptoCheck(): Promise<InteropCheck> {
  try {
    const keys = await getDeviceIdentityKeys(DEMO_USER_ID, DEMO_DEVICE_ID)
    const ok = keys.ed25519.length === 43 && keys.curve25519.length === 43
    return {
      name: 'real_crypto',
      ok,
      detail: ok
        ? 'the live machine reported two well-formed 43-character identity keys'
        : `unexpected key lengths: ${keys.ed25519.length}/${keys.curve25519.length}`,
    }
  } catch (e) {
    const kind = isCryptoError(e) ? e.kind : undefined
    return {
      name: 'real_crypto',
      ok: false,
      detail: kind
        ? `rejected with kind "${kind}"`
        : 'failed with a non-typed error',
    }
  }
}

/**
 * The one run this process performs, memoised at module scope.
 *
 * **This run is only meaningful once per process, and that is a property of
 * the machine, not a shortcut.** The crypto machine is process-wide and
 * created exactly once, and a device publishes its one-time keys exactly
 * once: upstream tops them up in response to a `/sync`'s
 * `one_time_keys_counts`, which reaches the machine only through
 * `receiveSyncChanges`, and this probe deliberately fakes no sync. So a
 * second run in the same process finds a machine that has already
 * published, `key_upload_present` fails on a device that is no longer
 * fresh, and every step after it reports "not reached" -- a correct result
 * for a question nobody meant to ask.
 *
 * Observed for real, not theorised: a Metro fast refresh remounted this
 * component and logged `PROBE_SUMMARY 6/12` and `7/12` after a cold start
 * had already logged `12/12`, in the same process. Memoising the run means
 * a remount re-renders the result it already has instead of manufacturing a
 * second, misleading one -- and CI still gets exactly one summary per app
 * launch, which is the only kind of run this probe claims anything about.
 *
 * `storeDir` is captured by the first call for the same reason: the machine
 * it created is process-wide, so a later, different value could not be
 * honoured even if this re-ran.
 */
let probeRun: Promise<InteropCheck[]> | null = null

export function ProbeHarness({ storeDir }: { storeDir: string }) {
  const [checks, setChecks] = useState<InteropCheck[]>([])

  useEffect(() => {
    let cancelled = false

    const run = async () => {
      const results: InteropCheck[] = []
      try {
        results.push(...(await runInteropSuite(jsiBinding())))
        // Task 10: the same chain, carrying real cryptography rather than
        // an echo. The suite reports every one of its steps on every run,
        // including the ones an earlier failure stopped it reaching.
        results.push(
          ...(await runCryptoSuite(jsiCryptoBinding(), {
            machine: demoMachineConfig(storeDir),
            scope: DEMO_SCOPE,
          })),
        )
        results.push(await realCryptoCheck())
        await timeASecondSignal()
        await timeOprfMasking()
      } catch (e) {
        // Neither suite is supposed to be able to reach this: both report
        // failing checks instead of throwing. If one ever does, the run
        // still has to produce a summary -- a harness that throws prints
        // no PROBE_SUMMARY at all, which reads as "CI found nothing" and
        // not as "everything failed".
        results.push({
          name: 'harness',
          ok: false,
          detail: `the harness itself failed with a ${e instanceof Error ? e.constructor.name : typeof e}`,
        })
      }

      for (const name of HARNESS_OWNED_CHECKS) {
        if (!results.some(c => c.name === name)) {
          results.push({
            name,
            ok: false,
            detail: 'not reported: the harness failed before this step',
          })
        }
      }

      // Printed here rather than in the effect, so it happens once per
      // process alongside the run itself: a remount awaits the same promise
      // and must not re-emit lines CI would count twice.
      for (const c of results) {
        // Machine-readable line scraped by CI. The example app is not the
        // bridge, so it may log; the bridge itself never does. Names and
        // outcomes only -- no plaintext, no key material, no passphrase
        // and no identifier reaches this line.
        console.log(
          `PROBE_CHECK ${c.name} ${c.ok ? 'PASS' : 'FAIL'} ${c.detail}`,
        )
      }
      console.log(
        `PROBE_SUMMARY ${results.filter(c => c.ok).length}/${results.length}`,
      )
      return results
    }

    if (probeRun === null) probeRun = run()
    void probeRun.then(results => {
      // Only the on-screen list is gated on the component still being
      // mounted: the lines CI scrapes were already emitted by the run
      // itself, so an unmount can never swallow them.
      if (!cancelled) setChecks(results)
    })
    return () => {
      cancelled = true
    }
    // `[]`, not `[storeDir]`, so this array and the memo above say the same
    // thing. `[storeDir]` would read as "re-run when the path changes",
    // which is the opposite of what the line above does and of what the
    // machine allows: the machine is process-wide and created once, so a
    // later path could not be honoured even if this did re-run. A
    // maintainer reads the dependency array first, and it must not be the
    // half of the contradiction that wins.
    //
    // The lint rule wants `storeDir` declared because the closure reads it.
    // Suppressed deliberately rather than satisfied: declaring it would
    // restore exactly the contradiction this comment removes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <View>
      {checks.map(c => (
        <Text
          key={c.name}
        >{`${c.name}: ${c.ok ? 'PASS' : 'FAIL'} (${c.detail})`}</Text>
      ))}
    </View>
  )
}
