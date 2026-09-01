/**
 * The camera-proof run's progress, reduced to a flat struct a test can drive.
 *
 * React-free, matching `scannedCodeRunner.ts`'s rule: a module that imports
 * `react` or `react-native` can only be checked by holding a phone, and the
 * whole point of this file is that it CAN be checked on a host. The harness
 * (`CameraProofHarness.tsx`) feeds it every published `ScannedCodeState` and
 * prints what comes back; this file decides what the five checks mean.
 *
 * # Why five checks, and why these five
 *
 * The claim under test is optical: a foreign camera read the symbol this
 * library drew. No line this file produces can observe that directly -- only
 * the protocol can: a flow that reaches `done` is only reachable if the
 * scanner decoded the exact bytes on screen (a wrong decode dies in the SAS,
 * long before `done`). So the checks are the chain of observable milestones
 * between "the app started" and "the library reports done", and each exists
 * to make a specific silent failure loud:
 *
 *   * `run_started` -- the runner published anything at all. It publishes
 *     only after `createCryptoMachine` resolved and key publication began,
 *     so an app that crashes at launch or a plan the app never fetched stops
 *     here, named, instead of downstream as a bare timeout.
 *   * `flow_exists` -- a verification flow the library knows about. The
 *     camera-proof run never asks from this side (`askOtherDevices` is not
 *     called), so a flow id can only arrive from the other device: the phone
 *     side really did start a verification against this device.
 *   * `code_shown` -- `getVerificationCode` returned and the symbol is on
 *     screen. Counts only (width, payload bytes); never a module, never a
 *     byte: the modules are the shared secret drawn as squares.
 *   * `scan_reported` -- the stage `code-scanned`, meaning the other device
 *     sent `m.key.verification.scanned`, meaning its decoder accepted the
 *     bytes. The harness confirms at this point without a person (see its
 *     own header for why that is honest here); this check is what makes the
 *     auto-confirm visible in the log instead of silent.
 *   * `flow_done` -- the stage `done`: the library's own verdict that the
 *     verification completed. This is the assertion CI actually gates on;
 *     the other four are what makes a failure diagnosable.
 *
 * # What this file deliberately does not do
 *
 * It never invents a check that did not happen: a run that stops before
 * `code-scanned` reports `scan_reported` as FAIL with "not reported", the
 * same reconciliation rule ProbeHarness and LevelTwoHarness keep. And it
 * cannot pass by finding nothing -- the summary's denominator is the pinned
 * step list, not however many checks were seen.
 */

import type { ScannableCode, VerificationStage } from 'react-native-matrix-crypto'

/**
 * The subset of `ScannedCodeState` the reduction reads, restated so this file
 * never imports the runner (it does not need the rest, and a type-only
 * import of the published surface is the whole of its dependency).
 */
export interface CameraProofStateView {
  verificationId?: string
  code?: ScannableCode
  stage?: VerificationStage
  finished: boolean
  failed: boolean
}

export interface CameraProofCheck {
  name: string
  ok: boolean
  detail: string
}

export const CAMERA_PROOF_STEPS = [
  'run_started',
  'flow_exists',
  'code_shown',
  'scan_reported',
  'flow_done',
] as const

export interface CameraProofProgress {
  started: boolean
  flowExists: boolean
  codeShown: boolean
  scanReported: boolean
  finished: boolean
  failed: boolean
}

export function initialCameraProofProgress(): CameraProofProgress {
  return {
    started: false,
    flowExists: false,
    codeShown: false,
    scanReported: false,
    finished: false,
    failed: false,
  }
}

/**
 * Folds one published state into the progress. Pure: the harness calls it
 * once per publish and the tests call it with hand-built sequences, and both
 * must see the same result.
 *
 * `started` is set on the FIRST call, not on any field of the state: the
 * runner's contract is that it publishes only after the machine exists, so
 * "we were called at all" is the honest condition. Encoding it as "first
 * call seen" rather than sniffing a headline string is what keeps this file
 * decoupled from the runner's prose.
 */
export function nextCameraProofProgress(
  previous: CameraProofProgress,
  state: CameraProofStateView,
): CameraProofProgress {
  return {
    started: true,
    flowExists: previous.flowExists || state.verificationId !== undefined,
    codeShown: previous.codeShown || state.code !== undefined,
    scanReported: previous.scanReported || state.stage === 'code-scanned',
    finished: previous.finished || state.finished,
    failed: previous.failed || state.failed,
  }
}

/**
 * The five checks for where the run has got to. Reconciled against the
 * pinned step list: a milestone the run never reached reports FAIL with
 * "not reported", never disappears -- the rule the other two harnesses keep,
 * for the reason in their headers.
 */
export function cameraProofChecks(progress: CameraProofProgress): CameraProofCheck[] {
  return [
    {
      name: 'run_started',
      ok: progress.started,
      detail: progress.started
        ? 'the runner published its first state, which happens only after createCryptoMachine resolved'
        : 'not reported: no state was ever published',
    },
    {
      name: 'flow_exists',
      ok: progress.flowExists,
      detail: progress.flowExists
        ? 'the phone side started a verification against this device; this run never asks from this side'
        : 'not reported: no verification flow reached this device',
    },
    {
      name: 'code_shown',
      ok: progress.codeShown,
      detail: progress.codeShown
        ? 'getVerificationCode returned and the symbol is on screen (width and payload size only in the log)'
        : 'not reported: getVerificationCode never returned, so no symbol was on screen',
    },
    {
      name: 'scan_reported',
      ok: progress.scanReported,
      detail: progress.scanReported
        ? 'the other device sent m.key.verification.scanned; the held confirmation was sent without a person'
        : 'not reported: the flow never reported its code scanned',
    },
    {
      name: 'flow_done',
      ok: progress.finished && !progress.failed,
      detail:
        progress.finished && !progress.failed
          ? 'the library reports the verification done'
          : progress.failed
            ? 'the flow ended without verifying'
            : 'not reported: the run stopped before the flow finished',
    },
  ]
}
