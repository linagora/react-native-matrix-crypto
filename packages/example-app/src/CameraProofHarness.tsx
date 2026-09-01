/**
 * The showing side of the camera proof: the screen a scanner in a fixed
 * mount is aimed at.
 *
 * This is the CI twin of `ScannedCodeWalkthrough`, and it differs from it in
 * exactly three ways, each deliberate:
 *
 *   * **Nobody asks from this side.** The walkthrough offers "ask my other
 *     devices to verify" because a person may hold the phone that answers;
 *     here the other side is a phone on a mount running an unmodified
 *     Element, and the observed-working direction (see
 *     `level-two/run_camera_proof.py`'s header) is Element starting the
 *     verification from its own sessions list. This harness waits for the
 *     flow instead of requesting one, so `flow_exists` in the log can only
 *     have come from the phone.
 *   * **The one decision a person would make is made at start.** The
 *     runner's `confirm()` is held, not dropped: called before any scan, it
 *     is acted on the moment the flow reaches `code-scanned`. That is honest
 *     here and would NOT be honest on the walkthrough screen: the
 *     confirmation answers "was the device that scanned really yours?", and
 *     on the walkthrough a person must answer it from their knowledge of
 *     their own devices. This run drives both sides and asserts both
 *     halves -- the showing side's log reaching `done` AND the account state
 *     over the client API (see `level-two/run_camera_proof_rig.py`) -- so
 *     there is no trust decision left for a human to make, and waiting for
 *     one would make the leg impossible to run at all. What the proof then
 *     claims is narrower than a person-driven verification and says so in
 *     the workflow's header comment: it proves a foreign camera reads the
 *     symbol; it does not exercise the user-facing confirmation UX.
 *   * **The symbol fills the screen.** A mount does not re-frame itself the
 *     way a person does, so the code is drawn at the largest square the
 *     smaller screen dimension allows (`CodeMatrix`'s `maxSide`), on white,
 *     with nothing else rendered while a code is up: everything a camera's
 *     viewfinder sees is symbol or quiet zone.
 *
 * What reaches the log follows the other harnesses' rule: step names, stages,
 * counts (symbol width, payload byte count). Never an identifier, never a
 * payload byte, never a module -- the payload is authentication material and
 * the modules are the same secret drawn as squares.
 *
 * VALIDATED vs AWAITING THE RIG: the reduction this feeds
 * (`cameraProofLog.ts`) and the runner it drives (`scannedCodeRunner.ts`)
 * are host-tested, and this component typechecks. Nothing here has run on a
 * device yet: the first real run is the rig's, and the leg fails closed if
 * any piece of it is absent.
 */

import React, { useEffect, useRef, useState } from 'react'
import { StyleSheet, Text, View, useWindowDimensions } from 'react-native'
import type { ScannableCode } from 'react-native-matrix-crypto'
import { CodeMatrix } from './CodeMatrix'
import {
  cameraProofChecks,
  initialCameraProofProgress,
  nextCameraProofProgress,
  type CameraProofProgress,
} from './cameraProofLog'
import { httpJson, type LevelTwoPlan } from './levelTwoTransport'
import { startScannedCodeRun, type ScannedCodeRun, type ScannedCodeState } from './scannedCodeRunner'

/**
 * The one run this process performs, memoised at module scope -- the same
 * rule ProbeHarness and LevelTwoHarness keep: the machine is process-wide
 * and created once, and a remount (Metro fast refresh) must re-render the
 * result it already has rather than manufacture a second run.
 */
let cameraProofRun: Promise<unknown> | null = null

export function CameraProofHarness({ plan, storeDir }: { plan: LevelTwoPlan; storeDir: string }) {
  const { width, height } = useWindowDimensions()
  const [code, setCode] = useState<ScannableCode | undefined>(undefined)
  const [headline, setHeadline] = useState('Starting…')
  const runRef = useRef<ScannedCodeRun | null>(null)

  useEffect(() => {
    let cancelled = false
    const progressRef: { current: CameraProofProgress } = { current: initialCameraProofProgress() }
    let lastStage: ScannedCodeState['stage']
    let loggedStarted = false
    let loggedCode = false
    let printed = false

    const logChecks = (progress: CameraProofProgress) => {
      // cameraProofChecks promises all five steps on every call: a milestone
      // the run never reached is a FAIL with "not reported", never a missing
      // row. So the denominator cannot shrink below five, and no further
      // reconciliation is needed here -- the pinning from outside lives in
      // run_camera_proof_rig.py, the same split EXPECTED_STEPS keeps for
      // LEVEL2_SUMMARY.
      const checks = cameraProofChecks(progress)
      for (const check of checks) {
        console.log(`CAMERA_PROOF_CHECK ${check.name} ${check.ok ? 'PASS' : 'FAIL'} ${check.detail}`)
      }
      console.log(
        `CAMERA_PROOF_SUMMARY ${checks.filter((check) => check.ok).length}/${checks.length}`,
      )
    }

    const publish = (state: ScannedCodeState) => {
      const hadCode = progressRef.current.codeShown
      const hadScan = progressRef.current.scanReported
      progressRef.current = nextCameraProofProgress(progressRef.current, state)
      const progress = progressRef.current

      // One line per milestone, not per publish: the stage below can change
      // dozens of times while a code is up, and a log CI greps should carry
      // each fact once.
      if (!loggedStarted) {
        loggedStarted = true
        console.log('CAMERA_PROOF run_started waiting for the phone side to start a verification')
      }
      if (state.stage !== lastStage) {
        lastStage = state.stage
        console.log(`CAMERA_PROOF stage ${state.stage ?? 'none'}`)
      }
      if (!loggedCode && !hadCode && progress.codeShown && state.code !== undefined) {
        loggedCode = true
        console.log(
          `CAMERA_PROOF code_shown width=${state.code.width} payload_bytes=${state.code.payload.length}`,
        )
      }
      if (!hadScan && progress.scanReported) {
        console.log('CAMERA_PROOF scan_reported confirming without a person')
      }
      if (progress.finished && !printed) {
        printed = true
        logChecks(progress)
      }

      if (!cancelled) {
        setCode(state.code)
        setHeadline(state.headline)
      }
    }

    const run = async () => {
      const handle = startScannedCodeRun(
        {
          homeserver: plan.homeserver,
          userId: plan.userId,
          deviceId: plan.deviceId,
          accessToken: plan.accessToken,
        },
        storeDir,
        httpJson,
        publish,
      )
      runRef.current = handle
      // Held, not dropped: acted on the moment the flow reaches
      // code-scanned. See this file's header for why a run that drives both
      // sides may do this and the walkthrough screen may not.
      handle.confirm()
      await handle.finished
    }

    if (cameraProofRun === null) cameraProofRun = run()
    return () => {
      cancelled = true
      runRef.current?.stop()
    }
    // `[]`, matching the module-scope memo: the machine this run creates is
    // process-wide and created once, so a later plan could not be honoured
    // even if this re-ran.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // While a code is up, the camera sees only the symbol and its quiet zone:
  // no status text, no buttons. Before that, the status line is what a
  // person debugging the rig reads on the machine's display.
  return (
    <View style={styles.screen}>
      {code !== undefined ? (
        <CodeMatrix code={code} maxSide={Math.min(width, height) - 16} />
      ) : (
        <Text style={styles.status}>{headline}</Text>
      )}
    </View>
  )
}

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    backgroundColor: '#ffffff',
    alignItems: 'center',
    justifyContent: 'center',
  },
  status: {
    fontSize: 14,
    opacity: 0.7,
    margin: 24,
    textAlign: 'center',
  },
})
