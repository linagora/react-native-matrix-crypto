/**
 * Host-side checks of the camera-proof reduction, exactly the split
 * `scannedCodeRunner.test.ts` keeps for the person-driven run: the component
 * can only be checked by holding a phone, so everything that can live off
 * the component lives off it, and is checked here.
 *
 * The sequences below are hand-built `CameraProofStateView`s, not a recorded
 * run: what they assert is the reduction's bookkeeping (which milestones
 * latch, which failures surface), not the runner's behaviour, which has its
 * own test file.
 */

import { describe, expect, it } from 'vitest'
import {
  CAMERA_PROOF_STEPS,
  cameraProofChecks,
  initialCameraProofProgress,
  nextCameraProofProgress,
  type CameraProofStateView,
} from './cameraProofLog'

/**
 * Folds a publish sequence into a progress, the same way the harness does.
 */
function fold(states: CameraProofStateView[]) {
  return states.reduce(nextCameraProofProgress, initialCameraProofProgress())
}

const STARTING: CameraProofStateView = {
  finished: false,
  failed: false,
}

const WAITING: CameraProofStateView = {
  verificationId: undefined,
  finished: false,
  failed: false,
}

const FLOW_ANNOUNCED: CameraProofStateView = {
  verificationId: '$flow',
  finished: false,
  failed: false,
}

const CODE_ON_SCREEN: CameraProofStateView = {
  verificationId: '$flow',
  code: { width: 45, modules: [], payload: new Uint8Array(64) } as never,
  stage: 'started',
  finished: false,
  failed: false,
}

const SCANNED: CameraProofStateView = {
  verificationId: '$flow',
  code: { width: 45, modules: [], payload: new Uint8Array(64) } as never,
  stage: 'code-scanned',
  finished: false,
  failed: false,
}

const DONE: CameraProofStateView = {
  verificationId: '$flow',
  stage: 'done',
  finished: true,
  failed: false,
}

describe('nextCameraProofProgress', () => {
  it('sets started on the very first publish, whatever the state carries', () => {
    const progress = fold([WAITING])
    expect(progress.started).toBe(true)
    expect(progress.flowExists).toBe(false)
    expect(progress.codeShown).toBe(false)
    expect(progress.scanReported).toBe(false)
    expect(progress.finished).toBe(false)
  })

  it('latches each milestone as it appears and keeps it afterwards', () => {
    const progress = fold([WAITING, FLOW_ANNOUNCED, CODE_ON_SCREEN, SCANNED, DONE])
    expect(progress).toEqual({
      started: true,
      flowExists: true,
      codeShown: true,
      scanReported: true,
      finished: true,
      failed: false,
    })
  })

  it('does not report scan_reported from any stage but code-scanned', () => {
    const progress = fold([CODE_ON_SCREEN])
    expect(progress.codeShown).toBe(true)
    expect(progress.scanReported).toBe(false)
  })

  it('records a failed finish', () => {
    const progress = fold([
      FLOW_ANNOUNCED,
      { stage: 'cancelled', finished: true, failed: true } as CameraProofStateView,
    ])
    expect(progress.finished).toBe(true)
    expect(progress.failed).toBe(true)
  })
})

describe('cameraProofChecks', () => {
  it('promises exactly the pinned five steps, in order', () => {
    expect(CAMERA_PROOF_STEPS).toEqual([
      'run_started',
      'flow_exists',
      'code_shown',
      'scan_reported',
      'flow_done',
    ])
    const checks = cameraProofChecks(fold([WAITING, FLOW_ANNOUNCED, CODE_ON_SCREEN, SCANNED, DONE]))
    expect(checks.map((check) => check.name)).toEqual([...CAMERA_PROOF_STEPS])
  })

  it('reports all five PASS on the happy path', () => {
    const checks = cameraProofChecks(fold([STARTING, WAITING, FLOW_ANNOUNCED, CODE_ON_SCREEN, SCANNED, DONE]))
    expect(checks.every((check) => check.ok)).toBe(true)
    expect(checks.filter((check) => check.ok).length).toBe(CAMERA_PROOF_STEPS.length)
  })

  it('reports un-reached milestones as FAIL with "not reported", never drops them', () => {
    // The run stalls waiting for a flow that never arrives.
    const checks = cameraProofChecks(fold([WAITING]))
    expect(checks.map((check) => check.name)).toEqual([...CAMERA_PROOF_STEPS])
    expect(checks.find((check) => check.name === 'run_started')?.ok).toBe(true)
    for (const name of ['flow_exists', 'code_shown', 'scan_reported', 'flow_done']) {
      const check = checks.find((entry) => entry.name === name)
      expect(check?.ok).toBe(false)
      expect(check?.detail).toContain('not reported')
    }
  })

  it('reports flow_done FAIL when the flow was cancelled', () => {
    const checks = cameraProofChecks(
      fold([FLOW_ANNOUNCED, { stage: 'cancelled', finished: true, failed: true } as CameraProofStateView]),
    )
    const done = checks.find((check) => check.name === 'flow_done')
    expect(done?.ok).toBe(false)
    expect(done?.detail).toContain('ended without verifying')
  })
})
