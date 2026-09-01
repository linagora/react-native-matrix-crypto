/**
 * The screen a person holds a phone in front of.
 *
 * Everything it shows comes from `scannedCodeRunner.ts`, which imports the
 * published TypeScript surface and no component. This file offers two buttons
 * and decides nothing; the squares themselves are drawn by the shared
 * `CodeMatrix.tsx`, which the camera-proof harness draws from too.
 *
 * # The library never sees a camera, and neither does this
 *
 * No camera, no image decoder, no permission prompt, here or anywhere in
 * `react-native-matrix-crypto`. The product owns the scanner and the screen.
 * What `CodeMatrix` draws is `getVerificationCode`'s own `modules`: a
 * row-major boolean grid where `true` is a dark square, at the width the
 * protocol fixes. It is not a re-encoding of the payload and there is no
 * honest string to hand a code-drawing component instead, which is why the
 * grid crosses the boundary rather than the bytes alone.
 *
 * # Why plain views and not an image (the renderer lives in CodeMatrix.tsx)
 *
 * A `<View>` per square, sized so the whole symbol fills the width. That is
 * about two thousand views for a 45-square code, which is more than a
 * production app should draw and exactly what this one should: it adds no
 * dependency, and every square on screen is one entry of the array the
 * library handed over, so what a camera reads is what crossed the boundary
 * rather than what an encoder made of it.
 */

import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Pressable, ScrollView, StyleSheet, Text } from 'react-native'
import { CodeMatrix } from './CodeMatrix'
import { httpJson } from './levelTwoTransport'
import type { LevelTwoPlan } from './levelTwoTransport'
import { startScannedCodeRun, type ScannedCodeRun, type ScannedCodeState } from './scannedCodeRunner'

export function ScannedCodeWalkthrough({
  plan,
  storeDir,
}: {
  plan: LevelTwoPlan
  storeDir: string
}) {
  const [state, setState] = useState<ScannedCodeState>({
    headline: 'Starting…',
    awaitingConfirmation: false,
    finished: false,
    failed: false,
  })
  const runRef = useRef<ScannedCodeRun | null>(null)
  const lastHeadlineRef = useRef<string>("")
  const mountedRef = useRef(true)

  useEffect(() => {
    mountedRef.current = true
    const run = startScannedCodeRun(
      {
        homeserver: plan.homeserver,
        userId: plan.userId,
        deviceId: plan.deviceId,
        accessToken: plan.accessToken,
      },
      storeDir,
      httpJson,
      next => {
        // One line per change of headline, so the operator running the
        // host-side program sees the same story without holding the phone up
        // to their face. Headline and stage only: never an identifier, never
        // a payload byte, never a module. The payload is authentication
        // material and the modules are the same secret drawn as squares.
        if (next.headline !== lastHeadlineRef.current) {
          lastHeadlineRef.current = next.headline
          console.log(`SCANNED_CODE ${next.stage ?? 'no-stage'} ${next.headline}`)
        }
        if (mountedRef.current) setState(next)
      },
    )
    runRef.current = run
    return () => {
      mountedRef.current = false
      run.stop()
    }
  }, [plan, storeDir])

  const onConfirm = useCallback(() => runRef.current?.confirm(), [])
  const onAsk = useCallback(() => runRef.current?.askOtherDevices(), [])

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>Verify by scanning a code</Text>
      <Text style={styles.intro}>
        This screen shows a real code for a real verification, produced by this build on this
        device. Point another Matrix client's camera at it. Nothing here decodes anything: this
        library never sees a camera, and the squares below are the grid it handed over.
      </Text>

      <Text style={state.failed ? styles.headlineBad : styles.headlineGood}>{state.headline}</Text>
      {state.detail ? <Text style={styles.detail}>{state.detail}</Text> : null}

      {state.code ? <CodeMatrix code={state.code} /> : null}

      {state.awaitingConfirmation ? (
        <Pressable accessibilityRole="button" onPress={onConfirm} style={styles.confirmButton}>
          <Text style={styles.confirmText}>Yes, that was my other device</Text>
        </Pressable>
      ) : null}

      {!state.finished && state.code === undefined ? (
        <Pressable accessibilityRole="button" onPress={onAsk} style={styles.askButton}>
          <Text style={styles.askText}>Ask my other devices to verify</Text>
        </Pressable>
      ) : null}

      <Text style={styles.label}>Stage</Text>
      <Text style={styles.mono}>{state.stage ?? 'not started'}</Text>
      {state.code ? (
        <>
          <Text style={styles.label}>Symbol</Text>
          <Text style={styles.mono}>
            {state.code.width} squares a side, {state.code.payload.length} bytes of payload
          </Text>
        </>
      ) : null}
    </ScrollView>
  )
}

const styles = StyleSheet.create({
  container: {
    padding: 16,
  },
  title: {
    fontSize: 20,
    fontWeight: '700',
    marginBottom: 8,
  },
  intro: {
    fontSize: 13,
    lineHeight: 19,
    opacity: 0.8,
    marginBottom: 16,
  },
  headlineGood: {
    fontSize: 15,
    fontWeight: '600',
    color: '#1a7f37',
  },
  headlineBad: {
    fontSize: 15,
    fontWeight: '600',
    color: '#cf222e',
  },
  detail: {
    fontSize: 13,
    lineHeight: 18,
    opacity: 0.75,
    marginTop: 4,
    marginBottom: 12,
  },
  confirmButton: {
    alignSelf: 'flex-start',
    backgroundColor: '#1a7f37',
    borderRadius: 6,
    marginTop: 8,
    paddingHorizontal: 16,
    paddingVertical: 12,
  },
  confirmText: {
    color: '#ffffff',
    fontSize: 15,
    fontWeight: '700',
  },
  askButton: {
    alignSelf: 'flex-start',
    borderColor: '#8888',
    borderRadius: 6,
    borderWidth: StyleSheet.hairlineWidth,
    marginTop: 8,
    paddingHorizontal: 12,
    paddingVertical: 8,
  },
  askText: {
    fontSize: 13,
    fontWeight: '600',
    opacity: 0.8,
  },
  label: {
    fontSize: 11,
    fontWeight: '700',
    textTransform: 'uppercase',
    opacity: 0.6,
    marginTop: 12,
  },
  mono: {
    fontFamily: 'Courier',
    fontSize: 12,
  },
})
