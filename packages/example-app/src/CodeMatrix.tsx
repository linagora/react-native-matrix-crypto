/**
 * The shared QR-symbol renderer: `getVerificationCode`'s own `modules` drawn
 * as squares, nothing re-encoded. Extracted from ScannedCodeWalkthrough so the
 * camera-proof harness draws the same symbol the walkthrough does, from the
 * same code path, with only its size different -- a second hand-written copy
 * of the row-major drawing loop would be a second thing to keep correct, and
 * a transposed or resized-wrong symbol is exactly the defect this render path
 * exists to surface (see ScannedCodeWalkthrough's own header for why plain
 * views and not an image).
 *
 * `maxSide` is the only parameter: the walkthrough caps the symbol because a
 * person holds a phone at it, the camera-proof harness passes the smaller of
 * the two screen dimensions because a fixed mount holds the scanner at it.
 * The quiet zone is part of the symbol, not of the screen: it scales with the
 * squares either way.
 */

import React from 'react'
import { StyleSheet, View, useWindowDimensions } from 'react-native'
import type { ScannableCode } from 'react-native-matrix-crypto'

/**
 * The pale border every QR symbol needs around it.
 *
 * Four squares rather than the specification's minimum, because the thing
 * pointed at this screen is a phone held by a person -- or fixed in a mount,
 * at a distance nobody re-measures per run -- rather than a scanner in a jig,
 * and a symbol that reaches the edge of a bright screen is the commonest
 * reason a scan fails.
 */
export const QUIET_ZONE_SQUARES = 4

export function CodeMatrix({ code, maxSide = 360 }: { code: ScannableCode; maxSide?: number }) {
  const { width: screenWidth } = useWindowDimensions()
  const side = Math.min(screenWidth - 32, maxSide)
  const squares = code.width + QUIET_ZONE_SQUARES * 2
  // Floored, so rounding never makes the drawn symbol wider than the space
  // it was given; the remainder becomes extra quiet zone rather than a
  // clipped final column.
  const squareSize = Math.floor((side / squares) * 100) / 100

  const rows = []
  for (let y = 0; y < code.width; y += 1) {
    const cells = []
    for (let x = 0; x < code.width; x += 1) {
      // Row-major, exactly as the surface documents it. Reading this the
      // other way round transposes the symbol, which for most codes still
      // decodes, to different bytes.
      const dark = code.modules[y * code.width + x]
      cells.push(
        <View
          key={x}
          style={{
            width: squareSize,
            height: squareSize,
            backgroundColor: dark ? '#000000' : '#ffffff',
          }}
        />,
      )
    }
    rows.push(
      <View key={y} style={styles.matrixRow}>
        {cells}
      </View>,
    )
  }

  return <View style={[styles.matrixFrame, { padding: squareSize * QUIET_ZONE_SQUARES }]}>{rows}</View>
}

const styles = StyleSheet.create({
  matrixFrame: {
    alignSelf: 'center',
    backgroundColor: '#ffffff',
    marginVertical: 16,
  },
  matrixRow: {
    flexDirection: 'row',
  },
})
