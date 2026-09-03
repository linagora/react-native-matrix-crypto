// The public API. Consumers import from here and nowhere else.
// Nothing from ./generated is re-exported: spec section 5 forbids leaking
// internal Rust structure.

// Side-effect only: ./index.tsx is ubrn's generated turbo-module bootstrap.
// It calls installer.installRustCrate(), which registers the Rust crate's
// JSI host object on the global object -- every generated function in
// ./generated/matrix_crypto (which ./probe imports directly, bypassing
// index.tsx) reads that global at call time and fails otherwise.
// ubrn's own convention is to point package.json's "react-native" field
// directly at index.tsx (confirmed in its getting-started guide), but that
// would make the generated file BE the public surface, which spec section 5
// forbids. Importing it here for its side effect, while this file keeps
// curating what actually gets exported, is what closes that gap. Without
// this line, nothing in the module graph reachable from the public package
// ever imports index.tsx, the install never runs, and every native call
// fails with "Cannot read property '...' of undefined" -- confirmed
// empirically on a real device build; every host-only test (vitest) missed
// it because there is no native module to install in Node either way.
import './index.tsx'

export type {
  CodeCapabilities,
  CryptoAlgorithm,
  CryptoScopeId,
  EventEnvelope,
  SasEmoji,
  SasMaterial,
  ScannableCode,
  SenderTrustRequirement,
  SenderVerification,
  SyncDelta,
  TrustState,
  VerificationStage,
} from './types'
export { asCryptoScopeId } from './types'

export type { CryptoError, CryptoErrorKind } from './errors'
export { isCryptoError } from './errors'

export type { CryptoSignal, Unsubscribe } from './signals'
export { onCryptoSignal } from './signals'

export type { ProbeResult, ProbeSignal } from './probe'
export { runProbe } from './probe'

export type {
  AccountDataEntry,
  CryptoMachineConfig,
  DeviceStatus,
  IdentityKeys,
  IdentityStatus,
  OutgoingRequest,
  RecoverySetup,
} from './facade'
export {
  acceptVerification,
  bootstrapCrossSigning,
  cancelVerification,
  confirmScan,
  confirmVerification,
  createCrossSigningIdentity,
  createCryptoMachine,
  createRecovery,
  decryptEvent,
  encryptEvent,
  encryptionSlice,
  exportSecrets,
  getDeviceIdentityKeys,
  getDeviceStatuses,
  getIdentityStatus,
  getSupportedAlgorithms,
  getVerificationCode,
  getVerificationMaterial,
  getVerificationStage,
  importSecrets,
  markRequestFailed,
  markRequestSent,
  offerScannableCodes,
  openCryptoStore,
  receiveSyncChanges,
  recoverIdentity,
  requestSelfVerification,
  requestVerification,
  restoreCryptoMachine,
  shareScopeKey,
  startVerificationComparison,
  submitScannedCode,
  takeOutgoingRequests,
} from './facade'
