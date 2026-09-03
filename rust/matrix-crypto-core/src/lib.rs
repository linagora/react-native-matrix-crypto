//! Core logic for the Matrix crypto bridge.
//!
//! This crate knows nothing about UniFFI, JSI, or React Native. It must never
//! take a direct dependency on `uniffi`; `scripts/assert-core-boundary.sh`
//! enforces that in CI.

mod error;
mod identity;
mod machine;
mod observer;
mod probe;
mod recovery;
mod runtime;
mod session;
mod signing;
mod verification;

pub use error::ProbeError;
pub use identity::{device_identity_keys, device_statuses, DeviceStatus, IdentityKeys, TrustState};
pub use machine::{create_machine, open_store, with_machine, MachineConfig, MachineError};
pub use observer::{
    clear_crypto_observer, probe_with_observer, set_crypto_observer, CryptoObserver, CryptoSignal,
    ProbeObserver, ProbeSignal,
};
pub use probe::{probe, ProbeReport};
pub use recovery::{create_recovery, recover_identity, AccountDataEntry, RecoverySetup};
pub use runtime::in_runtime;
pub use session::{
    decrypt_event, encrypt_event, mark_request_failed, mark_request_sent, receive_sync_changes,
    share_scope_key, take_outgoing_requests, Envelope, OutgoingRequest, SenderTrustRequirement,
    SenderVerification, SessionError, SyncOutcome,
};
pub use signing::{bootstrap_identity, create_identity, identity_status, IdentityStatus};
pub use verification::{
    accept_flow, begin_comparison, cancel_flow, code_capabilities, confirm_flow, confirm_scan,
    flow_stage, offer_codes, read_code, read_material, request_flow, request_self_flow,
    submit_scanned_code, CodeCapabilities, FlowId, FlowStage, SasEmoji, SasMaterial, ScannableCode,
};
