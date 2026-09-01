//! Verifying another device, by comparing a short authentication string
//! or by scanning a code off its screen.
//!
//! Two people who can talk to each other out of band read a seven-symbol
//! string off their screens and say whether it matches. If it does, each
//! side's device is proven to be the one holding the key it claims, and the
//! library records the other's device as verified. If it does not, the flow
//! is cancelled and nothing is recorded. That refusal is the entire point:
//! a comparison that can only ever agree proves nothing.
//!
//! # Flows are addressed by identifier, not by handle
//!
//! Upstream's verification API is handle-shaped -- a request and a
//! comparison are both objects with state that the caller holds. This
//! library's ownership model is not: `create_machine` returns nothing, the
//! machine lives here, and no handle crosses the boundary. So a flow is
//! named by an opaque identifier and the handles behind it live in this
//! module's own registry, which is the cost that decision carries and which
//! the outbound request pump in `session.rs` already paid once. Its
//! registry is the worked precedent for this one: key by the thing upstream
//! keys by, evict on a documented rule with upstream evidence, keep an
//! entry a failed call could still want, and be able to show the map does
//! not grow without bound.
//!
//! # Why the handles are held rather than looked up each time
//!
//! Upstream keeps its own map of live flows, and a lookup against it would
//! need no registry here at all. It cannot be used for this, because
//! upstream drops a flow from that map as soon as the flow is done or
//! cancelled -- `VerificationMachine::garbage_collect`, run at the top of
//! every `receive_sync_changes`. A caller that asked "what happened to my
//! verification?" one sync too late would be told the flow never existed,
//! which is the wrong answer to the most important question in this module.
//! Upstream's own callers survive that because they hold the handle: the
//! handle and the map entry share one observable state, and dropping the
//! map entry does not disturb the handle. So this registry holds handles,
//! and a finished flow keeps reporting how it finished.
//!
//! # What the registry does with a finished flow
//!
//! It releases it the next time a flow is registered, which is upstream's
//! own rule (`retain(|_, v| !(v.is_done() || v.is_cancelled()))`) moved
//! from "on the next sync" to "on the next registration". A caller can
//! therefore read a cancelled or completed flow's outcome for as long as it
//! takes to start another one, and no longer. The registry holds at most
//! the flows that are still live plus those that finished since the last
//! registration, which is bounded by how many a caller runs at once; it
//! does not accumulate one entry per verification ever attempted.
//! `a_finished_flow_is_not_retained_forever` in `tests/sas_two_party.rs` is
//! the proof, and it is the same shape as the pump's own
//! `a_stale_keys_upload_id_does_not_accumulate_across_repeated_calls`.
//!
//! # Two shapes of flow, and one surface over both
//!
//! A verification normally opens with an `m.key.verification.request`: one
//! side invites, the other agrees, and only then does either start the
//! comparison. That is the shape this library sends, and it was the only
//! one this module could answer until `091988f`. It is not the only one now
//! -- see "Every call on this surface answers both" below, which is the
//! current statement and which the sentence this replaces contradicted.
//!
//! The Matrix protocol also still carries the shape MSC3122 deprecated --
//! a bare `m.key.verification.start` with no request before it, to-device
//! only. It is not a legacy curiosity: it is what some third-party clients
//! implement and *all* they implement, `matrix-nio` among them, and
//! `matrix-sdk-crypto` 0.18.0 both emits it (`Device::start_verification`)
//! and accepts it (`verification/machine.rs:430-450`). A flow that arrives
//! that way exists inside upstream's machine as a comparison and nothing
//! else -- there is no request object behind it and there never will be.
//!
//! Every call on the short-string half of this surface answers both, and a
//! caller does not have to know which it has: [`accept_flow`] agrees to
//! whatever the flow is waiting on, [`read_material`] shows the string,
//! [`confirm_flow`] says it matched, [`cancel_flow`] refuses. The one
//! visible difference is that a bare-start flow is never
//! [`FlowStage::Ready`] -- it is a comparison from the moment it exists --
//! so [`begin_comparison`] has nothing to do on one and says so.
//!
//! **This said "every call on this surface" and the surface grew past it.**
//! A code needs a request object to hang off, so [`read_code`] and
//! [`submit_scanned_code`] refuse a bare-start flow with
//! [`MachineError::WrongStage`] rather than answering it. That is not a gap
//! to close: a peer that opened a comparison with no request before it has
//! announced no methods at all, so there is nothing on such a flow that
//! could have negotiated a code.
//!
//! The two shapes differ in *how many times* a caller agrees, not in what
//! agreeing means: a request-shaped flow can need [`accept_flow`] twice,
//! once for the invitation and once more if the peer opens the comparison
//! rather than waiting for this side to. See that function for why, and
//! for the silent stall that used to be.
//!
//! # The other way two devices verify each other
//!
//! A person who can point one phone's camera at another's screen does not
//! have to read seven symbols off both. The protocol's other method puts the
//! keys and a shared secret into about 126 bytes, one side draws them and
//! the other reads them, and the flow finishes with no string for anybody to
//! compare. [`read_code`] produces those bytes, [`submit_scanned_code`]
//! takes them back in, and [`confirm_scan`] is the one thing a person still
//! has to say: *yes, that was my phone that just scanned this*.
//!
//! **This library never sees a camera.** It has no image decoder, asks for
//! no permission and contains no scanner. The product owns all three, the
//! same way it owns the network, and what crosses this boundary is a byte
//! array in each direction plus a grid of squares to draw. That is the same
//! line M1 drew for the homeserver, and it is the line the design's section
//! 1.1 settles.
//!
//! It is also why none of this happens until a product asks for it, and
//! why what it asks for has two halves rather than one.
//! [`offer_codes`] takes [`CodeCapabilities`], both fields off until
//! called, and with both off this library announces on the wire exactly
//! what every release before it announced, so a consumer who never scans is
//! not quietly made to take part. **A product that can draw a code and
//! cannot read one says exactly that**, which is the thing a single boolean
//! could not say and the reason a person met a dead flow on hardware. See
//! that function for what each setting costs and who pays it.
//!
//! The three modes the protocol defines are all reachable here, and which
//! one a flow uses is decided by *which device is holding up its screen*
//! rather than by anything a caller passes:
//!
//! * verifying **another user**: both master signing keys travel in the
//!   payload, so this device needs its own private signing keys and the
//!   other user needs a published identity;
//! * verifying **our own new login, with the established device showing**:
//!   the shown code carries the account's master key, which the device
//!   showing it already trusts;
//! * verifying **our own new login, with the new login showing**: the same
//!   flow with the screens the other way round, and the code says so,
//!   because the device showing it holds none of the account's private
//!   keys yet.
//!
//! Both self modes are here because a product that implemented one of them
//! would work exactly half the time, and which half would be chosen by
//! whichever phone its user picked up.
//!
//! # A code and a string race, and the code can lose
//!
//! On a flow that announced both (see [`announced_methods`], and
//! [`offer_codes`] for when that happens), both are live at once and
//! either side may move first. This paragraph said both were announced on
//! every flow, and pointed at an `ANNOUNCED_METHODS` constant, which is
//! what the announcement was before it became a product's choice; neither
//! the claim nor the name survived, and nothing failed when they stopped
//! being true, because a doc link into a private module is not checked by
//! anything this repository runs. Upstream settles it: a *displayed* code may still give way to
//! a short-string comparison, but once either side has scanned it is too
//! late (`verification/requests.rs:1404-1422`). A code that loses that race
//! is cancelled without anybody refusing it, which is a thing a product
//! showing one has to be able to say -- the square on the screen is dead and
//! no error was returned to anybody, because nothing was asked.
//!
//! # Requests
//!
//! Every call here that produces a message hands it to
//! `session::queue_action_request`, because upstream does not queue the
//! messages it returns to its caller -- see that function's own doc
//! comment. They then leave through `take_outgoing_requests` and are
//! resolved through `mark_request_sent` like every other request this
//! library produces. That is not optional bookkeeping: upstream advances
//! the comparison from "accepted" to "keys exchanged" only when the key
//! message is reported sent, so a caller that never resolves what it
//! drained never sees a short authentication string at all. That failure is
//! named rather than silent -- see [`MachineError::MaterialNotReady`].

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex as StdMutex;

use matrix_sdk_common::deserialized_responses::ProcessedToDeviceEvent;
use matrix_sdk_common::ruma::events::key::verification::VerificationMethod;
use matrix_sdk_common::ruma::{OwnedDeviceId, OwnedUserId};
use matrix_sdk_crypto::matrix_sdk_qrcode::qrcode::Color;
use matrix_sdk_crypto::matrix_sdk_qrcode::{DecodingError, QrVerificationData};
use matrix_sdk_crypto::types::requests::OutgoingRequest as UpstreamOutgoingRequest;
use matrix_sdk_crypto::{
    QrVerification, QrVerificationState, Sas, SasState, ScanError, Verification,
    VerificationRequest, VerificationRequestState,
};

use crate::identity::TrustState;
use crate::machine::{with_machine, MachineError};
use crate::observer::CryptoSignal;

/// The opaque name of one verification flow.
///
/// Upstream's own identifier for the flow, which is the transaction id both
/// sides already carry in every message they exchange about it. Opaque on
/// this surface: nothing outside this module may parse it, and the only
/// thing a caller may do with one is hand it back.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowId(pub String);

/// One symbol of a short authentication string, with the word for it.
///
/// `description` is upstream's own English word for the symbol. A product
/// showing these to a user in another language looks the word up from the
/// symbol's position, which is why both sides of the pair travel together.
#[derive(Clone, PartialEq, Eq)]
pub struct SasEmoji {
    pub symbol: String,
    pub description: String,
}

/// The short authentication string, in both of the forms the protocol can
/// produce.
///
/// `emoji` is optional and `decimals` is not, and that asymmetry is
/// upstream's, not a convenience: the symbol form is only produced when
/// both sides negotiated it, and a surface offering only symbols therefore
/// has a live path with nothing to show. The digits are always there once
/// the keys are exchanged.
///
/// A caller must show one of these to a person and ask whether it matches
/// what the other person sees. Comparing them programmatically across a
/// channel the flow itself established would prove nothing -- the channel is
/// what is being verified.
#[derive(Clone, PartialEq, Eq)]
pub struct SasMaterial {
    pub emoji: Option<Vec<SasEmoji>>,
    pub decimals: (u16, u16, u16),
}

/// A hand-written, redacting `Debug`, like `MachineConfig`'s and
/// `Envelope`'s and for the same reason: this record *is* the
/// authentication material. Anything that learns it while a flow is open
/// learns what an interposed party would need to answer the comparison
/// correctly, so it must never reach a log line, a panic message or an
/// error's `Display`. Destructured rather than field-accessed, so a field
/// added later fails this to compile instead of being printed in full.
impl std::fmt::Debug for SasMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let SasMaterial { emoji, decimals: _ } = self;
        f.debug_struct("SasMaterial")
            .field("emoji_count", &emoji.as_ref().map(Vec::len))
            .field("decimals", &"[redacted]")
            .finish()
    }
}

/// See `SasMaterial`'s own `Debug`: one symbol is a seventh of the answer.
impl std::fmt::Debug for SasEmoji {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let SasEmoji {
            symbol: _,
            description: _,
        } = self;
        f.debug_struct("SasEmoji")
            .field("symbol", &"[redacted]")
            .finish()
    }
}

/// What this library announces when a product has not asked for verification
/// by a scannable code.
///
/// **Byte for byte what every release before this one announced**, and that
/// is the whole point of it: a build that never asks for codes says on the
/// wire exactly what it said before they existed, so nothing about a
/// consumer's flows changes because this library grew a feature they do not
/// use. `a_product_that_asks_for_nothing_announces_what_shipped_before_codes`
/// pins it, and `tests/qr_announcement.rs` pins it on the wire rather than
/// on this constant.
const WITHOUT_CODES: &[VerificationMethod] = &[VerificationMethod::SasV1];

/// What a product that can put a code on a screen and cannot read one says.
///
/// **`QrCodeScanV1` is deliberately absent, and that absence is the whole of
/// this constant.** Announcing it is a claim the far side acts on: it says
/// this product can point a camera at a screen, and a peer holding that
/// claim may answer by showing its own code and waiting. A product with no
/// scanner then leaves a person holding a phone in front of a square nothing
/// will ever read, with no error reaching either product, because nothing
/// was asked of either library. That is not a hypothetical: it is what a
/// real Element Web client chose on hardware on 2026-08-31, against a
/// product whose only way to ask for codes was to claim both halves.
///
/// **`ReciprocateV1` is present, and it was established rather than
/// assumed.** It names the message the *scanning* side sends once it has
/// read a code, so a first reading says a product that never scans has no
/// use for it. What was found:
///
/// * upstream's own default list, with the `qrcode` feature on, is
///   `SasV1`, `QrCodeShowV1`, `ReciprocateV1`
///   (`verification/requests.rs:60-65`). That is a show-only list and it
///   carries `ReciprocateV1`;
/// * mautrix-go v0.30.0 gates its entire scanning path on the far side
///   having announced it: `supportsReciprocate` is
///   `slices.Contains(vh.supportedMethods, Reciprocate) &&
///   slices.Contains(txn.TheirSupportedMethods, Reciprocate)`, and
///   `supportsScanQRCode` is `supportsReciprocate && ...`
///   (`crypto/verificationhelper/verificationhelper.go`). Leave it out of
///   this list and that counterparty declines to scan a code this library
///   shows, which is the whole flow;
/// * upstream itself enforces none of this in either direction:
///   `generate_qr_code` tests only the show and scan halves
///   (`verification/requests.rs:1222-1228`), `scan_qr_code` tests nothing,
///   and the reciprocate arm of `receive_start` looks the flow up in its own
///   cache without consulting anybody's announced methods
///   (`verification/requests.rs:1448-1467`). So **no test built on a bare
///   `OlmMachine` counterparty can watch this entry matter**, and that is
///   said here rather than left as an implied claim: the evidence for it is
///   the two implementations above, not a test in this repository.
///
/// So it is not the message this side sends. It is the far side's permission
/// to send one, and the side being reciprocated *to* is exactly the side
/// that has to grant it.
const SHOWING_ONLY: &[VerificationMethod] = &[
    VerificationMethod::SasV1,
    VerificationMethod::QrCodeShowV1,
    VerificationMethod::ReciprocateV1,
];

/// What a product that can read a code and cannot draw one says.
///
/// [`SHOWING_ONLY`]'s mirror, and it exists because the two facts really are
/// independent: a product owns a camera or it does not, it owns a surface a
/// code can be drawn on or it does not, and neither answer settles the
/// other. `ReciprocateV1` is here for the plain reason as well as
/// [`SHOWING_ONLY`]'s: this is the side that sends that message.
const SCANNING_ONLY: &[VerificationMethod] = &[
    VerificationMethod::SasV1,
    VerificationMethod::QrCodeScanV1,
    VerificationMethod::ReciprocateV1,
];

/// What a product that can do both says.
///
/// The list this library announced for every product that asked for codes at
/// all, which is the defect the two constants above exist to end. It is
/// still the right list, for a product that really can do both.
const SHOWING_AND_SCANNING: &[VerificationMethod] = &[
    VerificationMethod::SasV1,
    VerificationMethod::QrCodeShowV1,
    VerificationMethod::QrCodeScanV1,
    VerificationMethod::ReciprocateV1,
];

/// Bit for "this product can draw a code on a screen".
const SHOWING: u8 = 0b01;
/// Bit for "this product can read a code with a camera".
const SCANNING: u8 = 0b10;
/// Both bits, which is the only combination that needs a name of its own to
/// be matched on below.
const BOTH: u8 = SHOWING | SCANNING;
/// What a fresh process holds, and what a process that never calls
/// [`offer_codes`] keeps.
const NEITHER: u8 = 0;

/// What [`offer_codes`] was last told, packed into one word.
///
/// **One atomic and not two, and that is not tidiness.** The two halves are
/// read together, once, at the moment a flow is created or agreed to. Kept
/// in two atomics they could be read either side of a concurrent
/// [`offer_codes`], and a flow would then announce a pair no product ever
/// asked for: showing from the setting before the call and scanning from the
/// setting after it. One word makes that unrepresentable rather than
/// unlikely.
static CODE_CAPABILITIES: AtomicU8 = AtomicU8::new(NEITHER);

/// What a product can do with a scannable code, as the two separate facts it
/// really is.
///
/// # Why this is not a boolean, and what the boolean cost
///
/// It was one. A single `offer_scanning(bool)` announced showing and
/// scanning together, so a product could say "codes, both directions" or "no
/// codes at all" and had no way to say the one thing a product with a screen
/// and no scanner needs to say. On 2026-08-31 a product holding exactly that
/// shape told a real Element Web client on the same account that it could
/// scan; Element answered by showing its own code and waiting for a camera
/// that did not exist, and the flow died with a stage complaint that
/// explained none of it. Element did nothing wrong. The claim was ours.
///
/// # Why a record with two required fields
///
/// **Neither field has a default and this type has none.** There is no
/// `Default` impl, no `..` in any construction of it anywhere in this
/// workspace, and nothing on this surface builds one on a caller's behalf.
/// Leaving a field out is a compile error here and a type error across the
/// boundary. That is exactly the property the boolean lacked: with it, the
/// question "can you scan?" was never put to the product at all, and the
/// answer taken on its behalf was yes. **A shape where a forgotten field
/// silently means yes is how this defect started**, so the shape that
/// replaces it has no field that can be forgotten and no value that can be
/// defaulted.
///
/// Two named fields rather than two positional booleans for the neighbouring
/// reason: `offer_codes(true, false)` and `offer_codes(false, true)` are
/// both well-typed and mean opposite things, and nothing would ever say
/// which one a call site meant.
///
/// # This library cannot answer either question
///
/// It owns no camera, no permission and no screen, by design: the product
/// owns all three. Whether a scanner exists is therefore a fact only the
/// product knows, which is why both fields are the product's to state, and
/// why a process that has said nothing announces nothing. See
/// [`offer_codes`] for what each setting costs and who pays it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeCapabilities {
    /// This product can draw a code on a screen for another device's camera.
    pub can_show: bool,
    /// This product can read a code off another device's screen.
    pub can_scan: bool,
}

/// Says what this product can do with a scannable code.
///
/// **Both halves off until this is called, and the default is not caution
/// for its own sake.** Announcing a method is a claim the far side acts on,
/// and the two claims codes require are claims about the *product*, not
/// about this library: it owns the camera, the screen and the scanner, and
/// this library cannot know whether it built any of them. A library that
/// announced them on every product's behalf would be answering a question
/// only the product can, which is precisely what the boolean this replaced
/// did.
///
/// # What each setting costs, and who pays it
///
/// **`can_scan` on, wrongly:** a peer's client is told this side can scan,
/// so it may show its user a code and ask them to point a camera at it.
/// Nothing here can read it. No error is returned to anybody, because
/// nothing was asked of this library: the failure is invisible to both
/// products and lands on a person who did nothing wrong. If a reciprocation
/// ever did arrive for a flow with no code, upstream drops it with a warning
/// and sends no cancellation (`verification/requests.rs:1448-1467`), so the
/// flow stalls to the protocol's ten-minute timeout rather than failing.
/// **This is the setting that failed on hardware**, and it failed because
/// there was no way to leave it off while turning codes on at all.
///
/// **`can_show` off, wrongly:** [`read_code`] refuses with
/// [`MachineError::CodeNotOffered`] on the first flow a developer tries it
/// on. That is a named error, at integration time, in front of the person
/// who can fix it in one line.
///
/// The owner settled it in that direction on 2026-08-30: a developer with an
/// error message is cheap, and a user staring at a code nobody can scan,
/// with the product unable to detect it, is not.
///
/// # What each answer puts on the wire
///
/// Four answers and four lists, and three of them are observed off the
/// pump's own request body in `tests/qr_announcement.rs` rather than off the
/// constant that produced them:
///
/// * neither: `m.sas.v1` alone, which is what every release before codes
///   announced;
/// * showing only: `m.sas.v1`, `m.qr_code.show.v1`, `m.reciprocate.v1`. See
///   [`SHOWING_ONLY`] for why the third belongs to a side that never sends
///   it, and for the two implementations that settle the question;
/// * scanning only: `m.sas.v1`, `m.qr_code.scan.v1`, `m.reciprocate.v1`;
/// * both: all four.
///
/// # When to call it
///
/// Before opening or answering any flow a code might be used on. The
/// announcement is made once, when a flow is created or agreed to, and it
/// fixes what that flow can do for its whole life: calling this afterwards
/// changes nothing about a flow already under way, and there is no message
/// in the protocol that would.
///
/// Process-wide, like the observer registry and for the same reason: it
/// describes the product, and a product does not have a camera on some of
/// its verifications and not others.
///
/// # Off does more than stay quiet
///
/// A `can_show` this side did not announce makes a code genuinely
/// unavailable rather than merely unadvertised, in both directions, and
/// neither direction is this library's own choice: upstream refuses to build
/// one unless *both* sides announced their half
/// (`verification/requests.rs:1222-1228`). So with both halves off, a peer's
/// own `generate_qr_code` returns nothing and its client falls through to
/// the short string, exactly as it did against every release before this
/// one. `tests/qr_announcement.rs` observes both halves.
///
/// The same rule read the other way is what makes `can_show` alone useful:
/// a peer that has been told this side cannot scan **cannot choose to
/// show**, because its own `generate_qr_code` tests this side's list for
/// `m.qr_code.scan.v1` and does not find it. It scans, or there is no code.
/// `tests/qr_show_only.rs` watches a peer that announced every method be
/// left with no choice.
pub fn offer_codes(capabilities: CodeCapabilities) {
    // Destructured, not field-accessed: a field added to this record later
    // must be ruled on here rather than silently dropped, which is the rule
    // every record crossing the FFI boundary already keeps.
    let CodeCapabilities { can_show, can_scan } = capabilities;
    let mut bits = NEITHER;
    if can_show {
        bits |= SHOWING;
    }
    if can_scan {
        bits |= SCANNING;
    }
    CODE_CAPABILITIES.store(bits, Ordering::Relaxed);
}

/// What [`offer_codes`] was last told.
///
/// **Not a question a product has to ask**, and deliberately not crossed to
/// the published surface: the switch is the caller's own state. A getter on
/// that surface would invite a product to read back a decision it made, and
/// to treat the answer as though it described the wire, which it does not:
/// what a *flow* announces is fixed when that flow is created.
///
/// It is public for one reason, and it is a testing reason. Setting the
/// switch has no observable effect anywhere outside this module, so the
/// bridge that crosses [`offer_codes`] to another language has nothing to be
/// checked against: a bridge function whose body dropped its argument would
/// compile, export, and pass every test in this repository, and the symptom
/// would be a product that turned codes on and was told `CodeNotOffered` on
/// the first flow it tried. A bridge that dropped *one field* of the record
/// is the sharper version of the same hole, and it is the one that produced
/// the hardware failure this record exists to end. `matrix-crypto-ffi`'s own
/// tests read this to close both.
pub fn code_capabilities() -> CodeCapabilities {
    let bits = CODE_CAPABILITIES.load(Ordering::Relaxed);
    CodeCapabilities {
        can_show: bits & SHOWING != 0,
        can_scan: bits & SCANNING != 0,
    }
}

/// The methods this library announces, which is a product's own choice and
/// not the list of what this library can carry out.
///
/// Those two were the same thing until the switch existed, and the sentence
/// that said so has been corrected rather than struck, because the
/// distinction is the whole of the switch. Every method named in
/// [`SHOWING_AND_SCANNING`] is compiled in and reachable; a build that has
/// asked for less announces less, deliberately, since a code a product
/// cannot photograph is worse than one it never offered.
///
/// Read at each of the three call sites that name methods rather than being
/// captured once, so the answer describes the process at the moment a flow
/// is opened or agreed to. Passed explicitly rather than letting upstream
/// apply its own default: that has always been the rule here, and enabling
/// the code-scanning feature is what made it load-bearing rather than tidy,
/// because upstream's default list widens when that feature is on
/// (`verification/requests.rs:60-65`). Nothing here uses it, so nothing did.
fn announced_methods() -> &'static [VerificationMethod] {
    match CODE_CAPABILITIES.load(Ordering::Relaxed) {
        BOTH => SHOWING_AND_SCANNING,
        SHOWING => SHOWING_ONLY,
        SCANNING => SCANNING_ONLY,
        NEITHER => WITHOUT_CODES,
        // Unreachable: [`offer_codes`] is the only writer and it writes one
        // of the four values above. The safe answer for a value nothing can
        // produce is the list that claims nothing.
        _ => WITHOUT_CODES,
    }
}

/// Puts the switch back where a fresh process finds it, so one test's
/// product-level choice is not another's starting state. Called from
/// `machine::reset_for_test` beside the flow registry.
#[cfg(test)]
pub(crate) fn reset_code_capabilities_for_test() {
    CODE_CAPABILITIES.store(NEITHER, Ordering::Relaxed);
}

/// A code to show a person's other camera, in both of the forms a product
/// needs to draw one.
///
/// Two forms and not one, and the second is not a convenience. The payload
/// is **binary and is not UTF-8**: it carries two raw ed25519 keys and a
/// random shared secret, and there is no string it can honestly be turned
/// into. A product reaching for an ordinary JavaScript code-drawing
/// component would hand it a mangled string and draw a square that decodes
/// to something else. Upstream builds its own symbol at a fixed version and
/// error-correction level, in its own words because mobile clients have
/// trouble decoding otherwise, so `modules` is that exact symbol rather than
/// a re-encoding of the payload, and a product that draws it draws what
/// upstream meant.
pub struct ScannableCode {
    /// The bytes the specification defines. About 126 of them, binary.
    pub payload: Vec<u8>,
    /// The side length, in squares, of the symbol below.
    pub width: u32,
    /// The symbol, row-major, `width * width` entries. `true` is a dark
    /// square.
    pub modules: Vec<bool>,
}

/// A hand-written, redacting `Debug`, for [`SasMaterial`]'s reason and with
/// the same force behind it.
///
/// **The payload is authentication material.** It carries the shared secret
/// the whole method rests on: whoever learns it can answer the flow as if
/// they had read the screen, and the reason the method is secure at all is
/// that the secret travels over a channel an attacker would have to be
/// physically present to read. A log line, a panic message or an error's
/// `Display` is not that channel. The modules are the same secret drawn as
/// squares, so they are redacted too.
///
/// Destructured rather than field-accessed, so a field added later fails
/// this to compile instead of being printed in full.
impl std::fmt::Debug for ScannableCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ScannableCode {
            payload,
            width,
            modules,
        } = self;
        f.debug_struct("ScannableCode")
            .field("payload_len", &payload.len())
            .field("width", width)
            .field("module_count", &modules.len())
            .finish()
    }
}

/// How far along a flow is.
///
/// Deliberately coarser than upstream's **three** state enums, which
/// between them distinguish **nineteen** states: `VerificationRequestState`
/// 6, `SasState` 7, `QrVerificationState` 6, counted in
/// `matrix-sdk-crypto-0.18.0`. This said "two enums ... nineteen states",
/// which is no pairing of the three: two of them distinguish thirteen. The
/// third is the one the `qrcode` feature brought into this build, so
/// turning that feature on made the number right and left the noun wrong,
/// and the sentence was corrected once for what follows the number without
/// the number in front of it being counted.
///
/// **`stage_of` reads all three**, which it did not always: while
/// `QrVerificationState` was the one enum nothing here consulted, six
/// states of a real flow had no stage of their own. [`code_of`] records
/// why that held and [`stage_of_code`] is where the reading happens now.
///
/// What a caller has to decide is which of a small set of things to do next
/// -- wait, accept, show the string, show the code, confirm a scan, or tell
/// the user it is over -- and every distinction upstream draws that does not
/// change that answer is one this surface would be inviting a product to
/// branch on for no reason.
///
/// **This vocabulary was the short string's alone, and a flow that became
/// a code was described in it for want of one of its own. That limit is
/// lifted.** [`FlowStage::CodeScanned`] names the one state a scanned flow
/// reaches that a comparison never does, so such a flow is no longer
/// reported as the nearest string stage, and [`confirm_scan`] can tell a
/// caller whether to wait or to start again once [`flow_stage`] is read
/// first. What stays folded is upstream's `Confirmed` and `Reciprocated`,
/// which are one stage here on purpose: [`stage_of_code`] says why.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowStage {
    /// Asked for, by one side or the other, and not yet answered.
    Requested,
    /// Both sides have agreed to verify. One of them may now start the
    /// comparison, and on a flow that negotiated codes either may instead
    /// show one or hand in a scanned one.
    Ready,
    /// The flow has begun and nothing is waiting on this side yet.
    ///
    /// For a comparison, the keys are not exchanged, so there is nothing to
    /// show. For a flow that became a code, the code exists and nobody has
    /// scanned it: keep it on the screen. Neither asks anything of a person.
    Started,
    /// The short authentication string is available and waiting to be
    /// compared. Not reached by a flow proceeding by a code: there is no
    /// string on one.
    KeysExchanged,
    /// This side has done what was asked of it; the other side has not
    /// finished.
    ///
    /// Said the strings match, for a comparison. For a flow that became a
    /// code, either scanned the other device's code and told it so, or
    /// confirmed that the other device scanned this one's. All three are
    /// the same situation for a person looking at a screen: wait.
    Confirmed,
    /// The flow finished and the other device is now verified, whether both
    /// sides said the strings matched or one scanned the other's code and
    /// the shower confirmed it. This said "both sides said the strings
    /// match", which `tests/qr_cross_user.rs` contradicts while passing:
    /// it reaches this stage with no string ever produced.
    Done,
    /// Over without a verification, whether because a side refused, a side
    /// abandoned it, a scanned code was refused, or it timed out.
    Cancelled,
    /// The other device has scanned the code this one is showing, and a
    /// person must say whether that was really them.
    ///
    /// The one moment a flow with no string to compare asks a person
    /// anything, and the counterpart of [`FlowStage::KeysExchanged`] for a
    /// flow that became a code: something is waiting on this side, and
    /// [`confirm_scan`] is what answers it. Reached only on the side that
    /// showed a code; the side that scanned one is never scanned in turn.
    ///
    /// **Last rather than in its logical place, and the position is not a
    /// preference.** The FFI mirror assigns wire ordinals by declaration
    /// order and may only be appended to, so this enum keeps the mirror's
    /// order to make the `From` between them checkable by eye.
    CodeScanned,
}

/// One flow this process is taking part in.
///
/// The comparison handle is cached rather than stored at registration
/// because it does not exist yet at registration: a flow becomes a
/// comparison later, when one side starts one. It is filled in from the
/// request handle, which carries it once that has happened, so no separate
/// lookup against upstream's own map is needed -- and would not survive that
/// map's garbage collection anyway.
struct FlowRecord {
    /// The request handle, for a flow that began with one.
    ///
    /// `None` for a flow that began as a bare `m.key.verification.start`
    /// with no `m.key.verification.request` before it. That is the shape
    /// MSC3122 deprecated, and upstream still both emits it
    /// (`identities/device.rs`'s `Device::start_verification`) and accepts
    /// it (`verification/machine.rs:430-450`), where it builds the
    /// comparison straight from the start event and writes **nothing** to
    /// the map `get_verification_request` reads. So such a flow has no
    /// request behind it and never will. It is also the only shape some
    /// third-party clients speak, which is what this option is here for;
    /// see the module header's own section on it.
    request: Option<VerificationRequest>,
    comparison: Option<Sas>,
    /// The scanned-code handle, for a flow that became one.
    ///
    /// The third handle and the newest, and it is filled in the same way and
    /// for the same reason the comparison is: a flow becomes a code later
    /// than it is registered, and the request carries the handle once it
    /// has. `None` for every flow that is not a code, which is every flow
    /// this library ran before this milestone.
    ///
    /// It does **not** join the structural invariant the two constructors
    /// keep. A record is never built from a code alone: a code only ever
    /// exists behind a request, unlike a comparison, which a peer can open
    /// with a bare `m.key.verification.start` and no request at all.
    code: Option<QrVerification>,
    /// Whether this flow's completion has already been announced on the
    /// crypto signal channel.
    ///
    /// A flow reaches [`FlowStage::Done`] once and is announced once, but
    /// the two moments that can notice it -- the confirmation that finished
    /// it, and the next sync -- can both fire for the same flow. Without
    /// this, whichever ran second would emit a duplicate `TrustChanged`.
    /// Eviction is not a substitute: `release_finished` runs on the next
    /// registration, which is later than both.
    completion_announced: bool,
    /// What the two sides announced about codes on this flow, once
    /// anything here has been in a position to see it.
    ///
    /// # Why this is remembered rather than asked for
    ///
    /// Upstream carries `our_methods` and `their_methods` on
    /// `VerificationRequestState::Ready` and **on no other state**. The
    /// moment a flow becomes a code or a comparison it is `Transitioned`,
    /// which carries the verification and the other device and neither list
    /// (`verification/requests.rs:68-113`). The negotiation is still what
    /// decides whether a code is possible: upstream keeps reading the two
    /// lists off the `Ready` it stored inside the transition
    /// (`verification/requests.rs:995`), it just never shows them again.
    ///
    /// So a flow that has moved on could be asked "why is there no code?"
    /// and had no way to answer, and [`why_no_code`] answered it with
    /// [`MachineError::WrongStage`]: a stage complaint for a question about
    /// methods. That is the failure a person met on hardware. This field is
    /// the answer being kept while it is still visible.
    ///
    /// `None` until something looks at this flow while its request is
    /// `Ready`, which every call in this module does through
    /// [`handles`]: [`flow_stage`], [`read_code`], [`accept_flow`] and the
    /// rest all pass through [`cached`] or [`register`], and both stamp it.
    /// A `None` that survives is a flow nothing ever looked at before it
    /// transitioned, and [`why_no_code`] says less about such a flow rather
    /// than guessing.
    negotiation: Option<CodeNegotiation>,
    /// Whether the key query this flow's completion owes has been queued.
    ///
    /// [`completion_announced`](FlowRecord::completion_announced)'s sibling,
    /// and deliberately not the same flag, because the two passes that set
    /// them do not run under the same condition. [`announce_state_changes`]
    /// returns before it touches anything when no observer is registered;
    /// [`queue_peer_key_queries`] runs on every sync whether or not anybody
    /// is listening. Sharing one flag would mean a product that never
    /// subscribes never queued the query, and its answer about the person it
    /// had just verified would stay wrong for the life of the process.
    key_query_queued: bool,
}

impl FlowRecord {
    /// A flow that began with an `m.key.verification.request`.
    fn from_request(request: VerificationRequest) -> Self {
        FlowRecord {
            request: Some(request),
            comparison: None,
            code: None,
            negotiation: None,
            completion_announced: false,
            key_query_queued: false,
        }
    }

    /// A flow that began as a bare `m.key.verification.start`, registered
    /// with the comparison it produced.
    ///
    /// These two constructors are the only way a record is built, and
    /// between them they keep this module's one structural invariant:
    /// **every record holds at least one handle.** Neither the request nor
    /// the comparison field is ever set back to `None` afterwards, so a
    /// record keeps whichever it was built with for the life of the entry,
    /// and every function below can say truthfully which shape it is
    /// looking at.
    ///
    /// This said "neither field", which was a two-way word over a two-field
    /// struct and stopped being one when `code` was added beside them.
    /// `code` is a cache filled in later and is deliberately outside the
    /// invariant, as its own field doc says; the invariant is over the two
    /// named here and nothing else.
    fn from_comparison(comparison: Sas) -> Self {
        FlowRecord {
            request: None,
            comparison: Some(comparison),
            code: None,
            negotiation: None,
            completion_announced: false,
            key_query_queued: false,
        }
    }
}

/// Process-wide registry of the flows this library is taking part in.
///
/// A `std::sync::Mutex`, not `tokio::sync::Mutex`, and for the same reason
/// `session.rs`'s request registry is: every critical section below is a
/// plain synchronous map operation with no `.await` inside it. The handles
/// are cloned out from under the lock and the slow, fallible work is done
/// on the clones, which is safe because a clone and its original share one
/// observable state -- that is the property this whole module rests on.
static FLOWS: StdMutex<BTreeMap<String, FlowRecord>> = StdMutex::new(BTreeMap::new());

/// Empties the registry, so a test that registered a flow does not leave a
/// handle -- and through it an `Arc` on the crypto store -- alive past the
/// machine it belongs to. Called from `machine::reset_for_test`, and called
/// there *before* the store is dropped, for the reason that function's own
/// comment gives.
#[cfg(test)]
pub(crate) fn reset_flows_for_test() {
    FLOWS
        .lock()
        .expect("verification registry poisoned")
        .clear();
}

#[cfg(test)]
fn flow_count() -> usize {
    FLOWS.lock().expect("verification registry poisoned").len()
}

/// Errors must not carry an identifier or key material, so an upstream
/// store failure reports its shape and nothing else -- the same rule, and
/// the same fixed string, as `machine.rs`'s `store_error_detail`.
fn store_failed() -> MachineError {
    MachineError::Store {
        detail: "the crypto store could not be opened".to_string(),
    }
}

/// The handles for one flow, cloned out of the registry.
///
/// Cloned, not borrowed: two of the calls below are `async` and must not
/// hold a lock across an `.await`. A cloned handle is not a snapshot -- it
/// observes the same state the registry's copy does -- so nothing read
/// through one of these is stale by the time it is read.
struct Handles {
    /// `None` exactly when the flow began as a bare
    /// `m.key.verification.start` -- see [`FlowRecord::request`].
    request: Option<VerificationRequest>,
    comparison: Option<Sas>,
    /// `Some` once the flow has become a scanned code -- see
    /// [`FlowRecord::code`].
    code: Option<QrVerification>,
    /// What the two sides settled about codes on this flow, if anything here
    /// saw it settled. See [`FlowRecord::negotiation`].
    negotiation: Option<CodeNegotiation>,
}

/// Upstream's own condition for whether a code can exist on a flow, split
/// into the two halves it is made of, so a refusal can name which one
/// failed.
///
/// `generate_qr_code` bails unless `our_methods` contains
/// `m.qr_code.show.v1` **and** `their_methods` contains `m.qr_code.scan.v1`
/// (`verification/requests.rs:1222-1228`). Folded together those two are one
/// `Ok(None)` and one sentence; kept apart they are two different things to
/// tell a product, with opposite remedies:
///
/// * the first is this product's own answer to [`offer_codes`], fixed in one
///   line before the next flow;
/// * the second is the far side's, and nothing on this device can change it.
///
/// [`MachineError::CodeNotOffered`] used to carry both and told a caller to
/// work out which from the switch it had set. That advice was sound while
/// the switch was one boolean and stopped being sound the moment it became
/// two facts: a product that offered showing alone, correctly, is exactly
/// the product that would be told to go and check whether it had asked for
/// codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CodeNegotiation {
    /// This side announced `m.qr_code.show.v1` on this flow.
    we_announced_showing: bool,
    /// The other side announced `m.qr_code.scan.v1` on this flow.
    they_announced_scanning: bool,
}

/// Fills in a record's code negotiation while upstream is still willing to
/// say what it was, and returns it.
///
/// [`comparison_of`]'s and [`code_of`]'s sibling in shape and in reason: the
/// answer exists on the request for a while and then stops existing, so it
/// is read when it is there rather than asked for when it is needed.
///
/// **Written once and never revised.** The two lists are fixed when the flow
/// becomes ready and no message in the protocol changes them, so a second
/// reading could only ever agree; and a flow that transitioned between two
/// calls would otherwise have its remembered answer overwritten with
/// nothing.
fn negotiation_of(record: &mut FlowRecord) -> Option<CodeNegotiation> {
    if record.negotiation.is_none() {
        if let Some(VerificationRequestState::Ready {
            our_methods,
            their_methods,
            ..
        }) = record.request.as_ref().map(VerificationRequest::state)
        {
            record.negotiation = Some(CodeNegotiation {
                we_announced_showing: our_methods.contains(&VerificationMethod::QrCodeShowV1),
                they_announced_scanning: their_methods.contains(&VerificationMethod::QrCodeScanV1),
            });
        }
    }
    record.negotiation
}

/// Fills in a record's comparison handle if the flow has become one, and
/// returns it.
///
/// Read from the request handle rather than looked up in upstream's map:
/// the request carries the comparison once one has started, on both the
/// side that started it and the side that received the start, and unlike
/// the map it is not garbage-collected out from under us.
fn comparison_of(record: &mut FlowRecord) -> Option<&Sas> {
    if record.comparison.is_none() {
        // Only a request-shaped record can reach here with nothing cached:
        // a request-less one is registered with its comparison already in
        // hand and never loses it.
        if let Some(VerificationRequestState::Transitioned { verification, .. }) =
            record.request.as_ref().map(VerificationRequest::state)
        {
            record.comparison = verification.sas_v1().map(|boxed| *boxed);
        }
    }
    record.comparison.as_ref()
}

/// Fills in a record's code handle if the flow has become one, and returns
/// it.
///
/// [`comparison_of`]'s sibling, reading the same place for the other kind of
/// handle: upstream's `Verification` is one enum over both, and a
/// transitioned request carries whichever the flow became.
///
/// **It is what [`stage_of`] reads for a flow that became a code**, which it
/// did not always: until [`FlowStage::CodeScanned`] existed there was no
/// stage a scanned code could honestly be reported as, so such a flow said
/// [`FlowStage::Started`] for as long as the request said `Transitioned` --
/// from the moment a code was built until the moment the flow finished.
/// Reading the handle before there was a vocabulary for what it says would
/// have replaced one wrong answer with another; the design's section 5 is
/// where the vocabulary was granted.
///
/// # Why the cache is enough on its own
///
/// Filled from a `Transitioned` request, and a finished flow's request is
/// `Done` rather than `Transitioned`, so this cannot fill it at the moment
/// a completion is collected. It does not have to: a code only exists on
/// this side because [`read_code`] or [`submit_scanned_code`] built one,
/// and both call [`remember_code`] before they return. There is no flow
/// shape that reaches `Done` as a code without one of those two having run
/// here first.
fn code_of(record: &mut FlowRecord) -> Option<&QrVerification> {
    if record.code.is_none() {
        if let Some(VerificationRequestState::Transitioned { verification, .. }) =
            record.request.as_ref().map(VerificationRequest::state)
        {
            record.code = verification.qr_v1().map(|boxed| *boxed);
        }
    }
    record.code.as_ref()
}

fn stage_of(record: &mut FlowRecord) -> FlowStage {
    if let Some(comparison) = comparison_of(record) {
        return stage_of_comparison(comparison);
    }
    // The comparison first and the code second, and never both: upstream's
    // `Verification` is one enum over the two, so a transitioned request
    // carries whichever the flow became and the second lookup returns
    // `None` whenever the first returned `Some`. The order is therefore not
    // a precedence rule to reason about; it is written this way round so
    // the flow shape that predates codes is read by the same line it always
    // was.
    if let Some(code) = code_of(record) {
        return stage_of_code(code);
    }
    let Some(request) = record.request.as_ref() else {
        // Neither handle. Not reachable through either of `FlowRecord`'s
        // two constructors -- one supplies a request, the other supplies a
        // comparison, and nothing sets either back to `None` -- so this
        // arm keeps the function total rather than describing a flow
        // anything can produce. `Cancelled` is the one stage that cannot
        // mislead a caller into acting on it: it says "there is nothing
        // further to do here", which is exactly true of a flow with no
        // handle behind it. Named rather than left to a fallthrough, which
        // is the class this crate closed in `ecfd293`.
        return FlowStage::Cancelled;
    };
    // Exhaustive, no wildcard, like every other upstream match in this
    // crate: a state upstream adds later must fail this build rather than
    // be reported as whichever stage a wildcard happened to name.
    match request.state() {
        VerificationRequestState::Created { .. } | VerificationRequestState::Requested { .. } => {
            FlowStage::Requested
        }
        VerificationRequestState::Ready { .. } => FlowStage::Ready,
        // Unreachable: one of the two lookups above returns `Some` for
        // exactly this state -- a transitioned request carries either a
        // comparison or a code -- and returned before this match if it did.
        // Mapped truthfully anyway rather than left to a wildcard.
        VerificationRequestState::Transitioned { .. } => FlowStage::Started,
        VerificationRequestState::Done => FlowStage::Done,
        VerificationRequestState::Cancelled(_) => FlowStage::Cancelled,
    }
}

fn stage_of_comparison(comparison: &Sas) -> FlowStage {
    match comparison.state() {
        // Three upstream states, one stage: the comparison exists and has
        // nothing to show yet. Upstream's own public projection already
        // folds three more of its internal states into `Accepted` here.
        SasState::Created { .. } | SasState::Started { .. } | SasState::Accepted { .. } => {
            FlowStage::Started
        }
        SasState::KeysExchanged { .. } => FlowStage::KeysExchanged,
        SasState::Confirmed => FlowStage::Confirmed,
        SasState::Done { .. } => FlowStage::Done,
        SasState::Cancelled(_) => FlowStage::Cancelled,
    }
}

/// The stage a flow that became a code is at.
///
/// [`stage_of_comparison`]'s sibling, and the two answer the same question
/// about the two shapes a flow can take. Where they agree they say the same
/// thing on purpose: a person is being asked to wait, or to act, or told it
/// is over, and which of upstream's nineteen states produced that is not a
/// distinction a product should be invited to branch on.
///
/// **`Reciprocated` and `Confirmed` are one stage here, and that is not a
/// fold made to save a variant.** They are the same side of the same
/// situation: this device scanned and said so, or this device was scanned
/// and said so. Either way it has done everything asked of it and the other
/// side has not finished, which is precisely what [`FlowStage::Confirmed`]
/// says for a comparison.
///
/// Exhaustive, no wildcard, like every other upstream match in this crate.
fn stage_of_code(code: &QrVerification) -> FlowStage {
    match code.state() {
        // A code exists and nobody has read it off the screen yet. Nothing
        // is waiting on this side, which is what `Started` means.
        QrVerificationState::Started => FlowStage::Started,
        // The one moment a code flow asks a person anything.
        QrVerificationState::Scanned => FlowStage::CodeScanned,
        QrVerificationState::Confirmed | QrVerificationState::Reciprocated => FlowStage::Confirmed,
        QrVerificationState::Done { .. } => FlowStage::Done,
        QrVerificationState::Cancelled(_) => FlowStage::Cancelled,
    }
}

/// The stage a set of already-fetched handles describes.
///
/// Separate from [`stage_of`], which takes the registry's own record and can
/// fill its comparison cache in passing; this one reads handles that have
/// already been cloned out, which is what every public call below holds.
fn stage_from(handles: &Handles) -> FlowStage {
    let mut record = FlowRecord {
        request: handles.request.clone(),
        comparison: handles.comparison.clone(),
        code: handles.code.clone(),
        negotiation: handles.negotiation,
        completion_announced: false,
        key_query_queued: false,
    };
    stage_of(&mut record)
}

fn is_finished(stage: FlowStage) -> bool {
    matches!(stage, FlowStage::Done | FlowStage::Cancelled)
}

/// Drops every flow that is over, except one whose completion nobody has
/// collected yet.
///
/// Upstream's own rule, `retain(|_, v| !(v.is_done() || v.is_cancelled()))`
/// from `VerificationMachine::garbage_collect`, run here at the one moment
/// this registry can grow rather than on every sync. See the module's own
/// header for what that costs a caller and why it is bounded.
///
/// **Over** is two questions, not one: the stage a product would be told, and
/// whether the request behind the record has reached a state nothing moves it
/// out of. [`request_is_over`] is the second, and it says why one question is
/// not enough.
///
/// # The one exception, and why it does not reopen the growth question
///
/// Sweeping is not serialised against announcing. A comparison reaches
/// `Done` inside `receive_sync_changes`, and `announce_state_changes` runs
/// after that call has released the machine lock; any concurrent call that
/// reaches [`handles`] -> [`register`] in that window sweeps, and an
/// unconditional sweep would drop the record before
/// [`take_pending_completions`] had ever seen it. The `TrustChanged` would
/// be lost with nothing reporting it.
///
/// So a `Done` record whose completion has not been taken survives one more
/// pass. Three properties keep that from becoming unbounded retention:
///
/// * only `Done` is exempt. A `Cancelled` flow has no completion to
///   announce and is always swept, which is what
///   `a_finished_flow_is_not_retained_forever` measures.
/// * the exemption ends at the next sync. `take_pending_completions` marks
///   every `Done` record it inspects, whether or not it produced a signal,
///   so the record is sweepable from then on.
/// * with no observer registered, nothing will ever announce, so nothing is
///   exempt on that ground.
///
/// # The second exemption, which is not gated on an observer
///
/// [`queue_peer_key_queries`] loses the same race for the same reason, and
/// what it loses is not a signal but the answer to *is this person
/// verified?* It runs on every sync whether or not anybody has subscribed,
/// so its exemption cannot be gated the way the first one is, and a process
/// that never subscribes therefore no longer has exactly the retention it
/// had before this existed.
///
/// **The widening is one sync wide and no wider.** A record can only reach
/// `Done` inside `receive_sync_changes`, and `queue_peer_key_queries` runs
/// at the end of that same call and marks every `Done` record it inspects.
/// So by the time a sync returns there is no unmarked `Done` record left,
/// and the set this exemption can hold back is bounded by the flows that
/// finished during the sync currently running.
///
/// **And nothing in this repository measures it, which is said here rather
/// than left to be assumed.** Reverting this clause to the single-condition
/// rule it replaced leaves the whole suite green, which was watched rather
/// than guessed at. The clause is unobservable outside the interleaving it
/// exists for: a `register` from another thread landing between
/// `receive_sync_changes` releasing the machine lock and
/// `queue_peer_key_queries` taking the registry lock. That cannot be
/// scheduled from a test here, and it cannot be closed by moving the pass
/// inside the machine lock either, because `register` is itself called after
/// its own `with_machine` has returned. So this is reasoning, not a
/// measurement, and it is kept because the thing it protects is the answer
/// to *is this person verified?* rather than a signal a caller can go and
/// read again.
fn release_finished(flows: &mut BTreeMap<String, FlowRecord>) {
    // Read once, outside the loop: it takes the observer registry's read
    // lock, and this already holds the flow registry's. Nothing anywhere
    // takes those two in the other order.
    let something_will_announce = crate::observer::crypto_observer().is_some();
    flows.retain(|_, record| {
        let stage = stage_of(record);
        if !is_finished(stage) && !request_is_over(record) {
            return true;
        }
        if stage != FlowStage::Done {
            return false;
        }
        (!record.completion_announced && something_will_announce) || !record.key_query_queued
    });
}

/// Whether the request behind a record has reached a state nothing moves it
/// out of.
///
/// # Why the stage is not enough on its own
///
/// The stage is what a *product* is told, and it is read off whichever
/// handle the flow became: [`stage_of`] consults the comparison, then the
/// code, and only then the request. That is right for a caller and wrong for
/// eviction, because **upstream does not advance the two together.** One
/// `m.key.verification.done` reaches both
/// (`verification/machine.rs:501-527`), but
/// `VerificationRequest::receive_done` moves `Transitioned` to `Done`
/// unconditionally (`verification/requests.rs:934-940`) while
/// `QrVerification::receive_done` moves only a code that is `Confirmed` or
/// `Reciprocated`, and leaves a `Created` or `Scanned` one exactly where it
/// is (`verification/qrcode.rs:392-440`). `Sas` has the same shape.
///
/// So a peer that scans this device's code and then declares itself done,
/// without waiting for the person here to answer, leaves the request
/// finished and the code at `Scanned` for ever. Reading the stage alone,
/// that record is `CodeScanned`, is never finished, and is never swept: one
/// entry per such flow, for the life of the process, which is exactly the
/// unbounded growth this whole sweep exists to prevent.
///
/// **This is not a hazard codes invented.** The same hole was open for a
/// comparison whose peer sent `done` before the strings were confirmed, and
/// it was open before this milestone; reading the code handle is what made
/// it reachable by an ordinary flow shape and therefore what made it worth
/// finding. Asking both questions closes it for both shapes.
///
/// # What that costs a caller, which is nothing
///
/// A record retired this way is not reported differently. It is dropped from
/// the registry, and the next call naming it rebuilds from upstream, finds a
/// request that is over, and answers [`MachineError::UnknownFlow`] -- which
/// is what the caller was already told about any flow that had finished.
/// Nothing here reports `Done` for a flow that did not finish: the stage a
/// product reads is still the code's own, right up to the sweep.
///
/// # What measures it
///
/// Two assertions, both in
/// `another_user_verifies_by_scanning_a_code_this_library_showed` in
/// `tests/qr_cross_user.rs`, because both need a flow that really ran:
/// *"registering another flow must sweep the one that finished by
/// scanning"* for the ordinary shape, and *"a flow whose request is over
/// must be swept even though its code never finished"* for this one. The
/// second fails without the second question above, reporting `CodeScanned`
/// where it expects no flow at all.
///
/// The comparison side is measured by
/// `a_finished_flow_is_not_retained_forever` in `tests/sas_two_party.rs`,
/// which counts what the library still answers for after one cycle against
/// after three.
fn request_is_over(record: &FlowRecord) -> bool {
    matches!(
        record.request.as_ref().map(VerificationRequest::state),
        Some(VerificationRequestState::Done | VerificationRequestState::Cancelled(_))
    )
}

fn cached(flow_id: &str) -> Option<Handles> {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    let record = flows.get_mut(flow_id)?;
    let comparison = comparison_of(record).cloned();
    let code = code_of(record).cloned();
    let negotiation = negotiation_of(record);
    Some(Handles {
        request: record.request.clone(),
        comparison,
        code,
        negotiation,
    })
}

fn register(flow_id: &str, record: FlowRecord) -> Handles {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    release_finished(&mut flows);
    let record = flows.entry(flow_id.to_string()).or_insert(record);
    let comparison = comparison_of(record).cloned();
    let code = code_of(record).cloned();
    let negotiation = negotiation_of(record);
    Handles {
        request: record.request.clone(),
        comparison,
        code,
        negotiation,
    }
}

/// The identifier upstream itself gives the flow behind a record.
///
/// Read back off the handle rather than taken from whatever string the
/// caller passed, so the registry is keyed by exactly what upstream keys
/// by. `None` only for a record holding neither handle, which
/// [`FlowRecord`]'s two constructors cannot produce.
fn upstream_flow_id(record: &FlowRecord) -> Option<String> {
    if let Some(request) = &record.request {
        return Some(request.flow_id().as_str().to_string());
    }
    record
        .comparison
        .as_ref()
        .map(|comparison| comparison.flow_id().as_str().to_string())
}

/// Registers `request` under `flow_id` if the registry does not already
/// hold that flow, and reports whether it did.
///
/// Separate from [`register`] because the announcement path needs the
/// insertion and the "was it new?" question answered under one lock. Split
/// into a `contains_key` and a `register`, an inbound flow could be
/// announced twice by two syncs that interleaved between them.
///
/// Sweeps before it asks, which is [`register`]'s order rather than the
/// reverse. The two disagreed until a review noticed: asking first meant a
/// finished record still sitting in the registry would refuse an identifier
/// that reused its name. Matrix transaction ids are not reused, so nothing
/// observable changes -- but two functions doing the same two things in
/// opposite orders is a question a reader has to answer, and it costs
/// nothing not to ask it.
fn register_if_absent(flow_id: &str, record: FlowRecord) -> bool {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    release_finished(&mut flows);
    if flows.contains_key(flow_id) {
        return false;
    }
    flows.insert(flow_id.to_string(), record);
    true
}

/// Releases a flow the announcement pass registered and could not
/// announce, so the next pass can find it again.
///
/// The exact undo of [`register_if_absent`]'s insertion, and only legal
/// against a flow this same pass inserted -- see [`announce`], which is the
/// only caller and the only place that knows which those are. Nothing else
/// may call it: releasing a flow whose identifier a caller already holds
/// would take away a live verification and report nothing.
fn forget_flow(flow_id: &str) {
    FLOWS
        .lock()
        .expect("verification registry poisoned")
        .remove(flow_id);
}

/// Records a comparison handle against a flow already in the registry.
///
/// Only ever called with the handle upstream just produced for that flow.
/// A miss means the registry released the flow between this call and the
/// one that fetched its handles, which another thread registering a flow in
/// that window can cause -- registering is what sweeps, and nothing holds a
/// lock across the two. Ignored rather than reported: there is no caller
/// mistake to report, the cache is an optimisation, and the next call
/// recovers the same handle from the request's own state.
fn remember_comparison(flow_id: &str, comparison: Sas) {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    if let Some(record) = flows.get_mut(flow_id) {
        record.comparison = Some(comparison);
    }
}

/// Records a code handle against a flow already in the registry.
///
/// [`remember_comparison`]'s sibling, with that function's own reasoning
/// about a miss unchanged: the cache is an optimisation, a miss means the
/// registry released the flow in the window between two lock acquisitions,
/// and the next call recovers the same handle from the request's own state.
fn remember_code(flow_id: &str, code: QrVerification) {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    if let Some(record) = flows.get_mut(flow_id) {
        record.code = Some(code);
    }
}

/// The handles for `flow`, from the registry or, failing that, from
/// upstream.
///
/// The second half is what lets this library answer a flow the *other* side
/// started. Nothing local ever registered it, so the identifier misses; it
/// is found by asking upstream about each user this machine tracks, which
/// is the set a verification counterparty is necessarily in (a device has
/// to have been queried before it can be verified).
///
/// # A request first, and a comparison only where there is no request
///
/// Upstream keeps requests and comparisons in two separate maps, and a
/// request-shaped flow whose comparison has started is in **both**. The
/// request is the handle that carries the comparison along with it and
/// that still knows the flow began as a request, so it is the one this
/// registers; the comparison map is reached only for a flow that is in no
/// other map, one that began as a bare `m.key.verification.start`.
///
/// **Nothing observable turns on that ordering today, and it is worth
/// saying so rather than implying otherwise.** A flow that has both
/// handles is always already in this registry: the peer cannot open a
/// comparison until this side has sent `m.key.verification.ready`, the
/// only call that sends one is [`accept_flow`], and that call registers
/// the flow before it sends anything. So this lookup never meets a flow
/// with both, and reversing the two arms changes no answer any call in
/// this module gives -- measured, not assumed. The ordering is here so
/// that a record is built from the handle that describes how the flow
/// began, which is the thing a later reader has no way to recover.
///
/// A flow found either way is registered only if it is still live. Adopting
/// a finished one would undo the eviction rule -- an identifier released by
/// `release_finished` would be picked straight back up from upstream's map
/// on the next mention of it, and the registry would grow by one entry per
/// verification the process ever ran.
async fn handles(flow: &FlowId) -> Result<Handles, MachineError> {
    if let Some(handles) = cached(&flow.0) {
        return Ok(handles);
    }

    let flow_id = flow.0.clone();
    let found = with_machine(move |machine| {
        Box::pin(async move {
            let tracked = machine
                .tracked_users()
                .await
                .map_err(|_upstream| store_failed())?;
            if let Some(request) = tracked
                .iter()
                .find_map(|user| machine.get_verification_request(user, &flow_id))
            {
                return Ok(Some(FlowRecord::from_request(request)));
            }
            Ok(tracked
                .iter()
                .find_map(|user| machine.get_verification(user, &flow_id))
                .and_then(Verification::sas_v1)
                .map(|comparison| FlowRecord::from_comparison(*comparison)))
        })
    })
    .await??;

    let mut record = found.ok_or(MachineError::UnknownFlow)?;
    if is_finished(stage_of(&mut record)) {
        return Err(MachineError::UnknownFlow);
    }
    let flow_id = upstream_flow_id(&record).ok_or(MachineError::UnknownFlow)?;

    Ok(register(&flow_id, record))
}

/// Hands one request upstream produced to the outbound pump.
///
/// Infallible by construction: upstream's own `From` impls carry both
/// shapes a verification can produce into the same request type the pump
/// already knows how to describe, id and all, so there is no conversion
/// here that could fail and no id for this module to mint.
fn queue(request: impl Into<UpstreamOutgoingRequest>) {
    crate::session::queue_action_request(request.into());
}

/// Refuses a verification flow with **our own account** until this library
/// can say what identity that account has.
///
/// # One decision, three doors, and why it is not on the flow's other calls
///
/// Completing a self-verification signs another of our devices with **this**
/// device's self-signing key and asks the account's other devices for its
/// cross-signing seeds, both under whatever identity this store holds. That
/// is a property of the flow, so every call that can *open* one reads this:
/// [`request_self_flow`], [`accept_flow`], and [`request_flow`] when it is
/// handed our own identifiers. `begin_comparison` and `confirm_flow` do not,
/// because neither can be reached without one of those three having been
/// served first, and a check there would refuse a user after they had already
/// compared the string.
///
/// **The third door read nothing at all.** `request_flow(our own account, our
/// own other device)` ran a self-verification to `Done` and queued a
/// signature upload on a store whose identity the server had never been asked
/// about, while five other calls refused in the same instant. It was reached
/// through the public surface all the way up, and every existing call site
/// passes a peer, so closing it costs nothing that was working.
///
/// # Both conditions, and what each costs
///
/// **Never asked** (`account_keys_answered` false): the identity this store
/// holds may be one the account replaced long ago, so signing under it is
/// signing under nothing. The cost is one pump, and the refusal queues the
/// query itself.
///
/// **Asked, but our own publication is unconfirmed**
/// (`identity_publication_pending`): the identity exists on this device and
/// nowhere else that we know of, so a device that verifies against it is
/// verifying against something the account may never have. The cost here is
/// real and is the reason it is stated rather than assumed: a device that
/// minted and published, and is waiting only for the confirming answer, is
/// refused a self-verification it could have completed correctly. It is one
/// pump away from being served, and the alternative is a verification whose
/// signature may reference a key no other client can resolve.
///
/// **Another user's flow reads neither**, and that is measured rather than
/// argued: verifying somebody else needs nothing of our own identity. Taking
/// the scope off this helper reddens four targets, and not one of them is
/// about what identity this account has: `tests/sas_two_party.rs`,
/// `tests/verified_sender.rs`, `matrix-crypto-ffi`'s `tests/delegate_order.rs`
/// and this module's own unit tests.
///
/// How many individual tests go red is deliberately not stated here.
/// `sas_two_party.rs`'s own header says why a count in prose has no way to be
/// wrong out loud, and this particular count is not even stable: nine to
/// thirteen of that file's fourteen across repeated runs of one build,
/// because those tests share a machine and go red in whatever order the
/// refusal happens to reach them. This sentence said "11 of 13" until the
/// file gained a fourteenth test on a branch that could not see it.
///
/// # Where each arm is held, since one of them was held nowhere
///
/// Two conditions and three doors is six claims, and they are not covered by
/// one file each. Named here so that deleting either arm reddens something
/// findable rather than nothing:
///
/// * never asked, outgoing: `tests/self_verification_stale_identity.rs`
/// * never asked, incoming: `tests/self_verification_inbound_stale_identity.rs`
/// * publication unconfirmed, outgoing:
///   `tests/identity_publication_interrupted.rs`, which asserts it at both
///   outgoing doors and at the two recovery calls beside them
/// * publication unconfirmed, incoming:
///   `tests/self_verification_inbound_unconfirmed_identity.rs`
///
/// The last of those was written after the fact. The tenth round added the
/// second arm to this one helper, which carried it to all three doors at
/// once, and only the outgoing pair was ever measured: deleting the arm left
/// both files that drive `accept_flow` green. What found it was not a review
/// but a merge, when three M5 tests that mint an identity and never confirm
/// its publication met this arm for the first time.
async fn refuse_own_flow_until_the_identity_is_settled(
    other_user: &matrix_sdk_common::ruma::UserId,
) -> Result<(), MachineError> {
    let ours =
        with_machine(|machine| Box::pin(async move { machine.user_id().to_owned() })).await?;
    if other_user != ours {
        return Ok(());
    }
    if !crate::session::account_keys_answered() {
        // Queued *by* the refusal, so it is recoverable rather than a dead
        // end, for the reason `signing::bootstrap_identity` states in full.
        with_machine(|machine| {
            Box::pin(async move {
                let (id, request) =
                    machine.query_keys_for_users(std::iter::once(machine.user_id()));
                crate::session::queue_account_key_query(id, request);
            })
        })
        .await?;
        return Err(MachineError::AccountKeysNotFetched);
    }
    let pending = with_machine(|machine| {
        Box::pin(async move { crate::signing::identity_is_unpublished(machine).await })
    })
    .await?;
    if pending {
        return Err(MachineError::IdentityNotKnown);
    }
    Ok(())
}

/// Asks a device to verify itself against this one.
///
/// Advertises [`announced_methods`] rather than upstream's default list, for
/// the reason that function gives: taking a default is letting somebody
/// else decide what this library claims. The reason used to be that
/// advertising a method this library cannot carry out is a claim the far
/// side may act on, and it has moved rather than gone: this library can
/// carry out both methods now, and what it may not claim is that a
/// *product* can point a camera at a screen. Whether a scannable code is
/// among them is [`offer_codes`]'s answer, and it claims nothing until a
/// product says otherwise.
pub async fn request_flow(user_id: &str, device_id: &str) -> Result<FlowId, MachineError> {
    // Owned before the closure, not borrowed, for the reason
    // `identity.rs` documents: `with_machine` requires a `'static` closure.
    let user_id = user_id.to_owned();
    let device_id = device_id.to_owned();

    // **Parsed and checked before the machine is taken.** This call is the
    // third door into a self-verification and it read nothing at all: handed
    // this account's own identifiers it ran one to `Done` and signed another
    // device under an identity the server had never been asked about. The
    // identifier errors below still come first for anybody else's flow,
    // because they are about the arguments rather than about us.
    {
        let ours: OwnedUserId = user_id
            .parse()
            .map_err(|_| MachineError::MalformedIdentifier {
                detail: "user id".to_string(),
            })?;
        refuse_own_flow_until_the_identity_is_settled(&ours).await?;
    }

    let (flow_id, request, outgoing) = with_machine(move |machine| {
        Box::pin(async move {
            let user: OwnedUserId =
                user_id
                    .parse()
                    .map_err(|_| MachineError::MalformedIdentifier {
                        detail: "user id".to_string(),
                    })?;
            if device_id.is_empty() {
                return Err(MachineError::MalformedIdentifier {
                    detail: "device id".to_string(),
                });
            }
            let device: OwnedDeviceId = device_id.as_str().into();

            // `None`, not a timeout: waiting here would depend on the
            // caller draining the pump from another task while this call
            // holds the machine lock, which it cannot do. A caller that
            // does not know the device yet has to query for it and try
            // again -- reported as a named condition rather than as a wait
            // that quietly expires.
            let device = machine
                .get_device(&user, &device, None)
                .await
                .map_err(|_upstream| store_failed())?
                .ok_or(MachineError::UnknownDevice)?;

            let (request, outgoing) =
                device.request_verification_with_methods(announced_methods().to_vec());
            Ok((request.flow_id().as_str().to_string(), request, outgoing))
        })
    })
    .await??;

    register(&flow_id, FlowRecord::from_request(request));
    queue(outgoing);

    Ok(FlowId(flow_id))
}

/// Asks this account's *other* devices to verify this one, so that this
/// device can join the signing identity the account already has.
///
/// # Why this is not [`request_flow`] with our own identifiers
///
/// Three differences, all of them upstream's and none of them cosmetic.
///
/// **It names no device.** [`request_flow`] asks one device, chosen by the
/// caller, through `Device::request_verification_with_methods`. This asks
/// through `OwnUserIdentity::request_verification_with_methods`, which fans
/// the invitation out to *every* other device of ours at once and lets
/// whichever is in front of a person answer first. A new login normally has
/// no idea which of its owner's devices is to hand, so choosing one is a
/// question it cannot answer; the ones that do not answer see the flow
/// cancelled when one does.
///
/// **The signature it ends in is made with a different key.** Upstream's
/// `mark_as_done` signs a device with our *self-signing* key when the device
/// is ours, and another user's master key with our *user-signing* key when
/// it is not (`verification/mod.rs:513`, `:549`). Both sides of a
/// self-verification take the first branch, and only the side that already
/// holds the private keys can act on it: the device with the identity signs
/// the new one, and the new one finds it has nothing to sign with and
/// carries on.
///
/// **It asks for the account's secrets, which verifying somebody else never
/// does.** Marking our own identity verified sets upstream's
/// `should_request_secrets`, which asks our other devices for whatever
/// cross-signing seeds this device lacks. Those become ordinary to-device
/// requests that [`crate::take_outgoing_requests`] hands out, and the reply
/// arrives encrypted inside a later [`crate::receive_sync_changes`], where
/// upstream imports it if and only if the sending device is one of ours and
/// is verified. **Nothing returns to the caller when that lands.**
/// [`crate::identity_status`]' `private_keys_held` is the durable answer,
/// and the `trust_changed` signal on [`crate::CryptoSignal`] is how a caller
/// learns of it without asking repeatedly.
///
/// # This is not a bootstrap, and must never become one
///
/// A device that does not hold the account's private signing keys **joins**
/// the identity the account already has. [`crate::bootstrap_identity`]
/// refuses such a device with [`MachineError::IdentityAlreadyExists`], and
/// that refusal is the one thing standing between an ordinary second login
/// and an account whose identity has been silently replaced, resetting the
/// trust of every device and every user who had verified the old one. This
/// call is the remedy that refusal points at; it is not a way around it.
///
/// # After it returns
///
/// The flow is driven exactly like [`request_flow`]'s, **by either method**.
///
/// By short string: pump, wait for [`FlowStage::Ready`],
/// [`begin_comparison`], read the string with [`read_material`], show it to
/// a person, and [`confirm_flow`] or [`cancel_flow`]. The person is
/// comparing two of their own screens rather than talking to somebody else,
/// which changes nothing about the calls.
///
/// By scanned code, if [`offer_codes`] said so: from the same
/// [`FlowStage::Ready`], [`read_code`] and [`confirm_scan`] on the side
/// showing, or [`submit_scanned_code`] on the side reading. **Two of the
/// three modes a code has are self modes and both start here**, so this
/// call is where they are reached from and this paragraph described only
/// the string until the sweep that is correcting it.
/// `tests/qr_self_new_login_shows.rs` drives this exact call and then
/// [`read_code`], touching none of the short-string calls above.
///
/// Showing a code to verify this account's own new login needs none of the
/// account's private signing keys, which is what makes it reachable from
/// the device that is joining rather than only from the one already
/// holding them.
///
/// # Refusals
///
/// [`MachineError::AccountKeysNotFetched`] means this process has not asked
/// the server about this account yet, so it cannot know whether the account
/// has an identity to join. **This call queues that key query before
/// returning the refusal**, exactly as [`crate::bootstrap_identity`] does and
/// for the same reason, so the remedy is the ordinary loop: drain the pump,
/// send, report sent, call this again.
///
/// It has to queue it itself, and this is not defensive. Upstream volunteers
/// an own-account key query only while the account is not yet tracked
/// ("We always want to track our own user",
/// `identities/manager.rs:836-852`), and `update_tracked_users` re-flags only
/// accounts it did not already know (`store/mod.rs:258-273`). So on any
/// relaunch of an existing store, and on any process that shared a key before
/// asking, nothing would ever volunteer the query and this refusal would be
/// permanent on this call. The one escape would be
/// [`crate::bootstrap_identity`], which is precisely the call a joining device
/// must not reach for. `tests/self_verification_recovery.rs` constructs that
/// state, which a fresh machine cannot.
///
/// [`MachineError::IdentityNotKnown`] means the server was asked and named
/// no identity for this account. There is nothing to join, and the answer is
/// [`crate::create_identity`] rather than a retry. It said
/// [`crate::bootstrap_identity`], which minted at that point and no longer
/// does; that call now reports this same refusal rather than answering it.
pub async fn request_self_flow() -> Result<FlowId, MachineError> {
    // The same decision the other two doors read, taken before the machine
    // is held. It gained a second arm in the tenth round: a publication this
    // device has not seen confirmed is an identity to sign under that the
    // account may never have, and the flow signs under it either way.
    let ours =
        with_machine(|machine| Box::pin(async move { machine.user_id().to_owned() })).await?;
    refuse_own_flow_until_the_identity_is_settled(&ours).await?;

    let (flow_id, request, outgoing) = with_machine(|machine| {
        Box::pin(async move {
            // **The gate first, and unconditionally.** It used to be read
            // from inside the identity-absent branch below, which meant a
            // store that already held an identity reached the verification
            // request having consulted no gate at all. That is the same
            // shape `recovery.rs`'s `restore` documents and repairs, and
            // this was its fourth instance: measured on a store holding a
            // *stale* identity, `bootstrap_identity`, `create_identity`,
            // `create_recovery` and `recover_identity` all refused while
            // this call was served and broadcast a verification invitation
            // to every other device of the account under that stale
            // identity. Three doc comments claimed this call carried the
            // gate, including the one that used to sit ten lines below, and
            // deleting the whole guard left the suite green.
            //
            // It is a write rather than a read, which is why the gate
            // belongs here: completing the flow signs the other device with
            // this device's self-signing key and asks the account's other
            // devices for the cross-signing seeds, both under whatever
            // identity this store holds.
            if !crate::session::account_keys_answered() {
                // Queued *by* the refusal, so the refusal is recoverable
                // rather than a dead end. The reasoning is
                // `signing::bootstrap_identity`'s, unchanged and not
                // repeated here: upstream will not volunteer this query for
                // an account it is already tracking, which is every relaunch
                // of an existing store. The same single slot, so a caller
                // that reached both calls sends one query rather than two.
                let (id, request) =
                    machine.query_keys_for_users(std::iter::once(machine.user_id()));
                crate::session::queue_account_key_query(id, request);
                return Err(MachineError::AccountKeysNotFetched);
            }

            // `None` as the timeout, not a duration, for the reason
            // `signing::read_status` gives at more length.
            let identity = machine
                .get_identity(machine.user_id(), None)
                .await
                .map_err(|_upstream| store_failed())?
                .and_then(|identity| identity.own());

            let Some(identity) = identity else {
                return Err(MachineError::IdentityNotKnown);
            };

            // [`announced_methods`], not upstream's default list, for
            // `request_flow`'s reason: what a flow announces is a claim the
            // far side may act on, and with codes it is a claim about the
            // product rather than about this library. This is the third of
            // the three call sites, and the one `qr_self_new_login_shows`
            // reads off the wire.
            let (request, outgoing) = identity
                .request_verification_with_methods(announced_methods().to_vec())
                .await
                .map_err(|_upstream| store_failed())?;
            Ok((request.flow_id().as_str().to_string(), request, outgoing))
        })
    })
    .await??;

    register(&flow_id, FlowRecord::from_request(request));
    queue(outgoing);

    Ok(FlowId(flow_id))
}

/// Agrees to whatever the other side is currently asking of this device.
///
/// # There are two things a peer can ask, and this call answers both
///
/// An `m.key.verification.request` asks *may we verify?*, and answering it
/// advertises [`announced_methods`], which is what the product asked to
/// take part in rather than everything this library can carry out, and
/// moves the flow to [`FlowStage::Ready`]. This is one of the three places
/// that list reaches the wire, and the one a peer opened, which is the
/// half of real usage no test drove until `tests/qr_announcement.rs`. An `m.key.verification.start` asks *here is the
/// comparison, will you take part?*, and answering **that** is an
/// `m.key.verification.accept` naming the protocols both sides support --
/// the message the peer waits for before it will send its key.
///
/// Which of the two a flow needs depends on how it arrived and on who
/// moved first, and a caller does not have to work that out:
///
/// * a flow that arrived as a bare `m.key.verification.start` has no
///   request and skipped `Ready` entirely, so one call answers the
///   comparison;
/// * a flow that arrived as a request needs one call to answer the request
///   -- and **a second one if the peer then opens the comparison**, which
///   either side may do. Upstream builds the comparison and sends nothing
///   (`verification/requests.rs:1366-1396`), so until this is called again
///   the peer is waiting on a message no other call in this module
///   produces. Before that second call existed the flow simply stopped
///   there: `flow_stage` read `Started` forever, no error was returned
///   anywhere, and the string was never produced. That is the shape of
///   failure this whole module is written against.
///
/// So the rule is one sentence -- *call this whenever the flow is waiting
/// on your agreement* -- and [`flow_stage`] says when: `Requested` and
/// `Started` are both states where the answer is yours to give. The
/// difference between the two shapes is only that a bare-start flow is
/// never `Requested`, and that [`begin_comparison`] has nothing to do on
/// one.
///
/// # A refusal is never a silent no-op
///
/// Both handles report "not in a state where this applies" by returning
/// `None`: `VerificationRequest::accept_with_methods` for anything but
/// `Requested` (accepting our own request, or one already answered,
/// cancelled or finished), `Sas::accept` for anything but
/// `SasState::Started` (a comparison already accepted, cancelled or
/// finished). Neither is an absence, and neither is treated as one: they
/// are folded into [`MachineError::WrongStage`], which is what a caller
/// gets for a flow that is not waiting on it. [`flow_stage`] separates
/// "the other side is ahead" from "this is over" for free.
pub async fn accept_flow(flow: &FlowId) -> Result<(), MachineError> {
    let handles = handles(flow).await?;

    // **The gate, scoped to the flows it belongs to.**
    //
    // `request_self_flow` was gated in the eighth round because completing a
    // self-verification signs another of our devices with *this* device's
    // self-signing key and asks the account's other devices for its
    // cross-signing seeds, both under whatever identity this store happens
    // to hold. That is a property of **the flow**, not of the call that
    // starts it, and either side may start one. Measured on the store
    // `tests/self_verification_stale_identity.rs` builds: five calls refused
    // and this one was served, ran the comparison to `Done`, and queued a
    // signature upload signing another device with a stale identity's
    // self-signing key, with the gate never consulted.
    //
    // **Unconditionally it would be wrong**, and that was measured too:
    // adding a bare `account_keys_answered()` check here reddens
    // `tests/sas_two_party.rs` and nothing else in the workspace, and that
    // file verifies another user. Verifying somebody else needs nothing of
    // our own identity, and that whole file runs with the gate shut on
    // purpose. The file rather than a number of its tests, for the reason
    // `refuse_own_flow_until_the_identity_is_settled` gives at more length.
    //
    // So the scope is the distinction `request_self_flow` and `request_flow`
    // already draw between themselves and nobody had written down here: this
    // gate applies when the counterparty is our own account, and to nothing
    // else. Read before any handle is answered, so a refusal sends nothing.
    let other_user = match (&handles.request, &handles.comparison) {
        (Some(request), _) => request.other_user().to_owned(),
        (None, Some(comparison)) => comparison.other_user_id().to_owned(),
        (None, None) => return Err(MachineError::WrongStage),
    };
    refuse_own_flow_until_the_identity_is_settled(&other_user).await?;

    let outgoing = match (&handles.request, &handles.comparison) {
        // The request while there is a request to answer, and the
        // comparison once there is not. Not a precedence between two ways
        // of doing the same thing: at most one of the two is ever waiting
        // on an answer, so this is a search for whichever it is.
        (Some(request), comparison) => request
            .accept_with_methods(announced_methods().to_vec())
            .or_else(|| comparison.as_ref().and_then(Sas::accept)),
        (None, Some(comparison)) => comparison.accept(),
        // Unreachable: `handles` returns a record built by one of
        // `FlowRecord`'s two constructors, each of which supplies a handle.
        // Mapped to the same error the two real arms produce rather than
        // left to a fallthrough that would report success.
        (None, None) => None,
    }
    .ok_or(MachineError::WrongStage)?;
    queue(outgoing);
    Ok(())
}

/// Starts the comparison itself, once both sides are ready.
///
/// Either side may call this, and only while the flow is at
/// [`FlowStage::Ready`]. Two sides calling it at the same moment is safe --
/// each has a ready flow when it calls, upstream settles which comparison
/// survives, and the loser's is dropped without disturbing the flow. What
/// is not safe, and is refused here, is the *same* side calling twice: by
/// the second call the flow is no longer ready, and the reason that has to
/// be an error rather than a second attempt is below.
///
/// **For whoever bridges this.** `WrongStage` here covers two conditions a
/// person needs told apart: "the other side started it, carry on and wait
/// for the string" and "this flow is over, start again". This is the one
/// place in this module those are folded, and folding them is deliberate --
/// both mean *this call* has nothing to do -- but a surface that shows a
/// user one sentence for both is showing the wrong one half the time.
/// [`flow_stage`] separates them for free: `Started` or later is the first,
/// `Cancelled` or `Done` is the second.
pub async fn begin_comparison(flow: &FlowId) -> Result<(), MachineError> {
    let handles = handles(flow).await?;

    // Rejected before upstream is asked, because upstream does not reject
    // it. `start_sas` on a flow that is already a comparison builds a
    // *second* one under the same identifier and hands it to a cache whose
    // documented behaviour is to cancel every duplicate it finds, "including
    // the newly inserted one" -- so both are cancelled, the flow is
    // destroyed, and this function would return `Ok(())` having queued the
    // opening message of a comparison that no longer exists. A double tap on
    // a button, or a retry after an unrelated failure, is enough. The doc
    // comment above is about two *sides* racing, which upstream does handle;
    // this is one side calling twice, which it does not. A side whose peer
    // got there first is refused for the same reason and with the same
    // error: there is nothing left for it to start, and the comparison it
    // wanted is already under way.
    let stage = stage_from(&handles);
    if stage != FlowStage::Ready {
        return Err(MachineError::WrongStage);
    }

    let flow_id = flow.0.clone();
    // Only a request-shaped flow can be `Ready`: that stage comes from
    // `VerificationRequestState::Ready` and nowhere else, and a flow that
    // arrived as a bare `m.key.verification.start` is a comparison from the
    // moment it exists -- it is refused by the check above, which is
    // correct, because the comparison this call would start is the one
    // already running.
    let request = handles.request.ok_or(MachineError::WrongStage)?;

    // Through `with_machine` like every other operation in this crate, and
    // not because the machine itself is needed: this call reaches the
    // crypto store, so it needs the runtime `with_machine` enters and the
    // serialisation against other store-touching work that holding the
    // machine lock gives it.
    let started = with_machine(move |_machine| Box::pin(async move { request.start_sas().await }))
        .await?
        .map_err(|_upstream| store_failed())?;

    let (comparison, outgoing) = started.ok_or(MachineError::WrongStage)?;
    remember_comparison(&flow_id, comparison);
    queue(outgoing);
    Ok(())
}

/// How far along the flow is.
pub async fn flow_stage(flow: &FlowId) -> Result<FlowStage, MachineError> {
    let handles = handles(flow).await?;
    Ok(stage_from(&handles))
}

/// The short authentication string, once there is one.
///
/// The two failure kinds are kept apart on purpose. `MaterialNotReady`
/// means the flow is live and has not got there yet, and it has two causes
/// that want opposite things done about them. `SasState::Accepted` is the
/// one this comment used to name alone: the key message was never reported
/// sent, which parks the flow at that stage forever, and the remedy is the
/// pump. `SasState::Started` is the other, and it is the receiving side's:
/// the peer opened the comparison and this side has not answered it, so the
/// remedy is a second [`accept_flow`] and pumping alone never moves it. The
/// facade reads [`flow_stage`] to tell a product which it is in.
/// `WrongStage` means it never will: the flow is over, or has not become a
/// comparison at all.
pub async fn read_material(flow: &FlowId) -> Result<SasMaterial, MachineError> {
    let handles = handles(flow).await?;
    let comparison = handles.comparison.ok_or(MachineError::WrongStage)?;

    match comparison.state() {
        SasState::KeysExchanged { emojis, decimals } => Ok(SasMaterial {
            emoji: emojis.map(|short_auth_string| {
                short_auth_string
                    .emojis
                    .iter()
                    .map(|emoji| SasEmoji {
                        symbol: emoji.symbol.to_string(),
                        description: emoji.description.to_string(),
                    })
                    .collect()
            }),
            decimals,
        }),
        SasState::Created { .. } | SasState::Started { .. } | SasState::Accepted { .. } => {
            Err(MachineError::MaterialNotReady)
        }
        SasState::Confirmed | SasState::Done { .. } | SasState::Cancelled(_) => {
            Err(MachineError::WrongStage)
        }
    }
}

/// Says the strings matched.
///
/// Only legal while the string is actually on screen. Upstream's own
/// `confirm` does nothing at all in any other state and reports success for
/// it, which would let a product confirm a verification it never showed
/// anybody; the stage is checked here first so that cannot happen quietly.
pub async fn confirm_flow(flow: &FlowId) -> Result<(), MachineError> {
    let handles = handles(flow).await?;
    let comparison = handles.comparison.ok_or(MachineError::WrongStage)?;

    match stage_of_comparison(&comparison) {
        FlowStage::KeysExchanged => {}
        FlowStage::Started => return Err(MachineError::MaterialNotReady),
        _ => return Err(MachineError::WrongStage),
    }

    let (requests, signature_upload) =
        with_machine(move |_machine| Box::pin(async move { comparison.confirm().await }))
            .await?
            .map_err(|_upstream| store_failed())?;

    for request in requests {
        queue(request);
    }
    // Produced only once this device has a cross-signing identity to sign
    // with. This said nothing in this library sets one up, and that
    // stopped being true when `signing::bootstrap_identity` landed, so the
    // precondition is now satisfiable and the branch is live rather than
    // dead.
    //
    // It is one of two producers of the same request, and which one fires
    // is decided by the flow's shape, not by anything here. Upstream
    // finishes a comparison from a confirmation only out of
    // `InnerSas::MacReceived` with `started_from_request` false, so a flow
    // that arrived as a bare start is signed *here*, while a flow that came
    // from a request is signed later, when the peer's own acknowledgement
    // arrives: `VerificationMachine::mark_sas_as_done` queues the request
    // for itself and it reaches the pump through
    // `OlmMachine::outgoing_requests()` like any other reaction. Both
    // therefore reach the pump, and neither needed a change here.
    //
    // **Only the second of the two is driven by a test.**
    // `tests/verified_sender.rs` verifies through a requested flow, and
    // that was confirmed rather than assumed: asserting `is_none()` here
    // leaves that test passing. So this branch's own firing is still
    // unwitnessed, and a test that drives a bare-start comparison against
    // a cross-signed counterparty is what would witness it.
    //
    // Queued rather than dropped, which is what mattered before either
    // could run: this is the message that publishes the verification to
    // the rest of the account, and without it the sender's master key
    // never carries our signature, so nothing this device verified would
    // ever read as an authenticated sender. See `SenderVerification`'s own
    // doc comment for what the signature is worth and what still has to
    // happen to it.
    if let Some(upload) = signature_upload {
        queue(upload);
    }

    // Nothing is announced from here, and on one flow shape that is now a
    // visible delay rather than a technicality.
    //
    // Upstream finishes a comparison from a confirmation only out of
    // `InnerSas::MacReceived`, and then only when `started_from_request` is
    // false (`verification/sas/inner_sas.rs:243-258`). A flow that came
    // from a request therefore always lands in `WaitingForDone` here --
    // which reads as `Confirmed` -- and its trust change arrives later
    // anyway, with the peer's own acknowledgement. **A flow that arrived as
    // a bare `m.key.verification.start` takes the other branch and is
    // `Done` when this call returns**, with the device already verified,
    // and yet still nothing is emitted: `announce_state_changes` runs from
    // `receive_sync_changes` and nowhere else, so its `TrustChanged` waits
    // for the next sync.
    //
    // Left that way on purpose. One producer, one moment, one ordering to
    // reason about -- a second producer here would have to take the
    // registry lock, mark the completion and race the sync path for it, to
    // save a delay a product does not experience, because it is syncing.
    // What a product must not do is read a returned `Ok` as a
    // verification; `flow_stage` and `device_statuses` are the answers to
    // that, and both are correct the instant this returns. The delay is
    // asserted in both directions -- silent before the next sync,
    // announced after it -- by
    // `a_comparison_started_without_a_request_is_announced_and_completes`.
    Ok(())
}

// ------------------------------------------- verifying by scanning a code

/// The code for this flow, for a person to hold up to another camera.
///
/// # What upstream does here, and why this call does more than pass it on
///
/// `VerificationRequest::generate_qr_code` answers **seven** different
/// conditions with the same `Ok(None)`: the flow is not agreed yet, the
/// flow is over, the other device never offered to scan, this account has
/// no signing identity, the other user has none, this device does not hold
/// the private signing keys a cross-user code must carry, and the other
/// device published no usable key. One of those is a stage, one is a
/// negotiation, and the rest are the thing M4 exists to set up.
///
/// Passed on as an absence, every one of them shows a person the same
/// thing: **a screen with no code on it and no reason given.** That is the
/// exact failure this library refuses to hand a product, so this call asks
/// upstream's own questions again, in upstream's own order, and names what
/// it finds. [`crate::identity_status`] is where the two identity answers
/// come from, so the refusal and the status call cannot come to disagree
/// about whether this device can sign.
///
/// # Refusals
///
/// * [`MachineError::WrongStage`] -- the flow has not been agreed yet, or it
///   is over, or it never had a request behind it. A flow that arrived as a
///   bare `m.key.verification.start` has no request and never will, and a
///   code is only ever built from one.
/// * [`MachineError::CodeNotOffered`]: **this** build did not offer to
///   show a code on this flow, so there is nothing for it to produce.
///   [`offer_codes`] with `can_show`, before the next flow, is the whole of
///   the remedy. It used to fold the refusal below in with this one and tell
///   a caller to work out which from the switch it had set; that advice
///   stopped being sound the moment the switch became two facts rather than
///   one boolean.
/// * [`MachineError::PeerCannotScan`]: the other device did not announce
///   `m.qr_code.scan.v1`, so no code this side draws can be read. Nothing
///   here can change that and no amount of waiting will: the answer is to
///   compare the short string instead. Two devices that can each only show
///   are the ordinary way to arrive here, and it is what a person meets when
///   both ends of a self-verification are code-showing products.
/// * [`MachineError::IdentityNotKnown`] -- this account has no signing
///   identity for the code to carry. [`crate::create_identity`], which is
///   the call that mints one; [`crate::bootstrap_identity`] publishes an
///   identity this device already holds and answers this same refusal.
/// * [`MachineError::PeerIdentityNotKnown`] -- the other user has none, and
///   nothing this device does will produce one.
/// * [`MachineError::PrivateKeysNotHeld`] -- verifying *another user* puts
///   this account's own master key in the code, and this device does not
///   hold the private keys to prove it. [`crate::request_self_flow`],
///   [`crate::recover_identity`] or, on an account with no identity at all,
///   [`crate::create_identity`]. Note that verifying our *own* new login
///   does not need them: that is the mode the code itself declares, and it
///   is why both self modes exist.
/// * [`MachineError::MalformedIdentifier`] -- the flow's identifier is too
///   long to encode. Only reachable from a peer that chose one, since the
///   ones this library mints are ordinary transaction ids.
///
/// # Calling it twice
///
/// Legal, and it produces a code for the same flow rather than a second
/// flow: upstream rebuilds from the same ready state whether the request is
/// still `Ready` or has already transitioned. The bytes differ between
/// calls only in the shared secret, and a product that draws the newer one
/// is showing the live code, because upstream replaces its own handle too.
pub async fn read_code(flow: &FlowId) -> Result<ScannableCode, MachineError> {
    let handles = handles(flow).await?;
    // A code is only ever built from a request. See the refusal list above.
    let request = handles.request.ok_or(MachineError::WrongStage)?;
    let flow_id = flow.0.clone();

    let negotiation = handles.negotiation;

    let code = with_machine(move |machine| {
        Box::pin(async move {
            match request
                .generate_qr_code()
                .await
                .map_err(|_upstream| store_failed())?
            {
                Some(code) => Ok(code),
                // The whole point of this call. See the header.
                None => Err(why_no_code(machine, &request, negotiation).await),
            }
        })
    })
    .await??;

    let scannable = draw(&code)?;
    // After the drawing, not before: a code whose flow identifier will not
    // encode is one no product can show, and caching it would leave the
    // registry holding a handle for a flow that reported a failure.
    remember_code(&flow_id, code);
    Ok(scannable)
}

/// The two forms of one code: the bytes, and the symbol upstream built for
/// them.
///
/// The symbol comes from upstream's own `to_qr_code` rather than from
/// re-encoding `payload` here, which is the whole reason both forms cross.
/// See [`ScannableCode`].
fn draw(code: &QrVerification) -> Result<ScannableCode, MachineError> {
    // Both failures upstream can report here are the same failure: a flow
    // identifier that does not fit. `EncodingError::FlowId` is the length
    // conversion refusing outright, `EncodingError::Qr` is the symbol
    // refusing the bytes that length produced. Reported as the malformed
    // identifier it is, which also keeps this crate's rule that an error
    // never carries the identifier it is about.
    let too_long = || MachineError::MalformedIdentifier {
        detail: "flow id".to_string(),
    };
    let payload = code.to_bytes().map_err(|_upstream| too_long())?;
    let symbol = code.to_qr_code().map_err(|_upstream| too_long())?;
    Ok(ScannableCode {
        payload,
        // `usize` to `u32`: a symbol's side is at most 177 squares in the
        // specification and 45 in practice here, so this cannot truncate,
        // and it is a `u32` on this surface because the boundary this
        // crosses has no `usize`.
        width: symbol.width() as u32,
        // `to_colors`, not the deprecated `to_vec`, and mapped by name:
        // upstream's symbol is a grid of light and dark squares, and `true`
        // on this surface means dark. A `bool` conversion read the other way
        // round would draw the photographic negative of a valid code, which
        // most scanners refuse and some read as a different code.
        modules: symbol
            .to_colors()
            .into_iter()
            .map(|square| square == Color::Dark)
            .collect(),
    })
}

/// Which of `generate_qr_code`'s seven silent conditions this flow is in.
///
/// Asked only after upstream has already answered `Ok(None)`, so nothing
/// here decides anything: it explains a refusal that has already happened.
/// That is what lets it ask cheaper questions than upstream's own -- it
/// cannot produce a false refusal, only a less precise explanation of a
/// real one.
///
/// Upstream's order, deliberately, because the order is part of the answer:
/// a flow whose peer cannot scan is told so whether or not anybody has an
/// identity, since that is the condition upstream tests first
/// (`verification/requests.rs:1222-1228`).
///
/// # The negotiation is asked about a flow that has moved on, and that is
/// the fix
///
/// `remembered` is [`FlowRecord::negotiation`], and it is here because
/// upstream stops answering. The two method lists live on
/// `VerificationRequestState::Ready` and on nothing else, so a flow that has
/// become a code or a comparison used to reach the identity questions below
/// with the negotiation unasked, and a self flow then fell out of the far
/// end as [`MachineError::WrongStage`]. That is a stage complaint standing
/// in for an answer about methods, on the one call a product makes when it
/// wants to put a square on a screen, and it is what a person met on
/// hardware on 2026-08-31. The registry keeps the answer while upstream is
/// still giving it; this reads what was kept.
async fn why_no_code(
    machine: &matrix_sdk_crypto::OlmMachine,
    request: &VerificationRequest,
    remembered: Option<CodeNegotiation>,
) -> MachineError {
    // Exhaustive, no wildcard, like every other upstream match in this
    // crate.
    let negotiated = match request.state() {
        // Not agreed yet by one side or the other, or finished. Upstream
        // refuses all four of these before it looks at anything else
        // (`verification/requests.rs:988-996`).
        VerificationRequestState::Created { .. }
        | VerificationRequestState::Requested { .. }
        | VerificationRequestState::Done
        | VerificationRequestState::Cancelled(_) => return MachineError::WrongStage,
        VerificationRequestState::Ready {
            our_methods,
            their_methods,
            ..
        } => Some(CodeNegotiation {
            we_announced_showing: our_methods.contains(&VerificationMethod::QrCodeShowV1),
            they_announced_scanning: their_methods.contains(&VerificationMethod::QrCodeScanV1),
        }),
        // The methods are not carried on this state, so this is where what
        // was remembered earns its keep. `None` here means nothing ever
        // looked at this flow while it was ready, which leaves the
        // negotiation genuinely unknown rather than answerable by a guess.
        VerificationRequestState::Transitioned { .. } => remembered,
    };
    // **Both halves, ours first, which is upstream's own order and its own
    // single condition** (`verification/requests.rs:1222-1228`), and one
    // refusal each rather than one refusal for the pair. Ours is the half a
    // developer can fix: it is false exactly when this flow was opened or
    // agreed to without `can_show`, and the remedy is one call before the
    // next flow rather than anything about this one. Theirs is the half
    // nobody here can fix, and telling a product to go and re-check its own
    // switch when the far side is the problem sends it looking in the one
    // place the answer is not.
    if let Some(negotiation) = negotiated {
        if !negotiation.we_announced_showing {
            return MachineError::CodeNotOffered;
        }
        if !negotiation.they_announced_scanning {
            return MachineError::PeerCannotScan;
        }
    }

    // Whose identity the code would have to carry is decided by who is on
    // the other end, which is the same question that decides the mode.
    let other = request.other_user();
    let ours = other == machine.user_id();

    // `None` as the timeout, not a duration, for `signing::read_status`'
    // reason: this call holds the machine lock, and waiting here for a key
    // query the caller cannot send from another task would hang rather than
    // answer.
    let identity = match machine.get_identity(other, None).await {
        Ok(identity) => identity,
        Err(_upstream) => return store_failed(),
    };
    if identity.is_none() {
        return if ours {
            MachineError::IdentityNotKnown
        } else {
            MachineError::PeerIdentityNotKnown
        };
    }

    // Verifying our own new login needs the account's *public* identity and
    // nothing else: the device that holds none of the private keys shows
    // the mode that says so. So there is no private-key refusal on this
    // side of a self-verification, and reporting one would send a person to
    // set up something they do not need.
    if ours {
        return MachineError::WrongStage;
    }

    // Verifying somebody else puts this account's own master key in the
    // code, which needs the private seed behind it. Read through the same
    // question `crate::identity_status` answers, so the refusal and the
    // status call agree by construction. Upstream needs only the master
    // seed and this asks for all three; that cannot produce a false
    // refusal, because upstream has already refused -- it can only be a
    // less precise explanation, in a case (a partial private identity) that
    // nothing in this library can produce.
    if !machine.cross_signing_status().await.is_complete() {
        return MachineError::PrivateKeysNotHeld;
    }

    // Everything upstream asks has been asked. What is left is the other
    // device having published no usable key, which is upstream's last
    // branch and is not a condition a caller can act on.
    MachineError::WrongStage
}

/// Hands in the payload a product's scanner read off the other device's
/// screen.
///
/// **The bytes must be the ones that were encoded, not a string.** A
/// scanner library that returns a decoded `String` has already lost this
/// payload: it is binary, it is not UTF-8, and any string round trip
/// replaces the bytes it could not represent. A product must take the raw
/// byte output its scanner offers. That is not a caution about a
/// hypothetical: a payload put through a string is refused as
/// [`MachineError::ScannedCodeMalformed`], watched in
/// `tests/qr_refusals.rs`, and the refusal is the only thing that can tell a
/// product its scanner is the problem.
///
/// This is one call and two protocol steps, and it is one call on purpose:
/// upstream's scan produces the handle, and `reciprocate` produces the
/// message that tells the other side the code was read. A surface that
/// stopped after the first would leave a flow that had scanned successfully
/// and told nobody, which is the silent stall this module is written
/// against.
///
/// # Refusals
///
/// Four of them are about the payload, and they are four rather than one
/// because they are four different things to say to a person. The design's
/// section 4 requires the first three to be distinguishable.
///
/// * [`MachineError::ScannedCodeUnrecognised`] -- not one of these codes at
///   all: a camera pointed at some other square, or a client speaking a
///   revision of the format this library does not implement.
/// * [`MachineError::ScannedCodeMalformed`] -- damaged in transit. Above
///   all, a scanner that handed back text.
/// * [`MachineError::ScannedCodeForAnotherFlow`] -- a well-formed code, for
///   a different verification. The camera read the wrong screen.
/// * [`MachineError::ScannedCodeRefused`] -- a code for this flow whose keys
///   are not the ones this flow expects. The only one of the four that can
///   mean something is wrong rather than that somebody aimed badly.
/// * [`MachineError::IdentityNotKnown`] and
///   [`MachineError::PeerIdentityNotKnown`] -- scanning needs a signing
///   identity on *both* sides, unconditionally, and upstream names which one
///   is missing.
/// * [`MachineError::WrongStage`] -- the flow is not one a code can be
///   scanned into, or it is over.
pub async fn submit_scanned_code(flow: &FlowId, payload: &[u8]) -> Result<(), MachineError> {
    let handles = handles(flow).await?;
    let request = handles.request.ok_or(MachineError::WrongStage)?;
    // Owned before the closure, not borrowed: `with_machine` requires a
    // `'static` closure.
    let payload = payload.to_vec();
    let flow_id = flow.0.clone();

    let (code, outgoing) = with_machine(move |machine| {
        Box::pin(async move {
            // Decoding is a separate, earlier step with an error type of its
            // own, which is why a mangled payload cannot arrive as a
            // `ScanError`. Nothing here touches the store or a key.
            //
            // Upstream's seven decoding failures split in two, and the split
            // is the difference between two sentences a product shows a
            // person. Exhaustive, no wildcard, like every other upstream
            // match in this crate: a variant added later must be ruled on
            // here rather than land on whichever side a wildcard named.
            let scanned =
                QrVerificationData::from_bytes(&payload).map_err(|upstream| match upstream {
                    // Nothing about these bytes says they were ever one of
                    // these codes. The header is somebody else's, or the
                    // version or the mode is one this library does not
                    // implement -- upstream reads all three before it reads
                    // anything else (`types.rs:240-246`).
                    DecodingError::Header | DecodingError::Version(_) | DecodingError::Mode(_) => {
                        MachineError::ScannedCodeUnrecognised
                    }
                    // These four say the bytes were damaged: they ran out
                    // early, the identifier inside is not text, the secret
                    // is too short to be one, or the keys do not decompress
                    // to points on the curve. **A payload put through a
                    // string arrives here**, which is the misuse
                    // `submit_scanned_code`'s own documentation warns about,
                    // and `Keys` is the variant it was observed landing on.
                    //
                    // `Read` also catches a payload too short to carry a
                    // header at all, which nothing but a truncated read
                    // produces: bytes that stop before six is damage, not a
                    // code somebody else wrote.
                    DecodingError::Utf8(_)
                    | DecodingError::Read(_)
                    | DecodingError::SharedSecret(_)
                    | DecodingError::Keys(_) => MachineError::ScannedCodeMalformed,
                })?;

            let own = machine.user_id().to_owned();
            let code = request
                .scan_qr_code(scanned)
                .await
                // Exhaustive, no wildcard: a variant upstream adds later
                // must fail this build rather than be reported as whichever
                // refusal a wildcard happened to name.
                .map_err(|upstream| match upstream {
                    ScanError::Store(_) => store_failed(),
                    // Upstream names the user whose identity is missing, so
                    // the two sides are told apart from what it said rather
                    // than guessed at.
                    ScanError::MissingCrossSigningIdentity(user) if user == own => {
                        MachineError::IdentityNotKnown
                    }
                    ScanError::MissingCrossSigningIdentity(_) => MachineError::PeerIdentityNotKnown,
                    ScanError::FlowIdMismatch { .. } => MachineError::ScannedCodeForAnotherFlow,
                    // The keys in the code are not the ones this side holds
                    // for the device on the other end. Kept apart from
                    // `ScannedCodeForAnotherFlow` above, which is a code
                    // that never claimed to be this flow's, and from the arm
                    // below, which is this side knowing nothing about the
                    // device rather than knowing something different.
                    ScanError::KeyMismatch { .. } => MachineError::ScannedCodeRefused,
                    // This side holds no record of the other device, or one
                    // with no usable key in it. **Not the same thing as a
                    // mismatch, and it used to be folded with one.** A
                    // mismatch is refused and started over; this is fixed by
                    // querying that user's devices through the pump and
                    // scanning the very same code again, which is exactly
                    // what `UnknownDevice` already means everywhere else on
                    // this surface. Folding them put the second under a
                    // sentence telling a product not to retry the code,
                    // which was the one thing that would have worked.
                    //
                    // **Not reachable through this library today**, and said
                    // here rather than left as an implied claim. A code is
                    // only ever scanned into a flow, and a flow arrives in
                    // one of two ways: `request_flow` refuses an unknown
                    // device before any flow exists, and an invitation from
                    // a device this library has no record of never reaches
                    // the registry at all. `qr_refusals.rs` measures the
                    // second against a control, which is what makes this a
                    // finding rather than a guess. Mapped correctly anyway,
                    // because an arm nobody can reach is still an arm a
                    // later upstream can start reaching.
                    ScanError::MissingDeviceKeys(..) => MachineError::UnknownDevice,
                })?;

            // `Ok(None)` here means the flow is not one a scan applies to,
            // which upstream documents as "the verification request isn't in
            // the ready state or we don't support QR code verification".
            let code = code.ok_or(MachineError::WrongStage)?;

            // The second protocol step. Upstream returns `None` for a code
            // that is not in the state it just put this one in, so this is
            // an absence that cannot happen rather than one to report; it is
            // still reported rather than dropped, because a scan that told
            // nobody is exactly the failure this call exists to prevent.
            let outgoing = code.reciprocate().ok_or(MachineError::WrongStage)?;
            Ok((code, outgoing))
        })
    })
    .await??;

    remember_code(&flow_id, code);
    queue(outgoing);
    Ok(())
}

/// Says the other device really did scan the code this one showed.
///
/// The one thing a person still has to do in a flow with no string to
/// compare, and it is the same act: *that was my other phone, not
/// somebody's screenshot*. A product must ask before calling this. Skipping
/// it stalls the flow until the protocol's own ten-minute timeout, exactly
/// as a short-string confirmation nobody makes does.
///
/// # What `WrongStage` folds here, and what separates it
///
/// Two conditions arrive as [`MachineError::WrongStage`]: *nobody has
/// scanned this code yet*, and *this flow is over*. They want opposite
/// things done about them -- wait, versus start again -- and this call
/// still cannot tell a caller which. [`flow_stage`] is the answer everywhere
/// else in this module, and it is the answer here too, which it was not when
/// this fold was written: [`FlowStage::Started`] is nobody has scanned yet,
/// [`FlowStage::CodeScanned`] is the one stage this call succeeds at, and
/// [`FlowStage::Done`] or [`FlowStage::Cancelled`] is over. Reading it first
/// leaves this fold reachable only by a race.
pub async fn confirm_scan(flow: &FlowId) -> Result<(), MachineError> {
    let handles = handles(flow).await?;
    let code = handles.code.ok_or(MachineError::WrongStage)?;
    // Upstream returns `None` for every state but the one where the other
    // side has scanned and this side has not answered. Reported rather than
    // treated as success, for `cancel_flow`'s reason: a caller that gets
    // `Ok` for a confirmation it never made has been told something false.
    let outgoing = code.confirm_scanning().ok_or(MachineError::WrongStage)?;
    queue(outgoing);
    Ok(())
}

/// Refuses the verification, or abandons it.
///
/// The one call in this module a product must be able to make at any point
/// a person can look at a screen and say "that is not what I see". It
/// cancels the comparison if there is one, the code if the flow became one,
/// and the request otherwise. Each of the first two also cancels the request
/// behind it, because upstream's own handle does that: both
/// `Sas::cancel_with_code` and `QrVerification::cancel_with_code` open by
/// cancelling their `RequestHandle`.
///
/// # Why the code arm exists, and what its absence cost a person
///
/// Reading the comparison and the request was enough for as long as a flow
/// could only become a comparison. It is not enough for one that became a
/// code, and the gap was not cosmetic:
///
/// * upstream allows **one live verification per person**. Inserting a
///   second while an older uncancelled one with the same user is in its
///   cache cancels *both* (`verification/cache.rs:86-104`, "Received a new
///   verification whilst another one with the same user is ongoing.
///   Cancelling both verifications"), and its sweep keeps everything that is
///   neither done nor cancelled (`retain(|_, s| !(s.is_done() ||
///   s.is_cancelled()))`, same file);
/// * a code a peer scanned and this side never confirmed is neither of
///   those, so it stays in that cache and takes the **next two**
///   verifications with that person down with it, silently, before anybody
///   has refused anything. `tests/qr_halt_recovery.rs` measures both, and
///   why it is two rather than one or than all of them;
/// * and the request behind such a flow is already `Done`, because upstream
///   advances the two unalike from one `m.key.verification.done`:
///   `VerificationRequest::receive_done` moves a `Transitioned` request
///   unconditionally (`verification/requests.rs:934-940`) while
///   `QrVerification::receive_done` leaves a `Scanned` code exactly where it
///   is (`verification/qrcode.rs:392-440`). So the request arm has nothing
///   left to cancel and answers `None`.
///
/// Together those made this call answer [`MachineError::WrongStage`] to the
/// one situation a product most needs it for. A person whose scan went
/// wrong then had no call that freed them to try that contact again, and
/// their next attempt died with no error attached to it. Cancelling the code
/// is what puts the cache entry into the state upstream's own sweep removes.
/// `tests/qr_halt_recovery.rs` drives the whole sequence, halt then abandon
/// then verify again, rather than asserting that this call returned success,
/// and it measures the silent casualty first so that the recovery has
/// something to be measured against.
///
/// **The order is [`stage_of`]'s order and means the same thing.** A flow is
/// a comparison or a code and never both, because upstream's `Verification`
/// is one enum over the two, so these are alternatives rather than a
/// precedence rule to reason about.
pub async fn cancel_flow(flow: &FlowId) -> Result<(), MachineError> {
    let handles = handles(flow).await?;
    let outgoing = match (&handles.comparison, &handles.code, &handles.request) {
        (Some(comparison), _, _) => comparison.cancel(),
        (None, Some(code), _) => code.cancel(),
        (None, None, Some(request)) => request.cancel(),
        // Unreachable, for the reason `accept_flow` gives.
        (None, None, None) => None,
    }
    // Upstream returns `None` when the flow is already cancelled. Reported
    // rather than treated as success: "already refused" and "refused by
    // this call" are the same outcome, but a caller that gets `Ok` for a
    // flow it never actually cancelled has been told something false.
    .ok_or(MachineError::WrongStage)?;
    queue(outgoing);
    Ok(())
}

// ------------------------------------------------- the crypto signal channel

/// What one announcement pass owes, read out of the registry in a single
/// critical section.
///
/// Two fields rather than two functions, because the two are collected under
/// one lock and by one walk: splitting them would mean two passes over the
/// registry that could disagree about which records they had already marked.
struct Pending {
    /// Every device a completed comparison verified.
    verified: Vec<(OwnedUserId, OwnedDeviceId)>,
    /// The identifier of every flow that finished by scanning a code.
    scanned: Vec<String>,
}

/// What a completed flow owes its subscribers, for flows whose completion
/// has not been announced yet, marking them announced on the way out.
///
/// **A comparison's devices** are read from `SasState::Done`'s own
/// `verified_devices` rather than from the flow merely having finished.
/// Upstream sets local trust only for the devices that list names
/// (`verification/mod.rs:710-719`), so a flow that reached `Done` is not by
/// itself a claim that anything became verified, and a signal saying
/// otherwise would be a false one.
///
/// **A scanned flow's own completion** is the other thing collected here,
/// and it is a different kind of fact. What is announced for one is that it
/// finished, not that anything became verified, and the two are not the
/// same sentence: in two of the three modes a code can be shown in,
/// upstream's completed code names no device at all, and for another user
/// nothing this library will say about them changes until a later key query
/// brings our own signature back. [`CryptoSignal::VerificationCompleted`]
/// is where that is argued and where the measurements behind it are named.
///
/// Marks inside the same critical section that collects, so two callers
/// cannot both take the same completion. The cost is that a caller which
/// then fails to reach the machine loses the announcement -- acceptable,
/// because the only way to fail there is `NotInitialised`, and a process
/// with no machine has nothing to announce a trust change about.
///
/// Marks **every** `Done` record it inspects, not only the ones that
/// produced a completion. [`release_finished`] holds back a `Done` record
/// whose completion has not been taken, so a record this function looked at
/// and found nothing in must still come away marked, or it would be exempt
/// from eviction for the life of the process.
fn take_pending_completions() -> Pending {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    let mut pending = Pending {
        verified: Vec::new(),
        scanned: Vec::new(),
    };

    for record in flows.values_mut() {
        if record.completion_announced {
            continue;
        }
        if stage_of(record) != FlowStage::Done {
            continue;
        }

        // Marked on the *stage*, before anything is read out of it, and
        // that is what `release_finished`'s exemption depends on: a record
        // it holds back must become sweepable on the next pass whether or
        // not it turned out to have anything to announce. A flow can reach
        // `Done` through `VerificationRequestState::Done` with no
        // comparison behind it at all, and marking only the ones that
        // produced a signal would exempt those from eviction for the life
        // of the process.
        record.completion_announced = true;

        // `state()` returns by value, which ends the borrow on `record`.
        let state = comparison_of(record).map(|comparison| comparison.state());
        if let Some(SasState::Done {
            verified_devices, ..
        }) = state
        {
            for device in verified_devices {
                pending
                    .verified
                    .push((device.user_id().to_owned(), device.device_id().to_owned()));
            }
            continue;
        }

        // A flow that finished by scanning, which is the other shape a
        // record can have and is announced as itself rather than as a
        // trust change. [`CryptoSignal::VerificationCompleted`] carries the
        // measurements behind that; the short version is that in two of the
        // three modes this state names no device, so a `verified_devices`
        // walk here would announce nothing at all for them.
        //
        // Asked of the code's own `Done` rather than of the stage, which
        // would say the same thing today: this is the precise question, the
        // way `SasState::Done` above is for a comparison, and a flow whose
        // request reached `Done` without its code doing so is not one that
        // finished by scanning.
        //
        // The identifier is read off the handle upstream built, never off
        // the registry's key, for the reason `announce_state_changes` gives
        // about never handing a product a name no call of this module
        // answers to.
        let finished_by_scanning = code_of(record)
            .filter(|code| matches!(code.state(), QrVerificationState::Done { .. }))
            .map(|code| code.flow_id().as_str().to_string());
        if let Some(flow_id) = finished_by_scanning {
            pending.scanned.push(flow_id);
        }
    }

    pending
}

/// Everybody a flow that finished by scanning owes a `/keys/query` about,
/// marking each record on the way out so one flow owes it once.
///
/// [`take_pending_completions`]'s shape, walking the same registry for a
/// different fact, and marking on the *stage* for the same reason: a record
/// [`release_finished`] holds back must become sweepable on the next pass
/// whether or not it turned out to owe anything.
///
/// Every completed code flow is collected here, including one with this
/// account itself. Filtering that out needs the machine's own user id, which
/// this function has no business taking a lock for;
/// [`queue_peer_key_queries`] does it where the id is already in hand.
fn peers_owed_a_key_query() -> Vec<OwnedUserId> {
    let mut flows = FLOWS.lock().expect("verification registry poisoned");
    let mut owed = Vec::new();

    for record in flows.values_mut() {
        if record.key_query_queued {
            continue;
        }
        if stage_of(record) != FlowStage::Done {
            continue;
        }
        record.key_query_queued = true;

        // The code's own `Done`, not the stage, for `take_pending_completions`'
        // reason at the same question: a flow whose request reached `Done`
        // without its code doing so is not one that finished by scanning.
        let other = code_of(record)
            .filter(|code| matches!(code.state(), QrVerificationState::Done { .. }))
            .map(|code| code.other_user_id().to_owned());
        if let Some(other) = other {
            owed.push(other);
        }
    }

    owed
}

/// Asks the homeserver about the person a code verification just verified,
/// so that what this library says about them stops being wrong.
///
/// # The fact this closes
///
/// Verifying **another user** by code produces one thing: our user-signing
/// key's signature over their master key, made and uploaded in the code's
/// `Confirmed`/`Reciprocated` to `Done` transition. Nothing local records
/// it. Upstream marks an identity verified only when it is our own
/// (`verification/mod.rs:644-649` calls `mark_as_verified` inside
/// `if let UserIdentityData::Own`), and [`crate::device_statuses`] answers
/// upstream's `is_verified`, which for another person's device is
/// `is_locally_trusted() || is_cross_signing_trusted(..)`. A completed code
/// names no device to trust locally in this mode, and the cross-signing half
/// asks whether our signature is on their master key **as it stands in our
/// own store**. So until a `/keys/query` brings that signature back, this
/// library reports the person it has just verified as unverified.
///
/// # Why the query is queued here rather than asked of the product
///
/// Because there is no call a product could make. Tracking a user is the
/// only thing on the published surface that leads to a key query, and
/// upstream's `update_tracked_users` flags only the users it *newly*
/// inserts (`store/mod.rs:255-273`), so calling `share_scope_key` again for
/// somebody already tracked queues nothing at all. The other route,
/// `device_lists.changed`, is the homeserver's to send and it sends it only
/// for people an encrypted room is shared with. Making this the product's
/// job would therefore have meant adding a call whose whole content is a
/// protocol fact a product should not have to hold, and until it was called
/// [`crate::device_statuses`] would answer wrongly about a person the
/// library had just verified. A value that is wrong until an unqueued call
/// is worse than one documented as needing it, and worse again than one
/// that simply queues it.
///
/// Precedented rather than novel: `signing::bootstrap_identity` and
/// `recovery`'s writer both queue an out-of-band key query of their own
/// through `OlmMachine::query_keys_for_users` for the same class of reason,
/// which is that upstream will not volunteer the question and the caller
/// cannot ask it.
///
/// # What it still asks of a product, and where that is written
///
/// **Queued is not answered.** This puts one `keys_query` into
/// [`crate::take_outgoing_requests`]' output, and the trust answer does not
/// move until the product has sent it and reported it with
/// [`crate::mark_request_sent`], which is the same contract every other call
/// in this library carries. `getDeviceStatuses` in
/// `packages/react-native-matrix-crypto/src/facade.ts` says so where a
/// product author reads it.
///
/// # Only the cross-user code flow, and why the other shapes are not here
///
/// * **Both self modes** already read correctly at completion: the identity
///   is our own, so upstream does mark it verified, and
///   `tests/qr_self_new_login_shows.rs` asserts the device reads verified
///   the moment the flow finishes.
/// * **A cross-user comparison** already reads correctly too, by a different
///   route: `SasState::Done` names the device and upstream sets
///   `LocalTrust::Verified` on it (`verification/mod.rs:683-720`), so
///   `is_locally_trusted()` answers before any signature comes back. That
///   this leaves *their other* devices unverified until a key query is older
///   than this milestone and is `tests/verified_sender.rs`' step seven.
/// * A flow that was cancelled or that never became a code owes nothing:
///   nothing was signed.
///
/// # Called from `receive_sync_changes`, and before the announcement
///
/// It has to be a sync, because that is the only moment a flow can reach
/// `Done`. It is not folded into [`announce_state_changes`] because that
/// function returns before it touches anything when no observer is
/// registered, and a product that never subscribes needs this just as much
/// as one that does. It runs *before* the announcement so that the query is
/// already queued when a listener is told the flow finished: `emit_crypto`
/// detaches delivery into its own task, so a listener that reacts by
/// draining the pump can be running while this function's caller is still
/// returning.
pub(crate) async fn queue_peer_key_queries() {
    let owed = peers_owed_a_key_query();
    if owed.is_empty() {
        return;
    }

    // A failure here is `NotInitialised` and nothing else, and a process with
    // no machine has nobody to be wrong about. The marks are spent either
    // way, which matches `take_pending_completions`' own trade at the same
    // place.
    let _ = with_machine(move |machine| {
        Box::pin(async move {
            for user in owed {
                // Our own account never needs this, and cannot be reached by
                // mode `0x00` in any case. Filtered rather than assumed, so
                // that a self-mode flow which somehow reached the collector
                // costs a request nobody wanted rather than a query naming
                // this account, which `session.rs`'s ordering gate reads.
                if user == *machine.user_id() {
                    continue;
                }
                let (id, request) = machine.query_keys_for_users(std::iter::once(&*user));
                crate::session::queue_peer_key_query(id, request);
            }
        })
    })
    .await;
}

/// The `(sender, transaction id)` of every `m.key.verification.start` among
/// one sync's processed to-device events.
///
/// Read from what upstream handed *back*, never from what the caller passed
/// in, and the difference is not cosmetic: a verification event may arrive
/// Olm-encrypted, in which case `receive_sync_changes` returns the
/// decrypted event in its place (`ProcessedToDeviceEvent::Decrypted`).
/// Parsing the input would see `m.room.encrypted` and miss every encrypted
/// flow, silently.
///
/// A candidate is no more than a transaction id that might name a flow.
/// Nothing is announced from one until upstream has confirmed it; see
/// [`announce_state_changes`], which is the only caller.
fn bare_start_candidates(processed: &[ProcessedToDeviceEvent]) -> Vec<(OwnedUserId, String)> {
    processed
        .iter()
        .filter_map(|event| {
            let raw = event.as_raw().json().get();
            // A substring test before the parse. This runs once per
            // to-device event on a path that also carries every room key a
            // product receives, and a full parse of each would be real
            // per-sync work for a message type that appears only while
            // somebody is verifying.
            if !raw.contains(START_EVENT_TYPE) {
                return None;
            }
            let event: serde_json::Value = serde_json::from_str(raw).ok()?;
            if event.get("type")?.as_str()? != START_EVENT_TYPE {
                return None;
            }
            let sender: OwnedUserId = event.get("sender")?.as_str()?.parse().ok()?;
            let transaction = event.get("content")?.get("transaction_id")?.as_str()?;
            Some((sender, transaction.to_string()))
        })
        .collect()
}

/// The to-device event that opens a comparison.
///
/// Matched as a candidate only; nothing is believed on its say-so. See
/// [`bare_start_candidates`].
const START_EVENT_TYPE: &str = "m.key.verification.start";

/// Emits everything the crypto signal channel owes its subscribers, and
/// returns having emitted nothing when there are none.
///
/// Called from [`crate::receive_sync_changes`], and from nowhere else,
/// because that is the only moment either kind of change can happen: an
/// invitation exists once the event that carries it has been fed in, and a
/// comparison reaches `Done` only when the peer's acknowledgement arrives
/// (see [`confirm_flow`] for why confirming cannot finish one here).
///
/// # It asks what has changed rather than being told
///
/// Nothing on this path is driven by a particular event. It compares the
/// registry against what has already been announced, which is what makes it
/// correct under interleavings nobody enumerated: two transitions in one
/// sync are both announced, a transition that happens for a reason this
/// file did not predict is still announced, and calling it twice announces
/// nothing twice.
///
/// # Nothing is emitted from under the machine lock
///
/// The whole collection runs inside one `with_machine` closure and every
/// signal is emitted after it returns. `observer::emit_crypto` detaches
/// delivery anyway, so this is not what makes it safe -- but a listener
/// must never observe a signal before the operation that produced it has
/// visibly completed, and that is what the ordering here buys.
///
/// # What it costs
///
/// **With nobody listening, nothing.** The observer is read first, and with
/// none registered this returns before it takes the registry lock or
/// reaches the crypto store. That matters because the sync path calls this
/// on every sync a product performs, which is the highest-frequency call
/// this library has -- and it is why the TypeScript side uninstalls the
/// observer on the last unsubscribe rather than leaving it latched.
///
/// **With somebody listening, one `tracked_users()`, one
/// `get_verification_requests` per tracked user, and one
/// `cross_signing_status()`, per sync.** Measured against an empty sync on
/// an account with one tracked user, the difference was below the
/// resolution of the measurement -- but `tracked_users` clones the whole
/// tracked-user set into a fresh `HashSet<OwnedUserId>`
/// (`machine/mod.rs:482`), so on an account tracking thousands that is an
/// allocation proportional to the account on this library's most frequent
/// call. Nothing here has measured that case, and the small-account figure
/// must not be read as covering it.
///
/// The third is the one this milestone added, and it is the cheap one: it
/// takes two in-memory locks and reads three `Option`s
/// (`machine/mod.rs:2765-2767`), touching neither the store nor the
/// tracked-user set. It is listed rather than folded into the sentence
/// above because this block is read as an enumeration, and one that quietly
/// stopped enumerating would be worse than one that says a cheap thing
/// costs something.
///
/// # A verification begun without a request
///
/// A peer that starts a comparison the deprecated way -- an
/// `m.key.verification.start` with no `m.key.verification.request` before
/// it -- takes upstream's other branch
/// (`verification/machine.rs:430-450`): `Sas::from_start_event` followed by
/// `verifications.insert_sas`, which writes to the comparison cache and
/// *nothing* to the `requests` map the enumeration below reads. Such a flow
/// cannot be enumerated at all -- `VerificationCache` offers keyed lookup
/// and no listing -- so it is announced from `processed` instead.
///
/// Announced *from* it, not *off* it. The transaction id read off the start
/// event is only a candidate; the flow is then confirmed against upstream
/// through `OlmMachine::get_verification` (`machine/mod.rs:1444`), and
/// everything the announcement carries is read back off the comparison
/// upstream produced rather than off the wire. That keeps this function's
/// one invariant: never hand a product an identifier that no call in this
/// module answers to. A start from a device this machine has never met
/// builds no comparison -- upstream's branch returns without one when
/// `get_device` misses -- so nothing is announced for it, which is the same
/// rule, with the same remedy, as the request-shaped invitation from an
/// unmet device.
///
/// # The one property the two shapes do not share
///
/// A request-shaped invitation that arrives while nobody is subscribed is
/// announced on the first sync after somebody subscribes, because it is
/// re-enumerated from upstream every time -- and, since [`announce`]
/// releases what it could not deliver, that holds for an unsubscribe
/// landing *inside* this function too, not only for one that beat it here.
/// **A bare start is not.** Its
/// only witness is the sync that carried it, and this function returns
/// before looking at `processed` when there is no observer. Nothing cheaper
/// closes that: upstream has no enumerator to ask later, and the event is
/// delivered once. A product that wants inbound invitations has to
/// subscribe before it starts syncing, which is what the facade already
/// tells it to do -- and which is now load-bearing for one flow shape
/// rather than merely advisable for both.
pub(crate) async fn announce_state_changes(processed: &[ProcessedToDeviceEvent]) {
    // Silent by default, and free by default. See the doc comment above.
    if crate::observer::crypto_observer().is_none() {
        return;
    }

    let Pending {
        verified: completions,
        scanned,
    } = take_pending_completions();
    let candidates = bare_start_candidates(processed);

    let collected = with_machine(move |machine| {
        Box::pin(async move {
            let mut signals: Vec<CryptoSignal> = Vec::new();

            // Read the devices back rather than trusting that the
            // comparison naming them made them verified. `device_statuses`
            // asks upstream exactly this question, and asking it the same
            // way here is what stops the channel and the call from ever
            // disagreeing about a device.
            let mut changed: BTreeSet<String> = BTreeSet::new();
            for (user, device) in completions {
                let verified = machine
                    .get_device(&user, &device, None)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|device| device.is_verified());
                if verified {
                    changed.insert(user.to_string());
                }
            }
            for user in changed {
                signals.push(CryptoSignal::TrustChanged {
                    user,
                    state: TrustState::Verified,
                });
            }

            // Flows that finished by scanning a code. Nothing is read back
            // off the machine for these, and there is nothing to read back:
            // the fact announced is that the flow finished, which is read
            // off the handle upstream advanced rather than off anything
            // this side decided. What a product does about it is read the
            // durable trust answer, exactly as for a `TrustChanged`, and
            // the variant says so at its own declaration.
            for flow_id in scanned {
                signals.push(CryptoSignal::VerificationCompleted { flow_id });
            }

            // The account's own private signing keys arriving, which is a
            // trust change no comparison of this device's own reports.
            //
            // A device that joins an identity by verifying itself against
            // another of ours asks that device for the seeds it lacks, and
            // the answer comes back inside a later `receive_sync_changes` as
            // an encrypted secret upstream imports on its own. Nothing
            // returns to the caller when it lands, and nothing else on this
            // surface changes, so without this a product would have to poll
            // `identity_status` to find out that its new device can sign.
            //
            // The latch is what makes this an arrival rather than a report
            // repeated on every sync; `signing::note_private_keys_held`
            // owns it. Announced under our own user id, which is the shape
            // this variant has carried since M1: which of that user's
            // devices moved is `device_statuses`' answer, and here the
            // answer is potentially all of them at once, because a device
            // that holds the self-signing key can follow the account's own
            // signature over every device it signed.
            //
            // Consumed if it reaches nobody, like the completions above and
            // unlike an inbound invitation. `identity_status().private_keys_held`
            // is the durable answer and is correct the instant the import
            // lands, so a missed announcement costs a caller one call rather
            // than a state it can never recover.
            if crate::signing::note_private_keys_held(
                machine.cross_signing_status().await.is_complete(),
            ) {
                signals.push(CryptoSignal::TrustChanged {
                    user: machine.user_id().to_string(),
                    state: TrustState::Verified,
                });
            }

            // Inbound invitations. Enumerated from upstream rather than by
            // parsing the to-device events a sync carried, and the
            // difference is the point of the variant: upstream builds a
            // flow only when it can, so an invitation from a device this
            // machine has never met produces no flow and is therefore not
            // announced. Announcing on the wire event instead would hand a
            // product an identifier that no call of this library answers
            // to. The same rule is what makes a *re-fed* invitation
            // announce itself: the second arrival is when the flow first
            // exists.
            //
            // `tracked_users` is the same set `handles` searches, for the
            // same reason: a device has to have been queried before it can
            // be verified, so a counterparty is necessarily in it.
            let tracked = machine.tracked_users().await.unwrap_or_default();
            for user in &tracked {
                for request in machine.get_verification_requests(user) {
                    // `Requested` and nothing else: `Created` is a flow this
                    // device asked for and whose identifier the caller
                    // already holds, and a request another of our own
                    // devices answered presents as `Cancelled`.
                    let VerificationRequestState::Requested {
                        other_device_data, ..
                    } = request.state()
                    else {
                        continue;
                    };
                    let flow_id = request.flow_id().as_str().to_string();
                    let announcement = CryptoSignal::VerificationRequested {
                        user: request.other_user().to_string(),
                        device_id: other_device_data.device_id().to_string(),
                        flow_id: flow_id.clone(),
                    };
                    // Registering is the deduplication: a flow this
                    // registry already holds has been announced, or was
                    // started here and needs no announcement.
                    if register_if_absent(&flow_id, FlowRecord::from_request(request)) {
                        signals.push(announcement);
                    }
                }
            }

            // Inbound comparisons nobody requested: the deprecated shape,
            // reached from this sync's own start events because upstream
            // keeps them where nothing can enumerate them. See this
            // function's header.
            for (sender, transaction) in candidates {
                // A request wins wherever there is one, which is
                // `handles`'s rule, kept local here rather than argued
                // from a distance. A request-shaped flow whose comparison
                // has started carries an `m.key.verification.start` too,
                // and a record built from that start alone would hold no
                // request handle.
                //
                // Stated plainly: nothing reaches this line today. Such a
                // flow is already in the registry by the time its start
                // arrives -- the peer cannot start one until this side has
                // sent `m.key.verification.ready`, and the only call that
                // sends one registers the flow first -- so
                // `register_if_absent` below would refuse it anyway. That
                // is an argument about four other functions, and this is
                // one map lookup.
                if machine
                    .get_verification_request(&sender, &transaction)
                    .is_some()
                {
                    continue;
                }
                let Some(comparison) = machine
                    .get_verification(&sender, &transaction)
                    .and_then(Verification::sas_v1)
                else {
                    continue;
                };
                let comparison = *comparison;

                let mut record = FlowRecord::from_comparison(comparison.clone());
                // A flow already over announces nothing. Registering one
                // would also undo the eviction rule, for the reason
                // `handles` gives about adopting a finished flow.
                if is_finished(stage_of(&mut record)) {
                    continue;
                }

                let flow_id = comparison.flow_id().as_str().to_string();
                let announcement = CryptoSignal::VerificationRequested {
                    user: comparison.other_user_id().to_string(),
                    device_id: comparison.other_device_id().to_string(),
                    flow_id: flow_id.clone(),
                };
                // The same deduplication the request path uses, and it is
                // also what keeps a flow this process started from being
                // announced back to it: its identifier is already here.
                if register_if_absent(&flow_id, record) {
                    signals.push(announcement);
                }
            }

            signals
        })
    })
    .await;

    // A machine that has gone away has nothing to announce. Swallowed
    // rather than reported: this is a notification path with no caller to
    // return an error to, and it must never turn a successful sync into a
    // failed one.
    let Ok(signals) = collected else {
        return;
    };

    announce(signals);
}

/// Hands this pass's signals to the channel, and puts back what announcing
/// an invitation to nobody consumed.
///
/// # The window this exists for
///
/// [`announce_state_changes`] reads the observer registry **once**, at
/// entry, and everything after that reads is consumption:
/// [`register_if_absent`] inserts the inbound flow, and that insertion *is*
/// the deduplication which stops the same invitation being announced twice.
/// Delivery happens here, last. An unsubscribe arriving in between --
/// which the ordinary `useEffect(() => onCryptoSignal(h), [])` produces,
/// because the JavaScript thread is free while `await
/// receiveSyncChanges(..)` is in flight -- therefore used to leave the
/// invitation registered and undelivered: refused by `register_if_absent`
/// for the rest of its life, listed by no call, expiring silently ten
/// minutes later. That is exactly the consequence
/// [`crate::observer::clear_crypto_observer`] was written to prevent, and
/// it survived inside it through a narrower window: one sync call rather
/// than the whole time a product is unsubscribed.
///
/// So a signal that reaches nobody releases the registration that producing
/// it made, and the flow is enumerated and announced afresh by the next
/// pass that has somebody to announce it to.
///
/// # Why the flow identifier can be read off the signal
///
/// `forget_flow` is destructive and must never touch a flow a caller
/// already holds. It cannot here: [`announce_state_changes`] pushes a
/// `VerificationRequested` only where `register_if_absent` returned
/// `true`, and a flow this process started, or was already told about, is
/// in the registry and makes it return `false`. So every
/// `VerificationRequested` this function sees names a flow the same pass
/// inserted, and nothing else does. That is the contract: **only ever
/// called with the signals one announcement pass just produced.**
///
/// # What is deliberately not put back
///
/// A `TrustChanged` whose delivery finds nobody stays consumed --
/// [`take_pending_completions`] has already marked the record, and
/// un-marking it would re-exempt the record from eviction. It is not the
/// same loss: which devices are verified is `device_statuses`' durable
/// answer and always was, so a missed trust change is re-askable and a
/// missed invitation is not. `signals.ts` says the same thing to a product
/// in the same words.
///
/// A `VerificationCompleted` is consumed on exactly the same terms and for
/// exactly the same reason. What a product is told to do about one is read
/// the durable answer, so what a missed one costs is the same: a question
/// it has to ask rather than a state it can never recover.
///
/// # What it still does not close
///
/// [`crate::observer::emit_crypto`] reports whether an observer was
/// registered when it read the registry, not whether the listener behind it
/// still existed when the detached delivery thread ran. An unsubscribe
/// landing in *that* gap is indistinguishable from a delivery here, and
/// closing it would mean holding the observer registry's lock across a
/// foreign call from inside the sync path. `clear_crypto_observer` records
/// that residue with its measured bound.
fn announce(signals: Vec<CryptoSignal>) {
    for signal in signals {
        // Read before the move, not after: `emit_crypto` takes the signal
        // by value, and the identifier is needed only on the arm where it
        // did not go anywhere.
        let registered = match &signal {
            CryptoSignal::VerificationRequested { flow_id, .. } => Some(flow_id.clone()),
            // The two whose consumption is recoverable; see this function's
            // header. Matched by name rather than by `_` so a variant added
            // later has to be ruled on here instead of silently joining
            // them.
            //
            // A completion is put back no more than a trust change is, and
            // for the same reason: [`take_pending_completions`] has already
            // marked the record, and un-marking it would re-exempt the
            // record from eviction. The loss is also the same one. What a
            // product does with either is read the durable answer, which
            // `device_statuses` and `identity_status` give whether or not
            // anything was delivered.
            CryptoSignal::TrustChanged { .. } | CryptoSignal::VerificationCompleted { .. } => None,
        };
        if crate::observer::emit_crypto(signal) {
            continue;
        }
        if let Some(flow_id) = registered {
            forget_flow(&flow_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every refusal this module can produce is its own `MachineError`
    /// variant, none of them folded onto another.
    ///
    /// **This said "three distinct conditions" and pinned three, and the
    /// module refused with four on the day it was written.** The count and
    /// the list have been recounted against the code rather than carried
    /// forward, because the first correction of this comment got the
    /// arithmetic wrong in the commit whose whole purpose was to stop
    /// counts going stale.
    ///
    /// Counted at three commits, excluding `NotInitialised` and `Store`
    /// throughout, and excluding `IdentityAlreadyExists`, which appears in
    /// this module only as a doc link to `signing::bootstrap_identity`:
    ///
    /// * `cff97e3`, where the three-variant test was written: **four**
    ///   (`MalformedIdentifier`, `MaterialNotReady`, `UnknownFlow`,
    ///   `WrongStage`).
    /// * `bdf0545`, the last commit before verification by a scannable
    ///   code: **seven**. Self-verification added `UnknownDevice`,
    ///   `AccountKeysNotFetched` and `IdentityNotKnown`.
    /// * `bdf0545` plus scannable codes: **fourteen**. A scannable code
    ///   added six variants of its own and made this module the second
    ///   producer of `PrivateKeysNotHeld`, which existed for
    ///   `create_recovery` and which a cross-user code now needs too.
    /// * here: **fifteen**. `PeerCannotScan` split off the half of
    ///   `CodeNotOffered` that names the far side, which the code switch
    ///   became able to distinguish once it stopped being one boolean.
    ///
    /// The name and the list went on agreeing with each other while
    /// agreeing with nothing else. Extended rather than replaced, and
    /// pairwise over a list, so that a variant added later and forgotten
    /// here is the only way it goes stale again. **The list below is the
    /// authority and this paragraph is not**: if they disagree, the list is
    /// what the test asserts.
    ///
    /// **What this defends, said plainly, because it is less than it
    /// looks.** `MachineError` derives `PartialEq`, so distinctness is
    /// nearly free and a fold has to be written by hand to break it. What
    /// it catches is exactly that: a hand-written `PartialEq`, or a variant
    /// quietly re-pointed at another. The heavier work is elsewhere and
    /// stays there: `matrix-crypto-ffi/tests/error_mapping.rs` asserts that
    /// each of these crosses to its own kind, and `tests/qr_refusals.rs`
    /// drives **eleven** of the fifteen to a real condition rather than
    /// asserting them against each other. Counted rather than carried
    /// forward: this said eight, and eight was never any of the numbers in
    /// front of it, and it then said eleven of fourteen while the file drove
    /// `PeerCannotScan` where it used to drive `CodeNotOffered`.
    ///
    /// The four `qr_refusals.rs` leaves, checked one at a time rather than
    /// grouped by a guess: `MaterialNotReady` is driven in
    /// `tests/sas_two_party.rs`; `AccountKeysNotFetched` in
    /// `tests/self_verification_unasked.rs` and its siblings;
    /// `UnknownDevice` in **this module's own test below**,
    /// `an_unknown_device_is_not_reported_as_a_malformed_identifier`, which
    /// drives it through `request_flow`, plus across the boundary in
    /// `matrix-crypto-ffi/tests/delegate_order.rs`; and `CodeNotOffered` in
    /// `tests/qr_announcement.rs`, which is where a build that asked for
    /// nothing tries to show a code. That last one is a leaf because it
    /// stopped being the answer `qr_refusals.rs` drives: the condition that
    /// file sets up is a peer with no camera, which now has its own name.
    /// This said `UnknownDevice`
    /// was driven by no test of this crate at all and named the gap as a
    /// thing to fill; the test was thirty lines further down the same file,
    /// which is what a claim about coverage costs when it is written from
    /// the integration directory alone.
    #[test]
    fn every_refusal_this_module_produces_is_its_own_error() {
        let refusals = [
            MachineError::UnknownDevice,
            MachineError::AccountKeysNotFetched,
            MachineError::UnknownFlow,
            MachineError::WrongStage,
            MachineError::MaterialNotReady,
            MachineError::MalformedIdentifier {
                detail: "flow id".to_string(),
            },
            MachineError::IdentityNotKnown,
            MachineError::PeerIdentityNotKnown,
            MachineError::PrivateKeysNotHeld,
            MachineError::CodeNotOffered,
            MachineError::PeerCannotScan,
            MachineError::ScannedCodeRefused,
            MachineError::ScannedCodeUnrecognised,
            MachineError::ScannedCodeMalformed,
            MachineError::ScannedCodeForAnotherFlow,
        ];

        for (i, left) in refusals.iter().enumerate() {
            for right in refusals.iter().skip(i + 1) {
                assert_ne!(
                    left, right,
                    "two refusals this module produces compare equal, so a caller \
                     branching on them cannot tell the conditions apart"
                );
            }
        }
    }

    /// The redacting `Debug` impls, checked against the strings they must
    /// never contain. `MachineConfig` and `Envelope` have the same test for
    /// the same reason: a derived `Debug` reintroduced later would pass
    /// every other test in this crate.
    #[test]
    fn the_authentication_material_never_reaches_a_debug_line() {
        let material = SasMaterial {
            emoji: Some(vec![SasEmoji {
                symbol: "\u{1f436}".to_string(),
                description: "Dog".to_string(),
            }]),
            decimals: (1234, 5678, 9012),
        };
        let rendered = format!("{material:?}");
        assert!(
            !rendered.contains("1234") && !rendered.contains("5678") && !rendered.contains("9012"),
            "the decimal short authentication string must not be printable: {rendered}"
        );
        assert!(
            !rendered.contains('\u{1f436}') && !rendered.contains("Dog"),
            "the symbol short authentication string must not be printable: {rendered}"
        );
        let one = format!(
            "{:?}",
            SasEmoji {
                symbol: "\u{1f436}".to_string(),
                description: "Dog".to_string(),
            }
        );
        assert!(
            !one.contains('\u{1f436}') && !one.contains("Dog"),
            "one symbol is a seventh of the answer and must not be printable: {one}"
        );
    }

    /// The bytes of a code are the shared secret the whole method rests on,
    /// so they must never be printable either.
    ///
    /// The same test as the one above, for the same reason: a derived
    /// `Debug` reintroduced later would pass every other test in this
    /// crate. Kept here as well as in `tests/qr_cross_user.rs`, which
    /// checks a real payload, because this one fails the instant the impl
    /// changes rather than only when a whole flow is driven.
    #[test]
    fn the_bytes_of_a_code_never_reach_a_debug_line() {
        let code = ScannableCode {
            // Not a real payload. A real one is 126 bytes of binary and
            // this is the recognisable part of one: whatever a `Debug`
            // prints, it must not be these.
            payload: b"MATRIX\x02\x00SUPERSECRET".to_vec(),
            width: 3,
            modules: vec![true, false, true, false, true, false, true, false, true],
        };
        let rendered = format!("{code:?}");
        assert!(
            !rendered.contains("SUPERSECRET") && !rendered.contains("77"),
            "the payload of a code is authentication material and must not be \
             printable: {rendered}"
        );
        assert!(
            !rendered.contains("true") && !rendered.contains("false"),
            "the squares are the same secret drawn as a grid, so printing them \
             prints the secret: {rendered}"
        );
        assert!(
            rendered.contains('3'),
            "the shape of a code is not its content, and a `Debug` that said \
             nothing at all would be useless for the thing a `Debug` is for: \
             {rendered}"
        );
    }

    /// **The wire a build that never asks for codes puts out is the wire it
    /// put out before codes existed.**
    ///
    /// This is the criterion the design struck as unachievable and the owner
    /// then restored, so it gets the test the spec asked for and never got.
    /// Asserted as the whole list, not as "contains the short string": a list
    /// that had grown one entry would still contain it, and growing by one
    /// entry is exactly the change this exists to catch.
    ///
    /// The literal on the right is what every release before this one
    /// announced, written out here rather than referred to, because a
    /// constant compared against itself asserts nothing.
    #[test]
    fn a_product_that_asks_for_nothing_announces_what_shipped_before_codes() {
        // The switch is process-wide and every test in this group resets it,
        // offers something and reads it back, so the tests race each other
        // under cargo's default parallel harness -- which is how run
        // 33441556286 failed here, reading `BOTH` where a concurrent reset
        // had promised `NEITHER`. `machine`'s test lock is the one this
        // crate already keeps for exactly this, and flow-creating tests
        // below hold it too, so holding it here makes the whole switch
        // single-writer in tests.
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        reset_code_capabilities_for_test();
        assert_eq!(
            announced_methods(),
            &[VerificationMethod::SasV1],
            "a product that never asked for scannable codes must say on the wire \
             exactly what every release before this one said. One method becoming \
             four is a claim a peer acts on: it makes that peer's client show its \
             user a code and ask for it to be scanned, which nothing on this side \
             can do, and no error reaches anybody because nothing was asked of this \
             library"
        );
    }

    /// **A product that can draw a code and cannot read one says exactly
    /// that**, which is the sentence this library had no way to utter.
    ///
    /// The absent `m.qr_code.scan.v1` is the whole assertion. With it
    /// present a peer may choose to show its own code and wait for a camera
    /// this product does not have, which is what a real Element Web client
    /// chose on hardware on 2026-08-31; without it that peer's own
    /// `generate_qr_code` returns nothing and it has no choice but to scan.
    ///
    /// `m.reciprocate.v1` is present and it is not this side's own message.
    /// See `SHOWING_ONLY` for the two implementations that settle why a side
    /// which never sends it must still announce it, and for the plain
    /// statement that nothing in this repository can watch that.
    #[test]
    fn a_product_that_can_only_show_says_so_and_claims_no_camera() {
        // Serialised against the sibling switch tests: see the first of them.
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        reset_code_capabilities_for_test();
        offer_codes(CodeCapabilities {
            can_show: true,
            can_scan: false,
        });
        assert_eq!(
            announced_methods(),
            &[
                VerificationMethod::SasV1,
                VerificationMethod::QrCodeShowV1,
                VerificationMethod::ReciprocateV1,
            ],
            "a product with a screen and no scanner must announce the showing half \
             and the reciprocation that lets a peer answer a code, and must not \
             announce a camera it does not have. Announcing one lets the peer choose \
             to show instead, and nothing here can read what it shows"
        );
    }

    /// The mirror, because the two facts are independent and a product that
    /// owns a camera and no surface to draw on is as real as the one above.
    #[test]
    fn a_product_that_can_only_scan_says_that_instead() {
        // Serialised against the sibling switch tests: see the first of them.
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        reset_code_capabilities_for_test();
        offer_codes(CodeCapabilities {
            can_show: false,
            can_scan: true,
        });
        assert_eq!(
            announced_methods(),
            &[
                VerificationMethod::SasV1,
                VerificationMethod::QrCodeScanV1,
                VerificationMethod::ReciprocateV1,
            ],
            "a product that reads codes and draws none must announce the scanning \
             half alone, or a peer will wait for a square that is never drawn"
        );
    }

    /// And what a product that really can do both announces, plus the undo.
    ///
    /// The four answers together are the point. Any one of them alone would
    /// pass against a switch that ignored its argument, and the first three
    /// together would pass against one that ignored `can_scan`.
    #[test]
    fn asking_for_both_announces_both_and_the_switch_is_not_a_latch() {
        // Serialised against the sibling switch tests: see the first of them.
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        reset_code_capabilities_for_test();
        offer_codes(CodeCapabilities {
            can_show: true,
            can_scan: true,
        });
        assert_eq!(
            announced_methods(),
            &[
                VerificationMethod::SasV1,
                VerificationMethod::QrCodeShowV1,
                VerificationMethod::QrCodeScanV1,
                VerificationMethod::ReciprocateV1,
            ],
            "a product that owns both a screen and a scanner may claim both, and \
             this is the list it was always right to send"
        );
        offer_codes(CodeCapabilities {
            can_show: false,
            can_scan: false,
        });
        assert_eq!(
            announced_methods(),
            &[VerificationMethod::SasV1],
            "and taking both halves back must put the old wire back, or the switch \
             is a latch and a product could not undo it"
        );
    }

    /// What the switch was told is what it reports, field by field.
    ///
    /// **All four combinations, and each field read separately.** A store
    /// that raised both bits together, or that dropped one, satisfies any
    /// test that only ever asks for both at once, and dropping one field is
    /// the exact shape of the defect the record replaces.
    #[test]
    fn each_half_of_the_switch_is_stored_and_reported_on_its_own() {
        // Serialised against the sibling switch tests: see the first of them.
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        for can_show in [false, true] {
            for can_scan in [false, true] {
                reset_code_capabilities_for_test();
                offer_codes(CodeCapabilities { can_show, can_scan });
                assert_eq!(
                    code_capabilities(),
                    CodeCapabilities { can_show, can_scan },
                    "the two halves are independent facts about a product and a \
                     switch that folded them would announce a claim nobody made"
                );
            }
        }
        reset_code_capabilities_for_test();
        assert_eq!(
            code_capabilities(),
            CodeCapabilities {
                can_show: false,
                can_scan: false,
            },
            "and a fresh process claims neither"
        );
    }

    const OTHER_USER: &str = "@other:example.org";
    const OTHER_DEVICE: &str = "OTHERDEVICE";

    /// Teaches the live machine about one device of another user, so a flow
    /// can be started against it.
    ///
    /// Built the same way `session.rs`'s own tests build one: a bare
    /// upstream machine publishes real, self-signed device keys, and those
    /// keys come back through this crate's own pump as the response to a
    /// device query. Fabricated keys would be rejected, and no shortcut
    /// through `with_machine` is needed because the shipped surface can
    /// already do all of it.
    async fn teach_the_machine_about_a_device() {
        let other_user: matrix_sdk_common::ruma::OwnedUserId = OTHER_USER.parse().unwrap();
        let other_device: matrix_sdk_common::ruma::OwnedDeviceId = OTHER_DEVICE.into();
        let other = matrix_sdk_crypto::OlmMachine::new(&other_user, &other_device).await;
        let device_keys = other
            .outgoing_requests()
            .await
            .unwrap()
            .iter()
            .find_map(|request| match request.request() {
                matrix_sdk_crypto::types::requests::AnyOutgoingRequest::KeysUpload(upload) => {
                    upload.device_keys.clone()
                }
                _ => None,
            })
            .expect("a fresh machine always has device keys to upload");

        crate::session::receive_sync_changes(&format!(
            r#"{{"changed_devices":{{"changed":["{OTHER_USER}"],"left":[]}}}}"#
        ))
        .await
        .unwrap();
        let query_id = crate::session::take_outgoing_requests()
            .await
            .unwrap()
            .into_iter()
            .find(|request| request.kind == "keys_query")
            .expect("a machine that has been told a user changed asks about them")
            .id;
        crate::session::mark_request_sent(
            &query_id,
            &serde_json::json!({
                "device_keys": {
                    OTHER_USER: { OTHER_DEVICE: serde_json::to_value(&device_keys).unwrap() }
                }
            })
            .to_string(),
        )
        .await
        .unwrap();
    }

    /// The registry must be emptied while the machine still holds the store,
    /// not after it has been dropped.
    ///
    /// This test exists because getting that backwards does not fail an
    /// assertion. A registry entry holds an upstream verification handle,
    /// which holds an `Arc` on the crypto store; if `reset_for_test` drops
    /// the machine first, the entry's reference becomes the last one and is
    /// released on this bare synchronous test thread, where closing the
    /// pooled Sqlite connections panics with "no reactor running" -- twice,
    /// in a destructor, which is a non-unwinding panic that **aborts the
    /// whole test process** with SIGABRT. So the failure this guards
    /// against does not appear as a red test; it appears as the suite
    /// dying, which is why it needs a test that actually registers a flow
    /// rather than a comment saying it would matter if one ever did.
    /// Deliberately **not** `#[tokio::test]`, unlike its neighbours. The
    /// hazard exists only on a thread with no runtime in scope, and an
    /// ambient one hides it completely: under `#[tokio::test]` this passes
    /// whichever order the two statements are in, which was measured rather
    /// than assumed. So the setup runs inside `in_runtime` and the call
    /// under test runs outside it, on the bare synchronous thread
    /// `block_on` is driving -- which is where a test process actually is
    /// when it calls this.
    #[test]
    fn the_registry_is_emptied_before_the_store_it_holds_alive_is_dropped() {
        let _guard = futures::executor::block_on(crate::machine::lock_for_test());
        crate::machine::reset_for_test();
        // Held for the whole test rather than moved into the block below:
        // the store directory must not be deleted out from under the
        // machine that is still using it.
        let dir = tempfile::tempdir().unwrap();
        let machine_config = config(dir.path());

        let registered = futures::executor::block_on(crate::in_runtime(async move {
            crate::machine::create_machine(machine_config)
                .await
                .unwrap();
            teach_the_machine_about_a_device().await;
            let flow = request_flow(OTHER_USER, OTHER_DEVICE)
                .await
                .expect("a device the machine has been told about can be asked to verify");
            assert_eq!(
                flow_stage(&flow).await.expect("the flow exists"),
                FlowStage::Requested
            );
            flow_count()
        }));
        assert_eq!(
            registered, 1,
            "this test proves nothing unless the registry is actually holding a handle"
        );

        // The call under test, from a thread with no runtime in scope. It
        // either releases the registry's handle while the machine still
        // holds the store -- in which case this returns and the assertion
        // below runs -- or it makes the registry's the last reference and
        // drops the store here, in which case there is no assertion to
        // reach because the process is gone.
        crate::machine::reset_for_test();
        assert_eq!(
            flow_count(),
            0,
            "the registry must be empty once the machine it belongs to is gone"
        );
    }

    fn config(dir: &std::path::Path) -> crate::machine::MachineConfig {
        crate::machine::MachineConfig {
            user_id: "@self:example.org".to_string(),
            device_id: "SELFDEVICE".to_string(),
            store_path: dir.join("store").to_string_lossy().into_owned(),
            store_passphrase: Some("test-passphrase".to_string()),
        }
    }

    /// A device this machine has never been told about is not the same
    /// condition as an identifier that does not parse, and the two must not
    /// arrive as one error.
    ///
    /// They were one error until a review pointed out that they call for
    /// different things: the first is fixed by querying that user's devices
    /// through the pump and trying again, the second by passing something
    /// else. Both assertions are here because the pair is the point; either
    /// one alone would keep passing if the fold came back.
    #[tokio::test]
    async fn an_unknown_device_is_not_reported_as_a_malformed_identifier() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        crate::machine::create_machine(config(dir.path()))
            .await
            .unwrap();

        assert_eq!(
            request_flow("@nobody:example.org", "NOSUCHDEVICE")
                .await
                .expect_err("this machine has never queried that user"),
            MachineError::UnknownDevice
        );
        assert_eq!(
            request_flow("not-a-user-id", "NOSUCHDEVICE")
                .await
                .expect_err("that identifier does not parse"),
            MachineError::MalformedIdentifier {
                detail: "user id".to_string()
            }
        );

        crate::machine::reset_for_test();
    }

    /// A listener that does nothing, so a test can put an observer in the
    /// registry without also building a channel to read.
    struct Silent;

    impl crate::observer::CryptoObserver for Silent {
        fn on_signal(&self, _signal: CryptoSignal) {}
    }

    /// An announcement that reaches nobody must put back the registration
    /// that producing it made.
    ///
    /// # What it is protecting
    ///
    /// [`announce_state_changes`] reads the observer registry once, at
    /// entry, and consumes afterwards: `register_if_absent` inserts the
    /// inbound flow, and that insertion is the deduplication. So an
    /// unsubscribe landing between the entry read and the delivery left the
    /// invitation registered and undelivered -- announced to nobody, then
    /// refused to everybody, and gone when it expired ten minutes later.
    /// The same consequence `clear_crypto_observer` exists to prevent,
    /// surviving inside it through a one-sync window.
    ///
    /// # Why this is a unit test and not a race
    ///
    /// The window was reproduced through the public surface before it was
    /// closed, by racing `clear_crypto_observer` against
    /// `receive_sync_changes` on the `tests/sas_two_party.rs` arrangement,
    /// sweeping the unsubscribe across the sync in five-microsecond steps:
    /// an unsubscribe 76us before a 5.0ms sync returned consumed the
    /// invitation, and the next subscriber was never told about it. That
    /// reproduction is not kept, because it cannot be kept honestly. The
    /// announcing pass is the last few tens of microseconds of that five
    /// milliseconds, so a timing sweep lands in it on this machine and need
    /// not on another -- and once the loss is fixed, an unsubscribe before
    /// the entry guard and one after it are indistinguishable from outside,
    /// so nothing in such a test could assert that it had reached the state
    /// it is about. A check that reports success without examining its
    /// target is the failure this repository keeps finding; this one drives
    /// the seam instead, where the interleaving is decided rather than
    /// hoped for.
    ///
    /// The flow here is one this process started, which
    /// [`announce_state_changes`] would never announce -- it is in the
    /// registry, so `register_if_absent` returns `false` for it. That is
    /// the point: it stands in for "a flow the registry holds", and what is
    /// under test is what [`announce`] does with the pairing its caller
    /// hands it, which is the half a race cannot pin down.
    #[tokio::test]
    async fn an_invitation_announced_to_nobody_is_released_rather_than_left_registered() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();
        let dir = tempfile::tempdir().unwrap();
        crate::machine::create_machine(config(dir.path()))
            .await
            .unwrap();
        teach_the_machine_about_a_device().await;

        let flow = request_flow(OTHER_USER, OTHER_DEVICE)
            .await
            .expect("a device the machine has been told about can be asked to verify");
        assert_eq!(
            flow_count(),
            1,
            "this test proves nothing unless the registry is actually holding the flow"
        );
        let invitation = || CryptoSignal::VerificationRequested {
            user: OTHER_USER.to_string(),
            device_id: OTHER_DEVICE.to_string(),
            flow_id: flow.0.clone(),
        };

        // Somebody is listening: the signal is taken, and the registration
        // that produced it stands. Asserted first, because a `forget_flow`
        // that fired unconditionally would pass every assertion below.
        crate::observer::set_crypto_observer(std::sync::Arc::new(Silent));
        announce(vec![invitation()]);
        assert_eq!(
            flow_count(),
            1,
            "an invitation that reached a subscriber must stay registered, or the next sync \
             announces it a second time"
        );

        // Nobody is listening, and the consumption is not the same in both
        // directions. A trust change is re-askable through `device_statuses`
        // and its record must not be released with it -- `release_finished`
        // is what evicts a finished flow, on its own rule.
        crate::observer::clear_crypto_observer();
        announce(vec![CryptoSignal::TrustChanged {
            user: OTHER_USER.to_string(),
            state: TrustState::Verified,
        }]);
        assert_eq!(
            flow_count(),
            1,
            "a trust change nobody heard must not take a live flow with it"
        );

        // The invitation is the one that cannot be re-asked for, so it is
        // the one that has to be put back.
        announce(vec![invitation()]);
        assert_eq!(
            flow_count(),
            0,
            "an invitation announced to nobody must release its registration: leaving it is \
             what makes `register_if_absent` refuse the flow for the rest of its life, with no \
             call that lists inbound flows to recover it from"
        );

        crate::machine::reset_for_test();
    }

    /// A flow nothing ever registered, on a process with no machine at all:
    /// the registry misses, the resolution against upstream cannot even be
    /// attempted, and the caller is told so rather than left waiting.
    #[tokio::test]
    async fn an_identifier_no_flow_ever_had_is_reported() {
        let _guard = crate::machine::lock_for_test().await;
        crate::machine::reset_for_test();

        let error = flow_stage(&FlowId("not-a-flow".to_string()))
            .await
            .expect_err("no machine exists, so no flow can be found");
        assert_eq!(error, MachineError::NotInitialised);
    }
}
