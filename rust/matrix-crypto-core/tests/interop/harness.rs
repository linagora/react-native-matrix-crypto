//! The parts of level 2 that are not the proof: a homeserver spoken to over
//! HTTP, a login, the outbound pump addressed and posted, the `matrix-nio`
//! subprocess, and the teardown that removes whatever a run created.
//!
//! # Why this is a module and not two copies
//!
//! There are two level 2 proofs -- `level_two_interop.rs`, which asks
//! whether a third-party client decrypts what this library encrypts, and
//! `level_two_verification.rs`, which asks whether one will complete a
//! device verification with it. They are separate test binaries because
//! this library holds one crypto machine per process and Cargo gives each
//! file under `tests/` its own; they are separate *proofs* because they
//! answer different questions. What they share is all of the above, none of
//! which is the thing being proven. A second copy of the teardown guard, or
//! of the `kind` -> endpoint mapping, is a second thing to keep correct.
//!
//! Included with `#[path]` rather than as `tests/common/mod.rs`, so it sits
//! beside the Python counterparty it drives.
//!
//! # Nothing here asserts anything about cryptography
//!
//! Every assertion in this file is about the harness itself: that a request
//! could be sent, that a reply parsed, that the subprocess is alive. The
//! claims the milestone rests on are in the two test files, on purpose --
//! a proof whose load-bearing assertion lives in shared scaffolding is a
//! proof nobody reads.

// Each of the two test binaries compiles its own copy of this module and
// uses most, not all, of it: `level_two_verification.rs` creates no room
// and corrupts no ciphertext, so it never calls `addresses`. Allowed here
// rather than split into ever-smaller modules, because the alternative is
// arranging shared code around which consumer happens to use which half.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use matrix_crypto_core::{mark_request_sent, take_outgoing_requests, OutgoingRequest};
use serde_json::{json, Value};

pub const HOMESERVER_ENV: &str = "MATRIX_INTEROP_HOMESERVER";
pub const USER_ENV: &str = "MATRIX_INTEROP_USER";
pub const PASSWORD_ENV: &str = "MATRIX_INTEROP_PASSWORD";
pub const PYTHON_ENV: &str = "MATRIX_INTEROP_NIO_PYTHON";
pub const NIO_STORE_ENV: &str = "MATRIX_INTEROP_NIO_STORE";

/// Reads a required variable, naming it and never its value.
pub fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} must be set; see this file's header for the full invocation")
    })
}

pub fn run<F: std::future::Future>(future: F) -> F::Output {
    // Deliberately not wrapped in `in_runtime`, unlike `two_parties.rs`,
    // which needs a tokio context for the *bare* second machine it drives.
    // There is no bare machine here -- the counterparty is a separate
    // process -- so every library call below enters with genuinely no
    // ambient runtime, which is the calling context the FFI actually has.
    futures::executor::block_on(future)
}

/// Percent-encodes one path segment. Room ids and sync tokens are opaque
/// server-chosen strings; encoding everything outside the unreserved set is
/// the only assumption-free way to put one in a URL.
pub fn encode_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The homeserver, spoken to directly
// ---------------------------------------------------------------------------

pub struct Homeserver {
    pub agent: ureq::Agent,
    pub base: String,
}

impl Homeserver {
    pub fn new(base: String) -> Self {
        Homeserver {
            agent: ureq::AgentBuilder::new()
                .timeout_connect(Duration::from_secs(20))
                // Longer than any single call needs, because `/sync` is
                // long-polled below with a server-side timeout of its own.
                .timeout_read(Duration::from_secs(120))
                .build(),
            base: base.trim_end_matches('/').to_string(),
        }
    }

    /// Returns `(status, body)`, or `None` if the request could not be sent
    /// at all. **Never panics**, which is what makes it usable from a `Drop`
    /// during an unwind: a panic there would abort the process and replace a
    /// readable assertion failure with a SIGABRT.
    ///
    /// Never formats the token or the request body into anything either: a
    /// `/keys/upload` body is key material and an `Authorization` header is a
    /// live credential.
    pub fn try_call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&str>,
    ) -> Option<(u16, String)> {
        let url = format!("{}{path}", self.base);
        let mut request = self
            .agent
            .request(method, &url)
            .set("Content-Type", "application/json");
        if let Some(token) = token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        let result = match body {
            Some(body) => request.send_string(body),
            None => request.call(),
        };
        match result {
            Ok(response) => {
                let status = response.status();
                Some((status, response.into_string().unwrap_or_default()))
            }
            Err(ureq::Error::Status(status, response)) => {
                Some((status, response.into_string().unwrap_or_default()))
            }
            Err(ureq::Error::Transport(_)) => None,
        }
    }

    /// The same call, for the test body rather than for teardown: a request
    /// that cannot be sent at all is a failure worth stopping on. The
    /// transport error is not reproduced, only that the call could not be
    /// made -- `ureq`'s `Transport` display carries the URL, which is
    /// harmless, but this keeps the one rule about what may reach a panic
    /// message simple rather than case-by-case.
    pub fn call(
        &self,
        method: &str,
        path: &str,
        token: Option<&str>,
        body: Option<&str>,
    ) -> (u16, String) {
        self.try_call(method, path, token, body)
            .unwrap_or_else(|| panic!("{method} {path} could not be sent"))
    }

    /// The same call, insisting on a 2xx and a JSON body.
    pub fn ok(&self, method: &str, path: &str, token: Option<&str>, body: Option<&str>) -> Value {
        let (status, body) = self.call(method, path, token, body);
        assert!(
            (200..300).contains(&status),
            "{method} {path} returned {status}: {body}"
        );
        serde_json::from_str(&body)
            .unwrap_or_else(|_| panic!("{method} {path} returned a body that is not JSON: {body}"))
    }
}

pub struct LoggedIn {
    pub token: String,
    pub user_id: String,
    pub device_id: String,
}

// ---------------------------------------------------------------------------
// Teardown, on every path out
// ---------------------------------------------------------------------------

/// Everything this run created on somebody else's homeserver, removed by
/// `Drop` rather than by statements at the end of the test.
///
/// The first version of this test tidied up after its last assertion, which
/// meant every *failing* run left a device and a room behind on a shared
/// server -- and a test whose failures accumulate debris on real
/// infrastructure is a test people stop running. Six mutation runs left
/// twelve devices and six rooms to be removed by hand before this existed.
///
/// `Drop` runs while the thread unwinds from a failed assertion, so the whole
/// of this must be infallible: every call goes through `Homeserver::try_call`,
/// which returns `None` rather than panicking, and every result is discarded.
/// A panic raised during an unwind aborts the process, which would replace the
/// assertion message somebody needs to read with a SIGABRT.
///
/// Deleting the counterparty's device is done from *here*, over
/// `/delete_devices` with user-interactive auth, rather than by asking the nio
/// subprocess to log itself out. The subprocess is exactly what may have died,
/// and a teardown that depends on the thing that failed is not a teardown. The
/// happy path still asks nio to log out politely (`op: quit`) and then calls
/// `counterparty_logged_itself_out`, so the fallback costs a round trip only
/// when it is actually needed.
pub struct Teardown<'a> {
    pub homeserver: &'a Homeserver,
    pub token: String,
    pub user_id: String,
    pub password: String,
    pub room_id: Option<String>,
    pub devices: Vec<String>,
}

impl<'a> Teardown<'a> {
    pub fn new(homeserver: &'a Homeserver, library: &LoggedIn, password: &str) -> Self {
        Teardown {
            homeserver,
            token: library.token.clone(),
            user_id: library.user_id.clone(),
            password: password.to_string(),
            room_id: None,
            devices: Vec::new(),
        }
    }

    pub fn owns_room(&mut self, room_id: &str) {
        self.room_id = Some(room_id.to_string());
    }

    pub fn owns_device(&mut self, device_id: &str) {
        self.devices.push(device_id.to_string());
    }

    pub fn counterparty_logged_itself_out(&mut self) {
        self.devices.clear();
    }

    /// `POST /_matrix/client/v3/delete_devices`, answering the
    /// user-interactive-auth challenge it always issues first. Infallible by
    /// construction: every step that could fail returns early instead.
    pub fn delete_devices(&self) {
        let devices = json!({ "devices": self.devices }).to_string();
        let Some((status, challenge)) = self.homeserver.try_call(
            "POST",
            "/_matrix/client/v3/delete_devices",
            Some(&self.token),
            Some(&devices),
        ) else {
            return;
        };
        if status != 401 {
            return;
        }
        let Ok(challenge) = serde_json::from_str::<Value>(&challenge) else {
            return;
        };
        let Some(session) = challenge["session"].as_str() else {
            return;
        };
        // The password is used here and nowhere else in teardown, and this
        // body is never formatted into any message.
        let authenticated = json!({
            "devices": self.devices,
            "auth": {
                "type": "m.login.password",
                "identifier": { "type": "m.id.user", "user": self.user_id },
                "password": self.password,
                "session": session,
            },
        })
        .to_string();
        let _ = self.homeserver.try_call(
            "POST",
            "/_matrix/client/v3/delete_devices",
            Some(&self.token),
            Some(&authenticated),
        );
    }
}

impl Drop for Teardown<'_> {
    fn drop(&mut self) {
        if let Some(room_id) = &self.room_id {
            let path = encode_segment(room_id);
            let _ = self.homeserver.try_call(
                "POST",
                &format!("/_matrix/client/v3/rooms/{path}/leave"),
                Some(&self.token),
                Some("{}"),
            );
            let _ = self.homeserver.try_call(
                "POST",
                &format!("/_matrix/client/v3/rooms/{path}/forget"),
                Some(&self.token),
                Some("{}"),
            );
        }
        if !self.devices.is_empty() {
            self.delete_devices();
        }
        // Last: this deletes the device whose token every call above used.
        let _ = self.homeserver.try_call(
            "POST",
            "/_matrix/client/v3/logout",
            Some(&self.token),
            Some("{}"),
        );
    }
}

pub fn login(homeserver: &Homeserver, user: &str, password: &str, display_name: &str) -> LoggedIn {
    // Built with `json!` and never printed. The password reaches this
    // function as a borrowed `&str` read from the environment, is used once
    // here, and is not stored on the returned value.
    let body = json!({
        "type": "m.login.password",
        "identifier": { "type": "m.id.user", "user": user },
        "password": password,
        "initial_device_display_name": display_name,
    })
    .to_string();

    let (status, response) = homeserver.call("POST", "/_matrix/client/v3/login", None, Some(&body));
    assert_eq!(
        status, 200,
        "login as {user} failed with {status}; the response body is deliberately not \
         reproduced here because a login error body can echo the request"
    );
    let response: Value =
        serde_json::from_str(&response).expect("a successful login returns a JSON body");

    LoggedIn {
        token: response["access_token"]
            .as_str()
            .expect("a successful login carries an access token")
            .to_string(),
        user_id: response["user_id"]
            .as_str()
            .expect("a successful login carries a user id")
            .to_string(),
        device_id: response["device_id"]
            .as_str()
            .expect("a successful login carries a device id")
            .to_string(),
    }
}

// ---------------------------------------------------------------------------
// The pump, addressed and posted
// ---------------------------------------------------------------------------

/// The top-level `event_type` a to-device request's body declares.
///
/// Nothing in this file may assert on `kind == "to_device"` alone: an
/// `m.room_key.withheld` notice -- a message whose content is "I could not
/// send you the key" -- has the same kind as the key itself, and design doc
/// section 3ter exists because that difference is invisible from outside.
pub fn declared_event_type(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| value.get("event_type")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| "<no event_type in body>".to_string())
}

/// Whether a to-device request addresses this exact device.
pub fn addresses(body: &str, user_id: &str, device_id: &str) -> bool {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| {
            Some(
                value
                    .get("messages")?
                    .get(user_id)?
                    .get(device_id)
                    .is_some(),
            )
        })
        .unwrap_or(false)
}

/// Where one request the pump handed out has to be sent, and with what body.
///
/// The `kind` -> endpoint mapping is spec section 3bis's, extended for the
/// claim step section 3ter added and for the two publication steps M4 added.
/// An unrecognised kind panics rather than being skipped: `kind` is an open
/// tag, and a tag this harness cannot route is a finding about the surface,
/// not something to swallow.
///
/// Separate from [`send_outgoing`] because one of the seven kinds cannot be
/// posted the way the other six can. `signing_keys_upload` goes to a
/// user-interactive endpoint that refuses the first attempt with a `401` and
/// a challenge, so a caller has to send it, read the refusal, and send it
/// again with an `auth` object merged in. That loop is a proof rather than
/// plumbing -- it is where a product decides what to report through
/// `mark_request_failed` and what through `mark_request_sent` -- so it lives
/// in the test that makes the claim, and only the addressing lives here.
pub fn endpoint(request: &OutgoingRequest) -> (&'static str, String, String) {
    match request.kind.as_str() {
        "keys_upload" => (
            "POST",
            "/_matrix/client/v3/keys/upload".to_string(),
            request.body.clone(),
        ),
        "keys_query" => (
            "POST",
            "/_matrix/client/v3/keys/query".to_string(),
            request.body.clone(),
        ),
        "keys_claim" => (
            "POST",
            "/_matrix/client/v3/keys/claim".to_string(),
            request.body.clone(),
        ),
        // The two M4 added. `signing_keys_upload` is the user-interactive
        // one; see this function's own header for why its refusal loop is
        // not here. `signature_upload`'s body is the signed-keys map at the
        // top level rather than a wrapper around it, which is what
        // `describe_outgoing` already builds.
        "signing_keys_upload" => (
            "POST",
            "/_matrix/client/v3/keys/device_signing/upload".to_string(),
            request.body.clone(),
        ),
        "signature_upload" => (
            "POST",
            "/_matrix/client/v3/keys/signatures/upload".to_string(),
            request.body.clone(),
        ),
        "to_device" => {
            // The endpoint carries the event type and transaction id in its
            // URL and takes only `messages` as its body. The pump's body
            // additionally carries both, which is what makes building this
            // URL possible at all -- see `describe_outgoing`'s own comment
            // in `session.rs`.
            let parsed: Value = serde_json::from_str(&request.body)
                .expect("the pump's own to-device body is well-formed JSON");
            let event_type = parsed["event_type"]
                .as_str()
                .expect("a to-device request names its event type");
            let txn_id = parsed["txn_id"]
                .as_str()
                .expect("a to-device request names its transaction id");
            (
                "PUT",
                format!(
                    "/_matrix/client/v3/sendToDevice/{}/{}",
                    encode_segment(event_type),
                    encode_segment(txn_id)
                ),
                json!({ "messages": parsed["messages"] }).to_string(),
            )
        }
        other => panic!(
            "the pump handed out a request of kind {other:?}, which this harness does not \
             route. `kind` is an open tag, so this is a finding about the surface: either \
             the endpoint is missing from spec section 3bis's mapping, or the harness is \
             behind it."
        ),
    }
}

/// Sends one request the pump handed out, to the endpoint [`endpoint`] names,
/// and returns the homeserver's response body for `mark_request_sent`.
///
/// Insists on a 2xx, so this is the wrong call for a `signing_keys_upload`:
/// that request's first attempt is *supposed* to be refused. See
/// [`endpoint`] for where its loop lives instead.
pub fn send_outgoing(homeserver: &Homeserver, token: &str, request: &OutgoingRequest) -> String {
    let (method, path, body) = endpoint(request);

    let (status, response) = homeserver.call(method, &path, Some(token), Some(&body));
    assert!(
        (200..300).contains(&status),
        "{method} {path} for a {} request returned {status}: {response}",
        request.kind
    );
    response
}

/// Drains the pump once and posts everything it yields, returning the batch
/// so the caller can assert on what was in it.
pub fn pump_and_send(homeserver: &Homeserver, token: &str) -> Vec<OutgoingRequest> {
    let batch = run(take_outgoing_requests()).expect("the pump must be drainable");
    for request in &batch {
        let response = send_outgoing(homeserver, token, request);
        run(mark_request_sent(&request.id, &response)).unwrap_or_else(|error| {
            panic!(
                "the homeserver's own response to a {} request was rejected by \
                 mark_request_sent: {error:?}",
                request.kind
            )
        });
    }
    batch
}

/// The five fields `receive_sync_changes` reads, lifted out of a real
/// `/sync` body.
///
/// The rename is not incidental and is worth seeing in one place: the
/// accepted shape mirrors `matrix-sdk-crypto`'s own `EncryptionSyncChanges`
/// (spec section 3bis), not the `/sync` response, so `to_device.events`
/// becomes `to_device_events`, `device_lists` becomes `changed_devices`,
/// `device_one_time_keys_count` becomes `one_time_keys_counts`,
/// `device_unused_fallback_key_types` becomes `unused_fallback_keys` and
/// `next_batch` becomes `next_batch_token`. A product that passes the raw
/// `/sync` body straight through gets a successful call that teaches the
/// machine nothing -- which is what the facade's own documentation warns
/// about, and what this function is the working counter-example to.
pub fn encryption_slice(sync: &Value) -> Value {
    let mut slice = serde_json::Map::new();
    if let Some(events) = sync.get("to_device").and_then(|t| t.get("events")) {
        slice.insert("to_device_events".to_string(), events.clone());
    }
    if let Some(device_lists) = sync.get("device_lists") {
        slice.insert("changed_devices".to_string(), device_lists.clone());
    }
    if let Some(counts) = sync.get("device_one_time_keys_count") {
        slice.insert("one_time_keys_counts".to_string(), counts.clone());
    }
    if let Some(fallback) = sync.get("device_unused_fallback_key_types") {
        slice.insert("unused_fallback_keys".to_string(), fallback.clone());
    }
    if let Some(next_batch) = sync.get("next_batch") {
        slice.insert("next_batch_token".to_string(), next_batch.clone());
    }
    Value::Object(slice)
}

// ---------------------------------------------------------------------------
// The third-party client, driven as a subprocess
// ---------------------------------------------------------------------------

pub struct NioParty {
    pub child: Child,
    pub stdin: ChildStdin,
    pub stdout: BufReader<ChildStdout>,
    pub stderr: Arc<Mutex<String>>,
}

impl NioParty {
    pub fn start(python: &str, script: &std::path::Path, store_path: &std::path::Path) -> Self {
        Self::start_as(
            python,
            script,
            &[(NIO_STORE_ENV, store_path.to_string_lossy().into_owned())],
        )
    }

    /// The second counterparty child for the federated proof: the SAME
    /// interpreter and script, but a DIFFERENT account on a DIFFERENT
    /// homeserver, so this process must not read the first child's
    /// `MATRIX_INTEROP_HOMESERVER`/`MATRIX_INTEROP_USER`/store. Each entry in
    /// `env_overrides` replaces one variable in the child's environment; the
    /// password is deliberately NOT overridable -- both accounts share the one
    /// password, and it reaches the child by inheritance only, exactly as in
    /// `start`. Why the second user is a nio subprocess at all, rather than a
    /// second machine of this library, is `level_two_federated.rs`'s whole
    /// header: the machine registry holds one machine per process.
    pub fn start_as(
        python: &str,
        script: &std::path::Path,
        env_overrides: &[(&str, String)],
    ) -> Self {
        let mut command = Command::new(python);
        command.arg(script);
        for (name, value) in env_overrides {
            command.env(name, value);
        }
        // The password reaches the subprocess by inheriting this
        // process's environment, never on the command line: `ps` shows
        // argv to every user on the machine and environments only to the
        // owner.
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| {
                panic!(
                    "could not start the nio counterparty with {python:?}; set {PYTHON_ENV} to a \
                     Python that has matrix-nio[e2e] installed ({error})"
                )
            });

        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = BufReader::new(child.stdout.take().expect("stdout was piped"));
        let mut child_stderr = child.stderr.take().expect("stderr was piped");

        // Drained on its own thread rather than left to fill a 64 KiB pipe
        // buffer and deadlock the child mid-reply. Kept in memory and only
        // ever surfaced inside a panic message, so a passing run prints
        // nothing.
        let stderr = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&stderr);
        std::thread::spawn(move || {
            let mut buffer = Vec::new();
            let _ = child_stderr.read_to_end(&mut buffer);
            if let Ok(mut sink) = sink.lock() {
                sink.push_str(&String::from_utf8_lossy(&buffer));
            }
        });

        NioParty {
            child,
            stdin,
            stdout,
            stderr,
        }
    }

    pub fn stderr_so_far(&self) -> String {
        self.stderr
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    pub fn call(&mut self, command: Value) -> Value {
        let op = command["op"].as_str().unwrap_or("<none>").to_string();
        writeln!(self.stdin, "{command}").expect("the nio counterparty must accept a command");
        self.stdin.flush().expect("the command must be flushed");

        let mut line = String::new();
        let read = self
            .stdout
            .read_line(&mut line)
            .expect("the nio counterparty's reply must be readable");
        assert!(
            read > 0,
            "the nio counterparty closed its output without replying to {op:?}. Its stderr was:\n{}",
            self.stderr_so_far()
        );

        let reply: Value = serde_json::from_str(&line).unwrap_or_else(|_| {
            panic!(
                "the nio counterparty's reply to {op:?} is not JSON: {line}\nIts stderr was:\n{}",
                self.stderr_so_far()
            )
        });
        assert_eq!(
            reply["ok"],
            json!(true),
            "the nio counterparty failed {op:?}: {}",
            reply["error"]
        );
        reply
    }
}

impl Drop for NioParty {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
