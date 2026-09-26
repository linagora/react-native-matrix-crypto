//! The one tokio runtime this library owns.
//!
//! `matrix-sdk-crypto` reaches `tokio::task::spawn` through `matrix-sdk-common`
//! during group key sharing, and `matrix-sdk-sqlite` uses tokio's filesystem and
//! connection-pool primitives. Both panic outside a runtime context. UniFFI drives
//! this crate's `async fn` exports from the foreign side, which provides no such
//! context, so the library must supply its own.

use std::future::Future;
use std::sync::OnceLock;

use tokio::runtime::{Builder, Runtime};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Multi-threaded on purpose. On a `current_thread` runtime, work handed to
/// `tokio::task::spawn` only progresses while something is actively polling the
/// runtime, which is a deadlock waiting for a specific call pattern to find it.
fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the crypto runtime could not be built")
    })
}

/// Runs `work` on this library's blocking pool, and does not wait for it.
///
/// Three properties, each of which something in this crate depends on:
///
/// - **It needs no ambient runtime.** `tokio::task::spawn_blocking` is a free
///   function that reads the thread's ambient runtime and panics when there is
///   none. This reaches the runtime this crate owns directly, so it works from
///   any thread, including a foreign one that has never seen tokio. That is
///   the property `observer::emit` inherited from `std::thread::spawn` and
///   must keep: a signal can be produced on a path a foreign caller drove
///   without entering `in_runtime` first.
/// - **It cannot stall the runtime's async work.** The blocking pool is a
///   different set of threads from the two workers `in_runtime` schedules on,
///   so work handed here may block for as long as it likes -- and a foreign
///   callback may block for as long as the foreign side likes -- without
///   stopping encryption or any other call in flight. Handing the same work to
///   `spawn` would occupy a worker for its whole duration, and there are two.
/// - **It is bounded, unlike a thread per call.** Tokio caps the pool (512
///   threads by default) and reuses idle threads rather than creating one per
///   task. Past the cap, work queues. That cap is shared rather than ours
///   alone: `matrix-sdk-sqlite` reaches the same pool through `deadpool-sync`
///   and `deadpool-runtime`, whose `spawn_blocking` is tokio's.
///
/// **The sharing runs in both directions, and only one of them used to be
/// written down here.** Outbound: a caller that parked hundreds of pool
/// threads would delay the crypto store. Inbound, and this is the direction
/// `observer::emit` is about: the store's own blocking work now runs in the
/// same pool as signal delivery, so sqlite can delay a signal. A thread per
/// signal could not be delayed by anything, because it shared nothing.
///
/// That inbound half is judged acceptable, and here is the bound it rests on
/// rather than an assurance. `SqliteCryptoStore::open` -- what `machine.rs`
/// calls -- takes `SqliteStoreConfig`'s default pool size, which upstream
/// computes as `max(2, physical_cpus * 4)`: 32 on an eight-core phone, four
/// on a single-core one. The store therefore cannot occupy more than a few
/// dozen of the 512, so it cannot make a signal *queue*; queueing needs more
/// than an order of magnitude more parked threads than the store can produce,
/// and those would have to come from listener callbacks, which is the
/// outbound half above. What the store can do is compete for CPU with a
/// delivery thread, which delays it by scheduling latency -- the same delay
/// it already imposed on everything else on the device, and milliseconds
/// rather than the seconds B2 was opened for. If that bound ever stops
/// holding -- a caller raising `pool_max_size`, or upstream changing the
/// default -- this is the paragraph that has gone stale, and the way to tell
/// is that a signal starts waiting on store work rather than on a scheduler.
///
/// A thread per call has no shared cap to exhaust and none of this coupling;
/// the trade is taken deliberately, because its own bound is the process's
/// thread table, which fails harder and later.
///
/// **Building the runtime is on this path.** `runtime()` is
/// `OnceLock::get_or_init`, so the first call into this function in a process
/// where nothing has built the runtime yet builds it -- two workers, reactor
/// and timer -- on the calling thread before anything is handed off. That is
/// a real path rather than a theoretical one: nothing on the way to
/// `observer::emit` enters `in_runtime` -- neither the FFI export nor
/// `observer::probe_with_observer`, which emits before it awaits -- so on a
/// cold process whose first native call is the probe, this function builds
/// the runtime on a thread that has never seen tokio. One-off per process,
/// and named here so nobody reads "does not wait for it" as "does nothing
/// before it returns".
pub(crate) fn spawn_blocking_detached<F>(work: F)
where
    F: FnOnce() + Send + 'static,
{
    // Dropped rather than awaited: that is what "detached" means here.
    // Dropping the handle does not cancel the closure -- a blocking task
    // handed to the pool runs to completion regardless -- it only stops
    // anyone from waiting on it.
    drop(runtime().spawn_blocking(work));
}

/// Runs `future` inside this library's runtime, so anything it calls sees a
/// runtime context.
///
/// A panic inside `future` propagates here and is caught by UniFFI's
/// `catch_unwind`, reaching the caller as a typed error rather than aborting
/// the host application.
pub async fn in_runtime<F, T>(future: F) -> T
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    value_or_its_panic(runtime().spawn(future).await)
}

/// The value a task returned, or its panic resumed on the caller's side, so
/// that UniFFI's `catch_unwind` turns it into a typed error there.
fn value_or_its_panic<T>(joined: Result<T, tokio::task::JoinError>) -> T {
    match joined {
        Ok(value) => value,
        Err(joined) => std::panic::resume_unwind(
            joined
                .try_into_panic()
                .unwrap_or_else(|_| Box::new("crypto task cancelled")),
        ),
    }
}

/// Runs `work` on this library's blocking pool and waits for its result.
///
/// For computation that holds a thread for a long time and awaits nothing,
/// such as blinding two thousand inputs in `oprf.rs`. Handed to `in_runtime`, it
/// would occupy one of the two async workers for its whole duration, and
/// encryption, decryption and every other call in flight would wait on the
/// one left. The blocking pool is a different set of threads, as
/// `spawn_blocking_detached` explains; this is that pool, with the result
/// awaited instead of dropped.
///
/// A panic inside `work` propagates here, like `in_runtime`'s, and reaches the
/// caller as a typed error.
pub(crate) async fn on_blocking_pool<F, T>(work: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    value_or_its_panic(runtime().spawn_blocking(work).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deliberately NOT `#[tokio::test]`. Under `#[tokio::test]` the harness
    /// supplies an ambient runtime, and this test would pass even if
    /// `in_runtime` did nothing at all. The point is that the runtime context
    /// comes from this library.
    #[test]
    fn a_spawn_inside_in_runtime_succeeds_with_no_ambient_runtime() {
        let doubled = futures::executor::block_on(in_runtime(async {
            tokio::task::spawn(async { 21 * 2 })
                .await
                .expect("task joined")
        }));

        assert_eq!(doubled, 42);
    }

    /// Like the test above, with no ambient runtime: the pool is this
    /// library's own, and the value comes back to a caller that has none.
    #[test]
    fn work_on_the_blocking_pool_returns_its_value_with_no_ambient_runtime() {
        let doubled = futures::executor::block_on(on_blocking_pool(|| 21 * 2));

        assert_eq!(doubled, 42);
    }

    /// A panic inside the work reaches the caller, rather than a value that
    /// never comes.
    #[test]
    fn a_panic_on_the_blocking_pool_reaches_the_caller() {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let outcome = std::panic::catch_unwind(|| {
            futures::executor::block_on(on_blocking_pool(|| -> u32 { panic!("inside the work") }))
        });

        std::panic::set_hook(previous);

        assert!(outcome.is_err(), "the panic must propagate to the caller");
    }

    /// The control. Without `in_runtime` the same spawn panics, which is the
    /// whole reason `in_runtime` exists. A test suite that only shows the
    /// green path cannot tell a working runtime from a redundant one.
    #[test]
    fn the_same_spawn_panics_without_in_runtime() {
        // Rust's default panic hook prints a backtrace even when the panic is
        // caught. Left in place, this test's output reads as a failure to
        // anyone scanning the log. Silence the hook for the duration and put
        // it back, so a green run looks green.
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));

        let outcome = std::panic::catch_unwind(|| {
            futures::executor::block_on(async {
                tokio::task::spawn(async { 42 }).await.expect("task joined")
            })
        });

        std::panic::set_hook(previous);

        assert!(outcome.is_err(), "spawn outside a runtime must panic");
    }
}
