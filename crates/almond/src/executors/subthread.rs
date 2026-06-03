// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! A wrapper executor that encapsulates InProcessExecutor as an inner executor.
//!
//! The SubthreadInProcessExecutor provides a clean abstraction layer around
//! InProcessExecutor, allowing for additional functionality and customization
//! while maintaining compatibility with the existing LibAFL ecosystem.

use core::fmt::Debug;
use core::time::Duration;
use std::sync::Mutex;
use std::thread::JoinHandle;

use crossbeam::channel::{Receiver, Sender, unbounded};
use libafl::{
    Error,
    executors::{Executor, ExitKind, HasObservers, InProcessExecutor},
    inputs::Input,
    observers::ObserversTuple,
    state::{HasCurrentTestcase, HasExecutions, HasSolutions},
};
use libafl_bolts::tuples::RefIndexable;

use crate::observers::kcov_globals::init_syscall_kcov;

/// A single-thread pool that reuses one worker thread for all executions.
/// KCov is initialized once when the thread starts, avoiding repeated KCov::new calls.
struct SingleThreadPool {
    /// Channel to send jobs to the worker thread
    job_sender: Sender<Job>,
    /// Channel to receive results from the worker thread (wrapped in Mutex for Sync)
    result_receiver: Mutex<Receiver<Result<ExitKind, Error>>>,
    /// Handle to the worker thread
    _worker_handle: JoinHandle<()>,
}

type Job = Box<dyn FnOnce() -> Result<ExitKind, Error> + Send>;

impl SingleThreadPool {
    /// Create a new single-thread pool.
    /// The worker thread initializes KCov once at startup.
    fn new() -> Result<Self, Error> {
        let (job_sender, job_receiver) = unbounded::<Job>();
        let (result_sender, result_receiver) = unbounded::<Result<ExitKind, Error>>();

        let worker_handle = std::thread::spawn(move || {
            // Unmask SIGALRM in the worker thread so that InProcessExecutor's
            // setitimer-based timeout signals are delivered here (where setjmp
            // context exists), not to the main thread.
            unsafe {
                let mut set: libc::sigset_t = std::mem::zeroed();
                libc::sigemptyset(&mut set);
                libc::sigaddset(&mut set, libc::SIGALRM);
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
            }

            // Initialize KCov once at thread startup
            if let Err(e) = init_syscall_kcov() {
                log::error!("Failed to initialize KCov in worker thread: {:?}", e);
                return;
            }

            // Process jobs until channel is closed
            while let Ok(job) = job_receiver.recv() {
                let result = job();
                if result_sender.send(result).is_err() {
                    break;
                }
            }
        });

        Ok(Self {
            job_sender,
            result_receiver: Mutex::new(result_receiver),
            _worker_handle: worker_handle,
        })
    }

    /// Execute a job on the worker thread and return the result.
    fn execute(&self, job: Job) -> Result<ExitKind, Error> {
        self.job_sender.send(job).map_err(|e| {
            Error::Runtime(
                format!("Failed to send job to worker thread: {}", e),
                libafl_bolts::ErrorBacktrace::new(),
            )
        })?;

        let receiver = self.result_receiver.lock().map_err(|e| {
            Error::Runtime(
                format!("Failed to lock result receiver: {}", e),
                libafl_bolts::ErrorBacktrace::new(),
            )
        })?;

        receiver
            .recv()
            .expect("Failed to receive result from worker thread")
    }
}

// Safety: SingleThreadPool is Sync because:
// - job_sender is Send+Sync (crossbeam Sender)
// - result_receiver is protected by Mutex
// - _worker_handle is only used for cleanup
unsafe impl Sync for SingleThreadPool {}

/// Global single-thread pool instance.
static POOL: std::sync::OnceLock<SingleThreadPool> = std::sync::OnceLock::new();

/// Get or initialize the global thread pool.
fn get_pool() -> &'static SingleThreadPool {
    POOL.get_or_init(|| SingleThreadPool::new().expect("Failed to create thread pool"))
}

/// Executes a function in the worker thread with KCov already initialized.
/// A `sandwitch`: main thread is the bread, subthread the magical filling.
///
/// # Safety
///
/// The closure is transmuted to `Send`. This is safe because:
/// - The worker thread processes jobs sequentially (single thread)
/// - Each job completes before the next one starts
/// - The main thread waits for each job to complete before submitting another
pub fn sandwitch(f: impl FnOnce() -> Result<ExitKind, Error>) -> Result<ExitKind, Error> {
    // Block SIGALRM in the calling (main) thread so that InProcessExecutor's
    // timer signals are delivered only to the worker thread (which has it unmasked).
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGALRM);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    let pool = get_pool();

    // Safety: We transmute the closure to Send. This is safe because:
    // 1. The pool processes jobs sequentially (single thread)
    // 2. The main thread waits for completion before continuing
    // 3. No concurrent access to non-Send data occurs
    let job: Job = unsafe {
        std::mem::transmute::<
            Box<dyn FnOnce() -> Result<ExitKind, Error>>,
            Box<dyn FnOnce() -> Result<ExitKind, Error> + Send>,
        >(Box::new(f))
    };

    pool.execute(job)
}

/// A wrapper executor that encapsulates an InProcessExecutor as its inner executor.
///
/// This wrapper provides several benefits:
/// - Clean separation of concerns between the executor logic and the harness
/// - Ability to add custom pre/post processing around the inner executor
/// - Compatibility with existing LibAFL infrastructure
/// - Easy extension points for future functionality
///
/// # Type Parameters
///
/// * `EM` - Event manager type
/// * `H` - Harness function type
/// * `I` - Input type
/// * `OT` - Observers tuple type
/// * `S` - State type
/// * `Z` - Fuzzer type
///
/// # Example
///
/// ```ignore
/// use std::time::Duration;
///
/// use almond::executors::subthread::SubthreadInProcessExecutor;
/// use libafl::executors::ExitKind;
/// use libafl::inputs::BytesInput;
/// use libafl_bolts::tuples::tuple_list;
///
/// let mut harness = |input: &BytesInput| {
///     // Your target code here
///     ExitKind::Ok
/// };
///
/// let executor = SubthreadInProcessExecutor::with_timeout(
///     &mut harness,
///     tuple_list!(observer),
///     &mut fuzzer,
///     &mut state,
///     &mut event_mgr,
///     Duration::from_secs(10),
/// )?;
/// ```
pub struct SubthreadInProcessExecutor<'a, EM, H, I, OT, S, Z>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    S: HasExecutions,
{
    /// The inner InProcessExecutor that handles the actual execution
    inner: InProcessExecutor<'a, EM, H, I, OT, S, Z>,
}

impl<'a, EM, H, I, OT, S, Z> Debug for SubthreadInProcessExecutor<'a, EM, H, I, OT, S, Z>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: Debug + ObserversTuple<I, S>,
    S: HasExecutions,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SubthreadInProcessExecutor")
            .field("inner", &self.inner)
            .finish()
    }
}

impl<'a, EM, H, I, OT, S, Z> Executor<EM, I, S, Z>
    for SubthreadInProcessExecutor<'a, EM, H, I, OT, S, Z>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    S: HasExecutions,
{
    fn run_target(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        let f = || self.run_target_inner(fuzzer, state, mgr, input);
        sandwitch(f)
    }
}

impl<'a, EM, H, I, OT, S, Z> SubthreadInProcessExecutor<'a, EM, H, I, OT, S, Z>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    S: HasExecutions,
{
    fn run_target_inner(
        &mut self,
        fuzzer: &mut Z,
        state: &mut S,
        mgr: &mut EM,
        input: &I,
    ) -> Result<ExitKind, Error> {
        self.observers_mut().pre_exec_child_all(state, input)?;
        let exit = self.inner.run_target(fuzzer, state, mgr, input)?;
        self.observers_mut()
            .post_exec_child_all(state, input, &exit)?;
        Ok::<ExitKind, Error>(exit)
    }
}

impl<'a, EM, H, I, OT, S, Z> HasObservers for SubthreadInProcessExecutor<'a, EM, H, I, OT, S, Z>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    S: HasExecutions,
{
    type Observers = OT;

    #[inline]
    fn observers(&self) -> RefIndexable<&Self::Observers, Self::Observers> {
        self.inner.observers()
    }

    #[inline]
    fn observers_mut(&mut self) -> RefIndexable<&mut Self::Observers, Self::Observers> {
        self.inner.observers_mut()
    }
}

impl<'a, EM, H, I, OT, S, Z> SubthreadInProcessExecutor<'a, EM, H, I, OT, S, Z>
where
    H: FnMut(&I) -> ExitKind,
    I: Input,
    OT: ObserversTuple<I, S>,
    S: HasExecutions + HasCurrentTestcase<I> + HasSolutions<I>,
{
    /// Create a new SubthreadInProcessExecutor with a custom timeout.
    ///
    /// # Arguments
    ///
    /// * `harness_fn` - The harness function that executes the target
    /// * `observers` - Tuple of observers to collect feedback during execution
    /// * `fuzzer` - The fuzzer instance
    /// * `state` - The fuzzer state
    /// * `event_mgr` - The event manager for handling events
    /// * `timeout` - Custom timeout duration for target execution
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying InProcessExecutor creation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use std::time::Duration;
    ///
    /// let executor = SubthreadInProcessExecutor::with_timeout(
    ///     &mut harness,
    ///     tuple_list!(edges_observer),
    ///     &mut fuzzer,
    ///     &mut state,
    ///     &mut event_mgr,
    ///     Duration::from_secs(10),
    /// )?;
    /// ```
    pub fn with_timeout<OF>(
        harness_fn: &'a mut H,
        observers: OT,
        fuzzer: &mut Z,
        state: &mut S,
        event_mgr: &mut EM,
        timeout: Duration,
    ) -> Result<Self, Error>
    where
        EM: libafl::events::EventFirer<I, S> + libafl::events::EventRestarter<S>,
        OF: libafl::feedbacks::Feedback<EM, I, OT, S>,
        Z: libafl::fuzzer::HasObjective<Objective = OF>,
    {
        let inner = InProcessExecutor::with_timeout(
            harness_fn, observers, fuzzer, state, event_mgr, timeout,
        )?;

        Ok(Self { inner })
    }
}
