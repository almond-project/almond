// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

use std::env::args;
use std::sync::atomic::{AtomicPtr, Ordering};

use crate::input::AlmondInput;

// Global storage for current fuzzing input.
//
// Uses AtomicPtr instead of Mutex to be signal-safe. InProcessExecutor uses
// SIGALRM + longjmp for timeouts. If longjmp fires while a MutexGuard is held,
// the guard is never dropped and the mutex deadlocks on the next execution.
// AtomicPtr has no lock to leak, so longjmp is harmless.
pub static CURRENT_INPUT: AtomicPtr<AlmondInput> = AtomicPtr::new(std::ptr::null_mut());

/// RAII guard that blocks `SIGALRM` for the duration of a critical section.
///
/// The `CURRENT_INPUT` pointer is lock-free, but the `AlmondInput` it points at
/// is not: `begin_syscall`, `get`, `capture`, etc. all take the inner `RwLock`
/// write lock (and `begin_syscall` additionally locks the syscall-tree
/// `Mutex`). `InProcessExecutor` enforces timeouts with `setitimer` + `SIGALRM`,
/// whose handler `longjmp`s back to the executor's `setjmp` point. If that fires
/// while one of those locks is held, the `longjmp` skips the guard's destructor
/// and the lock is never released — every subsequent `fuzz()` call then
/// deadlocks on it. Blocking `SIGALRM` across the locked section keeps the
/// timeout pending until the guard is dropped and the lock is released, at which
/// point the signal is delivered and `longjmp` fires safely.
struct SigAlrmGuard {
    prev: libc::sigset_t,
}

impl SigAlrmGuard {
    fn new() -> Self {
        unsafe {
            let mut block: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut block);
            libc::sigaddset(&mut block, libc::SIGALRM);
            let mut prev: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_BLOCK, &block, &mut prev);
            Self { prev }
        }
    }
}

impl Drop for SigAlrmGuard {
    fn drop(&mut self) {
        // Restore the previous mask. If a SIGALRM arrived while blocked it is
        // still pending and gets delivered here, after the lock is released.
        unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.prev, std::ptr::null_mut());
        }
    }
}

unsafe extern "C" {
    // real main function of the target source
    fn almond_shell(argc: i32, argv: *const *const u8);
}

/// Store an AlmondInput as the current input for the next harness execution.
///
/// The input is heap-allocated and stored via AtomicPtr. The previous input
/// is freed. This is signal-safe: if longjmp interrupts the execution, the
/// pointer remains valid and no lock is left held.
pub fn set_current_input(input: AlmondInput) {
    let ptr = Box::into_raw(Box::new(input));
    let old = CURRENT_INPUT.swap(ptr, Ordering::Release);
    if !old.is_null() {
        unsafe {
            drop(Box::from_raw(old));
        }
    }
}

pub fn harness_run() {
    let argv = [args().next().unwrap()];
    let c_argv: Vec<*const u8> = argv.iter().map(|arg| arg.as_ptr()).collect();
    let c_argv_ptr = c_argv.as_ptr();
    unsafe {
        almond_shell(1, c_argv_ptr);
    }
}

/// Get mutated input data for fuzzing
///
/// # Safety
///
/// If `buffer` is non-null it must be a valid writable buffer of at least
/// `size` bytes. A null `buffer` is accepted (common for optional fields like
/// `msghdr.msg_name` and `msghdr.msg_control`) and is a no-op for that arg.
/// This function is called from instrumented target code during fuzzing.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fuzz(buffer: *mut u8, syscall_no: i32, arg_no: i32, size: i32) {
    let syscall_no_u32 = syscall_no as u32;
    let arg_no_u32 = arg_no as u32;
    assert!(
        size >= 0,
        "fuzz() received negative size {size} for syscall {syscall_no} arg {arg_no} — LLVM pass bug"
    );
    let size_usize = size as usize;

    // Read CURRENT_INPUT via atomic pointer — no lock, signal-safe.
    let ptr = CURRENT_INPUT.load(Ordering::Acquire);
    if ptr.is_null() {
        // Called outside of fuzzing context (e.g. instrumented init code). No-op.
        return;
    }
    let input_data = unsafe { &*ptr };

    // Hold off the timeout SIGALRM while we touch the lock-protected input
    // state below, so a longjmp can't strand a held lock and deadlock the
    // next execution. Dropped at end of scope, before returning to target.
    let _sigalrm_guard = SigAlrmGuard::new();

    // On the first argument of each syscall, record the syscall in the
    // access sequence and check if this is a new path (enables capture).
    if arg_no_u32 == 0 {
        input_data.begin_syscall(syscall_no_u32);
    }

    // Legal NULL / empty buffers (msg_name/msg_control when unused, etc.)
    // have no bytes to mutate or capture.
    if buffer.is_null() || size_usize == 0 {
        return;
    }

    // When capturing, store ALL arguments with their original testcase
    // constants so the seed in the corpus has every argument populated.
    if input_data.is_capturing() {
        let data = unsafe { std::slice::from_raw_parts(buffer, size_usize) };
        input_data.capture(syscall_no_u32, arg_no_u32, data);
        return;
    }

    if crate::skipped_args::is_skipped(syscall_no_u32, arg_no_u32) {
        return;
    }

    // Provide mutated data
    let real_input = input_data.get(syscall_no_u32, arg_no_u32, size_usize);
    let bytes = real_input.as_ref();
    let copy_len = std::cmp::min(size_usize, bytes.len());
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, copy_len);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn advance_offset(syscall_no: i32) {
    let syscall_no_u32 = syscall_no as u32;

    // Read CURRENT_INPUT via atomic pointer — no lock, signal-safe.
    let ptr = CURRENT_INPUT.load(Ordering::Acquire);
    if ptr.is_null() {
        return;
    }
    let input_data = unsafe { &*ptr };

    // Same rationale as fuzz(): keep the timeout from longjmp-ing out while the
    // input's write lock is held. See SigAlrmGuard.
    let _sigalrm_guard = SigAlrmGuard::new();
    input_data.advance_offset_for_syscall(syscall_no_u32);
}

