// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! Global KCov instances for coverage collection.
//!
//! This module provides thread-local and global KCov instances:
//! - `SYSCALL_KCOV`: Thread-local KCov for syscall coverage (one per worker thread)
//! - `REMOTE_KCOV`: Global KCov for remote coverage (shared across all threads)

use std::cell::RefCell;
use std::sync::Mutex;

use libafl::Error;
use libafl_bolts::ErrorBacktrace;

use crate::kcov::KCov;

// ============================================================================
// SYSCALL_KCOV - Thread-local KCov for syscall coverage
// ============================================================================

// Thread-local KCov instance for syscall coverage.
// Initialized once per thread, reused across executions.
thread_local! {
    pub static SYSCALL_KCOV: RefCell<Option<KCov>> = const { RefCell::new(None) };
}

/// Initialize the thread-local syscall KCov.
/// Called once when the worker thread starts.
pub fn init_syscall_kcov() -> Result<(), Error> {
    SYSCALL_KCOV.with(|kcov_cell| {
        let mut kcov_opt = kcov_cell.borrow_mut();
        if kcov_opt.is_none() {
            *kcov_opt = Some(KCov::new(false).map_err(|e| {
                Error::Runtime(
                    format!("Failed to create syscall KCov instance: {}", e),
                    ErrorBacktrace::new(),
                )
            })?);
        }
        Ok(())
    })
}

/// Get the thread-local syscall KCov.
/// Returns the KCov instance initialized by the worker thread.
pub fn get_syscall_kcov() -> Result<&'static mut KCov, Error> {
    SYSCALL_KCOV.with(|kcov_cell| {
        let mut kcov_opt = kcov_cell.borrow_mut();
        if kcov_opt.is_some() {
            let ptr = kcov_opt.as_mut().unwrap() as *mut KCov;
            // Safety: The KCov lives for the lifetime of the thread.
            // We return a static reference because thread_local! guarantees
            // the data won't be moved or dropped until thread exit.
            Ok(unsafe { &mut *ptr })
        } else {
            Err(Error::Runtime(
                "KCov not initialized in this thread".to_string(),
                ErrorBacktrace::new(),
            ))
        }
    })
}

// ============================================================================
// REMOTE_KCOV - Global KCov for remote coverage
// ============================================================================

/// Global KCov instance for remote coverage.
/// Shared across all threads, protected by a Mutex.
static REMOTE_KCOV: std::sync::OnceLock<Mutex<KCov>> = std::sync::OnceLock::new();

/// Get or initialize the global remote KCov.
pub fn get_remote_kcov() -> &'static Mutex<KCov> {
    REMOTE_KCOV
        .get_or_init(|| Mutex::new(KCov::new(true).expect("Failed to create remote KCov instance")))
}
