// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! Async Kcov Map Observer with background remote thread
//! This observer uses a dedicated background thread for remote Kcov collection
//! while maintaining LibAFL compatibility by avoiding serialization requirements.
//!
//! # Coverage Streaming
//!
//! Coverage edges are pushed to a global ring buffer (see `coverage_ring` module)
//! for transmission to the Python manager via Unix domain sockets (SSH-forwarded).
//! The ring is stored globally to survive observer serialization/deserialization.

use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
};
use libafl_bolts::{ErrorBacktrace, hash_64_fast};
use libafl_bolts::{HasLen, Named, ownedref::OwnedMutSizedSlice};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use libafl::{
    Error,
    executors::ExitKind,
    observers::{ConstLenMapObserver, Observer, map::MapObserver},
};

use crate::observers::{
    coverage_ring,
    kcov_globals::{get_remote_kcov, get_syscall_kcov},
    signal_ring,
};

/// Kcov Map Observer with always-enabled remote coverage collection
/// This observer maintains LibAFL compatibility while using a background thread
/// with always-enabled remote Kcov collection and normal Kcov for the subthread.
///
/// # Coverage Streaming
///
/// Coverage edges are automatically pushed to a global ring buffer for
/// transmission to the Python manager via Unix domain sockets.
#[derive(Serialize, Deserialize, Debug)]
pub struct KcovMapObserver<const N: usize> {
    map: OwnedMutSizedSlice<'static, u8, N>,
    initial: u8,
    name: Cow<'static, str>,
    /// Length of syscall coverage collected in the worker thread
    syscall_len: usize,
    /// Length of remote coverage collected in the main thread
    remote_len: usize,
}

impl<I, S, const N: usize> Observer<I, S> for KcovMapObserver<N>
where
    Self: MapObserver<Entry = u8>,
{
    #[inline]
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.reset_map()?;

        let mut remote_kcov = get_remote_kcov().lock().map_err(|e| {
            Error::Runtime(
                format!("Failed to lock remote KCov: {}", e),
                ErrorBacktrace::new(),
            )
        })?;

        remote_kcov.enable().map_err(|e| {
            Error::Runtime(
                format!("Failed to enable remote KCov: {}", e),
                ErrorBacktrace::new(),
            )
        })?;

        Ok(())
    }

    #[inline]
    fn post_exec(&mut self, _state: &mut S, _input: &I, _k: &ExitKind) -> Result<(), Error> {
        // This method may be called from InProcessExecutor's timeout signal handler
        // running in the worker thread. Remote KCov is per-task (main thread), so
        // the KCOV_DISABLE ioctl fails from a different thread. Use try_lock to
        // avoid blocking in signal handler context, and tolerate disable failures
        // so that run_observers_and_save_state can finish and _exit(55) cleanly.
        let mut remote_kcov = match get_remote_kcov().try_lock() {
            Ok(guard) => guard,
            Err(_) => return Ok(()),
        };

        let len = match remote_kcov.disable() {
            Ok(len) => len,
            Err(_) => return Ok(()),
        };
        let coverage_ptr = remote_kcov.ptr();
        self.remote_len = len;

        let mut prev = 0u64;
        for i in 1..=len {
            let bb = unsafe { *coverage_ptr.add(i) };
            coverage_ring::push_if_new(bb);
            let signal = ((hash_64_fast(bb) ^ hash_64_fast(prev)) & Self::MASK as u64) as u32;
            self.set(signal as usize, self.get(signal as usize).wrapping_add(1));
            signal_ring::push_if_new(signal);
            prev = bb >> 1;
        }

        Ok(())
    }

    // This should be always run in the child thread as kcov needs a separate work_struct in the kernel.
    // Uses thread-local KCov from the thread pool - KCov::new is called once at thread startup.
    fn pre_exec_child(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        let kcov = get_syscall_kcov()?;
        kcov.enable().map_err(|e| {
            Error::Runtime(
                format!("Failed to enable syscall KCov: {}", e),
                ErrorBacktrace::new(),
            )
        })?;
        Ok(())
    }

    fn post_exec_child(
        &mut self,
        _state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        let kcov = get_syscall_kcov()?;
        let (coverage_ptr, len) = (
            kcov.ptr(),
            kcov.disable().map_err(|e| {
                Error::Runtime(
                    format!("Failed to disable syscall KCov: {}", e),
                    ErrorBacktrace::new(),
                )
            })?,
        );
        self.syscall_len = len;

        let mut prev = 0u64;
        for i in 1..=len {
            let bb = unsafe { *coverage_ptr.add(i) };
            coverage_ring::push_if_new(bb);
            let signal = ((hash_64_fast(bb) ^ hash_64_fast(prev)) & Self::MASK as u64) as u32;
            self.set(signal as usize, self.get(signal as usize).wrapping_add(1));
            signal_ring::push_if_new(signal);
            prev = bb >> 1;
        }

        Ok(())
    }
}

impl<const N: usize> Named for KcovMapObserver<N> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<const N: usize> Hash for KcovMapObserver<N> {
    #[inline]
    fn hash<H: Hasher>(&self, hasher: &mut H) {
        self.map.as_slice().hash(hasher);
    }
}

impl<const N: usize> HasLen for KcovMapObserver<N> {
    #[inline]
    fn len(&self) -> usize {
        N
    }
}

impl<const N: usize> AsRef<Self> for KcovMapObserver<N> {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl<const N: usize> AsMut<Self> for KcovMapObserver<N> {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

impl<const N: usize> MapObserver for KcovMapObserver<N> {
    type Entry = u8;

    #[inline]
    fn initial(&self) -> u8 {
        self.initial
    }

    #[inline]
    fn get(&self, idx: usize) -> u8 {
        let slice = self.map.as_slice();
        if idx < slice.len() {
            slice[idx]
        } else {
            // Return initial value if out of bounds to prevent panic
            self.initial
        }
    }

    #[inline]
    fn set(&mut self, idx: usize, val: u8) {
        let slice = self.map.as_mut_slice();
        if idx < slice.len() {
            slice[idx] = val;
        }
        // Silently ignore out of bounds writes to prevent panic
    }

    /// Count the set bytes in the map
    fn count_bytes(&self) -> u64 {
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.map.as_slice();
        let mut res = 0;
        for x in &map[0..cnt] {
            if *x != initial {
                res += 1;
            }
        }
        res
    }

    fn usable_count(&self) -> usize {
        self.len()
    }

    /// Reset the map
    #[inline]
    fn reset_map(&mut self) -> Result<(), Error> {
        // Normal memset, see https://rust.godbolt.org/z/Trs5hv
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = &mut (*self);
        for x in &mut map[0..cnt] {
            *x = initial;
        }
        Ok(())
    }

    fn to_vec(&self) -> Vec<Self::Entry> {
        self.map.to_vec()
    }

    /// Get the number of set entries with the specified indexes
    fn how_many_set(&self, indexes: &[usize]) -> usize {
        let initial = self.initial();
        let cnt = self.usable_count();
        let map = self.map.as_slice();
        let mut res = 0;
        for i in indexes {
            if *i < cnt && map[*i] != initial {
                res += 1;
            }
        }
        res
    }
}

impl<const N: usize> ConstLenMapObserver<N> for KcovMapObserver<N> {
    fn map_slice(&self) -> &[Self::Entry; N] {
        &self.map
    }

    fn map_slice_mut(&mut self) -> &mut [Self::Entry; N] {
        &mut self.map
    }
}

impl<const N: usize> Deref for KcovMapObserver<N> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.map.as_slice()
    }
}

impl<const N: usize> DerefMut for KcovMapObserver<N> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.map.as_mut_slice()
    }
}

impl<const N: usize> KcovMapObserver<N> {
    const MASK: usize = N - 1;

    /// Creates a new KcovMapObserver with always-enabled remote collection
    pub fn new(name: &'static str) -> Result<Self, Error> {
        assert!(
            N.is_power_of_two(),
            "KcovMapObserver size must be a power of two"
        );

        // Initialize the remote KCov instance
        let _ = get_remote_kcov();

        Ok(Self {
            map: OwnedMutSizedSlice::from(Box::new([0u8; N])),
            name: Cow::from(name),
            initial: u8::default(),
            syscall_len: 0,
            remote_len: 0,
        })
    }

    /// Returns the syscall coverage length from the last execution
    pub fn syscall_len(&self) -> usize {
        self.syscall_len
    }

    /// Returns the remote coverage length from the last execution
    pub fn remote_len(&self) -> usize {
        self.remote_len
    }
}
