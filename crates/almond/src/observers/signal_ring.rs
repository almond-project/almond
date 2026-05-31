// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

use std::sync::{Arc, Mutex, OnceLock};

use crate::ring::SignalRing;

static SIGNAL_RING: OnceLock<Arc<SignalRing>> = OnceLock::new();

/// Process-local set of signal slot indices already forwarded to the manager.
/// Not fuzzer state — resets when the process restarts (e.g. on VM snapshot restore).
/// Cross-VM aggregation is the Python manager's responsibility.
static SEEN_SIGNALS: OnceLock<Mutex<hashbrown::HashSet<u32>>> = OnceLock::new();

/// Push a signal slot index to the ring if this process has not sent it before.
/// Returns true if the signal was novel and successfully enqueued.
#[inline(always)]
pub fn push_if_new(signal: u32) -> bool {
    let seen = SEEN_SIGNALS.get_or_init(|| Mutex::new(hashbrown::HashSet::new()));
    let mut guard = seen.lock().unwrap_or_else(|e| e.into_inner());
    if guard.insert(signal) {
        drop(guard);
        SIGNAL_RING
            .get_or_init(|| Arc::new(SignalRing::new()))
            .push(signal)
    } else {
        false
    }
}

/// Drain all pending signal slot indices from the global ring.
/// Returns an empty vector if the ring has not been initialized.
pub fn drain() -> Vec<u32> {
    SIGNAL_RING.get().map_or_else(Vec::new, |ring| {
        let mut buf = Vec::new();
        ring.drain(&mut buf);
        buf
    })
}

/// Drain the overflow counter, returning entries dropped since last call.
pub fn drain_overflow() -> u64 {
    SIGNAL_RING.get().map_or(0, |ring| ring.drain_overflow())
}
