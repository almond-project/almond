// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

use std::sync::{Arc, Mutex, OnceLock};

use crate::ring::CoverageRing;

static COVERAGE_RING: OnceLock<Arc<CoverageRing>> = OnceLock::new();

/// Size the global coverage ring before fuzzing starts.
///
/// Optional: the ring is lazily created with [`CoverageRing::new`]'s default
/// capacity on first [`push_if_new`] if this is never called. Call once at
/// startup, before any push, when the default overflows (watch
/// [`drain_overflow`]). Returns `false` if the ring was already initialized.
pub fn init_with_capacity(capacity: usize) -> bool {
    COVERAGE_RING
        .set(Arc::new(CoverageRing::with_capacity(capacity)))
        .is_ok()
}

/// Process-local set of BB addresses already forwarded to the manager.
/// Not fuzzer state — resets when the process restarts (e.g. on VM snapshot restore).
/// Cross-VM aggregation is the Python manager's responsibility.
static SEEN_COVERAGE: OnceLock<Mutex<hashbrown::HashSet<u64>>> = OnceLock::new();

/// Push a BB address to the ring if this process has not sent it before.
/// Returns true if the BB was novel and successfully enqueued.
#[inline(always)]
pub fn push_if_new(bb: u64) -> bool {
    let seen = SEEN_COVERAGE.get_or_init(|| Mutex::new(hashbrown::HashSet::new()));
    let mut guard = seen.lock().unwrap_or_else(|e| e.into_inner());
    if guard.insert(bb) {
        drop(guard);
        COVERAGE_RING
            .get_or_init(|| Arc::new(CoverageRing::new()))
            .push(bb)
    } else {
        false
    }
}

/// Drain all pending coverage BBs from the global ring.
/// Returns an empty vector if the ring has not been initialized.
pub fn drain() -> Vec<u64> {
    COVERAGE_RING.get().map_or_else(Vec::new, |ring| {
        let mut buf = Vec::new();
        ring.drain(&mut buf);
        buf
    })
}

/// Drain the overflow counter, returning entries dropped since last call.
pub fn drain_overflow() -> u64 {
    COVERAGE_RING.get().map_or(0, |ring| ring.drain_overflow())
}
