// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! Lock-free SPSC Ring Buffer for Coverage Data
//!
//! This module provides single-producer single-consumer ring buffers optimized for
//! streaming coverage data from the fuzzer's hot path to a background flush thread.
//!
//! # Design Goals
//!
//! - **Non-blocking**: `push()` never blocks, drops data if full
//! - **Fast hot path**: `push()` is `#[inline(always)]`, targets <10ns
//! - **No allocations**: Pre-allocated buffer, no heap allocation in hot path
//! - **Thread-safe**: `Send + Sync` via atomics only
//!
//! # Available Rings
//!
//! - `CoverageRing`: For kcov edge coverage (u64 addresses)

use std::cell::UnsafeCell;
use std::fmt;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Default ring buffer size: 64K entries (~512KB)
const DEFAULT_SIZE: usize = 1 << 16;

/// Lock-free SPSC ring buffer for `u64` coverage addresses.
///
/// This buffer is optimized for the single-producer single-consumer pattern where:
/// - The producer (fuzzer observer) calls `push()` from a hot path
/// - The consumer (flush thread) calls `drain()` from a background thread
///
/// # Memory Layout
///
/// The buffer uses a power-of-two sized array for efficient modular arithmetic.
/// Head and tail are atomic indices that wrap around the buffer.
///
/// ```text
/// [entry0][entry1][entry2]...[entryN-1]
///   ^                          ^
///  tail                       head
/// ```
///
/// - `head`: Index where the next push will write
/// - `tail`: Index of the oldest unread entry
/// - Empty when `head == tail`
/// - Full when `head - tail == capacity`
pub struct CoverageRing {
    /// The underlying buffer, wrapped in UnsafeCell for interior mutability
    buffer: UnsafeCell<Box<[u64; DEFAULT_SIZE]>>,
    /// Next write position (producer)
    head: AtomicUsize,
    /// Next read position (consumer)
    tail: AtomicUsize,
    /// Number of entries dropped because the ring was full
    overflow_count: AtomicU64,
}

impl fmt::Debug for CoverageRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CoverageRing")
            .field("capacity", &DEFAULT_SIZE)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl CoverageRing {
    /// Create a new ring buffer with default capacity.
    ///
    /// The default capacity is 64K entries (~512KB).
    pub fn new() -> Self {
        Self {
            buffer: UnsafeCell::new(Box::new([0u64; DEFAULT_SIZE])),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            overflow_count: AtomicU64::new(0),
        }
    }

    /// Returns the capacity of the ring buffer.
    #[inline]
    pub fn capacity(&self) -> usize {
        DEFAULT_SIZE
    }

    /// Atomically drain the overflow counter, returning the number of entries
    /// dropped since the last call.
    pub fn drain_overflow(&self) -> u64 {
        self.overflow_count.swap(0, Ordering::Relaxed)
    }

    /// Push a coverage address to the ring.
    ///
    /// This function is non-blocking and lock-free. If the ring is full,
    /// the entry is dropped and `false` is returned.
    ///
    /// # Performance
    ///
    /// This function targets <10ns per call on modern hardware.
    /// It is marked `#[inline(always)]` to ensure zero overhead.
    ///
    /// # Memory Ordering
    ///
    /// - `Relaxed` load of head: We're the only writer, no synchronization needed
    /// - `Acquire` load of tail: Synchronize with consumer's `Release` store
    /// - `Release` store of head: Synchronize with consumer's `Acquire` load
    #[inline(always)]
    pub fn push(&self, value: u64) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);

        // Check if full
        let next_head = head.wrapping_add(1);
        if next_head.wrapping_sub(tail) > DEFAULT_SIZE {
            self.overflow_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }

        // Safety: We're the only producer (SPSC), and we've verified there's space.
        // The index is always within bounds because we use modular arithmetic.
        // The consumer won't read this position until we update head with Release ordering.
        let idx = head % DEFAULT_SIZE;
        unsafe {
            let buffer = &mut *self.buffer.get();
            (*buffer)[idx] = value;
        }

        // Release store so consumer sees the written value
        self.head.store(next_head, Ordering::Release);
        true
    }

    /// Drain all available entries into the provided vector.
    ///
    /// This function is called by the consumer (flush thread) to bulk-read
    /// all pending coverage addresses. The vector is cleared before draining.
    ///
    /// # Arguments
    ///
    /// * `out` - Pre-allocated vector to receive the entries
    ///
    /// # Memory Ordering
    ///
    /// - `Relaxed` load of tail: We're the only reader, no synchronization needed
    /// - `Acquire` load of head: Synchronize with producer's `Release` store
    /// - `Release` store of tail: Synchronize with producer's `Acquire` load
    pub fn drain(&self, out: &mut Vec<u64>) {
        out.clear();

        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);

        let count = head.wrapping_sub(tail);
        if count == 0 {
            return;
        }

        // Reserve space for the entries
        out.reserve(count);

        // Safety: We're the only consumer (SPSC). The producer won't write to
        // positions we're reading because they're behind head, which we've
        // already loaded with Acquire ordering.
        unsafe {
            let buffer = &*self.buffer.get();
            for i in 0..count {
                let idx = (tail + i) % DEFAULT_SIZE;
                out.push(buffer[idx]);
            }
        }

        // Update tail with Release ordering
        self.tail.store(head, Ordering::Release);
    }

    /// Returns the approximate number of pending entries.
    ///
    /// This is approximate because it doesn't synchronize with concurrent
    /// producers/consumers. Use only for heuristics.
    #[inline]
    pub fn len(&self) -> usize {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Relaxed);
        head.wrapping_sub(tail)
    }

    /// Returns true if the ring is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for CoverageRing {
    fn default() -> Self {
        Self::new()
    }
}

// Safety: The ring buffer uses atomic operations for all shared state.
// UnsafeCell is used for interior mutability, but access is coordinated
// through atomic head/tail indices with proper memory ordering:
// - Producer only writes to positions [tail, head) and updates head with Release
// - Consumer only reads from positions [tail, head) and updates tail with Release
// This ensures no data races occur in the SPSC pattern.
unsafe impl Send for CoverageRing {}
unsafe impl Sync for CoverageRing {}

/// Default signal ring buffer size: 16K entries (64KB for u32).
/// At most N unique signal slots exist (N = map size, typically 8192), so this
/// is ample — once all slots are seen, the ring stays empty.
const SIGNAL_DEFAULT_SIZE: usize = 1 << 14;

/// Lock-free SPSC ring buffer for kcov edge signal slot indices (u32).
///
/// Each entry is a signal slot index computed as
/// `(hash(bb) ^ hash(prev)) & (N-1)` in the kcov observer. Streaming only
/// *newly-seen* slot indices lets the Python manager aggregate unique edge
/// coverage across multiple VMs without recomputing edges from BB addresses.
pub struct SignalRing {
    buffer: UnsafeCell<Box<[u32; SIGNAL_DEFAULT_SIZE]>>,
    head: AtomicUsize,
    tail: AtomicUsize,
    overflow_count: AtomicU64,
}

impl fmt::Debug for SignalRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignalRing")
            .field("capacity", &SIGNAL_DEFAULT_SIZE)
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl SignalRing {
    pub fn new() -> Self {
        Self {
            buffer: UnsafeCell::new(Box::new([0u32; SIGNAL_DEFAULT_SIZE])),
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            overflow_count: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        SIGNAL_DEFAULT_SIZE
    }

    pub fn drain_overflow(&self) -> u64 {
        self.overflow_count.swap(0, Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn push(&self, value: u32) -> bool {
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        let next_head = head.wrapping_add(1);
        if next_head.wrapping_sub(tail) > SIGNAL_DEFAULT_SIZE {
            self.overflow_count.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let idx = head % SIGNAL_DEFAULT_SIZE;
        unsafe {
            (*self.buffer.get())[idx] = value;
        }
        self.head.store(next_head, Ordering::Release);
        true
    }

    pub fn drain(&self, out: &mut Vec<u32>) {
        out.clear();
        let tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        let count = head.wrapping_sub(tail);
        if count == 0 {
            return;
        }
        out.reserve(count);
        unsafe {
            let buffer = &*self.buffer.get();
            for i in 0..count {
                out.push(buffer[(tail + i) % SIGNAL_DEFAULT_SIZE]);
            }
        }
        self.tail.store(head, Ordering::Release);
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.head
            .load(Ordering::Relaxed)
            .wrapping_sub(self.tail.load(Ordering::Relaxed))
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SignalRing {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl Send for SignalRing {}
unsafe impl Sync for SignalRing {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_basic_push_drain() {
        let ring = CoverageRing::new();

        assert!(ring.is_empty());
        assert!(ring.push(42));
        assert!(!ring.is_empty());
        assert_eq!(ring.len(), 1);

        let mut buf = Vec::new();
        ring.drain(&mut buf);
        assert_eq!(buf, vec![42]);
        assert!(ring.is_empty());
    }

    #[test]
    fn test_fill_and_drain() {
        let ring = CoverageRing::new();
        let cap = ring.capacity();

        // Fill exactly to capacity
        for i in 0..cap {
            assert!(ring.push(i as u64), "push failed at {i}");
        }
        assert_eq!(ring.len(), cap);

        // One more should fail
        assert!(!ring.push(0xDEAD));

        // Drain all
        let mut buf = Vec::new();
        ring.drain(&mut buf);
        assert_eq!(buf.len(), cap);

        for (i, &v) in buf.iter().enumerate() {
            assert_eq!(v, i as u64);
        }
    }

    #[test]
    fn test_wrap_around() {
        let ring = CoverageRing::new();

        // Push and drain multiple times to test wrap-around
        for batch in 0..10 {
            let start = (batch * 1000) as u64;
            for i in 0..1000 {
                assert!(ring.push(start + i));
            }

            let mut buf = Vec::new();
            ring.drain(&mut buf);
            assert_eq!(buf.len(), 1000);

            for (i, &v) in buf.iter().enumerate() {
                assert_eq!(v, start + i as u64);
            }
        }
    }

    #[test]
    fn test_concurrent_producer_consumer() {
        let ring = Arc::new(CoverageRing::new());
        let ring_producer = Arc::clone(&ring);
        let ring_consumer = Arc::clone(&ring);

        const COUNT: usize = 100_000;

        let producer = thread::spawn(move || {
            for i in 0..COUNT {
                // Spin if full
                while !ring_producer.push(i as u64) {
                    thread::yield_now();
                }
            }
        });

        let consumer = thread::spawn(move || {
            let mut received = Vec::with_capacity(COUNT);
            while received.len() < COUNT {
                let mut buf = Vec::new();
                ring_consumer.drain(&mut buf);
                received.extend(buf);
                thread::yield_now();
            }
            received
        });

        producer.join().unwrap();
        let mut received = consumer.join().unwrap();

        assert_eq!(received.len(), COUNT);
        // Check that all values are present (may be out of order due to batching)
        received.sort();
        for (i, &v) in received.iter().enumerate() {
            assert_eq!(v, i as u64);
        }
    }

    #[test]
    fn test_overflow_counter() {
        let ring = CoverageRing::new();
        let cap = ring.capacity();

        assert_eq!(ring.drain_overflow(), 0);

        for i in 0..cap {
            assert!(ring.push(i as u64));
        }

        // These should all fail and increment the overflow counter
        for _ in 0..100 {
            assert!(!ring.push(0xDEAD));
        }
        assert_eq!(ring.drain_overflow(), 100);

        // Counter should be reset after drain
        assert_eq!(ring.drain_overflow(), 0);

        // Drain the ring, push more, overflow again
        let mut buf = Vec::new();
        ring.drain(&mut buf);
        assert_eq!(buf.len(), cap);

        for i in 0..cap {
            assert!(ring.push(i as u64));
        }
        assert!(!ring.push(0xDEAD));
        assert!(!ring.push(0xBEEF));
        assert_eq!(ring.drain_overflow(), 2);
    }

    #[test]
    fn test_signal_ring_overflow() {
        let ring = SignalRing::new();
        let cap = ring.capacity();

        for i in 0..cap {
            assert!(ring.push(i as u32));
        }
        assert!(!ring.push(0));
        assert!(!ring.push(1));
        assert!(!ring.push(2));
        assert_eq!(ring.drain_overflow(), 3);
        assert_eq!(ring.drain_overflow(), 0);
    }
}
