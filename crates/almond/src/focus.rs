// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! Which accessed syscalls a round of mutation may aim at.
//!
//! Selection aims half its picks at the roadblock, the last call a run
//! reached, and spreads the rest over the accessed calls in proportion to how
//! often each ran. Calls whose mutation changes nothing the target reads are
//! left out of both: a program whose `connect()` fails typically runs
//! `close(fd)` before it returns, and aiming at that `close()` wastes the pick.
//!
//! A syscall is mutable once a run reads bytes for it from an argument outside
//! [`crate::skipped_args`], whether or not the input holds a call for it yet:
//! the run then asks crossover to import one.
//! `close(fd)`, `fsync(fd)` and marker-only pseudo-calls never read any.
//!
//! Mutability comes from the last run, which no mutator changes, so one
//! [`Focus`] stays valid for a whole stack of mutations.

use libafl_bolts::rands::Rand;
use std::num::NonZero;

use crate::input::SyscallID;

/// The syscalls one round of mutation may aim at, built by
/// [`AlmondInput::focus`](crate::input::AlmondInput::focus).
#[derive(Debug, Clone)]
pub struct Focus {
    /// The accesses of mutable syscalls in run order, or every access if none
    /// is mutable. The last one is the roadblock.
    pool: Vec<SyscallID>,
}

impl Focus {
    /// # Panics
    ///
    /// If `accessed` is empty.
    pub(crate) fn new(accessed: &[SyscallID], is_mutable: impl Fn(SyscallID) -> bool) -> Self {
        assert!(
            !accessed.is_empty(),
            "no syscall accessed yet — mutator invoked before any syscall ran"
        );

        // A pick that lands on a call with nothing to mutate is lost. If
        // nothing is mutable, no pick helps, so choose among everything.
        let mut pool: Vec<SyscallID> = accessed
            .iter()
            .copied()
            .filter(|&id| is_mutable(id))
            .collect();
        if pool.is_empty() {
            pool = accessed.to_vec();
        }
        Self { pool }
    }

    /// Heuristic: 50% chance to select the roadblock, 50% chance to select a
    /// random access from the pool.
    pub fn select<R: Rand>(&self, rand: &mut R) -> SyscallID {
        if rand.below(NonZero::new(10).unwrap()) < 5 {
            return *self.pool.last().expect("the pool is never empty");
        }
        let len = NonZero::new(self.pool.len()).expect("the pool is never empty");
        self.pool[rand.below(len)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hashbrown::HashMap;
    use libafl_bolts::rands::StdRand;

    const DRAWS: usize = 20_000;

    /// Fraction of `DRAWS` selections that aimed at each syscall, when the run
    /// read mutable bytes for each of `mutable`.
    fn aim_shares(accessed: &[SyscallID], mutable: &[SyscallID]) -> HashMap<SyscallID, f64> {
        let focus = Focus::new(accessed, |s| mutable.contains(&s));
        let mut rand = StdRand::with_seed(42);
        let mut counts: HashMap<SyscallID, usize> = HashMap::new();
        for _ in 0..DRAWS {
            *counts.entry(focus.select(&mut rand)).or_default() += 1;
        }
        counts
            .into_iter()
            .map(|(id, n)| (id, n as f64 / DRAWS as f64))
            .collect()
    }

    fn assert_share(shares: &HashMap<SyscallID, f64>, id: SyscallID, expected: f64) {
        let got = shares.get(&id).copied().unwrap_or(0.0);
        assert!(
            (got - expected).abs() < 0.03,
            "syscall {id}: aimed {got:.3}, expected {expected:.3}"
        );
    }

    const READ: SyscallID = 0;
    const WRITE: SyscallID = 1;
    const SOCKET: SyscallID = 41;
    const CONNECT: SyscallID = 42;
    const BIND: SyscallID = 49;
    const CLOSE: SyscallID = 3;
    const FSYNC: SyscallID = 74;
    const DUP: SyscallID = 32;

    #[test]
    fn select_looks_past_syscalls_that_read_no_mutable_bytes() {
        // socket(), connect() fails, then the error branch runs close(fd),
        // whose only fuzz() call is a NULL marker.
        let shares = aim_shares(&[SOCKET, CONNECT, CLOSE], &[SOCKET, CONNECT]);

        assert_share(&shares, CONNECT, 0.75);
        assert_share(&shares, SOCKET, 0.25);
        assert!(
            !shares.contains_key(&CLOSE),
            "close was aimed at: {shares:?}"
        );
    }

    #[test]
    fn select_looks_past_a_cleanup_chain() {
        // goto-style cleanup: an fsync(fd) and two close(fd) after the failure.
        let shares = aim_shares(&[SOCKET, BIND, FSYNC, CLOSE, CLOSE], &[SOCKET, BIND]);

        assert_share(&shares, BIND, 0.75);
        assert_share(&shares, SOCKET, 0.25);
        assert_eq!(shares.len(), 2, "aimed at a cleanup call: {shares:?}");
    }

    #[test]
    fn uniform_pick_follows_access_counts() {
        let shares = aim_shares(&[READ, READ, READ, WRITE], &[READ, WRITE]);

        assert_share(&shares, WRITE, 0.5 + 0.5 / 4.0);
        assert_share(&shares, READ, 0.5 * 3.0 / 4.0);
    }

    #[test]
    fn select_falls_back_when_nothing_is_mutable() {
        let shares = aim_shares(&[DUP, CLOSE], &[]);

        assert_share(&shares, CLOSE, 0.75);
        assert_share(&shares, DUP, 0.25);
    }

    #[test]
    #[should_panic(expected = "no syscall accessed yet")]
    fn focus_needs_an_accessed_syscall() {
        Focus::new(&[], |_| false);
    }
}
