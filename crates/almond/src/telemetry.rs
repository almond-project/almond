// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! Facts recorded for offline analysis only.
//!
//! Nothing here is read back by scheduling, feedback or mutation: the types are
//! filled in as a side effect of work the engine already does, and no extra
//! random draw is taken to fill them, so recording them cannot change which
//! inputs a campaign generates, keeps or mutates.
//!
//! The types are always compiled. The `telemetry` feature only switches on
//! the recording that costs something on the mutation path: extending each
//! mutant's [`Lineage`] and the scheduled mutator's [`ReportsRound`].

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// Which family of mutator an applied operation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationClass {
    /// Byte-level havoc and token mutators applied to one argument.
    Bytes,
    /// Call-list mutators that reorder, add, delete, rotate or splice calls.
    Calls,
    /// Corpus crossover that imports calls or arguments from another input.
    Crossover,
}

/// A mutator whose class is fixed by its type.
///
/// The scheduled mutator only accepts tuples of these, so a mutator that
/// would go uncounted fails to compile instead of silently missing from the
/// per-class tallies.
pub trait Classified {
    const CLASS: MutationClass;
}

/// The classes of a mutator tuple, in tuple order.
pub trait ClassifiedTuple {
    fn collect_classes(out: &mut Vec<MutationClass>);

    #[must_use]
    fn classes() -> Vec<MutationClass> {
        let mut out = Vec::new();
        Self::collect_classes(&mut out);
        out
    }
}

impl ClassifiedTuple for () {
    fn collect_classes(_out: &mut Vec<MutationClass>) {}
}

impl<Head, Tail> ClassifiedTuple for (Head, Tail)
where
    Head: Classified,
    Tail: ClassifiedTuple,
{
    fn collect_classes(out: &mut Vec<MutationClass>) {
        out.push(Head::CLASS);
        Tail::collect_classes(out);
    }
}

/// The ancestry of an input, counted from the seed it descends from.
///
/// It travels inside the input, so a corpus entry passes it on to every
/// mutant drawn from it and a crashing input carries it to the host.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Lineage {
    /// Mutation rounds between the seed (depth 0) and this input.
    pub depth: u32,
    /// Individual mutator applications that changed the input, over all rounds.
    pub ops: u32,
    /// The part of `ops` applied by byte mutators.
    pub bytes: u32,
    /// The part of `ops` applied by call-list mutators.
    pub calls: u32,
    /// The part of `ops` applied by corpus crossover.
    pub crossover: u32,
}

impl Lineage {
    /// Extend the ancestry by one round of mutation.
    pub fn extend(&mut self, round: &RoundTally) {
        self.depth = self.depth.saturating_add(1);
        self.ops = self.ops.saturating_add(round.ops);
        self.bytes = self.bytes.saturating_add(round.bytes);
        self.calls = self.calls.saturating_add(round.calls);
        self.crossover = self.crossover.saturating_add(round.crossover);
    }
}

/// Applied operations of one round of mutation, by class.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoundTally {
    pub ops: u32,
    pub bytes: u32,
    pub calls: u32,
    pub crossover: u32,
}

impl RoundTally {
    /// Count one applied operation of `class`.
    pub fn count(&mut self, class: MutationClass) {
        self.ops = self.ops.saturating_add(1);
        let counter = match class {
            MutationClass::Bytes => &mut self.bytes,
            MutationClass::Calls => &mut self.calls,
            MutationClass::Crossover => &mut self.crossover,
        };
        *counter = counter.saturating_add(1);
    }
}

/// Where the stacked operations of one round of mutation aimed.
///
/// Only operations that changed the input are counted. It describes the round
/// the scheduled mutator ran last and is read from the mutator, not from the
/// input: an input keeps no record of it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MutationRound {
    /// Stacked operations that changed the input.
    pub ops: u32,
    /// The part of `ops` whose target was the roadblock, the last call the
    /// parent's run reached (see [`crate::focus::Focus::roadblock`]).
    pub ops_on_roadblock: u32,
}

/// A mutator that can say where its last round of mutation aimed.
///
/// [`crate::mutations::AlmondScheduledMutator`] implements it only with the
/// `telemetry` feature.
pub trait ReportsRound {
    /// Focus statistics of the round the last `mutate` call ran; all zero
    /// when that call changed nothing.
    fn last_round(&self) -> MutationRound;
}

/// A mutator that changes nothing has no round to report.
impl ReportsRound for libafl::mutators::NopMutator {
    fn last_round(&self) -> MutationRound {
        MutationRound::default()
    }
}

/// One-based index, within the fuzzer state, of the execution in flight.
///
/// Only [`crate::executors::subthread::SubthreadInProcessExecutor`] sets it.
/// Under any other executor it stays `0`, and a slot written from an
/// observer's `pre_exec` carries the previous execution's index.
static EXEC_INDEX: AtomicU64 = AtomicU64::new(0);

/// Record the index of the execution about to start.
///
/// The executor takes it from the state's execution counter. That counter
/// survives a client restart that restores the state, and starts again from
/// zero with a fresh state. A VM snapshot restore also sets it back, while
/// the ivshmem ring, which lives outside the guest, keeps slots written
/// before the restore. An index is therefore unique only within one launch
/// of the fuzzer between two restores; the host has to number those itself.
pub fn set_exec_index(index: u64) {
    EXEC_INDEX.store(index, Ordering::Relaxed);
}

/// Index of the execution in flight, or of the last one if none is running.
/// `0` before the first execution.
#[must_use]
pub fn exec_index() -> u64 {
    EXEC_INDEX.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Bytes;
    struct Calls;
    impl Classified for Bytes {
        const CLASS: MutationClass = MutationClass::Bytes;
    }
    impl Classified for Calls {
        const CLASS: MutationClass = MutationClass::Calls;
    }

    #[test]
    fn tuple_classes_follow_tuple_order() {
        assert_eq!(<()>::classes(), vec![]);
        assert_eq!(
            <(Calls, (Bytes, (Calls, ())))>::classes(),
            vec![
                MutationClass::Calls,
                MutationClass::Bytes,
                MutationClass::Calls
            ]
        );
    }

    #[test]
    fn extend_adds_one_level_and_the_round_counts() {
        let mut lineage = Lineage::default();
        let mut round = RoundTally::default();
        round.count(MutationClass::Calls);
        round.count(MutationClass::Bytes);
        round.count(MutationClass::Crossover);

        lineage.extend(&round);
        lineage.extend(&round);

        assert_eq!(
            lineage,
            Lineage {
                depth: 2,
                ops: 6,
                bytes: 2,
                calls: 2,
                crossover: 2
            }
        );
    }
}
