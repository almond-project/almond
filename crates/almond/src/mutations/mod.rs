// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

use std::{borrow::Cow, num::NonZero};

use libafl::{
    Error,
    corpus::CorpusId,
    mutators::{
        ComposedByMutations, MutationId, MutationResult, Mutator, MutatorsTuple, ScheduledMutator,
        mutations::BytesExpandMutator,
    },
    state::{HasCorpus, HasMaxSize, HasRand},
};
use libafl_bolts::{
    HasLen, Named,
    rands::Rand,
    tuples::{Map, NamedTuple, tuple_list},
};

use crate::{
    input::AlmondInput,
    mutations::mapping::ToAlmondTargetedBytesMutator,
    telemetry::{ClassifiedTuple, MutationClass, RoundTally},
};
#[cfg(feature = "telemetry")]
use crate::telemetry::{MutationRound, ReportsRound};
pub use crossover::{
    AlmondCrossoverArgsMutator, AlmondCrossoverInsertMutator, AlmondCrossoverReplaceMutator,
};

pub mod calls;
pub mod crossover;
pub mod mapping;

#[derive(Debug)]
pub struct AlmondScheduledMutator<MT> {
    name: Cow<'static, str>,
    mutations: MT,
    crossover_insert_mutator: AlmondCrossoverInsertMutator,
    max_stack_pow: usize,
    classes: Vec<MutationClass>,
    #[cfg(feature = "telemetry")]
    last_round: MutationRound,
}

impl<MT> Named for AlmondScheduledMutator<MT> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S, MT> Mutator<AlmondInput, S> for AlmondScheduledMutator<MT>
where
    S: HasCorpus<AlmondInput> + HasRand + HasMaxSize,
    MT: MutatorsTuple<AlmondInput, S>,
{
    #[inline]
    fn mutate(&mut self, state: &mut S, input: &mut AlmondInput) -> Result<MutationResult, Error> {
        // The repairs below change the input too, so they belong to its
        // lineage; they are not aimed by the focus, so not to its round.
        let mut applied = RoundTally::default();
        if input.has_insufficient_indicators() {
            // The sets iterate in an order that differs from process to
            // process, and each repair draws from the RNG: sorting keeps the
            // mutants a seed produces the same across runs.
            let mut short_args: Vec<_> =
                input.insufficient_bytes_indicators().into_iter().collect();
            short_args.sort_unstable();
            for indicator in short_args {
                let mut mutator =
                    tuple_list!(BytesExpandMutator::new()).map(ToAlmondTargetedBytesMutator::new(
                        indicator.0,
                        indicator.1,
                        indicator.2 as usize,
                    ));
                if mutator.mutate_all(state, input)? == MutationResult::Mutated {
                    applied.count(MutationClass::Bytes);
                }
            }

            let mut missing_calls: Vec<_> =
                input.insufficient_calls_indicators().into_iter().collect();
            missing_calls.sort_unstable();
            for syscall_no in missing_calls {
                input.set_current_syscall_id(syscall_no);
                if self.crossover_insert_mutator.mutate(state, input)? == MutationResult::Mutated {
                    applied.count(MutationClass::Crossover);
                }
            }
        }
        self.run_round(state, input, applied)
    }

    #[inline]
    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl<MT> ComposedByMutations for AlmondScheduledMutator<MT> {
    type Mutations = MT;
    /// Get the mutations
    #[inline]
    fn mutations(&self) -> &MT {
        &self.mutations
    }

    // Get the mutations (mutable)
    #[inline]
    fn mutations_mut(&mut self) -> &mut MT {
        &mut self.mutations
    }
}

impl<S, MT> ScheduledMutator<AlmondInput, S> for AlmondScheduledMutator<MT>
where
    MT: MutatorsTuple<AlmondInput, S>,
    S: HasCorpus<AlmondInput> + HasRand + HasMaxSize,
{
    /// Compute the number of iterations used to apply stacked mutations
    fn iterations(&self, state: &mut S, _: &AlmondInput) -> u64 {
        1 << (1 + state.rand_mut().below_or_zero(self.max_stack_pow))
    }

    /// Get the next mutation to apply
    fn schedule(&self, state: &mut S, _: &AlmondInput) -> MutationId {
        self.schedule_index(state).into()
    }

    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut AlmondInput,
    ) -> Result<MutationResult, Error> {
        self.run_round(state, input, RoundTally::default())
    }
}

#[cfg(feature = "telemetry")]
impl<MT> ReportsRound for AlmondScheduledMutator<MT> {
    fn last_round(&self) -> MutationRound {
        self.last_round
    }
}

impl<MT> AlmondScheduledMutator<MT> {
    /// Index of the next mutation; `0` for an empty tuple, which then has
    /// nothing at that index to apply.
    fn schedule_index<S: HasRand>(&self, state: &mut S) -> usize
    where
        MT: HasLen,
    {
        NonZero::new(self.mutations.len()).map_or(0, |len| state.rand_mut().below(len))
    }

    /// Run one stack of scheduled mutations on top of the repairs already
    /// tallied in `applied`. With the `telemetry` feature, also record the
    /// round on the input if it changed.
    ///
    /// The tallies only observe the stack: they take no random draw, so the
    /// mutation stream is the same with or without the feature.
    fn run_round<S>(
        &mut self,
        state: &mut S,
        input: &mut AlmondInput,
        mut applied: RoundTally,
    ) -> Result<MutationResult, Error>
    where
        MT: MutatorsTuple<AlmondInput, S>,
        S: HasCorpus<AlmondInput> + HasRand + HasMaxSize,
    {
        #[cfg(feature = "telemetry")]
        {
            self.last_round = MutationRound::default();
        }
        let repairs = applied.ops;
        let num = self.iterations(state, input);
        // The focus depends only on what the last run read, which no mutator
        // changes, so one focus serves the whole stack.
        let focus = input.focus();
        #[cfg(feature = "telemetry")]
        let roadblock = focus.roadblock();
        #[cfg(feature = "telemetry")]
        let mut ops_on_roadblock = 0u32;
        for _ in 0..num {
            let idx = self.schedule_index(state);
            let target = focus.select(state.rand_mut());
            input.set_current_syscall_id(target);
            let outcome = self
                .mutations_mut()
                .get_and_mutate(idx.into(), state, input)?;
            if outcome != MutationResult::Mutated {
                continue;
            }
            if let Some(&class) = self.classes.get(idx) {
                applied.count(class);
            }
            #[cfg(feature = "telemetry")]
            if target == roadblock {
                ops_on_roadblock = ops_on_roadblock.saturating_add(1);
            }
        }
        let stacked = applied.ops - repairs;
        if stacked == 0 {
            // A repaired input whose stack changed nothing is reported as
            // skipped, as before lineage existed: the caller drops it.
            return Ok(MutationResult::Skipped);
        }
        // Extending the lineage takes the input's write lock once per round.
        #[cfg(feature = "telemetry")]
        {
            input.record_round(&applied);
            self.last_round = MutationRound {
                ops: stacked,
                ops_on_roadblock,
            };
        }
        Ok(MutationResult::Mutated)
    }
}

impl<MT> AlmondScheduledMutator<MT>
where
    MT: NamedTuple + ClassifiedTuple,
{
    /// Create a new [`AlmondScheduledMutator`] instance specifying mutations
    pub fn new(mutations: MT) -> Self {
        AlmondScheduledMutator {
            name: Cow::from(format!(
                "AlmondScheduledMutator[{}]",
                mutations.names().join(", ")
            )),
            classes: MT::classes(),
            mutations,
            crossover_insert_mutator: AlmondCrossoverInsertMutator::new(),
            max_stack_pow: 8,
            #[cfg(feature = "telemetry")]
            last_round: MutationRound::default(),
        }
    }

    /// The class of each mutation, indexed like the tuple.
    pub fn classes(&self) -> &[MutationClass] {
        &self.classes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        input::{Call, Calls, SyscallID, list::CallsInput},
        mutations::{
            calls::CallReorderMutator,
            mapping::{ToAlmondBytesMutator, ToAlmondCallsMutator},
        },
    };
    use libafl::{
        corpus::InMemoryCorpus, feedbacks::ConstFeedback, inputs::BytesInput,
        mutators::mutations::BitFlipMutator, state::StdState,
    };
    use libafl_bolts::{rands::StdRand, tuples::MappingFunctor};

    type TestState =
        StdState<InMemoryCorpus<AlmondInput>, AlmondInput, StdRand, InMemoryCorpus<AlmondInput>>;

    const SOCKET: SyscallID = 41;
    #[cfg(feature = "telemetry")]
    const CONNECT: SyscallID = 42;

    fn state() -> TestState {
        StdState::new(
            StdRand::with_seed(7),
            InMemoryCorpus::new(),
            InMemoryCorpus::new(),
            &mut ConstFeedback::new(false),
            &mut ConstFeedback::new(false),
        )
        .expect("state")
    }

    fn calls(count: u8) -> Calls {
        let parts: Vec<Call> = (0..count)
            .map(|i| std::array::from_fn(|arg| BytesInput::new(vec![i, arg as u8, 0xaa])))
            .collect();
        CallsInput::new(parts)
    }

    /// An input whose last run reached `reached` in order, each syscall
    /// holding two calls with non-empty arguments so every mutator applies.
    fn input_that_reached(reached: &[SyscallID]) -> AlmondInput {
        let input = AlmondInput::new();
        {
            let mut inner = input.inner.write().unwrap();
            for &id in reached {
                inner.map.insert(id, calls(2));
                inner.mutable_indicators.insert(id);
            }
            inner.accessed_indicators = reached.to_vec();
        }
        input
    }

    #[test]
    #[cfg(not(feature = "telemetry"))]
    fn without_telemetry_mutants_stay_at_the_seed_lineage() {
        let mut state = state();
        let mut mutator = AlmondScheduledMutator::new(tuple_list!(
            ToAlmondBytesMutator.apply(BitFlipMutator::new())
        ));
        let mut input = input_that_reached(&[SOCKET]);

        assert_eq!(
            mutator.mutate(&mut state, &mut input).unwrap(),
            MutationResult::Mutated
        );
        assert_eq!(input.lineage(), crate::telemetry::Lineage::default());
    }

    #[test]
    #[cfg(feature = "telemetry")]
    fn a_mutant_of_a_mutant_is_two_rounds_from_the_seed() {
        let mut state = state();
        let mut mutator = AlmondScheduledMutator::new(tuple_list!(
            ToAlmondBytesMutator.apply(BitFlipMutator::new())
        ));
        let seed = input_that_reached(&[SOCKET]);
        assert_eq!(seed.lineage().depth, 0);

        let mut child = seed.clone();
        assert_eq!(
            mutator.mutate(&mut state, &mut child).unwrap(),
            MutationResult::Mutated
        );
        let mut grandchild = child.clone();
        assert_eq!(
            mutator.mutate(&mut state, &mut grandchild).unwrap(),
            MutationResult::Mutated
        );

        let lineage = grandchild.lineage();
        assert_eq!(lineage.depth, 2);
        assert!(
            lineage.ops >= 2,
            "each round applies at least one op: {lineage:?}"
        );
        assert_eq!(lineage.bytes, lineage.ops);
        assert_eq!(lineage.calls, 0);
        assert!(lineage.ops > child.lineage().ops);
        assert_eq!(
            seed.lineage().depth,
            0,
            "mutating a clone leaves the parent alone"
        );
    }

    #[test]
    #[cfg(feature = "telemetry")]
    fn call_list_mutations_count_as_calls_not_bytes() {
        let mut state = state();
        let mut mutator = AlmondScheduledMutator::new(tuple_list!(
            ToAlmondCallsMutator.apply(CallReorderMutator::new())
        ));
        let mut input = input_that_reached(&[SOCKET]);

        mutator.mutate(&mut state, &mut input).unwrap();

        let lineage = input.lineage();
        assert!(lineage.calls >= 1);
        assert_eq!(lineage.calls, lineage.ops);
        assert_eq!(lineage.bytes, 0);
        assert_eq!(lineage.crossover, 0);
    }

    #[test]
    #[cfg(feature = "telemetry")]
    fn the_round_counts_ops_aimed_at_the_roadblock() {
        let mut state = state();
        let mut mutator = AlmondScheduledMutator::new(tuple_list!(
            ToAlmondBytesMutator.apply(BitFlipMutator::new())
        ));

        // One reachable syscall: every op aims at the roadblock.
        let mut single = input_that_reached(&[SOCKET]);
        mutator.mutate(&mut state, &mut single).unwrap();
        let round = mutator.last_round();
        assert!(round.ops >= 1);
        assert_eq!(round.ops_on_roadblock, round.ops);

        // Two: half the picks go to the roadblock and some go elsewhere.
        let (mut ops, mut on_roadblock) = (0, 0);
        for _ in 0..20 {
            let mut input = input_that_reached(&[SOCKET, CONNECT]);
            mutator.mutate(&mut state, &mut input).unwrap();
            let round = mutator.last_round();
            assert!(round.ops_on_roadblock <= round.ops);
            assert_eq!(round.ops, input.lineage().ops);
            ops += round.ops;
            on_roadblock += round.ops_on_roadblock;
        }
        assert!(
            on_roadblock > 0 && on_roadblock < ops,
            "{on_roadblock}/{ops}"
        );
    }

    #[test]
    fn classes_follow_the_tuple_order() {
        let mutator = AlmondScheduledMutator::new(tuple_list!(
            ToAlmondBytesMutator.apply(BitFlipMutator::new()),
            ToAlmondCallsMutator.apply(CallReorderMutator::new()),
            AlmondCrossoverArgsMutator::new(),
        ));
        assert_eq!(
            mutator.classes(),
            &[
                MutationClass::Bytes,
                MutationClass::Calls,
                MutationClass::Crossover
            ]
        );
    }
}
