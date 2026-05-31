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
    Named,
    rands::Rand,
    tuples::{Map, NamedTuple, tuple_list},
};

use crate::{input::AlmondInput, mutations::mapping::ToAlmondTargetedBytesMutator};
use crossover::AlmondCrossoverInsertMutator;

pub mod calls;
pub mod crossover;
pub mod mapping;

#[derive(Debug)]
pub struct AlmondScheduledMutator<MT> {
    name: Cow<'static, str>,
    mutations: MT,
    crossover_insert_mutator: AlmondCrossoverInsertMutator,
    max_stack_pow: usize,
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
        if input.has_insufficient_indicators() {
            for indicator in input.insufficient_bytes_indicators() {
                let mut mutator =
                    tuple_list!(BytesExpandMutator::new()).map(ToAlmondTargetedBytesMutator::new(
                        indicator.0,
                        indicator.1,
                        indicator.2 as usize,
                    ));
                mutator.mutate_all(state, input)?;
            }

            for syscall_no in input.insufficient_calls_indicators() {
                input.set_current_syscall_id(syscall_no);
                self.crossover_insert_mutator.mutate(state, input)?;
            }
        }
        self.scheduled_mutate(state, input)
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
        debug_assert_ne!(self.mutations.len(), 0);
        // # Safety
        // We check for empty mutations
        state
            .rand_mut()
            .below(unsafe { NonZero::new(self.mutations.len()).unwrap_unchecked() })
            .into()
    }

    fn scheduled_mutate(
        &mut self,
        state: &mut S,
        input: &mut AlmondInput,
    ) -> Result<MutationResult, Error> {
        let mut r = MutationResult::Skipped;
        let num = self.iterations(state, input);
        for _ in 0..num {
            let idx = self.schedule(state, input);
            input.select_syscall_id(state);
            let outcome = self.mutations_mut().get_and_mutate(idx, state, input)?;
            if outcome == MutationResult::Mutated {
                r = MutationResult::Mutated;
            }
        }
        Ok(r)
    }
}

impl<MT> AlmondScheduledMutator<MT>
where
    MT: NamedTuple,
{
    /// Create a new [`AlmondScheduledMutator`] instance specifying mutations
    pub fn new(mutations: MT) -> Self {
        AlmondScheduledMutator {
            name: Cow::from(format!(
                "AlmondScheduledMutator[{}]",
                mutations.names().join(", ")
            )),
            mutations,
            crossover_insert_mutator: AlmondCrossoverInsertMutator::new(),
            max_stack_pow: 8,
        }
    }
}
