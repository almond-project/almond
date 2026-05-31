// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! Crossover mutators for AlmondInput that work with the corpus.
//!
//! These mutators perform crossover between the current input and a random
//! input from the corpus.

use core::num::NonZero;
use std::borrow::Cow;

use libafl::{
    Error,
    corpus::{Corpus, CorpusId},
    mutators::{MutationResult, Mutator},
    state::{HasCorpus, HasRand},
};
use libafl_bolts::{HasLen, Named, rands::Rand};

use crate::input::AlmondInput;

/// Crossover mutator that inserts calls from a corpus input into the current input.
#[derive(Debug)]
pub struct AlmondCrossoverInsertMutator {
    name: Cow<'static, str>,
}

impl AlmondCrossoverInsertMutator {
    /// Create a new [`AlmondCrossoverInsertMutator`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("AlmondCrossoverInsertMutator"),
        }
    }
}

impl Default for AlmondCrossoverInsertMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Mutator<AlmondInput, S> for AlmondCrossoverInsertMutator
where
    S: HasCorpus<AlmondInput> + HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut AlmondInput) -> Result<MutationResult, Error> {
        // Get corpus count and current ID first
        let (corpus_count, current_id) = {
            let corpus = state.corpus();
            (corpus.count(), *corpus.current())
        };

        if corpus_count < 2 {
            return Ok(MutationResult::Skipped);
        }

        // Get a random corpus id
        let rand_id = libafl::random_corpus_id!(state.corpus(), state.rand_mut());

        // Don't crossover with the current input
        if current_id == Some(rand_id) {
            return Ok(MutationResult::Skipped);
        }

        // Get the other input from corpus
        let other_input = {
            let corpus = state.corpus();
            let other_testcase = corpus.get(rand_id)?;
            let borrowed = other_testcase.borrow();
            (*borrowed.input()).clone()
        };

        let Some(other_input) = other_input else {
            return Ok(MutationResult::Skipped);
        };

        // Get the target syscall from current input
        let target_syscall = input.current_syscall_id();

        // Lock both inputs
        let mut inner = input.inner.write().unwrap();
        let other_inner = other_input.inner.read().unwrap();

        // Get calls from other input for the current syscall
        let Some(other_calls) = other_inner.map.get(&target_syscall) else {
            return Ok(MutationResult::Skipped);
        };

        if other_calls.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // Select a random call to insert
        let call_idx = state
            .rand_mut()
            .below(unsafe { NonZero::new(other_calls.len()).unwrap_unchecked() });

        let Some(call_to_insert) = other_calls.part_at_index(call_idx).cloned() else {
            return Ok(MutationResult::Skipped);
        };

        // Insert the call into current input
        inner
            .map
            .entry(target_syscall)
            .or_insert_with(|| Vec::new().into())
            .append_part(call_to_insert);

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for AlmondCrossoverInsertMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Crossover mutator that replaces calls in the current input with calls from corpus.
#[derive(Debug)]
pub struct AlmondCrossoverReplaceMutator {
    name: Cow<'static, str>,
}

impl AlmondCrossoverReplaceMutator {
    /// Create a new [`AlmondCrossoverReplaceMutator`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("AlmondCrossoverReplaceMutator"),
        }
    }
}

impl Default for AlmondCrossoverReplaceMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Mutator<AlmondInput, S> for AlmondCrossoverReplaceMutator
where
    S: HasCorpus<AlmondInput> + HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut AlmondInput) -> Result<MutationResult, Error> {
        // Get corpus count and current ID first
        let (corpus_count, current_id) = {
            let corpus = state.corpus();
            (corpus.count(), *corpus.current())
        };

        if corpus_count < 2 {
            return Ok(MutationResult::Skipped);
        }

        // Get a random corpus id
        let rand_id = libafl::random_corpus_id!(state.corpus(), state.rand_mut());

        // Don't crossover with the current input
        if current_id == Some(rand_id) {
            return Ok(MutationResult::Skipped);
        }

        // Get the other input from corpus
        let other_input = {
            let corpus = state.corpus();
            let other_testcase = corpus.get(rand_id)?;
            let borrowed = other_testcase.borrow();
            (*borrowed.input()).clone()
        };

        let Some(other_input) = other_input else {
            return Ok(MutationResult::Skipped);
        };

        // Get the target syscall from current input
        let target_syscall = input.current_syscall_id();

        // Lock both inputs
        let mut inner = input.inner.write().unwrap();
        let other_inner = other_input.inner.read().unwrap();

        // Get calls from both inputs for the current syscall
        let Some(current_calls) = inner.map.get_mut(&target_syscall) else {
            return Ok(MutationResult::Skipped);
        };
        let Some(other_calls) = other_inner.map.get(&target_syscall) else {
            return Ok(MutationResult::Skipped);
        };

        if current_calls.is_empty() || other_calls.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // Select indices for replacement
        let current_idx = state
            .rand_mut()
            .below(unsafe { NonZero::new(current_calls.len()).unwrap_unchecked() });
        let other_idx = state
            .rand_mut()
            .below(unsafe { NonZero::new(other_calls.len()).unwrap_unchecked() });

        // Get the call to replace with
        let Some(replacement_call) = other_calls.part_at_index(other_idx).cloned() else {
            return Ok(MutationResult::Skipped);
        };

        // Replace the call
        if let Some(call) = current_calls.part_at_index_mut(current_idx) {
            *call = replacement_call;
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for AlmondCrossoverReplaceMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Crossover mutator that copies argument values from a corpus input.
#[derive(Debug)]
pub struct AlmondCrossoverArgsMutator {
    name: Cow<'static, str>,
}

impl AlmondCrossoverArgsMutator {
    /// Create a new [`AlmondCrossoverArgsMutator`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("AlmondCrossoverArgsMutator"),
        }
    }
}

impl Default for AlmondCrossoverArgsMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Mutator<AlmondInput, S> for AlmondCrossoverArgsMutator
where
    S: HasCorpus<AlmondInput> + HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut AlmondInput) -> Result<MutationResult, Error> {
        // Get corpus count and current ID first
        let (corpus_count, current_id) = {
            let corpus = state.corpus();
            (corpus.count(), *corpus.current())
        };

        if corpus_count < 2 {
            return Ok(MutationResult::Skipped);
        }

        // Get a random corpus id
        let rand_id = libafl::random_corpus_id!(state.corpus(), state.rand_mut());

        // Don't crossover with the current input
        if current_id == Some(rand_id) {
            return Ok(MutationResult::Skipped);
        }

        // Get the other input from corpus
        let other_input = {
            let corpus = state.corpus();
            let other_testcase = corpus.get(rand_id)?;
            let borrowed = other_testcase.borrow();
            (*borrowed.input()).clone()
        };

        let Some(other_input) = other_input else {
            return Ok(MutationResult::Skipped);
        };

        // Get the target syscall from current input
        let target_syscall = input.current_syscall_id();

        // Lock both inputs
        let mut inner = input.inner.write().unwrap();
        let other_inner = other_input.inner.read().unwrap();

        // Get calls from other input for the current syscall
        let Some(other_calls) = other_inner.map.get(&target_syscall) else {
            return Ok(MutationResult::Skipped);
        };

        if other_calls.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // Collect non-empty argument candidates from other input
        let mut candidates: Vec<(usize, usize)> = Vec::new();
        for call_idx in 0..other_calls.len() {
            if let Some(call) = other_calls.part_at_index(call_idx) {
                for (arg_idx, arg) in call.iter().enumerate() {
                    if !arg.is_empty() {
                        candidates.push((call_idx, arg_idx));
                    }
                }
            }
        }

        if candidates.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // Select a random candidate
        let idx = state
            .rand_mut()
            .below(unsafe { NonZero::new(candidates.len()).unwrap_unchecked() });
        let (other_call_idx, arg_idx) = candidates[idx];

        // Get the argument value from other input
        let Some(other_call) = other_calls.part_at_index(other_call_idx) else {
            return Ok(MutationResult::Skipped);
        };
        let arg_value = other_call[arg_idx].clone();

        // Apply to current input
        let Some(current_calls) = inner.map.get_mut(&target_syscall) else {
            return Ok(MutationResult::Skipped);
        };

        if current_calls.is_empty() {
            return Ok(MutationResult::Skipped);
        }

        // Select a call to modify in current input
        let current_call_idx = state
            .rand_mut()
            .below(unsafe { NonZero::new(current_calls.len()).unwrap_unchecked() });

        if let Some(call) = current_calls.part_at_index_mut(current_call_idx) {
            call[arg_idx] = arg_value;
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for AlmondCrossoverArgsMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::Call;
    use libafl::inputs::BytesInput;

    fn create_test_input() -> AlmondInput {
        let input = AlmondInput::new();
        let mut inner = input.inner.write().unwrap();

        // Add some test calls
        let call1: Call = [
            BytesInput::new(vec![1, 2, 3]),
            BytesInput::new(vec![4, 5, 6]),
            BytesInput::new(vec![]),
            BytesInput::new(vec![]),
            BytesInput::new(vec![]),
            BytesInput::new(vec![]),
        ];
        let call2: Call = [
            BytesInput::new(vec![7, 8, 9]),
            BytesInput::new(vec![10, 11, 12]),
            BytesInput::new(vec![]),
            BytesInput::new(vec![]),
            BytesInput::new(vec![]),
            BytesInput::new(vec![]),
        ];

        inner.map.insert(41, vec![call1, call2].into());
        drop(inner);
        input
    }

    #[test]
    fn test_crossover_mutator_names() {
        let insert = AlmondCrossoverInsertMutator::new();
        let replace = AlmondCrossoverReplaceMutator::new();
        let args = AlmondCrossoverArgsMutator::new();

        assert_eq!(insert.name(), "AlmondCrossoverInsertMutator");
        assert_eq!(replace.name(), "AlmondCrossoverReplaceMutator");
        assert_eq!(args.name(), "AlmondCrossoverArgsMutator");
    }

    #[test]
    fn test_create_test_input() {
        let input = create_test_input();
        let inner = input.inner.read().unwrap();
        assert!(inner.map.contains_key(&41));
        let calls = inner.map.get(&41).unwrap();
        assert_eq!(calls.len(), 2);
    }
}
