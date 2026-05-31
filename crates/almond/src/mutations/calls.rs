// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! Enhanced mutation operators for AlmondInput call manipulation
//!
//! This module provides advanced mutation capabilities including:
//! - Call reordering within a syscall
//! - Call addition and deletion
//! - Crossover mutations between different inputs

use core::num::NonZero;
use std::borrow::Cow;

use libafl::{
    Error,
    corpus::CorpusId,
    inputs::BytesInput,
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand};

use crate::input::{Call, Calls, NUM_ARGS};

/// Mutator that reorders calls within a syscall by swapping two random positions
#[derive(Debug)]
pub struct CallReorderMutator {
    name: Cow<'static, str>,
}

impl CallReorderMutator {
    /// Create a new [`CallReorderMutator`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("CallReorderMutator"),
        }
    }
}

impl Default for CallReorderMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Mutator<Calls, S> for CallReorderMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, calls: &mut Calls) -> Result<MutationResult, Error> {
        if calls.len() < 2 {
            return Ok(MutationResult::Skipped);
        }

        let rand = state.rand_mut();

        // Select two distinct random positions
        let len = unsafe { NonZero::new(calls.len()).unwrap_unchecked() };
        let pos1 = rand.below(len);
        let mut pos2 = rand.below(len);
        while pos2 == pos1 {
            pos2 = rand.below(len);
        }

        // Swap the calls at these positions
        calls.parts_mut().swap(pos1, pos2);

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for CallReorderMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mutator that reverses the order of all calls within a syscall
#[derive(Debug)]
#[allow(dead_code)]
pub struct CallReverseMutator {
    name: Cow<'static, str>,
}

impl CallReverseMutator {
    /// Create a new [`CallReverseMutator`]
    #[must_use]
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("CallReverseMutator"),
        }
    }
}

impl Default for CallReverseMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Mutator<Calls, S> for CallReverseMutator
where
    S: HasRand,
{
    fn mutate(&mut self, _state: &mut S, calls: &mut Calls) -> Result<MutationResult, Error> {
        if calls.len() < 2 {
            return Ok(MutationResult::Skipped);
        }

        calls.parts_mut().reverse();
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for CallReverseMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mutator that rotates calls within a syscall by a random offset
#[derive(Debug)]
pub struct CallRotateMutator {
    name: Cow<'static, str>,
}

impl CallRotateMutator {
    /// Create a new [`CallRotateMutator`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("CallRotateMutator"),
        }
    }
}

impl Default for CallRotateMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Mutator<Calls, S> for CallRotateMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, calls: &mut Calls) -> Result<MutationResult, Error> {
        if calls.len() < 2 {
            return Ok(MutationResult::Skipped);
        }

        let rand = state.rand_mut();
        let rotate_amount = if calls.len() > 1 {
            rand.below(unsafe { NonZero::new(calls.len() - 1).unwrap_unchecked() }) + 1
        } else {
            1
        };

        calls.parts_mut().rotate_left(rotate_amount);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for CallRotateMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mutator that adds a new call by duplicating an existing one
#[derive(Debug)]
pub struct CallAddMutator {
    name: Cow<'static, str>,
}

impl CallAddMutator {
    /// Create a new [`CallAddMutator`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("CallAddMutator"),
        }
    }
}

impl Default for CallAddMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Mutator<Calls, S> for CallAddMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, calls: &mut Calls) -> Result<MutationResult, Error> {
        if calls.is_empty() {
            // If no calls exist, we can't add by duplication
            return Ok(MutationResult::Skipped);
        }

        if calls.len() >= 5 {
            // Limit the number of calls to prevent excessive growth
            return Ok(MutationResult::Skipped);
        }

        let rand = state.rand_mut();

        // Select a random call to duplicate
        let source_idx = rand.below(unsafe { NonZero::new(calls.len()).unwrap_unchecked() });
        let source_call = calls.part_at_index(source_idx).unwrap().clone();

        // Insert at random position (including at the end)
        let insert_pos = if !calls.is_empty() {
            rand.below(unsafe { NonZero::new(calls.len() + 1).unwrap_unchecked() })
        } else {
            0
        };

        calls.insert_part(insert_pos, source_call);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for CallAddMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mutator that deletes a random call from a syscall
#[derive(Debug)]
pub struct CallDeleteMutator {
    name: Cow<'static, str>,
}

impl CallDeleteMutator {
    /// Create a new [`CallDeleteMutator`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("CallDeleteMutator"),
        }
    }
}

impl Default for CallDeleteMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Mutator<Calls, S> for CallDeleteMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, calls: &mut Calls) -> Result<MutationResult, Error> {
        if calls.len() < 2 {
            return Ok(MutationResult::Skipped);
        }

        let rand = state.rand_mut();

        // Select a random call to delete
        let delete_idx = rand.below(unsafe { NonZero::new(calls.len()).unwrap_unchecked() });

        calls.remove_part_at_index(delete_idx);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for CallDeleteMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mutator that performs crossover between two calls by swapping arguments
#[derive(Debug)]
pub struct CallCrossoverMutator {
    name: Cow<'static, str>,
}

impl CallCrossoverMutator {
    /// Create a new [`CallCrossoverMutator`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("CallCrossoverMutator"),
        }
    }
}

impl Default for CallCrossoverMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Mutator<Calls, S> for CallCrossoverMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, calls: &mut Calls) -> Result<MutationResult, Error> {
        if calls.len() < 2 {
            return Ok(MutationResult::Skipped);
        }

        let rand = state.rand_mut();

        // Select two distinct calls
        let len = unsafe { NonZero::new(calls.len()).unwrap_unchecked() };
        let idx1 = rand.below(len);
        let mut idx2 = rand.below(len);
        while idx2 == idx1 {
            idx2 = rand.below(len);
        }

        // Select random arguments to swap between calls
        let arg_idx = rand.below(unsafe { NonZero::new(NUM_ARGS).unwrap_unchecked() });

        // Get mutable access to the calls using parts_at_indices_mut to avoid borrowing conflicts
        if idx1 < idx2 {
            let [call1, call2] = calls.parts_at_indices_mut([idx1, idx2]);
            std::mem::swap(&mut call1[arg_idx], &mut call2[arg_idx]);
        } else {
            let [call2, call1] = calls.parts_at_indices_mut([idx2, idx1]);
            std::mem::swap(&mut call1[arg_idx], &mut call2[arg_idx]);
        }

        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for CallCrossoverMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mutator that creates a new call with minimal valid data
#[derive(Debug)]
#[allow(dead_code)]
pub struct CallCreateMutator {
    name: Cow<'static, str>,
}

impl CallCreateMutator {
    /// Create a new [`CallCreateMutator`]
    #[must_use]
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            name: Cow::Borrowed("CallCreateMutator"),
        }
    }
}

impl Default for CallCreateMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Mutator<Calls, S> for CallCreateMutator
where
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, calls: &mut Calls) -> Result<MutationResult, Error> {
        if !calls.is_empty() {
            // Should use CallAddMutator if calls already exist, to preserve the structure
            return Ok(MutationResult::Skipped);
        }
        let rand = state.rand_mut();

        let new_call: Call = std::array::from_fn(|_| BytesInput::new(vec![0]));

        // Randomly modify one argument to make it more interesting
        let arg_idx = rand.below(unsafe { NonZero::new(NUM_ARGS).unwrap_unchecked() });
        let arg_len = rand.below(unsafe { NonZero::new(16).unwrap_unchecked() }) + 1; // 1-16 bytes
        let arg_bytes: Vec<u8> = (0..arg_len).map(|_| rand.next() as u8).collect();

        let mut new_call_mut = new_call;
        new_call_mut[arg_idx] = BytesInput::new(arg_bytes);

        // Insert at random position
        let insert_pos = if !calls.is_empty() {
            rand.below(unsafe { NonZero::new(calls.len() + 1).unwrap_unchecked() })
        } else {
            0
        };

        calls.insert_part(insert_pos, new_call_mut);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

impl Named for CallCreateMutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::Call;
    use crate::input::list::CallsInput;
    use libafl_bolts::{HasLen, rands::StdRand};

    /// Create test calls for testing the direct call mutators
    fn create_test_calls(count: usize) -> Calls {
        let mut calls = Vec::new();
        for i in 0..count {
            let call: Call = [
                libafl::inputs::BytesInput::new(vec![i as u8, 1, 2]), // arg0
                libafl::inputs::BytesInput::new(vec![i as u8, 3, 4]), // arg1
                libafl::inputs::BytesInput::new(vec![i as u8, 5, 6]), // arg2
                libafl::inputs::BytesInput::new(vec![i as u8, 7, 8]), // arg3
                libafl::inputs::BytesInput::new(vec![i as u8, 9, 10]), // arg4
                libafl::inputs::BytesInput::new(vec![i as u8, 11, 12]), // arg5
            ];
            calls.push(call);
        }
        CallsInput::new(calls)
    }

    /// Simple mock state for testing
    struct MockState {
        rand: StdRand,
    }

    impl MockState {
        fn new() -> Self {
            Self {
                rand: StdRand::with_seed(42),
            }
        }
    }

    impl HasRand for MockState {
        type Rand = StdRand;

        fn rand(&self) -> &Self::Rand {
            &self.rand
        }

        fn rand_mut(&mut self) -> &mut Self::Rand {
            &mut self.rand
        }
    }

    #[test]
    fn test_call_reorder_mutator_basic() {
        let mut state = MockState::new();
        let mut calls = create_test_calls(2);
        let original_first = calls.part_at_index(0).unwrap().clone();
        let original_second = calls.part_at_index(1).unwrap().clone();

        let mut mutator = CallReorderMutator::new();
        let result = mutator.mutate(&mut state, &mut calls).unwrap();

        assert_eq!(result, MutationResult::Mutated);
        assert_eq!(calls.len(), 2);

        let new_first = calls.part_at_index(0).unwrap();
        let new_second = calls.part_at_index(1).unwrap();

        assert_eq!(new_first, &original_second);
        assert_eq!(new_second, &original_first);
    }

    #[test]
    fn test_call_reverse_mutator() {
        let mut state = MockState::new();
        let mut calls = create_test_calls(3);
        let original_first = calls.part_at_index(0).unwrap().clone();
        let original_last = calls.part_at_index(2).unwrap().clone();

        let mut mutator = CallReverseMutator::new();
        let result = mutator.mutate(&mut state, &mut calls).unwrap();

        assert_eq!(result, MutationResult::Mutated);
        assert_eq!(calls.part_at_index(0).unwrap(), &original_last);
        assert_eq!(calls.part_at_index(2).unwrap(), &original_first);
    }

    #[test]
    fn test_call_add_mutator() {
        let mut state = MockState::new();
        let mut calls = create_test_calls(1);
        let original_len = calls.len();

        let mut mutator = CallAddMutator::new();
        let result = mutator.mutate(&mut state, &mut calls).unwrap();

        assert_eq!(result, MutationResult::Mutated);
        assert_eq!(calls.len(), original_len + 1);
        assert_eq!(calls.len(), 2);

        // The added call should be a duplicate of the original
        let original_call = calls.part_at_index(0).unwrap();
        let added_call = calls.part_at_index(1).unwrap();
        assert_eq!(original_call, added_call);
    }

    #[test]
    fn test_call_delete_mutator() {
        let mut state = MockState::new();
        let mut calls = create_test_calls(2);
        let original_len = calls.len();

        let mut mutator = CallDeleteMutator::new();
        let result = mutator.mutate(&mut state, &mut calls).unwrap();

        assert_eq!(result, MutationResult::Mutated);
        assert_eq!(calls.len(), original_len - 1);
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn test_call_create_mutator() {
        let mut state = MockState::new();
        let mut calls = CallsInput::empty();

        let mut mutator = CallCreateMutator::new();
        let result = mutator.mutate(&mut state, &mut calls).unwrap();

        assert_eq!(result, MutationResult::Mutated);
        assert_eq!(calls.len(), 1);

        // Verify that the created call has some content beyond just zeros
        let created_call = calls.part_at_index(0).unwrap();
        let has_content = created_call.iter().any(|arg| arg.len() > 1);
        assert!(
            has_content,
            "Created call should have some content beyond default zeros"
        );
    }

    #[test]
    fn test_call_reorder_single_call() {
        let mut state = MockState::new();
        let mut calls = create_test_calls(1);

        let mut mutator = CallReorderMutator::new();
        let result = mutator.mutate(&mut state, &mut calls).unwrap();

        // Should be skipped with only 1 call
        assert_eq!(result, MutationResult::Skipped);
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn test_call_delete_empty() {
        let mut state = MockState::new();
        let mut calls = CallsInput::empty();

        let mut mutator = CallDeleteMutator::new();
        let result = mutator.mutate(&mut state, &mut calls).unwrap();

        // Should be skipped with empty calls
        assert_eq!(result, MutationResult::Skipped);
        assert_eq!(calls.len(), 0);
    }

    #[test]
    fn test_call_rotate_mutator() {
        let mut state = MockState::new();
        let mut calls = create_test_calls(3);
        let original_first = calls.part_at_index(0).unwrap().clone();

        let mut mutator = CallRotateMutator::new();
        let result = mutator.mutate(&mut state, &mut calls).unwrap();

        assert_eq!(result, MutationResult::Mutated);
        assert_eq!(calls.len(), 3);

        // With our fixed seed, the rotation amount should be predictable
        let new_first = calls.part_at_index(0).unwrap();
        // The rotation should change the first element
        assert_ne!(new_first, &original_first);
    }

    #[test]
    fn test_all_mutators_preserve_call_structure() {
        let mut state = MockState::new();

        // Test that mutators preserve the structure of individual calls
        // Use CallAddMutator which can work with 1 call and preserves structure
        let mut calls = create_test_calls(1);

        let mut mutator = CallAddMutator::new();
        let result = mutator.mutate(&mut state, &mut calls).unwrap();

        assert_eq!(result, MutationResult::Mutated);
        assert_eq!(calls.len(), 2);

        // Both calls should have valid structure (6 arguments)
        for i in 0..calls.len() {
            let call = calls.part_at_index(i).unwrap();
            assert_eq!(call.len(), 6, "Call at index {} should have 6 arguments", i);

            // Each argument should be a BytesInput with at least some content
            for (j, arg) in call.iter().enumerate() {
                assert!(
                    arg.len() >= 1,
                    "Argument {} of call {} should have content",
                    j,
                    i
                );
            }
        }
    }

    #[test]
    fn test_call_crossover_mutator() {
        let mut state = MockState::new();
        let mut calls = create_test_calls(2);
        let original_arg0_call1 = calls.part_at_index(0).unwrap()[0].clone();
        let original_arg0_call2 = calls.part_at_index(1).unwrap()[0].clone();

        let mut mutator = CallCrossoverMutator::new();
        let result = mutator.mutate(&mut state, &mut calls).unwrap();

        assert_eq!(result, MutationResult::Mutated);
        assert_eq!(calls.len(), 2);

        // With the fixed seed, the first arguments should be swapped
        let new_arg0_call1 = calls.part_at_index(0).unwrap()[0].clone();
        let new_arg0_call2 = calls.part_at_index(1).unwrap()[0].clone();

        // The arguments should be swapped
        assert_eq!(new_arg0_call1, original_arg0_call2);
        assert_eq!(new_arg0_call2, original_arg0_call1);
    }

    #[test]
    fn test_call_crossover_single_call() {
        let mut state = MockState::new();
        let mut calls = create_test_calls(1);

        let mut mutator = CallCrossoverMutator::new();
        let result = mutator.mutate(&mut state, &mut calls).unwrap();

        // Should be skipped with only 1 call
        assert_eq!(result, MutationResult::Skipped);
        assert_eq!(calls.len(), 1);
    }
}
