// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

use core::num::NonZero;
use std::borrow::Cow;

use libafl::{
    Error,
    corpus::CorpusId,
    inputs::BytesInput,
    mutators::{MutationResult, Mutator},
    state::HasRand,
};
use libafl_bolts::{Named, rands::Rand, tuples::MappingFunctor};

use crate::input::{Calls, AlmondInput, NUM_ARGS};

/// Mutator that applies mutations to bytes input within an AlmondInput.
///
/// This mutator extracts a BytesInput from the currently selected syscall
/// and applies the inner bytes mutator to it.
#[derive(Debug)]
pub struct AlmondBytesMutator<M> {
    inner: M,
    name: Cow<'static, str>,
}

impl<M: Named> AlmondBytesMutator<M> {
    /// Create a new [`AlmondBytesMutator`].
    #[must_use]
    pub fn new(inner: M) -> Self {
        let name = Cow::Owned(format!("AlmondBytesMutator<{}>", inner.name()));
        Self { inner, name }
    }
}

impl<M, S> Mutator<AlmondInput, S> for AlmondBytesMutator<M>
where
    M: Mutator<BytesInput, S>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut AlmondInput) -> Result<MutationResult, Error> {
        let current_syscall_id = input.current_syscall_id();
        let inner = input.inner.read().unwrap();

        // Check if we have any calls for this syscall
        let calls_len = inner
            .map
            .get(&current_syscall_id)
            .map(|c| c.len())
            .unwrap_or(0);

        if calls_len == 0 {
            return Ok(MutationResult::Skipped);
        }

        // Select a random call from the available calls
        let call_idx = state
            .rand_mut()
            .below(unsafe { NonZero::new(calls_len).unwrap_unchecked() });

        // Select a random argument from the call
        let arg_idx = state
            .rand_mut()
            .below(unsafe { NonZero::new(NUM_ARGS).unwrap_unchecked() });

        if crate::skipped_args::is_skipped(current_syscall_id, arg_idx as u32) {
            return Ok(MutationResult::Skipped);
        }

        drop(inner); // Release read lock before mutation

        // Get mutable access and apply standard mutation
        let mut inner = input.inner.write().unwrap();
        if let Some(calls) = inner.map.get_mut(&current_syscall_id)
            && let Some(call) = calls.part_at_index_mut(call_idx)
        {
            let mut bytes_input = call[arg_idx].clone();

            // Apply the inner bytes mutator
            let result = self.inner.mutate(state, &mut bytes_input)?;

            // Update the call with the mutated bytes input
            call[arg_idx] = bytes_input;

            return Ok(result);
        }
        Ok(MutationResult::Skipped)
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

/// Mapping functor to convert bytes mutators to [`AlmondBytesMutator`].
#[derive(Debug)]
pub struct ToAlmondBytesMutator;

impl<M: Named> MappingFunctor<M> for ToAlmondBytesMutator {
    type Output = AlmondBytesMutator<M>;

    fn apply(&mut self, from: M) -> AlmondBytesMutator<M> {
        AlmondBytesMutator::new(from)
    }
}

impl<M> Named for AlmondBytesMutator<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mutator that applies mutations to bytes input within an AlmondInput.
///
/// This mutator extracts a BytesInput from the currently selected syscall
/// and applies the inner bytes mutator to it.
#[derive(Debug)]
pub struct AlmondTargetedBytesMutator<M> {
    inner: M,
    name: Cow<'static, str>,
    syscall_no: u32,
    call_idx: usize,
    arg_idx: usize,
}

impl<M: Named> AlmondTargetedBytesMutator<M> {
    /// Create a new [`AlmondTargetedBytesMutator`].
    #[must_use]
    pub fn new(inner: M, syscall_no: u32, call_idx: usize, arg_idx: usize) -> Self {
        let name = Cow::Owned(format!("AlmondTargetedBytesMutator<{}>", inner.name()));
        Self {
            inner,
            name,
            syscall_no,
            call_idx,
            arg_idx,
        }
    }
}

impl<M, S> Mutator<AlmondInput, S> for AlmondTargetedBytesMutator<M>
where
    M: Mutator<BytesInput, S>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut AlmondInput) -> Result<MutationResult, Error> {
        let current_syscall_id = self.syscall_no;
        let inner = input.inner.read().unwrap();

        // Check if we have any calls for this syscall
        let calls_len = inner
            .map
            .get(&current_syscall_id)
            .map(|c| c.len())
            .unwrap_or(0);

        if calls_len == 0 {
            return Ok(MutationResult::Skipped);
        }

        if crate::skipped_args::is_skipped(current_syscall_id, self.arg_idx as u32) {
            return Ok(MutationResult::Skipped);
        }

        drop(inner); // Release read lock before mutation

        // Get mutable access and apply standard mutation
        let mut inner = input.inner.write().unwrap();
        if let Some(calls) = inner.map.get_mut(&current_syscall_id)
            && let Some(call) = calls.part_at_index_mut(self.call_idx)
        {
            let mut bytes_input = call[self.arg_idx].clone();

            // Apply the inner bytes mutator
            let result = self.inner.mutate(state, &mut bytes_input)?;

            // Update the call with the mutated bytes input
            call[self.arg_idx] = bytes_input;

            return Ok(result);
        }
        Ok(MutationResult::Skipped)
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

/// Mapping functor to convert bytes mutators to [`AlmondTargetedBytesMutator`].
#[derive(Debug)]
pub struct ToAlmondTargetedBytesMutator {
    syscall_no: u32,
    call_idx: usize,
    arg_idx: usize,
}

impl ToAlmondTargetedBytesMutator {
    /// Create a new [`ToAlmondTargetedBytesMutator`].
    #[must_use]
    pub fn new(syscall_no: u32, call_idx: usize, arg_idx: usize) -> Self {
        Self {
            syscall_no,
            call_idx,
            arg_idx,
        }
    }
}

impl<M: Named> MappingFunctor<M> for ToAlmondTargetedBytesMutator {
    type Output = AlmondTargetedBytesMutator<M>;

    fn apply(&mut self, from: M) -> AlmondTargetedBytesMutator<M> {
        AlmondTargetedBytesMutator::new(from, self.syscall_no, self.call_idx, self.arg_idx)
    }
}

impl<M> Named for AlmondTargetedBytesMutator<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

/// Mutator that applies mutations to calls input within an AlmondInput.
///
/// This mutator extracts the Calls from the currently selected syscall
/// and applies the inner list mutator to it.
#[derive(Debug)]
pub struct AlmondCallsMutator<M> {
    inner: M,
    name: Cow<'static, str>,
}

impl<M: Named> AlmondCallsMutator<M> {
    /// Create a new [`AlmondCallsMutator`].
    #[must_use]
    pub fn new(inner: M) -> Self {
        let name = Cow::Owned(format!("AlmondCallsMutator<{}>", inner.name()));
        Self { inner, name }
    }
}

impl<M, S> Mutator<AlmondInput, S> for AlmondCallsMutator<M>
where
    M: Mutator<Calls, S>,
    S: HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut AlmondInput) -> Result<MutationResult, Error> {
        let current_syscall_id = input.current_syscall_id();
        let mut inner = input.inner.write().unwrap();

        // Check if we have any calls for this syscall
        if let Some(calls) = inner.map.get_mut(&current_syscall_id) {
            // Apply the inner calls mutator
            self.inner.mutate(state, calls)
        } else {
            Ok(MutationResult::Skipped)
        }
    }

    fn post_exec(&mut self, state: &mut S, new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        self.inner.post_exec(state, new_corpus_id)
    }
}

/// Mapping functor to convert calls mutators to [`AlmondCallsMutator`].
#[derive(Debug)]
pub struct ToAlmondCallsMutator;

impl<M: Named> MappingFunctor<M> for ToAlmondCallsMutator {
    type Output = AlmondCallsMutator<M>;

    fn apply(&mut self, from: M) -> AlmondCallsMutator<M> {
        AlmondCallsMutator::new(from)
    }
}

impl<M> Named for AlmondCallsMutator<M> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}
