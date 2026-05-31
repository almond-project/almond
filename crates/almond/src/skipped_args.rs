// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

use hashbrown::HashMap;
use std::sync::OnceLock;

use crate::input::SyscallID;

pub type SkippedArgsMap = HashMap<SyscallID, Vec<u32>>;

static SKIPPED_ARGS: OnceLock<SkippedArgsMap> = OnceLock::new();

/// Register the set of arguments that should never be mutated.
///
/// Call once before fuzzing starts. The map keys are syscall numbers and the
/// values are argument indices (0-based) that the mutation engine and the
/// `fuzz()` C entry point will leave untouched.
///
/// Returns `Err` with the supplied map if it was already set.
pub fn set(map: SkippedArgsMap) -> Result<(), SkippedArgsMap> {
    SKIPPED_ARGS.set(map)
}

/// Returns `true` if `(syscall_no, arg_no)` should be skipped.
#[inline]
pub fn is_skipped(syscall_no: SyscallID, arg_no: u32) -> bool {
    SKIPPED_ARGS
        .get()
        .is_some_and(|m| m.get(&syscall_no).is_some_and(|v| v.contains(&arg_no)))
}
