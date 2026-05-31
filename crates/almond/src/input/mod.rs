// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

use hashbrown::{HashMap, HashSet};
use libafl::{
    inputs::{BytesInput, Input},
    state::HasRand,
};
use libafl_bolts::{HasLen, rands::Rand};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
    num::NonZero,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

/// Global flag set by `capture()` to signal the feedback that a new syscall
/// sequence was captured and the input must be added to the corpus.
pub static CAPTURE_HAPPENED: AtomicBool = AtomicBool::new(false);

pub mod list;

use list::CallsInput;

use crate::syscall_tree;

pub const NUM_ARGS: usize = 6;

pub type Call = [BytesInput; NUM_ARGS];

pub type Calls = CallsInput<Call>;

pub type SyscallID = u32;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct AlmondInputInner {
    // Map from SyscallID to an array of syscalls and then their parameters
    // In this case, we can recoustruct the constraints after mutation
    pub map: BTreeMap<SyscallID, Calls>,
    // Offsets for multiple reads
    #[serde(skip)]
    pub offsets: HashMap<SyscallID, usize>,
    // Per-(syscall_no, arg_no) read cursor into parts[offset][arg_no]. A
    // single arg slot is treated as a continuous byte stream that may be
    // consumed by multiple fuzz() calls within one syscall invocation (e.g.
    // msghdr's msg_name / iov[i] / msg_control all read from arg_no=1).
    // Cursors reset on advance_offset() — each new dynamic offset starts
    // reading from byte 0 again.
    #[serde(skip)]
    pub cursors: HashMap<(SyscallID, u32), usize>,
    // During mutation, decide which syscall to focus on.
    #[serde(skip)]
    pub current: SyscallID,
    // Mutation indicators collected during execution - Vec preserves order
    // to identify roadblocks (last accessed = likely roadblock)
    pub accessed_indicators: Vec<SyscallID>,
    #[serde(skip)]
    pub insufficient_calls_indicators: HashSet<SyscallID>,
    // SyscallID, Offset, ArgNo, ExpectedLen
    #[serde(skip)]
    pub insufficient_bytes_indicators: HashSet<(SyscallID, usize, u32, usize)>,
    // Set to true when a new syscall sequence is detected; all subsequent
    // fuzz() calls for the current syscall capture original data instead of
    // mutating. Cleared by advance_offset() after the syscall completes.
    #[serde(skip)]
    pub capturing: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AlmondInput {
    pub inner: Arc<RwLock<AlmondInputInner>>,
}

impl Clone for AlmondInput {
    /// Default to deep clone as LibAFL use .clone() for new inputs. Use arc_clone() for shallow clone when needed.
    fn clone(&self) -> Self {
        let inner = self.inner.read().unwrap();
        Self {
            inner: Arc::new(RwLock::new(inner.clone())),
        }
    }
}

impl AlmondInput {
    /// Shallow clone: creates a new AlmondInput sharing the same underlying Arc.
    #[must_use]
    pub fn arc_clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Hash for AlmondInput {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let inner = self.inner.read().unwrap();
        for (syscall_id, calls) in &inner.map {
            syscall_id.hash(state);
            calls.hash(state);
        }
    }
}

impl PartialEq for AlmondInput {
    fn eq(&self, other: &Self) -> bool {
        let self_inner = self.inner.read().unwrap();
        let other_inner = other.inner.read().unwrap();
        self_inner.map == other_inner.map
    }
}

impl Default for AlmondInput {
    fn default() -> Self {
        Self::new()
    }
}

impl AlmondInput {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(AlmondInputInner::default())),
        }
    }

    pub fn with_syscall(syscall_id: u32, call: Call) -> Self {
        let input = Self::new();
        input
            .inner
            .write()
            .unwrap()
            .map
            .insert(syscall_id, vec![call].into());
        input
    }

    pub fn get(&self, syscall_no: u32, arg_no: u32, expected_len: usize) -> BytesInput {
        let mut inner = self.inner.write().unwrap();
        inner.current = syscall_no;

        // Continuous-buffer model: parts[offset][arg_no] is a single byte
        // stream. Multiple fuzz() calls within one syscall (msghdr's
        // msg_name / iov[i] / msg_control all hit arg_no=1) consume bytes
        // sequentially via a per-(syscall, arg) cursor that resets on
        // advance_offset(). On EOF we zero-pad to expected_len.
        let offset = inner.offsets.get(&syscall_no).copied().unwrap_or(0);
        let cursor = inner
            .cursors
            .get(&(syscall_no, arg_no))
            .copied()
            .unwrap_or(0);

        // Snapshot the byte slice so the immutable borrow on inner.map
        // ends before the mutable updates below.
        let snapshot: Option<(usize, usize, Vec<u8>)> =
            inner.map.get(&syscall_no).map(|calls| {
                let calls_len = calls.len();
                let real_offset = offset % calls_len;
                let stream = calls
                    .part_at_index(real_offset)
                    .unwrap()[arg_no as usize]
                    .as_ref();
                let take = expected_len.min(stream.len().saturating_sub(cursor));
                let bytes = stream[cursor..cursor + take].to_vec();
                (calls_len, real_offset, bytes)
            });

        let Some((calls_len, real_offset, mut bytes)) = snapshot else {
            return BytesInput::new(vec![0u8; expected_len]);
        };
        let take = bytes.len();
        if take < expected_len {
            bytes.resize(expected_len, 0);
        }

        inner.cursors.insert((syscall_no, arg_no), cursor + take);
        if offset > calls_len {
            inner.insufficient_calls_indicators.insert(syscall_no);
        }
        if take < expected_len {
            inner.insufficient_bytes_indicators.insert((
                syscall_no,
                real_offset,
                arg_no,
                expected_len,
            ));
        }
        BytesInput::new(bytes)
    }

    pub fn reset(&self) {
        // Clear the capture flag before each execution to avoid stale signals
        CAPTURE_HAPPENED.store(false, Ordering::Release);
        let mut inner = self.inner.write().unwrap();
        inner.offsets.clear();
        inner.accessed_indicators.clear();
        inner.insufficient_calls_indicators.clear();
        inner.insufficient_bytes_indicators.clear();
        inner.capturing = false;
        inner.cursors.clear();
    }

    /// Begin processing a new syscall. Called once on the first fuzz() call
    /// for each syscall (arg_no == 0). Records the syscall in the sequence
    /// and checks whether capture mode should be enabled.
    pub fn begin_syscall(&self, syscall_no: u32) {
        let mut inner = self.inner.write().unwrap();

        // Record this syscall once in the access sequence
        inner.accessed_indicators.push(syscall_no);

        // Check if the extended sequence is new in the tree
        let need_capture = syscall_tree::get().record_sequence(&inner.accessed_indicators);
        if need_capture {
            inner.capturing = true;
        }
    }

    /// Called after all fuzz() calls for a syscall complete.
    /// Signals the corpus if capture occurred and advances the offset.
    pub fn advance_offset_for_syscall(&self, syscall_no: u32) {
        let mut inner = self.inner.write().unwrap();

        // If this syscall was being captured, signal the feedback now that
        // all arguments are properly stored in the input.
        if inner.capturing {
            inner.capturing = false;
            CAPTURE_HAPPENED.store(true, Ordering::Release);
        }

        let entry = inner.offsets.entry(syscall_no).or_insert(0);
        *entry += 1;
        // Reset per-arg read cursors for the syscall so the next dynamic
        // call starts at byte 0 of each arg's stream.
        inner.cursors.retain(|(s, _), _| *s != syscall_no);
    }

    pub fn select_syscall_id<S: HasRand>(&self, state: &mut S) {
        let mut inner = self.inner.write().unwrap();
        let accessed = &inner.accessed_indicators;

        let accessed_len = NonZero::new(accessed.len())
            .expect("select_syscall_id called with empty accessed_indicators — mutator invoked before any syscall ran");

        // Heuristic: 50% chance to select the last accessed syscall (likely roadblock),
        // 50% chance to select a random one from the accessed list.
        let last_idx = accessed.len() - 1;
        let select_last = state.rand_mut().below(NonZero::new(10).unwrap()) < 5;

        if select_last {
            inner.current = accessed[last_idx];
        } else {
            let idx = state.rand_mut().below(accessed_len);
            inner.current = accessed[idx];
        }
    }

    pub fn current_syscall_id(&self) -> u32 {
        self.inner.read().unwrap().current
    }

    pub fn set_current_syscall_id(&self, syscall_id: u32) {
        self.inner.write().unwrap().current = syscall_id;
    }

    pub fn insufficient_calls_indicators(&self) -> HashSet<u32> {
        self.inner
            .read()
            .unwrap()
            .insufficient_calls_indicators
            .clone()
    }

    pub fn insufficient_bytes_indicators(&self) -> HashSet<(u32, usize, u32, usize)> {
        self.inner
            .read()
            .unwrap()
            .insufficient_bytes_indicators
            .clone()
    }

    // Whether we need to iterate insufficient indicators
    pub fn has_insufficient_indicators(&self) -> bool {
        let inner = self.inner.read().unwrap();
        !inner.insufficient_calls_indicators.is_empty()
            || !inner.insufficient_bytes_indicators.is_empty()
    }

    /// Capture original buffer data into this input during first-encounter execution.
    /// Called when `capturing` flag is set to record testcase constants
    /// so the mutation engine has real values as the base for future mutations.
    pub fn capture(&self, syscall_no: u32, arg_no: u32, data: &[u8]) {
        let mut inner = self.inner.write().unwrap();
        let offset = inner.offsets.get(&syscall_no).copied().unwrap_or(0);

        let calls = inner
            .map
            .entry(syscall_no)
            .or_insert_with(CallsInput::empty);

        // Grow the calls list to include the current offset
        while calls.len() <= offset {
            calls.append_part(std::array::from_fn(|_| BytesInput::new(Vec::new())));
        }

        let arg_idx = arg_no as usize;
        if arg_idx >= NUM_ARGS {
            return;
        }
        // Append, not overwrite: nested args (msghdr's msg_name / iov[i] /
        // msg_control) all capture under the parent's arg_no and share the
        // same continuous byte stream. Replay walks it back via a cursor.
        let slot = &mut calls.parts_mut()[offset][arg_idx];
        let mut bytes: Vec<u8> = slot.as_ref().to_vec();
        bytes.extend_from_slice(data);
        *slot = BytesInput::new(bytes);
    }

    /// Returns true if the input is currently in capture mode.
    pub fn is_capturing(&self) -> bool {
        self.inner.read().unwrap().capturing
    }
}

impl HasLen for AlmondInput {
    fn len(&self) -> usize {
        self.inner
            .read()
            .unwrap()
            .map
            .values()
            .map(|calls| calls.len())
            .sum()
    }
}

impl Input for AlmondInput {}
