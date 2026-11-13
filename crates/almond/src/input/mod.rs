// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

use hashbrown::{HashMap, HashSet};
use libafl::inputs::{BytesInput, Input};
use libafl_bolts::HasLen;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
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

use crate::{
    focus::Focus,
    skipped_args, syscall_tree,
    telemetry::{Lineage, RoundTally},
};

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
    // Syscalls that read bytes from an argument outside skipped_args during
    // execution, so mutating them changes what the target sees
    pub mutable_indicators: HashSet<SyscallID>,
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
    // Position in accessed_indicators of the first syscall whose sequence
    // was new to the syscall tree during this execution, i.e. where capture
    // grew the program. Every later position is new too, so the first one
    // is the growth point.
    #[serde(skip)]
    pub capture_growth: Option<u32>,
    // Part of the serialized form, so it survives the corpus, a client
    // restart and the broker. Postcard, which LibAFL uses for all three,
    // reads fields in order: data written before this field existed does not
    // load. Present in every build so corpora move between builds; only the
    // `telemetry` feature advances it, otherwise it stays at the seed's.
    pub lineage: Lineage,
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
        // fuzz() only reads unskipped args through here, so the mutators can
        // change what this syscall sees, even before the input holds a call
        // for it: the miss below asks crossover to import one.
        inner.mutable_indicators.insert(syscall_no);

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
        let snapshot: Option<(usize, usize, Vec<u8>)> = inner.map.get(&syscall_no).map(|calls| {
            let calls_len = calls.len();
            let real_offset = offset % calls_len;
            let stream = calls.part_at_index(real_offset).unwrap()[arg_no as usize].as_ref();
            let take = expected_len.min(stream.len().saturating_sub(cursor));
            let bytes = stream[cursor..cursor + take].to_vec();
            (calls_len, real_offset, bytes)
        });

        let Some((calls_len, real_offset, mut bytes)) = snapshot else {
            inner.insufficient_calls_indicators.insert(syscall_no);
            return BytesInput::new(vec![0u8; expected_len]);
        };
        let take = bytes.len();
        if take < expected_len {
            bytes.resize(expected_len, 0);
        }

        inner.cursors.insert((syscall_no, arg_no), cursor + take);
        // offset counts the calls before this one, so this one needs
        // offset + 1 stored calls.
        if offset >= calls_len {
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
        inner.mutable_indicators.clear();
        inner.insufficient_calls_indicators.clear();
        inner.insufficient_bytes_indicators.clear();
        inner.capturing = false;
        inner.capture_growth = None;
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
            if inner.capture_growth.is_none() {
                let position = inner.accessed_indicators.len() - 1;
                inner.capture_growth = Some(u32::try_from(position).unwrap_or(u32::MAX));
            }
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

    /// Work out which accessed syscalls a round of mutation may aim at. See
    /// [`crate::focus`].
    ///
    /// # Panics
    ///
    /// If no syscall has run yet.
    pub fn focus(&self) -> Focus {
        let inner = self.inner.read().unwrap();
        Focus::new(&inner.accessed_indicators, |id| {
            inner.mutable_indicators.contains(&id)
        })
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
        if !skipped_args::is_skipped(syscall_no, arg_no) {
            inner.mutable_indicators.insert(syscall_no);
        }
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

    /// Where in the run's syscall sequence the last execution first reached a
    /// sequence the syscall tree had not seen, if it did.
    pub fn capture_growth(&self) -> Option<u32> {
        self.inner.read().unwrap().capture_growth
    }

    pub fn lineage(&self) -> Lineage {
        self.inner.read().unwrap().lineage
    }

    /// Extend the lineage by one finished round of mutation.
    pub fn record_round(&self, applied: &RoundTally) {
        self.inner.write().unwrap().lineage.extend(applied);
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

#[cfg(test)]
mod tests {
    use super::*;
    use libafl_bolts::rands::StdRand;

    const SOCKET: SyscallID = 41;
    const ACCEPT: SyscallID = 43;
    const CLOSE: SyscallID = 3;

    fn input_that_reached(accessed: &[SyscallID]) -> AlmondInput {
        let input = AlmondInput::new();
        input.inner.write().unwrap().accessed_indicators = accessed.to_vec();
        input
    }

    #[test]
    fn a_read_makes_a_syscall_mutable_before_the_input_holds_bytes_for_it() {
        // Another input captured this sequence first, so this one holds no
        // bytes for accept(), but the run reads its addr buffer.
        let input = input_that_reached(&[SOCKET, ACCEPT, CLOSE]);
        input.get(ACCEPT, 1, 16);

        let focus = input.focus();
        let mut rand = StdRand::with_seed(42);
        assert!((0..100).all(|_| focus.select(&mut rand) == ACCEPT));
    }

    #[test]
    fn a_read_with_no_stored_call_asks_for_one() {
        let input = input_that_reached(&[SOCKET, ACCEPT]);

        input.get(ACCEPT, 1, 16);

        assert!(input.insufficient_calls_indicators().contains(&ACCEPT));
    }

    #[test]
    fn a_call_beyond_the_stored_ones_asks_for_another() {
        let call = std::array::from_fn(|_| BytesInput::new(vec![0u8; 4]));
        let input = AlmondInput::with_syscall(ACCEPT, call);

        input.get(ACCEPT, 1, 4);
        assert!(
            input.insufficient_calls_indicators().is_empty(),
            "the stored call covers the first accept()"
        );

        input.advance_offset_for_syscall(ACCEPT);
        input.get(ACCEPT, 1, 4);
        assert!(input.insufficient_calls_indicators().contains(&ACCEPT));
    }

    #[test]
    fn capture_growth_is_the_first_position_new_to_the_tree() {
        // IDs no other test uses, so the global syscall tree starts empty
        // below this prefix whatever order tests run in.
        const OPEN: SyscallID = 9_001;
        const READ: SyscallID = 9_002;
        const IOCTL: SyscallID = 9_003;
        let input = AlmondInput::new();
        for id in [OPEN, READ] {
            input.begin_syscall(id);
            input.advance_offset_for_syscall(id);
        }
        input.reset();
        assert_eq!(input.capture_growth(), None, "reset forgets the growth");

        // The second run repeats the known prefix and grows at position 2.
        for id in [OPEN, READ, IOCTL] {
            input.begin_syscall(id);
            input.advance_offset_for_syscall(id);
        }
        assert_eq!(input.capture_growth(), Some(2));

        // A third identical run reaches nothing new.
        input.reset();
        for id in [OPEN, READ, IOCTL] {
            input.begin_syscall(id);
            input.advance_offset_for_syscall(id);
        }
        assert_eq!(input.capture_growth(), None);
    }

    #[test]
    fn lineage_does_not_change_equality_or_hash() {
        use std::collections::hash_map::DefaultHasher;
        let call = std::array::from_fn(|_| BytesInput::new(vec![1u8; 4]));
        let parent = AlmondInput::with_syscall(ACCEPT, call);
        let child = parent.clone();
        let mut applied = RoundTally::default();
        applied.count(crate::telemetry::MutationClass::Bytes);
        child.record_round(&applied);

        let hash = |input: &AlmondInput| {
            let mut h = DefaultHasher::new();
            input.hash(&mut h);
            h.finish()
        };
        assert_eq!(child.lineage().depth, 1);
        assert_eq!(parent, child);
        assert_eq!(hash(&parent), hash(&child));
    }

    #[test]
    fn lineage_survives_the_postcard_round_trip_libafl_uses() {
        let call = std::array::from_fn(|_| BytesInput::new(vec![7u8; 2]));
        let input = AlmondInput::with_syscall(ACCEPT, call);
        let mut applied = RoundTally::default();
        applied.count(crate::telemetry::MutationClass::Calls);
        input.record_round(&applied);

        let bytes = postcard::to_allocvec(&*input.inner.read().unwrap()).unwrap();
        let restored: AlmondInputInner = postcard::from_bytes(&bytes).unwrap();

        assert_eq!(restored.lineage.depth, 1);
        assert_eq!(restored.lineage.calls, 1);
        assert_eq!(restored.map, input.inner.read().unwrap().map);
    }

    #[test]
    fn data_written_before_lineage_existed_does_not_load() {
        // The serialized fields of the input as they were before `lineage`.
        #[derive(Serialize)]
        struct BeforeLineage {
            map: BTreeMap<SyscallID, Calls>,
            accessed_indicators: Vec<SyscallID>,
            mutable_indicators: HashSet<SyscallID>,
        }
        let call = std::array::from_fn(|_| BytesInput::new(vec![7u8; 2]));
        let current = AlmondInput::with_syscall(ACCEPT, call);
        let old = BeforeLineage {
            map: current.inner.read().unwrap().map.clone(),
            accessed_indicators: vec![ACCEPT],
            mutable_indicators: HashSet::new(),
        };

        let bytes = postcard::to_allocvec(&old).unwrap();

        assert!(postcard::from_bytes::<AlmondInputInner>(&bytes).is_err());
    }

    #[test]
    fn reset_forgets_reads() {
        let input = input_that_reached(&[ACCEPT]);
        input.get(ACCEPT, 1, 16);

        input.reset();

        assert!(input.inner.read().unwrap().mutable_indicators.is_empty());
    }
}
