// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

use std::borrow::Cow;
use std::sync::atomic::Ordering;

use libafl::{
    Error,
    executors::ExitKind,
    feedbacks::{Feedback, StateInitializer},
};
use libafl_bolts::Named;
use serde::{Deserialize, Serialize};

use crate::input::CAPTURE_HAPPENED;

/// Feedback that returns `true` when a capture event occurred during execution.
///
/// When [`AlmondInput::capture`] records a new syscall sequence's constants,
/// it sets the global [`CAPTURE_HAPPENED`] flag. This feedback consumes that
/// flag (swap to false) and returns `true`, ensuring the captured input is
/// unconditionally added to the corpus.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CaptureFeedback {
    #[serde(skip)]
    last: bool,
}

impl CaptureFeedback {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> StateInitializer<S> for CaptureFeedback {}

impl Named for CaptureFeedback {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: Cow<'static, str> = Cow::Borrowed("CaptureFeedback");
        &NAME
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for CaptureFeedback {
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let captured = CAPTURE_HAPPENED.swap(false, Ordering::AcqRel);
        self.last = captured;
        Ok(captured)
    }

    #[cfg(feature = "track_hit_feedbacks")]
    fn last_result(&self) -> Result<bool, Error> {
        Ok(self.last)
    }
}
