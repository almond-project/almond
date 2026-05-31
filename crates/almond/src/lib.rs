// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! # Almond
//!
//! A syscall fuzzer library built on [LibAFL]. 
//! 

pub use hashbrown;

pub mod executors;
pub mod feedbacks;
pub mod input;
pub mod ivshmem;
pub mod kcov;
pub mod kmsg;
pub mod mutations;
pub mod observers;
pub mod ring;
pub mod skipped_args;
pub mod stats_client;
pub mod stats_monitor;
pub mod syscall_tree;
pub mod target;

/// Common building blocks for assembling a fuzz driver.
///
/// ```no_run
/// use almond::prelude::*;
/// ```
pub mod prelude {
    pub use crate::executors::subthread::SubthreadInProcessExecutor;
    pub use crate::feedbacks::CaptureFeedback;
    pub use crate::input::AlmondInput;
    pub use crate::mutations::AlmondScheduledMutator;
    pub use crate::observers::kcov_map::KcovMapObserver;
    pub use crate::stats_monitor::StatsMonitor;
    pub use crate::target::{harness_run, set_current_input};
}
