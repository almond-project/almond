// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! Syscall sequence tree for recording syscall execution patterns.

use hashbrown::HashMap;
use std::sync::{Mutex, OnceLock};

pub type SyscallID = u32;

/// A node in the syscall sequence tree
#[derive(Debug, Default)]
pub struct SyscallNode {
    /// Children: syscall_id -> child node
    children: HashMap<SyscallID, SyscallNode>,
}

/// Global syscall sequence tree (singleton)
#[derive(Debug, Default)]
pub struct SyscallTree {
    root: Mutex<SyscallNode>,
}

impl SyscallTree {
    /// Record a syscall sequence, returning true if any new nodes were created
    pub fn record_sequence(&self, sequence: &[SyscallID]) -> bool {
        if sequence.is_empty() {
            return false;
        }
        let mut root = self.root.lock().unwrap();
        let mut node = &mut *root;
        let mut is_new = false;

        for &syscall_id in sequence {
            let child_is_new = !node.children.contains_key(&syscall_id);
            node = node.children.entry(syscall_id).or_default();
            if child_is_new {
                is_new = true;
            }
        }

        is_new
    }
}

/// Global singleton
pub static SYSCALL_TREE: OnceLock<SyscallTree> = OnceLock::new();

pub fn get() -> &'static SyscallTree {
    SYSCALL_TREE.get_or_init(SyscallTree::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_sequence() {
        let tree = SyscallTree::default();

        // First recording should be new
        assert!(tree.record_sequence(&[41, 42, 43]));
        // Same sequence again should not be new
        assert!(!tree.record_sequence(&[41, 42, 43]));
        // Extension should be new
        assert!(tree.record_sequence(&[41, 42, 43, 44]));
        // Different branch should be new
        assert!(tree.record_sequence(&[41, 45]));
        // Same branch again should not be new
        assert!(!tree.record_sequence(&[41, 45]));
    }
}
