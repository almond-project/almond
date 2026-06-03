// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.
//
// Nonfatal crash detection via /dev/kmsg.
//
// With panic_on_warn=0, kernel warnings (KASAN, UBSAN, etc.) don't cause
// panics -- the fuzzer keeps running and overwrites the ivshmem pre-execution
// section before the manager can read it.
//
// This module opens /dev/kmsg in non-blocking mode and checks for new
// crash-level messages after each harness execution. When one is found,
// the current input is written to the crash section of ivshmem (separate
// from the pre-execution section) so the manager can pair it with the
// crash report. Zero disk writes.

use std::os::unix::io::RawFd;
use std::sync::OnceLock;

use crate::input::AlmondInput;
use crate::ivshmem;

static KMSG_FD: OnceLock<Option<RawFd>> = OnceLock::new();

const CRASH_PATTERNS: &[&[u8]] = &[
    // Memory corruption detectors
    b"KASAN:",
    b"KFENCE:",
    b"KCSAN:",
    b"UBSAN:",
    b"use-after-free",
    b"double-free",
    b"slab-out-of-bounds",
    b"slab-use-after-free",
    b"stack-out-of-bounds",
    b"kernel NULL pointer",
    b"unable to handle",
    b"general protection fault",
    // Locking / general
    b"WARNING:",
    b"Oops:",
];

/// Initialize the kmsg reader. Call once at startup.
pub fn init() -> bool {
    KMSG_FD
        .get_or_init(|| {
            let fd = unsafe {
                libc::open(
                    c"/dev/kmsg".as_ptr(),
                    libc::O_RDONLY | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                eprintln!(
                    "[kmsg] Cannot open /dev/kmsg: {}",
                    std::io::Error::last_os_error()
                );
                return None;
            }

            let ret = unsafe { libc::lseek(fd, 0, libc::SEEK_END) };
            if ret < 0 {
                eprintln!(
                    "[kmsg] Cannot seek /dev/kmsg: {}",
                    std::io::Error::last_os_error()
                );
                unsafe { libc::close(fd) };
                return None;
            }

            eprintln!("[kmsg] Monitoring /dev/kmsg for nonfatal crashes");
            Some(fd)
        })
        .is_some()
}

/// Check /dev/kmsg for new crash-level messages since the last call.
///
/// Drains all pending messages and returns true if any matched crash
/// patterns. Designed to be called after every `harness_run()`.
pub fn has_new_crash() -> bool {
    let Some(&Some(fd)) = KMSG_FD.get() else {
        return false;
    };

    let mut buf = [0u8; 8192];
    let mut found_crash = false;

    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            break;
        }
        let msg = &buf[..n as usize];

        if !found_crash && contains_crash_pattern(msg) {
            found_crash = true;
            // Keep draining to advance the read position
        }
    }

    found_crash
}

/// Save the current input to the crash section of ivshmem and freeze the
/// ring so subsequent (post-crash) iterations don't overwrite the input
/// that actually triggered the bug.
pub fn save_crash_input(input: &AlmondInput) {
    ivshmem::write_crash_input(input);
    ivshmem::freeze_ring();
    eprintln!("[kmsg] Saved crash input + froze ring");
}

fn contains_crash_pattern(msg: &[u8]) -> bool {
    CRASH_PATTERNS.iter().any(|pattern| memmem(msg, pattern))
}

fn memmem(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
