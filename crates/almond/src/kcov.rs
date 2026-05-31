// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

use anyhow::{Context, Result};
use std::fs::OpenOptions;
use std::os::fd::FromRawFd;
use std::ptr::NonNull;
use std::sync::atomic::{Ordering, fence};

use core::ffi::c_void;
use rustix::ioctl::{IntegerSetter, Opcode, Setter, ioctl, opcode};
use rustix::mm::{MapFlags, ProtFlags, mmap, munmap};
use std::os::unix::io::AsRawFd;
use std::process;

#[repr(C)]
struct KcovRemoteArg {
    trace_mode: u32,
    area_size: u32,
    num_handles: u32,
    _pad: u32, // Padding for 8-byte alignment of common_handle
    common_handle: u64,
    handles: [u64; 0],
}

const KCOV_INIT_TRACE: Opcode = opcode::read::<u64>(b'c', 1);
const KCOV_ENABLE: Opcode = opcode::none(b'c', 100);
const KCOV_REMOTE_ENABLE: Opcode = opcode::write::<KcovRemoteArg>(b'c', 102);
const KCOV_DISABLE: Opcode = opcode::none(b'c', 101);
#[cfg(feature = "future")]
const KCOV_RESET_TRACE: Opcode = opcode::none(b'c', 104);
const COVER_SIZE: usize = 16 << 20;

const KCOV_TRACE_PC: usize = 0;
#[expect(dead_code)]
const KCOV_TRACE_CMP: usize = 1;

#[derive(Debug)]
pub struct KCov {
    file: std::fs::File,
    cover: NonNull<u64>,
    remote: bool,
    enabled: bool,
}

unsafe impl Send for KCov {}
unsafe impl Sync for KCov {}

impl Default for KCov {
    fn default() -> Self {
        Self::new(false).expect("Failed to create KCov instance")
    }
}

impl KCov {
    pub fn new(remote: bool) -> Result<Self> {
        // Open /sys/kernel/debug/kcov
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/sys/kernel/debug/kcov")
            .context("Failed to open /sys/kernel/debug/kcov")?;

        // Setup trace mode and trace size
        unsafe {
            ioctl(
                &file,
                IntegerSetter::<KCOV_INIT_TRACE>::new_usize(COVER_SIZE),
            )
            .context(format!(
                "Failed to initialize kcov with size {}",
                COVER_SIZE
            ))?;
        }

        // Mmap buffer shared between kernel- and user-space
        let size = COVER_SIZE * std::mem::size_of::<u64>();
        let cover_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                size,
                ProtFlags::READ | ProtFlags::WRITE,
                MapFlags::SHARED,
                &file,
                0,
            )
            .context(format!("Failed to mmap kcov buffer of size {}", size))?
        };

        let cover = NonNull::new(cover_ptr as *mut u64)
            .ok_or_else(|| std::io::Error::other("mmap returned null pointer"))
            .context("Failed to create NonNull pointer for kcov buffer")?;

        let fd = file.as_raw_fd();
        let dst = if remote { 204 } else { 203 };
        let dup_fd = unsafe { libc::dup2(fd, dst) };
        if dup_fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("Failed to dup kcov file descriptor");
        }

        let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };

        Ok(KCov {
            file,
            cover,
            remote,
            enabled: false,
        })
    }

    pub fn enable(&mut self) -> Result<()> {
        if self.enabled {
            return Err(anyhow::anyhow!("Kcov is already enabled"));
        }

        // Reset counter
        unsafe {
            self.cover.as_ptr().write_volatile(0);
        }

        // Enable coverage tracking
        if self.remote {
            let arg = KcovRemoteArg {
                trace_mode: KCOV_TRACE_PC as u32,
                area_size: COVER_SIZE as u32,
                // We don't care the usb subsystem
                num_handles: 0,
                _pad: 0,
                common_handle: process::id() as u64,
                handles: [],
            };
            unsafe {
                ioctl(
                    &self.file,
                    Setter::<KCOV_REMOTE_ENABLE, KcovRemoteArg>::new(arg),
                )
                .context("Failed to enable remote Kcov")?;
            }
        } else {
            unsafe {
                ioctl(
                    &self.file,
                    IntegerSetter::<KCOV_ENABLE>::new_usize(KCOV_TRACE_PC),
                )
                .context("Failed to enable Kcov")?;
            }
        }

        self.enabled = true;

        Ok(())
    }

    pub fn disable(&mut self) -> Result<usize> {
        if !self.enabled {
            // Already disabled, return 0 (no new coverage collected)
            return Ok(0);
        }

        // Memory fence to ensure all writes are visible
        fence(Ordering::SeqCst);

        // Read the counter
        let current_len = unsafe { self.cover.as_ptr().read_volatile() };

        debug_assert!(current_len < COVER_SIZE as u64);

        // Disable coverage tracking
        unsafe {
            ioctl(&self.file, IntegerSetter::<KCOV_DISABLE>::new_usize(0))
                .context("Failed to disable Kcov")?;
        }

        self.enabled = false;

        Ok(current_len as usize)
    }

    /// Get the current coverage length without resetting the buffer
    ///
    /// This function reads the current coverage counter to determine how many
    /// edges have been collected so far. It does not modify the Kcov state
    /// and can be called multiple times to monitor coverage collection progress.
    ///
    /// # Returns
    ///
    /// Returns `Ok(len)` where len is the number of coverage edges currently collected,
    /// or an error if reading the counter fails.
    ///
    /// # Safety
    ///
    /// This function can be safely called at any time when Kcov is enabled
    /// and will not interfere with ongoing coverage collection.
    #[cfg(test)] // Only used in tests for now, TODO: verify correctness
    pub fn len(&self) -> Result<usize> {
        // Memory fence to ensure all writes are visible
        fence(Ordering::SeqCst);

        // Read the current counter
        let current_len = unsafe { self.cover.as_ptr().read_volatile() };

        debug_assert!(current_len < COVER_SIZE as u64);

        Ok(current_len as usize)
    }

    /// Returns `true` if the coverage length is zero
    #[cfg(test)]
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Reset the Kcov trace buffer without returning coverage length
    ///
    /// This function uses the KCOV_RESET_TRACE ioctl to reset the coverage
    /// buffer and counter to zero. This is particularly useful for remote Kcov
    /// where you want to clear the buffer between test cases without disabling
    /// and re-enabling the entire Kcov instance.
    ///
    /// If you need to get the coverage length before resetting, call `len()` first.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the reset was successful, or an error if the reset ioctl fails.
    ///
    /// # Safety
    ///
    /// This function should only be called when Kcov is enabled but not actively
    /// collecting coverage for a specific test case.
    #[cfg(test)] // Only used in tests for now, TODO: verify correctness
    pub fn reset(&mut self) -> Result<()> {
        #[cfg(feature = "future")]
        unsafe {
            // https://lore.kernel.org/lkml/20250416085446.480069-1-glider@google.com/
            ioctl(&self.file, IntegerSetter::<KCOV_RESET_TRACE>::new_usize(0))
                .context("Failed to reset Kcov trace buffer")?;
        }

        #[cfg(not(feature = "future"))]
        {
            // Memory fence to ensure proper ordering before reset
            fence(Ordering::SeqCst);
            unsafe {
                self.cover.as_ptr().write_volatile(0);
            }
        }

        Ok(())
    }

    /// Returns a raw pointer to the mmap'd coverage buffer.
    ///
    /// # Buffer Layout
    /// - Index 0: Coverage counter (number of edges collected)
    /// - Indices 1..=kcov_len: Coverage edges (program counters)
    ///
    /// # Safety
    /// The pointer is valid for the lifetime of this `KCov` instance.
    /// The buffer size is `COVER_SIZE` (16 << 20) elements.
    /// After calling `disable()`, only indices 0..=kcov_len contain valid data.
    pub fn ptr(&self) -> *const u64 {
        self.cover.as_ptr()
    }
}

impl Drop for KCov {
    fn drop(&mut self) {
        // Unmap the memory
        let size = COVER_SIZE * std::mem::size_of::<u64>();
        if self.enabled {
            let _ = self.disable();
        }
        unsafe {
            let _ = munmap(self.cover.as_ptr() as *mut c_void, size);
        }

        // File is automatically closed when dropped
    }
}
