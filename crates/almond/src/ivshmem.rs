// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.
//
// Pre-execution input persistence via ivshmem.
//
// Before each harness execution the current AlmondInput is serialized to
// the ivshmem mmap'd region so the host manager can read it after a
// kernel panic and generate a reproducer.
//
// The ivshmem-plain PCI device is hot-plugged after snapshot save/load
// so it doesn't block QEMU snapshots.
//
// Region layout (4MB total):
//   [0 .. 512K)   — pre-execution input (overwritten every execution)
//   [512K .. 4M)  — crash ring (each nonfatal crash gets its own drain window)
//
// Pre-exec section wire format (little-endian):
//   bytes 0..4:   magic  0x46414952 ("FAIR")
//   bytes 4..8:   length of JSON payload (u32)
//   bytes 8..8+N: JSON payload (AlmondInputInner)
//
// Crash ring header (16 bytes):
//   bytes 0..4:   ring_magic  0x52494E47 ("RING")
//   bytes 4..8:   write_idx   (fuzzer-written, reset to 0 when manager acks)
//   bytes 8..12:  crash_epoch (fuzzer-written, ++ on each freeze_ring)
//   bytes 12..16: ack_epoch   (manager-written, catches up to crash_epoch
//                              after consuming the ring contents)
//
// Stop-and-drain: on the first nonfatal crash the fuzzer freezes the ring and
// bumps crash_epoch.  The manager reads the ring, generates a reproducer, then
// writes ack_epoch = crash_epoch.  The fuzzer notices the ack on its next ring
// write, resets write_idx, and resumes.  This way the *next* crash's preceding
// state-setup inputs get captured fresh instead of being buried under stale
// pre-crash-1 context.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::input::AlmondInput;

const MAGIC: u32 = 0x4641_4952; // "FAIR" in LE
const HEADER_SIZE: usize = 8; // magic(4) + len(4)

/// Pre-exec section is the first 512K. Ring buffer uses the rest of the
/// 4MB ivshmem region (3.5MB), enough for ~1700 inputs to cover deferred
/// timer-based crashes that fire up to ~55s later at 30 exec/s.
const CRASH_SECTION_OFFSET: usize = 512 * 1024;
// Dynamically computed from actual mmap size; at 4MB this is 3.5MB.
const RING_MAGIC: u32 = 0x5249_4E47; // "RING" in LE
const RING_HEADER_SIZE: usize = 16; // magic(4) + write_idx(4) + crash_epoch(4) + ack_epoch(4)
const RING_SLOT_SIZE: usize = 4096; // 4KB per slot — accommodates large AlmondInput JSON
const RING_SLOT_COUNT: usize = 850; // ~3.5MB / 4KB

// ivshmem-plain PCI vendor/device IDs
const IVSHMEM_VENDOR: &str = "0x1af4";
const IVSHMEM_DEVICE: &str = "0x1110";

struct Ivshmem {
    ptr: *mut u8,
    size: usize,
}

// SAFETY: The mmap'd region is only written from the fuzzer's single
// execution thread (inside the harness closure). No concurrent access.
unsafe impl Send for Ivshmem {}
unsafe impl Sync for Ivshmem {}

static BACKEND: OnceLock<Option<Ivshmem>> = OnceLock::new();

/// Initialize the ivshmem backend. Call once at startup.
pub fn init() -> bool {
    BACKEND
        .get_or_init(|| match find_and_map_ivshmem() {
            Ok(backend) => {
                eprintln!("[repro] Using ivshmem backend ({} bytes)", backend.size);
                Some(backend)
            }
            Err(e) => {
                eprintln!("[repro] ivshmem not available: {e}");
                None
            }
        })
        .is_some()
}

/// Serialize an AlmondInput to the pre-execution section of ivshmem.
/// Called before each harness execution.
pub fn write_input(input: &AlmondInput) {
    write_to_offset(input, 0);
}

/// Once true, no more entries are appended to the ring.  Set by
/// `freeze_ring()` after kmsg detects a crash so the triggering input and
/// its preceding context stay stable while the host-side manager consumes
/// them.  Cleared once the manager acks by writing ack_epoch == crash_epoch.
static RING_FROZEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Bump crash_epoch (bytes 8..12 of the ring header) and freeze the ring.
/// The manager polls crash_epoch, reads the frozen ring, then catches
/// ack_epoch up — at which point `maybe_drain_and_unfreeze` wipes write_idx
/// and lets the fuzzer start collecting context for the next crash.
pub fn freeze_ring() {
    if let Some(Some(ivshmem)) = BACKEND.get() {
        let ring_base = unsafe { ivshmem.ptr.add(CRASH_SECTION_OFFSET) };
        unsafe {
            let cur = u32::from_le(ring_base.add(8).cast::<u32>().read_volatile());
            ring_base
                .add(8)
                .cast::<u32>()
                .write_volatile(cur.wrapping_add(1).to_le());
        }
    }
    RING_FROZEN.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// If the manager has acked the current crash_epoch, reset write_idx to 0
/// and unfreeze.  Called before every ring write.  Cheap when unfrozen:
/// a single relaxed atomic load.
fn maybe_drain_and_unfreeze() {
    if !RING_FROZEN.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let Some(Some(ivshmem)) = BACKEND.get() else {
        return;
    };
    let ring_base = unsafe { ivshmem.ptr.add(CRASH_SECTION_OFFSET) };
    let crash_epoch = u32::from_le(unsafe { ring_base.add(8).cast::<u32>().read_volatile() });
    let ack_epoch = u32::from_le(unsafe { ring_base.add(12).cast::<u32>().read_volatile() });
    // freeze_ring always bumps crash_epoch before setting RING_FROZEN, so
    // crash_epoch >= 1 whenever we reach here.  Compare via wrapping
    // subtraction so a u32 wrap-around (after ~4B crashes) stays sane.
    if ack_epoch.wrapping_sub(crash_epoch) <= u32::MAX / 2 {
        // ack has caught up — reset write_idx and resume.
        unsafe {
            ring_base.cast::<u32>().write_volatile(RING_MAGIC.to_le());
            ring_base.add(4).cast::<u32>().write_volatile(0u32.to_le());
        }
        RING_FROZEN.store(false, std::sync::atomic::Ordering::Relaxed);
        eprintln!("[repro] Ring drained at epoch {crash_epoch}, resuming");
    }
}

/// Write every input to the ring buffer so deferred (timer-based) crashes
/// can be correlated with the input that set up the timer.  Called before
/// each harness execution.
pub fn write_input_to_ring(input: &AlmondInput) {
    maybe_drain_and_unfreeze();
    if RING_FROZEN.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    write_crash_input(input);
}

/// Serialize an AlmondInput to the next ring buffer slot in the crash section.
/// Called when the kmsg detector finds a nonfatal kernel warning.
pub fn write_crash_input(input: &AlmondInput) {
    let Some(Some(ivshmem)) = BACKEND.get() else {
        return;
    };

    let inner = input.inner.read().unwrap();
    let json = match serde_json::to_vec(&*inner) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("[repro] Serialization failed: {e}");
            return;
        }
    };

    let total = HEADER_SIZE + json.len();
    if total > RING_SLOT_SIZE {
        eprintln!("[repro] Crash input too large for ring slot ({total} > {RING_SLOT_SIZE})");
        return;
    }

    let ring_base = unsafe { ivshmem.ptr.add(CRASH_SECTION_OFFSET) };

    // Read current write_idx, compute slot, then increment
    let write_idx = unsafe { ring_base.add(4).cast::<u32>().read() }.to_le();
    let slot = (write_idx as usize) % RING_SLOT_COUNT;
    let slot_ptr = unsafe { ring_base.add(RING_HEADER_SIZE + slot * RING_SLOT_SIZE) };

    // Write entry to slot
    unsafe {
        slot_ptr.cast::<u32>().write(MAGIC.to_le());
        slot_ptr
            .add(4)
            .cast::<u32>()
            .write((json.len() as u32).to_le());
        std::ptr::copy_nonoverlapping(json.as_ptr(), slot_ptr.add(HEADER_SIZE), json.len());
    }

    // Update write_idx (after data is written)
    let new_idx = write_idx.wrapping_add(1);
    unsafe {
        ring_base.cast::<u32>().write(RING_MAGIC.to_le());
        ring_base.add(4).cast::<u32>().write(new_idx.to_le());
    }
}

fn write_to_offset(input: &AlmondInput, offset: usize) {
    let Some(Some(ivshmem)) = BACKEND.get() else {
        return;
    };

    let inner = input.inner.read().unwrap();
    let json = match serde_json::to_vec(&*inner) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("[repro] Serialization failed: {e}");
            return;
        }
    };

    let section_size = if offset == 0 {
        CRASH_SECTION_OFFSET
    } else {
        ivshmem.size - offset
    };
    let total = HEADER_SIZE + json.len();
    if total > section_size {
        return;
    }

    let buf = unsafe { ivshmem.ptr.add(offset) };
    unsafe {
        buf.cast::<u32>().write(MAGIC.to_le());
        buf.add(4).cast::<u32>().write((json.len() as u32).to_le());
        std::ptr::copy_nonoverlapping(json.as_ptr(), buf.add(HEADER_SIZE), json.len());
    }
}

// ---- ivshmem PCI detection ----

fn find_and_map_ivshmem() -> Result<Ivshmem, String> {
    let pci_dir = PathBuf::from("/sys/bus/pci/devices");
    let entries = fs::read_dir(&pci_dir).map_err(|e| format!("Cannot read {pci_dir:?}: {e}"))?;

    for entry in entries.flatten() {
        let dev_path = entry.path();

        let vendor = read_sysfs_str(&dev_path.join("vendor"));
        let device = read_sysfs_str(&dev_path.join("device"));

        if vendor.as_deref() == Some(IVSHMEM_VENDOR) && device.as_deref() == Some(IVSHMEM_DEVICE) {
            // Enable PCI memory space — required after hot-plug
            enable_pci_device(&dev_path)?;
            let resource = dev_path.join("resource2");
            return map_bar(&resource);
        }
    }

    Err("ivshmem PCI device not found".into())
}

fn enable_pci_device(dev_path: &Path) -> Result<(), String> {
    let enable_path = dev_path.join("enable");
    fs::write(&enable_path, b"1").map_err(|e| format!("Cannot enable PCI device {dev_path:?}: {e}"))
}

fn read_sysfs_str(path: &Path) -> Option<String> {
    let mut f = File::open(path).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    Some(s.trim().to_string())
}

fn map_bar(resource_path: &Path) -> Result<Ivshmem, String> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(resource_path)
        .map_err(|e| format!("Cannot open {resource_path:?}: {e}"))?;

    let size = file
        .metadata()
        .map_err(|e| format!("Cannot stat {resource_path:?}: {e}"))?
        .len() as usize;

    if size == 0 {
        return Err(format!("{resource_path:?} has zero size"));
    }

    let fd = file.as_raw_fd();
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };

    if ptr == libc::MAP_FAILED {
        return Err(format!(
            "mmap failed on {resource_path:?}: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(Ivshmem {
        ptr: ptr as *mut u8,
        size,
    })
}
