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
// Region layout (one fixed-size slot for the pre-exec input, then the ring):
//   [0 .. slot)            — pre-execution input (overwritten every execution)
//   [slot .. slot+16)      — ring header
//   [slot+16 .. end)       — crash ring of `ring_slot_count` slots
//
// Every slot — the pre-exec one and each ring slot — is `slot_size` bytes, so
// the *same* serialized input goes to both without one limit accepting it and
// the other dropping it. The layout is configurable via `IvshmemConfig` /
// `init_with_config`: raise `slot_size` when inputs are "not large enough" to
// fit, and `ring_slot_count` for a longer deferred-crash window. Defaults
// (1MB slot, 62 ring slots ≈ 63MB) assume a 64MB ivshmem device — size the
// QEMU device (`-device ivshmem-plain` backing memory) to match, or shrink the
// config. `init` warns when the mapped device is smaller than the config needs.
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

const RING_MAGIC: u32 = 0x5249_4E47; // "RING" in LE
const RING_HEADER_SIZE: usize = 16; // magic(4) + write_idx(4) + crash_epoch(4) + ack_epoch(4)

// Defaults target a 64MB ivshmem device: 1MB per slot (ample for even large
// serialized inputs), and 62 ring slots ≈ 63MB of deferred-crash context.
// The QEMU ivshmem device must be sized to match (64MB); `init` warns if not.
const DEFAULT_SLOT_SIZE: usize = 1024 * 1024;
const DEFAULT_RING_SLOT_COUNT: usize = 62;

// ivshmem-plain PCI vendor/device IDs
const IVSHMEM_VENDOR: &str = "0x1af4";
const IVSHMEM_DEVICE: &str = "0x1110";

/// Runtime-configurable layout of the ivshmem region.
///
/// One `slot_size` governs both the pre-exec slot and every ring slot, so an
/// input either fits everywhere or nowhere — it can't be saved for fatal-panic
/// repro but silently dropped from the crash ring. Inputs that don't fit are
/// dropped (with a logged diagnostic), so size `slot_size` to your largest
/// serialized [`AlmondInput`] (plus an 8-byte header). The region must satisfy
/// `slot_size * (1 + ring_slot_count) + 16 <= device size`.
#[derive(Clone, Copy, Debug)]
pub struct IvshmemConfig {
    /// Bytes per slot, shared by the pre-exec slot and each ring slot. Must
    /// hold the serialized input plus an 8-byte header.
    pub slot_size: usize,
    /// Number of slots in the crash ring. More slots cover deferred
    /// (timer-based) crashes that fire further after the input that armed them.
    pub ring_slot_count: usize,
}

impl Default for IvshmemConfig {
    fn default() -> Self {
        Self {
            slot_size: DEFAULT_SLOT_SIZE,
            ring_slot_count: DEFAULT_RING_SLOT_COUNT,
        }
    }
}

impl IvshmemConfig {
    /// Total bytes this layout requires from the ivshmem region.
    fn required_size(&self) -> usize {
        self.slot_size * (1 + self.ring_slot_count) + RING_HEADER_SIZE
    }
}

static CONFIG: OnceLock<IvshmemConfig> = OnceLock::new();

/// The active layout — the value passed to [`init_with_config`], or the
/// default if [`init`] was used.
fn config() -> IvshmemConfig {
    CONFIG.get().copied().unwrap_or_default()
}

struct Ivshmem {
    ptr: *mut u8,
    size: usize,
}

// SAFETY: The mmap'd region is only written from the fuzzer's single
// execution thread (inside the harness closure). No concurrent access.
unsafe impl Send for Ivshmem {}
unsafe impl Sync for Ivshmem {}

static BACKEND: OnceLock<Option<Ivshmem>> = OnceLock::new();

/// Initialize the ivshmem backend with the default [`IvshmemConfig`].
/// Call once at startup.
pub fn init() -> bool {
    init_with_config(IvshmemConfig::default())
}

/// Initialize the ivshmem backend with a custom [`IvshmemConfig`].
///
/// Use this instead of [`init`] to match the ivshmem device size or trade slot
/// size against ring depth — e.g. smaller slots + more slots for a longer
/// deferred-crash window on a fixed device. Call once at startup, before any
/// `write_input`; the first init call wins.
pub fn init_with_config(config: IvshmemConfig) -> bool {
    let _ = CONFIG.set(config);
    BACKEND
        .get_or_init(|| match find_and_map_ivshmem() {
            Ok(backend) => {
                let needed = config.required_size();
                if needed > backend.size {
                    eprintln!(
                        "[repro] WARNING: configured ivshmem layout needs {needed} bytes but \
                         region is only {} bytes — inputs may be dropped",
                        backend.size
                    );
                }
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

/// Persist an input before a harness execution.
///
/// Writes the serialized input to both the pre-exec section (for fatal-panic
/// reproduction) and the crash ring (for deferred timer-based crashes). This
/// is the single entry point a harness calls before each execution — it
/// replaces the old separate `write_input` + `write_input_to_ring` pair.
pub fn write_input(input: &AlmondInput) {
    let Some(Some(ivshmem)) = BACKEND.get() else {
        return;
    };
    let Some(json) = serialize(input) else {
        return;
    };
    let cfg = config();

    write_pre_exec(ivshmem, &json, &cfg);

    // Ring write respects the stop-and-drain freeze so a crash's context stays
    // stable while the manager consumes it.
    maybe_drain_and_unfreeze();
    if RING_FROZEN.load(std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    write_ring_slot(ivshmem, &json, &cfg);
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
        let ring_base = unsafe { ivshmem.ptr.add(config().slot_size) };
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
    let ring_base = unsafe { ivshmem.ptr.add(config().slot_size) };
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

/// Serialize an input straight into the next crash-ring slot, bypassing the
/// freeze check. Called by the kmsg detector when it finds a nonfatal kernel
/// warning, so the triggering input lands in the ring before `freeze_ring`.
pub fn write_crash_input(input: &AlmondInput) {
    let Some(Some(ivshmem)) = BACKEND.get() else {
        return;
    };
    let Some(json) = serialize(input) else {
        return;
    };
    write_ring_slot(ivshmem, &json, &config());
}

/// Serialize an input to JSON, logging on failure.
fn serialize(input: &AlmondInput) -> Option<Vec<u8>> {
    let inner = input.inner.read().unwrap();
    match serde_json::to_vec(&*inner) {
        Ok(json) => Some(json),
        Err(e) => {
            eprintln!("[repro] Serialization failed: {e}");
            None
        }
    }
}

/// Write a serialized input to the pre-exec slot at offset 0.
fn write_pre_exec(ivshmem: &Ivshmem, json: &[u8], cfg: &IvshmemConfig) {
    let total = HEADER_SIZE + json.len();
    if total > cfg.slot_size {
        eprintln!(
            "[repro] Input too large for pre-exec slot ({total} > {}) — \
             increase IvshmemConfig::slot_size",
            cfg.slot_size
        );
        return;
    }
    let buf = ivshmem.ptr;
    unsafe {
        buf.cast::<u32>().write(MAGIC.to_le());
        buf.add(4).cast::<u32>().write((json.len() as u32).to_le());
        std::ptr::copy_nonoverlapping(json.as_ptr(), buf.add(HEADER_SIZE), json.len());
    }
}

/// Append a serialized input to the next crash-ring slot and bump write_idx.
fn write_ring_slot(ivshmem: &Ivshmem, json: &[u8], cfg: &IvshmemConfig) {
    let total = HEADER_SIZE + json.len();
    if total > cfg.slot_size {
        eprintln!(
            "[repro] Crash input too large for ring slot ({total} > {}) — \
             increase IvshmemConfig::slot_size",
            cfg.slot_size
        );
        return;
    }

    let ring_base = unsafe { ivshmem.ptr.add(cfg.slot_size) };

    // Read current write_idx, compute slot, then increment.
    let write_idx = unsafe { ring_base.add(4).cast::<u32>().read() }.to_le();
    let slot = (write_idx as usize) % cfg.ring_slot_count;
    let slot_ptr = unsafe { ring_base.add(RING_HEADER_SIZE + slot * cfg.slot_size) };

    unsafe {
        slot_ptr.cast::<u32>().write(MAGIC.to_le());
        slot_ptr
            .add(4)
            .cast::<u32>()
            .write((json.len() as u32).to_le());
        std::ptr::copy_nonoverlapping(json.as_ptr(), slot_ptr.add(HEADER_SIZE), json.len());
    }

    // Update write_idx after the data is written.
    let new_idx = write_idx.wrapping_add(1);
    unsafe {
        ring_base.cast::<u32>().write(RING_MAGIC.to_le());
        ring_base.add(4).cast::<u32>().write(new_idx.to_le());
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
