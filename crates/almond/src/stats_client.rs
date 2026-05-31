// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! Statistics client for sending execution statistics to the manager.
//!
//! This module provides a client that sends fuzzing statistics
//! to the Python manager via a Unix domain socket.
//!
//! Two message types are sent:
//! - **Aggregate**: Sent by the broker with coverage counts and execution stats.
//! - **Rings**: Sent by the client with raw coverage data drained from ring buffers.

use anyhow::{Context, Result};
use serde::Serialize;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Tagged union of messages sent to the manager via UDS.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "msg_type", rename_all = "snake_case")]
pub enum StatsMessage {
    /// Aggregate statistics from the broker process.
    Aggregate(AggregateStats),
    /// Raw ring-buffer data from the client process.
    Rings(RingsData),
}

/// Aggregate statistics sent by the broker.
#[derive(Debug, Clone, Serialize)]
pub struct AggregateStats {
    pub vm_id: u32,
    pub target: String,
    pub coverage_signal: usize,
    pub corpus_size: usize,
    pub execs_per_sec: u64,
    pub total_execs: u64,
}

/// Raw ring-buffer data sent by the client.
#[derive(Debug, Clone, Serialize)]
pub struct RingsData {
    pub vm_id: u32,
    pub target: String,
    pub bbs: Vec<u64>,
    /// Newly-seen kcov edge signal slot indices, for cross-VM edge aggregation.
    pub signals: Vec<u32>,
    pub coverage_ring_overflows: u64,
    pub signal_ring_overflows: u64,
}

/// Client for sending statistics to the manager
///
/// This is a simple data holder that can be cloned.
/// Rate limiting is handled by the caller (StatsMonitor).
#[derive(Debug, Clone)]
pub struct StatsClient {
    pub vm_id: u32,
    pub target: String,
    pub socket_path: String,
}

impl StatsClient {
    /// Create a new stats client
    ///
    /// # Arguments
    /// * `vm_id` - The VM ID (0-indexed)
    /// * `target` - The target name
    /// * `socket_path` - Path to the Unix domain socket (e.g., "/tmp/almond-stats-0.sock")
    pub fn new(vm_id: u32, target: &str, socket_path: &str) -> Self {
        Self {
            vm_id,
            target: target.to_string(),
            socket_path: socket_path.to_string(),
        }
    }

    /// Send aggregate statistics from the broker process.
    pub fn send_aggregate(
        &self,
        coverage_signal: usize,
        corpus_size: usize,
        execs_per_sec: u64,
        total_execs: u64,
    ) -> Result<()> {
        let msg = StatsMessage::Aggregate(AggregateStats {
            vm_id: self.vm_id,
            target: self.target.clone(),
            coverage_signal,
            corpus_size,
            execs_per_sec,
            total_execs,
        });
        self.send_message(&msg)
    }

    /// Send raw ring buffer data from the client process.
    pub fn send_rings_only(&self) -> Result<()> {
        let bbs = crate::observers::coverage_ring::drain();
        let signals = crate::observers::signal_ring::drain();
        let coverage_ring_overflows = crate::observers::coverage_ring::drain_overflow();
        let signal_ring_overflows = crate::observers::signal_ring::drain_overflow();

        if bbs.is_empty()
            && signals.is_empty()
            && coverage_ring_overflows == 0
            && signal_ring_overflows == 0
        {
            return Ok(());
        }

        let msg = StatsMessage::Rings(RingsData {
            vm_id: self.vm_id,
            target: self.target.clone(),
            bbs,
            signals,
            coverage_ring_overflows,
            signal_ring_overflows,
        });
        self.send_message(&msg)
    }

    fn send_message(&self, msg: &StatsMessage) -> Result<()> {
        let stream = UnixStream::connect(&self.socket_path);

        match stream {
            Ok(mut stream) => {
                let json =
                    serde_json::to_string(msg).context("Failed to serialize stats message")?;
                let data = format!("{}\n", json);
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .context("Failed to set write timeout")?;

                use std::io::Write;
                stream
                    .write_all(data.as_bytes())
                    .context("Failed to write stats message")?;
                stream.flush().context("Failed to flush stats message")?;
                Ok(())
            }
            Err(e) => {
                // Only swallow "the manager isn't listening yet / anymore"
                // states. Real configuration problems (EACCES, EADDR) must
                // surface so misconfiguration doesn't masquerade as success.
                match e.kind() {
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => Ok(()),
                    _ => Err(e).context("Failed to connect to stats socket"),
                }
            }
        }
    }

    /// Check if the stats socket exists
    pub fn socket_exists(&self) -> bool {
        Path::new(&self.socket_path).exists()
    }

    /// Start a background thread that periodically drains ring buffers and
    /// sends raw coverage data to the manager.
    ///
    /// This is necessary because the ring buffers are process-local: observers
    /// populate them in the client process, but `StatsMonitor::display()` runs
    /// in the broker process (a separate process) where the rings are always empty.
    ///
    /// Returns a handle that stops the thread when dropped.
    pub fn start_rings_thread(&self, interval: Duration) -> ClientStatsHandle {
        let client = self.clone();
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);

        let handle = std::thread::Builder::new()
            .name("almond-client-stats".into())
            .spawn(move || {
                while running_clone.load(Ordering::Relaxed) {
                    std::thread::sleep(interval);
                    let _ = client.send_rings_only();
                }
            })
            .expect("Failed to spawn client stats thread");

        ClientStatsHandle {
            running,
            thread: Some(handle),
        }
    }
}

/// Handle for the client-side stats thread. Stops the thread on drop.
pub struct ClientStatsHandle {
    running: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for ClientStatsHandle {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggregate_message_serialization() {
        let msg = StatsMessage::Aggregate(AggregateStats {
            vm_id: 0,
            target: "test_target".to_string(),
            coverage_signal: 12345,
            corpus_size: 56,
            execs_per_sec: 1234,
            total_execs: 999999,
        });

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"msg_type\":\"aggregate\""));
        assert!(json.contains("\"coverage_signal\":12345"));
        assert!(!json.contains("\"bbs\""));
    }

    #[test]
    fn test_rings_message_serialization() {
        let msg = StatsMessage::Rings(RingsData {
            vm_id: 0,
            target: "test_target".to_string(),
            bbs: vec![0x1000, 0x2000, 0x3000],
            signals: vec![42, 100, 8191],
            coverage_ring_overflows: 0,
            signal_ring_overflows: 0,
        });

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"msg_type\":\"rings\""));
        assert!(json.contains("\"bbs\""));
        assert!(json.contains("\"signals\""));
        assert!(!json.contains("\"coverage_signal\""));
    }

    #[test]
    fn test_stats_client_clone() {
        let client = StatsClient::new(0, "test_target", "/tmp/test-stats-clone.sock");
        let cloned = client.clone();

        assert_eq!(client.vm_id, cloned.vm_id);
        assert_eq!(client.target, cloned.target);
        assert_eq!(client.socket_path, cloned.socket_path);
    }
}
