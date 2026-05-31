// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2025 Almond Contributors.

//! Statistics monitor for sending coverage and execution statistics to the manager.
//!
//! This module provides a monitor that integrates with LibAFL's Monitor trait
//! to send fuzzing statistics to the Python manager via a Unix domain socket.

use crate::stats_client::{ClientStatsHandle, StatsClient};
use libafl::Error;
use libafl::monitors::Monitor;
use libafl::monitors::stats::{ClientStatsManager, UserStatsValue};
use libafl_bolts::ClientId;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Monitor that sends statistics to the manager via Unix socket
///
/// This monitor implements the LibAFL `Monitor` trait and is called by the
/// restarting manager to display stats. It sends the stats to the Python
/// manager via a Unix domain socket.
#[derive(Clone)]
pub struct StatsMonitor {
    client: StatsClient,
    /// Last time we sent stats (for rate limiting) - uses Arc<Mutex<>> for cloneability
    last_send: Arc<Mutex<Instant>>,
    /// Minimum interval between sends (rate limiting)
    min_interval: Duration,
}

impl StatsMonitor {
    /// Create a new stats monitor
    ///
    /// # Arguments
    /// * `vm_id` - The VM ID (0-indexed)
    /// * `target` - The target name
    /// * `socket_path` - Path to the Unix domain socket (e.g., "/tmp/almond-stats-0.sock")
    pub fn new(vm_id: u32, target: &str, socket_path: &str) -> Self {
        Self {
            client: StatsClient::new(vm_id, target, socket_path),
            last_send: Arc::new(Mutex::new(Instant::now() - Duration::from_secs(10))), // Start with old time to allow first send
            min_interval: Duration::from_secs(1), // Send at most once per second
        }
    }

    /// Create a new stats monitor with custom rate limit interval
    pub fn with_interval(vm_id: u32, target: &str, socket_path: &str, interval: Duration) -> Self {
        Self {
            client: StatsClient::new(vm_id, target, socket_path),
            last_send: Arc::new(Mutex::new(Instant::now() - Duration::from_secs(10))),
            min_interval: interval,
        }
    }

    /// Start a background thread that periodically drains ring buffers and
    /// sends raw coverage data to the manager via the same socket.
    ///
    /// This must be called in the client process (after `setup_restarting_mgr_std`),
    /// because ring buffers are process-local and `display()` runs in the broker.
    pub fn start_rings_thread(&self, interval: Duration) -> ClientStatsHandle {
        self.client.start_rings_thread(interval)
    }

    /// Send aggregate statistics if enough time has elapsed (rate limited).
    ///
    /// This only sends aggregate stats (counts). Raw ring buffer data is sent
    /// separately by the client-side stats thread (see `start_client_stats_thread`),
    /// because the ring buffers are populated in the fuzzer client process while
    /// this monitor runs in the broker process (separate address space).
    fn try_send_stats(
        &self,
        coverage_signal: usize,
        corpus_size: usize,
        execs_per_sec: u64,
        total_execs: u64,
    ) {
        // Check rate limit
        {
            let mut last_send = self.last_send.lock().unwrap();
            if last_send.elapsed() < self.min_interval {
                return;
            }
            *last_send = Instant::now();
        }

        // Send aggregate stats only (no ring drain - rings are in the client process)
        let _ = self.client.send_aggregate(
            coverage_signal,
            corpus_size,
            execs_per_sec,
            total_execs,
        );
    }
}

impl Monitor for StatsMonitor {
    /// Display (send) the stats to the manager
    ///
    /// This method is called by LibAFL's restarting manager with updated statistics.
    /// We extract the relevant stats and send them to the Python manager via Unix socket.
    fn display(
        &mut self,
        client_stats_manager: &mut ClientStatsManager,
        _event_msg: &str,
        _sender_id: ClientId,
    ) -> Result<(), Error> {
        // Get global stats
        let global_stats = client_stats_manager.global_stats();

        // Extract the statistics we need
        let corpus_size = global_stats.corpus_size as usize;
        let execs_per_sec = global_stats.execs_per_sec as u64;
        let total_execs = global_stats.total_execs;

        // Extract coverage from UserStats populated by feedbacks
        // LibAFL's MapFeedback populates UserStats with coverage data
        let coverage_signal = self.extract_coverage_from_stats(
            client_stats_manager,
            "signal", // Observer name for Kcov edge coverage
        );

        // Send stats (rate-limited)
        self.try_send_stats(
            coverage_signal,
            corpus_size,
            execs_per_sec,
            total_execs,
        );

        Ok(())
    }
}

impl StatsMonitor {
    /// Extract coverage count from UserStats
    ///
    /// LibAFL's MapFeedback sends UpdateUserStats events with coverage data.
    /// The stats are aggregated per-client and we sum them up for total coverage.
    fn extract_coverage_from_stats(
        &self,
        client_stats_manager: &ClientStatsManager,
        observer_name: &str,
    ) -> usize {
        let mut total_coverage = 0usize;

        // Iterate through all clients and sum up their coverage
        // The UserStats key format is typically "{observer_name}_cov" or just the observer name
        for (_client_id, client) in client_stats_manager.client_stats() {
            if !client.enabled() {
                continue;
            }

            // Try common UserStats key formats for coverage
            let keys_to_try = vec![
                observer_name.to_string(),
                format!("{}_cov", observer_name),
                format!("{}_coverage", observer_name),
            ];

            for key in keys_to_try {
                if let Some(user_stat) = client.user_stats().get(key.as_str()) {
                    match user_stat.value() {
                        UserStatsValue::Ratio(hit, _total) => {
                            total_coverage += *hit as usize;
                        }
                        UserStatsValue::Number(val) => {
                            total_coverage += *val as usize;
                        }
                        UserStatsValue::Float(val) => {
                            total_coverage += *val as usize;
                        }
                        _ => {}
                    }
                }
            }
        }

        // If no per-client coverage found, try aggregated stats
        if total_coverage == 0 {
            let aggregated = client_stats_manager.aggregated();
            for key in [observer_name, &format!("{}_cov", observer_name)] {
                if let Some(val) = aggregated.get(key) {
                    match val {
                        UserStatsValue::Ratio(hit, _) => {
                            total_coverage = *hit as usize;
                            break;
                        }
                        UserStatsValue::Number(v) => {
                            total_coverage = *v as usize;
                            break;
                        }
                        UserStatsValue::Float(v) => {
                            total_coverage = *v as usize;
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        total_coverage
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libafl::monitors::stats::{AggregatorOps, UserStats};
    use libafl_bolts::ClientId;
    use std::borrow::Cow;

    /// Helper to create a mock ClientStatsManager with coverage data
    fn create_manager_with_coverage(
        client_id: u32,
        observer_name: &str,
        coverage_hit: u64,
        coverage_total: u64,
    ) -> ClientStatsManager {
        let mut manager = ClientStatsManager::new();
        let id = ClientId(client_id);
        let name = Cow::from(observer_name.to_string());

        // Insert and enable the client
        manager.client_stats_insert(id).unwrap();

        // Update client with coverage UserStats
        manager
            .update_client_stats_for(id, |client| {
                client.update_user_stats(
                    name.clone(),
                    UserStats::new(
                        UserStatsValue::Ratio(coverage_hit, coverage_total),
                        AggregatorOps::Avg,
                    ),
                );
            })
            .unwrap();

        // Aggregate the stats
        manager.aggregate(&name);

        manager
    }

    #[test]
    fn test_stats_monitor_rate_limit() {
        let monitor = StatsMonitor::with_interval(
            0,
            "test_target",
            "/tmp/test-stats-rate.sock",
            Duration::from_millis(100),
        );

        // Test rate limiting
        monitor.try_send_stats(100, 5, 1000, 50000);

        // Immediate second call should be rate-limited
        monitor.try_send_stats(200, 10, 2000, 100000);

        std::thread::sleep(Duration::from_millis(150));
        monitor.try_send_stats(300, 15, 3000, 150000);

        // Clean up
        let _ = std::fs::remove_file("/tmp/test-stats-rate.sock");
    }

    #[test]
    fn test_extract_coverage_from_user_stats_ratio() {
        // Test extracting coverage from UserStatsValue::Ratio
        // (what LibAFL's MapFeedback sends)
        let monitor = StatsMonitor::new(0, "test", "/tmp/test-extract-ratio.sock");
        let manager = create_manager_with_coverage(0, "signal", 1234, 10000);

        let coverage = monitor.extract_coverage_from_stats(&manager, "signal");

        assert_eq!(coverage, 1234);
    }

    #[test]
    fn test_extract_coverage_from_user_stats_number() {
        // Test extracting coverage from UserStatsValue::Number

        let mut manager = ClientStatsManager::new();
        let id = ClientId(0);
        manager.client_stats_insert(id).unwrap();

        manager
            .update_client_stats_for(id, |client| {
                client.update_user_stats(
                    Cow::from("signal"),
                    UserStats::new(UserStatsValue::Number(5678), AggregatorOps::Sum),
                );
            })
            .unwrap();

        manager.aggregate(&Cow::from("signal"));

        let monitor = StatsMonitor::new(0, "test", "/tmp/test-extract-number.sock");
        let coverage = monitor.extract_coverage_from_stats(&manager, "signal");

        assert_eq!(coverage, 5678);
    }

    #[test]
    fn test_extract_coverage_from_aggregated_stats() {
        // Test extracting from aggregated stats when per-client lookup fails
        let monitor = StatsMonitor::new(0, "test", "/tmp/test-aggregated.sock");

        // Create manager with no per-client UserStats, but add aggregated stats

        let mut manager = ClientStatsManager::new();

        // Manually insert aggregated stats

        let id = ClientId(0);
        manager.client_stats_insert(id).unwrap();

        manager
            .update_client_stats_for(id, |client| {
                client.update_user_stats(
                    Cow::from("signal_cov"),
                    UserStats::new(UserStatsValue::Ratio(9999, 50000), AggregatorOps::Avg),
                );
            })
            .unwrap();

        manager.aggregate(&Cow::from("signal_cov"));

        let coverage = monitor.extract_coverage_from_stats(&manager, "signal_cov");

        assert_eq!(coverage, 9999);
    }

    #[test]
    fn test_extract_coverage_returns_zero_when_not_found() {
        // Test that zero is returned when coverage stats don't exist
        let monitor = StatsMonitor::new(0, "test", "/tmp/test-zero.sock");
        let manager = ClientStatsManager::new();

        let coverage = monitor.extract_coverage_from_stats(&manager, "nonexistent");

        assert_eq!(coverage, 0);
    }

    #[test]
    fn test_extract_coverage_multiple_clients() {
        // Test summing coverage from multiple clients

        let mut manager = ClientStatsManager::new();

        // Add first client with coverage
        let id1 = ClientId(0);
        manager.client_stats_insert(id1).unwrap();
        manager
            .update_client_stats_for(id1, |client| {
                client.update_user_stats(
                    Cow::from("signal"),
                    UserStats::new(UserStatsValue::Ratio(100, 1000), AggregatorOps::Avg),
                );
            })
            .unwrap();

        // Add second client with coverage
        let id2 = ClientId(1);
        manager.client_stats_insert(id2).unwrap();
        manager
            .update_client_stats_for(id2, |client| {
                client.update_user_stats(
                    Cow::from("signal"),
                    UserStats::new(UserStatsValue::Ratio(200, 1000), AggregatorOps::Avg),
                );
            })
            .unwrap();

        manager.aggregate(&Cow::from("signal"));

        let monitor = StatsMonitor::new(0, "test", "/tmp/test-multi-client.sock");
        let coverage = monitor.extract_coverage_from_stats(&manager, "signal");

        // Should sum coverage from both clients
        assert_eq!(coverage, 300);
    }

    #[test]
    fn test_display_with_coverage() {
        // Test the full display() method with coverage data

        use std::fs;
        use std::io::Read;
        use std::os::unix::net::UnixListener;
        use std::thread;
        use std::time::Duration;

        let socket_path = "/tmp/test-display-coverage.sock";

        // Clean up any existing socket
        let _ = fs::remove_file(socket_path);

        // Start a listener thread to receive the stats
        let socket_path_clone = socket_path.to_string();
        let handle = thread::spawn(move || {
            let listener = UnixListener::bind(socket_path_clone).unwrap();
            listener
                .set_nonblocking(true)
                .expect("set_nonblocking call failed");
            // Use a timeout with accept by sleeping
            std::thread::sleep(Duration::from_millis(200));
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut buffer = vec![0u8; 4096];
                if let Ok(n) = stream.read(&mut buffer) {
                    buffer.truncate(n);
                    Some(String::from_utf8(buffer).unwrap())
                } else {
                    None
                }
            } else {
                None
            }
        });

        // Give the listener time to start
        thread::sleep(Duration::from_millis(100));

        // Create manager with coverage
        let mut manager = create_manager_with_coverage(0, "signal", 555, 2000);
        let id = ClientId(0);

        // Create monitor and call display
        let mut monitor = StatsMonitor::new(0, "test_target", socket_path);

        // Call display - this should send stats to the socket
        let result = monitor.display(&mut manager, "test", id);
        assert!(result.is_ok());

        // Wait for the message and verify
        let msg_opt = handle.join().unwrap();
        if let Some(msg) = msg_opt {
            assert!(msg.contains("\"msg_type\":\"aggregate\""));
            assert!(msg.contains("\"coverage_signal\":555"));
            assert!(msg.contains("\"vm_id\":0"));
            assert!(msg.contains("\"target\":\"test_target\""));
        }

        // Clean up
        let _ = fs::remove_file(socket_path);
    }

    #[test]
    fn test_observer_name_fallback() {
        // Test that various observer name formats work

        let mut manager = ClientStatsManager::new();
        let id = ClientId(0);
        manager.client_stats_insert(id).unwrap();

        // Add coverage with "_cov" suffix
        manager
            .update_client_stats_for(id, |client| {
                client.update_user_stats(
                    Cow::from("signal_cov"),
                    UserStats::new(UserStatsValue::Ratio(333, 1000), AggregatorOps::Avg),
                );
            })
            .unwrap();

        manager.aggregate(&Cow::from("signal_cov"));

        let monitor = StatsMonitor::new(0, "test", "/tmp/test-fallback.sock");

        // Should find coverage with "signal_cov" key when looking for "signal"
        let coverage = monitor.extract_coverage_from_stats(&manager, "signal");

        assert_eq!(coverage, 333);
    }
}
