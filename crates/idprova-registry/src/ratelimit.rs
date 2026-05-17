//! Per-IP rate limiter for the registry HTTP layer.
//!
//! Tracks request timestamps per source IP within a 60-second window and
//! enforces a configurable maximum count. Caps the total number of unique
//! IPs at [`RATE_LIMITER_MAX_ENTRIES`] with LRU eviction so an attacker
//! cannot exhaust memory by rotating source IPs.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Maximum number of unique IPs tracked by the rate limiter.
/// When exceeded, the oldest entries are evicted (LRU).
pub const RATE_LIMITER_MAX_ENTRIES: usize = 10_000;

/// Sliding-window per-IP rate limiter with LRU bounded-size eviction.
#[derive(Default)]
pub struct RateLimiter {
    /// Per-IP request timestamps within the current window.
    windows: HashMap<String, Vec<Instant>>,
    /// Insertion-order queue for LRU eviction.
    order: VecDeque<String>,
}

impl RateLimiter {
    /// Record a request for `ip` and return `true` if it is allowed (i.e.
    /// fewer than `limit` requests have been seen from this IP in the
    /// trailing 60 s window).
    pub fn check_and_record(&mut self, ip: &str, limit: usize) -> bool {
        let now = Instant::now();

        // LRU eviction: if at capacity and this is a new IP, evict
        // oldest entries (10% of capacity, amortised cleanup).
        if !self.windows.contains_key(ip) && self.windows.len() >= RATE_LIMITER_MAX_ENTRIES {
            let evict_count = RATE_LIMITER_MAX_ENTRIES / 10;
            for _ in 0..evict_count {
                if let Some(old_ip) = self.order.pop_front() {
                    self.windows.remove(&old_ip);
                }
            }
        }

        let is_new = !self.windows.contains_key(ip);
        let window = self.windows.entry(ip.to_string()).or_default();
        window.retain(|t| now.duration_since(*t).as_secs() < 60);
        if window.len() >= limit {
            return false;
        }
        window.push(now);

        // Track insertion order for LRU.
        if is_new {
            self.order.push_back(ip.to_string());
        }
        true
    }
}
