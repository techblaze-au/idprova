//! In-memory rate tracking for constraint enforcement.
//!
//! `RateTracker` maintains sliding-window action counts per agent DID,
//! used to populate `EvaluationContext` fields for rate limit constraints.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Thread-safe in-memory rate tracker.
///
/// Tracks action timestamps per agent DID using sliding windows.
/// Not persistent — resets on process restart (by design; DATs
/// are short-lived and rate limits are best-effort).
pub struct RateTracker {
    inner: Mutex<RateTrackerInner>,
    hour_window: Duration,
    day_window: Duration,
}

struct RateTrackerInner {
    /// Sliding-window timestamps per agent DID.
    actions: HashMap<String, VecDeque<Instant>>,
    /// Active concurrent operation counts per agent DID.
    concurrent: HashMap<String, u64>,
}

impl RateTracker {
    /// Create a new rate tracker with standard 1-hour and 24-hour windows.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RateTrackerInner {
                actions: HashMap::new(),
                concurrent: HashMap::new(),
            }),
            hour_window: Duration::from_secs(3600),
            day_window: Duration::from_secs(86400),
        }
    }

    /// Record an action for the given agent.
    pub fn record_action(&self, agent_did: &str) {
        let mut inner = self.inner.lock().unwrap();
        let timestamps = inner.actions.entry(agent_did.to_string()).or_default();
        timestamps.push_back(Instant::now());
    }

    /// Get current rate counts for an agent: (hourly, daily, concurrent).
    pub fn get_counts(&self, agent_did: &str) -> (u64, u64, u64) {
        let mut inner = self.inner.lock().unwrap();
        let now = Instant::now();

        let (hourly, daily) = if let Some(timestamps) = inner.actions.get_mut(agent_did) {
            // Evict entries older than the day window
            while timestamps
                .front()
                .is_some_and(|t| now.duration_since(*t) > self.day_window)
            {
                timestamps.pop_front();
            }

            let daily = timestamps.len() as u64;
            let hourly = timestamps
                .iter()
                .filter(|t| now.duration_since(**t) <= self.hour_window)
                .count() as u64;

            (hourly, daily)
        } else {
            (0, 0)
        };

        let concurrent = inner.concurrent.get(agent_did).copied().unwrap_or(0);
        (hourly, daily, concurrent)
    }

    /// Increment the concurrent operation count for an agent.
    pub fn acquire_concurrent(&self, agent_did: &str) {
        let mut inner = self.inner.lock().unwrap();
        let count = inner.concurrent.entry(agent_did.to_string()).or_insert(0);
        *count += 1;
    }

    /// Decrement the concurrent operation count for an agent.
    pub fn release_concurrent(&self, agent_did: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(count) = inner.concurrent.get_mut(agent_did) {
            *count = count.saturating_sub(1);
        }
    }
}

impl Default for RateTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_record_and_count() {
        let tracker = RateTracker::new();
        let did = "did:idprova:test:agent1";

        assert_eq!(tracker.get_counts(did), (0, 0, 0));

        tracker.record_action(did);
        tracker.record_action(did);
        tracker.record_action(did);

        let (hourly, daily, concurrent) = tracker.get_counts(did);
        assert_eq!(hourly, 3);
        assert_eq!(daily, 3);
        assert_eq!(concurrent, 0);
    }

    #[test]
    fn test_concurrent_tracking() {
        let tracker = RateTracker::new();
        let did = "did:idprova:test:agent1";

        tracker.acquire_concurrent(did);
        tracker.acquire_concurrent(did);
        assert_eq!(tracker.get_counts(did).2, 2);

        tracker.release_concurrent(did);
        assert_eq!(tracker.get_counts(did).2, 1);

        tracker.release_concurrent(did);
        assert_eq!(tracker.get_counts(did).2, 0);

        // Release below zero should saturate at 0
        tracker.release_concurrent(did);
        assert_eq!(tracker.get_counts(did).2, 0);
    }

    #[test]
    fn test_separate_agents() {
        let tracker = RateTracker::new();
        let agent1 = "did:idprova:test:agent1";
        let agent2 = "did:idprova:test:agent2";

        tracker.record_action(agent1);
        tracker.record_action(agent1);
        tracker.record_action(agent2);

        assert_eq!(tracker.get_counts(agent1).0, 2);
        assert_eq!(tracker.get_counts(agent2).0, 1);
    }

    #[test]
    fn test_thread_safety() {
        let tracker = std::sync::Arc::new(RateTracker::new());
        let did = "did:idprova:test:agent1";
        let mut handles = vec![];

        for _ in 0..10 {
            let t = tracker.clone();
            let d = did.to_string();
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    t.record_action(&d);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let (hourly, daily, _) = tracker.get_counts(did);
        assert_eq!(hourly, 1000);
        assert_eq!(daily, 1000);
    }
}
