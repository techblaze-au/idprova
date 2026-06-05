//! Release-blocking guardrails for live anchoring (ADR 0012, step e).
//!
//! These are the controls that make turning anchoring ON in production safe.
//! They are deliberately **pure and clock-injected** (the caller supplies Unix
//! seconds), so the policy logic is fully unit-testable and carries no timers
//! or I/O. The live submitter that drives them (network calls to Rekor) is a
//! deployment-time concern and is intentionally not wired here.
//!
//! * [`CircuitBreaker`] — trips OPEN after consecutive submit failures, stays
//!   open for a cooldown, then allows a single HALF-OPEN probe before closing.
//!   Keeps a flapping or rate-limited transparency log from burning the rate
//!   budget or blocking the receipt hot path.
//! * [`jittered_backoff_secs`] — decorrelated exponential backoff with full
//!   jitter (the jitter fraction is supplied so callers stay deterministic in
//!   tests).
//! * [`RateBudget`] — a per-minute token bucket bounding how many root anchors
//!   may be submitted, protecting the shared public good instance.
//! * [`AnchorMetrics`] — plain counters the submitter increments for
//!   observability.

/// State of a [`CircuitBreaker`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Submissions are allowed.
    Closed,
    /// Submissions are blocked until the cooldown elapses.
    Open,
    /// A single probe submission is allowed to test recovery.
    HalfOpen,
}

/// A circuit breaker over transparency-log submissions.
///
/// Anchoring is best-effort and off the receipt hot path, so a tripped breaker
/// simply leaves receipts unanchored until the log recovers — it never fails an
/// action.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    failure_threshold: u32,
    cooldown_secs: i64,
    consecutive_failures: u32,
    state: BreakerState,
    opened_at: Option<i64>,
}

impl CircuitBreaker {
    /// Create a breaker that opens after `failure_threshold` consecutive
    /// failures and stays open for `cooldown_secs`.
    ///
    /// `failure_threshold` is clamped to at least 1.
    pub fn new(failure_threshold: u32, cooldown_secs: i64) -> Self {
        Self {
            failure_threshold: failure_threshold.max(1),
            cooldown_secs: cooldown_secs.max(0),
            consecutive_failures: 0,
            state: BreakerState::Closed,
            opened_at: None,
        }
    }

    /// The breaker's current state (without advancing the clock).
    pub fn state(&self) -> BreakerState {
        self.state
    }

    /// Whether a submission is allowed at `now`.
    ///
    /// In `Open`, this transitions to `HalfOpen` (allowing one probe) once the
    /// cooldown has elapsed. Calling `allow` may mutate state, so call it once
    /// per submission attempt.
    pub fn allow(&mut self, now_unix: i64) -> bool {
        match self.state {
            BreakerState::Closed => true,
            BreakerState::HalfOpen => true,
            BreakerState::Open => {
                let elapsed = self
                    .opened_at
                    .map(|o| now_unix.saturating_sub(o))
                    .unwrap_or(i64::MAX);
                if elapsed >= self.cooldown_secs {
                    self.state = BreakerState::HalfOpen;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Record a successful submission: resets failures and closes the breaker.
    pub fn on_success(&mut self) {
        self.consecutive_failures = 0;
        self.state = BreakerState::Closed;
        self.opened_at = None;
    }

    /// Record a failed submission at `now`.
    ///
    /// A failure in `HalfOpen` re-opens immediately; otherwise failures
    /// accumulate and open the breaker once the threshold is reached.
    pub fn on_failure(&mut self, now_unix: i64) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.state == BreakerState::HalfOpen
            || self.consecutive_failures >= self.failure_threshold
        {
            self.state = BreakerState::Open;
            self.opened_at = Some(now_unix);
        }
    }
}

/// Decorrelated exponential backoff with full jitter, in seconds.
///
/// Computes `base * 2^attempt` (saturating, capped at `cap_secs`) and then
/// scales it by `jitter01 ∈ [0, 1]` (full jitter — AWS architecture blog). The
/// jitter fraction is supplied by the caller so this function is deterministic
/// and testable; production callers pass a fresh random value in `[0, 1)`.
///
/// `attempt` is 0-based (attempt 0 → up to `base` seconds).
pub fn jittered_backoff_secs(base_secs: u64, attempt: u32, cap_secs: u64, jitter01: f64) -> u64 {
    let exp = base_secs.saturating_mul(1u64.checked_shl(attempt).unwrap_or(u64::MAX));
    let ceiling = exp.min(cap_secs);
    let frac = jitter01.clamp(0.0, 1.0);
    (ceiling as f64 * frac) as u64
}

/// A per-minute token bucket bounding root-anchor submissions.
///
/// The window is a fixed 60-second tumbling window keyed off the caller's
/// clock; `max_per_min` tokens are available per window.
#[derive(Debug, Clone)]
pub struct RateBudget {
    max_per_min: u32,
    used: u32,
    window_start: Option<i64>,
}

impl RateBudget {
    /// Create a budget allowing `max_per_min` submissions per 60-second window.
    pub fn new(max_per_min: u32) -> Self {
        Self {
            max_per_min,
            used: 0,
            window_start: None,
        }
    }

    /// Try to consume one token at `now`. Returns `true` if within budget
    /// (token consumed), `false` if the current window is exhausted.
    pub fn try_acquire(&mut self, now_unix: i64) -> bool {
        let rolled =
            !matches!(self.window_start, Some(start) if now_unix.saturating_sub(start) < 60);
        if rolled {
            self.window_start = Some(now_unix);
            self.used = 0;
        }
        if self.used < self.max_per_min {
            self.used += 1;
            true
        } else {
            false
        }
    }

    /// Tokens remaining in the current window (0 if the window has rolled and
    /// not yet been re-opened by a call to [`Self::try_acquire`]).
    pub fn remaining(&self) -> u32 {
        self.max_per_min.saturating_sub(self.used)
    }
}

/// Observability counters for the anchoring subsystem.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnchorMetrics {
    /// Number of batch roots successfully anchored.
    pub batches_anchored: u64,
    /// Total leaves (receipts) anchored across all batches.
    pub leaves_anchored: u64,
    /// Number of failed submit attempts.
    pub submit_failures: u64,
    /// Number of times the circuit breaker tripped open.
    pub breaker_trips: u64,
    /// Number of submissions skipped because the rate budget was exhausted.
    pub rate_limited: u64,
}

impl AnchorMetrics {
    /// Record a successful batch anchor of `leaves` receipts.
    pub fn record_anchor(&mut self, leaves: u64) {
        self.batches_anchored += 1;
        self.leaves_anchored += leaves;
    }

    /// Record a failed submission.
    pub fn record_failure(&mut self) {
        self.submit_failures += 1;
    }

    /// Record a breaker trip.
    pub fn record_breaker_trip(&mut self) {
        self.breaker_trips += 1;
    }

    /// Record a rate-limited (skipped) submission.
    pub fn record_rate_limited(&mut self) {
        self.rate_limited += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breaker_opens_after_threshold_and_recovers() {
        let mut b = CircuitBreaker::new(3, 30);
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(b.allow(0));

        b.on_failure(0);
        b.on_failure(1);
        assert_eq!(b.state(), BreakerState::Closed, "2 < threshold 3");
        b.on_failure(2);
        assert_eq!(b.state(), BreakerState::Open, "3rd failure trips open");

        // Blocked during cooldown.
        assert!(!b.allow(10), "still within 30s cooldown");
        // After cooldown → one half-open probe allowed.
        assert!(b.allow(32));
        assert_eq!(b.state(), BreakerState::HalfOpen);

        // A success closes it and resets the failure count.
        b.on_success();
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(b.allow(40));
    }

    #[test]
    fn half_open_failure_reopens_immediately() {
        let mut b = CircuitBreaker::new(2, 10);
        b.on_failure(0);
        b.on_failure(1);
        assert_eq!(b.state(), BreakerState::Open);
        assert!(b.allow(11)); // → HalfOpen
        assert_eq!(b.state(), BreakerState::HalfOpen);
        b.on_failure(11);
        assert_eq!(b.state(), BreakerState::Open, "half-open failure re-opens");
        assert!(!b.allow(12));
    }

    #[test]
    fn backoff_is_exponential_capped_and_jittered() {
        // Full jitter at fraction 1.0 yields the ceiling.
        assert_eq!(jittered_backoff_secs(1, 0, 60, 1.0), 1);
        assert_eq!(jittered_backoff_secs(1, 1, 60, 1.0), 2);
        assert_eq!(jittered_backoff_secs(1, 4, 60, 1.0), 16);
        // Capped.
        assert_eq!(jittered_backoff_secs(1, 10, 60, 1.0), 60);
        // Jitter scales down; zero fraction → zero wait.
        assert_eq!(jittered_backoff_secs(1, 4, 60, 0.5), 8);
        assert_eq!(jittered_backoff_secs(1, 4, 60, 0.0), 0);
        // Huge attempt must not overflow/panic.
        let _ = jittered_backoff_secs(1, 1000, 60, 1.0);
    }

    #[test]
    fn rate_budget_limits_per_minute_and_rolls_window() {
        let mut rb = RateBudget::new(2);
        assert!(rb.try_acquire(1000));
        assert!(rb.try_acquire(1001));
        assert!(!rb.try_acquire(1002), "3rd in the window is over budget");
        assert_eq!(rb.remaining(), 0);
        // New window after 60s.
        assert!(rb.try_acquire(1060));
        assert_eq!(rb.remaining(), 1);
    }

    #[test]
    fn metrics_accumulate() {
        let mut m = AnchorMetrics::default();
        m.record_anchor(256);
        m.record_anchor(10);
        m.record_failure();
        m.record_breaker_trip();
        m.record_rate_limited();
        assert_eq!(m.batches_anchored, 2);
        assert_eq!(m.leaves_anchored, 266);
        assert_eq!(m.submit_failures, 1);
        assert_eq!(m.breaker_trips, 1);
        assert_eq!(m.rate_limited, 1);
    }
}
