//! `AuditExporter` — port for shipping receipts to external SIEMs.
//!
//! IDProva agents emit action receipts (`idprova_core::receipt::Receipt`)
//! that form a hash-chained, signed audit log. The `AuditExporter`
//! trait describes how an adapter ships those receipts to an external
//! sink — typically an OpenTelemetry collector that fan-outs to
//! Splunk / Datadog / Sentinel / Elastic / Sumo / Chronicle.
//!
//! Periodic `ChainCheckpoint` receipts (added in IDP-002) are exported
//! alongside data receipts so the downstream SIEM can independently
//! verify chain integrity without replaying the full log.

use crate::error::AdapterResult;
use idprova_core::receipt::Receipt;

/// SIEM-export port.
///
/// Implementations sit between the registry / agent SDKs and the
/// external collector. They batch receipts (typically 100 receipts or
/// 5 s, whichever fires first — see RFC 0001 §6.5) and emit
/// periodic `ChainCheckpoint` receipts (one per 1000 data receipts or
/// 1 h, whichever fires first).
pub trait AuditExporter: Send + Sync {
    /// Export a batch of receipts to the configured sink. Implementations
    /// MUST be at-least-once — they MAY duplicate receipts on retry but
    /// MUST NOT drop them. Downstream SIEMs deduplicate by `Receipt.id`.
    fn export_batch<'a>(
        &'a self,
        receipts: &'a [Receipt],
    ) -> impl std::future::Future<Output = AdapterResult<()>> + Send + 'a;

    /// Flush any in-flight batches and return when the sink has
    /// acknowledged them. Called on graceful shutdown.
    fn flush(&self) -> impl std::future::Future<Output = AdapterResult<()>> + Send;
}
