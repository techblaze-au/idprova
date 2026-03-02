//! Action Receipts — hash-chained, signed audit trail.
//!
//! Every action taken by an agent produces a receipt that is:
//! - Signed by the agent
//! - Hash-chained to the previous receipt (tamper-evident)
//! - Contains hashes of inputs and outputs (privacy-preserving)

pub mod entry;
pub mod log;

pub use entry::{ActionDetails, Receipt, ReceiptContext};
pub use log::ReceiptLog;
