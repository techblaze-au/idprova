//! Action Receipts — hash-chained, signed audit trail.
//!
//! Every action taken by an agent produces a receipt that is:
//! - Signed by the agent
//! - Hash-chained to the previous receipt (tamper-evident)
//! - Contains hashes of inputs and outputs (privacy-preserving)

pub mod anchor;
pub mod batch;
pub mod commitment;
pub mod entry;
pub mod guardrails;
pub mod log;
pub mod merkle;

pub use anchor::{TransparencyAnchor, TransparencyLog};
pub use batch::{
    attach_commitment_evidence, verify_commitment_anchor, AnchorConfig, BatchAccumulator,
    ReadyBatch,
};
pub use commitment::{commit, generate_nonce};
pub use entry::{ActionDetails, Receipt, ReceiptContext, ReceiptKind};
pub use guardrails::{AnchorMetrics, BreakerState, CircuitBreaker, RateBudget};
pub use log::ReceiptLog;
pub use merkle::{InclusionProof, MerkleTree};
