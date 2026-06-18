use anyhow::{bail, Result};
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use idprova_core::crypto::KeyPair;
use idprova_core::receipt::{
    build_record_from_receipts, receipt_leaf, verify_local_anchor, LocalAnchorLog, Receipt,
    ReceiptLog,
};
use std::fs;
use std::path::Path;

pub fn verify(file: &str) -> Result<()> {
    let content = fs::read_to_string(file)?;
    let entries: Vec<Receipt> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let log = ReceiptLog::from_entries(entries);

    match log.verify_integrity() {
        Ok(()) => {
            println!("Receipt chain integrity: VALID");
            println!("Entries: {}", log.len());
        }
        Err(e) => {
            println!("Receipt chain integrity: BROKEN");
            println!("Error: {e}");
        }
    }

    Ok(())
}

pub fn stats(file: &str) -> Result<()> {
    let content = fs::read_to_string(file)?;
    let entries: Vec<Receipt> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<_>, _>>()?;

    println!("Receipt Log Statistics:");
    println!("  Total entries: {}", entries.len());

    if let Some(first) = entries.first() {
        println!("  First entry:   {}", first.timestamp);
    }
    if let Some(last) = entries.last() {
        println!("  Last entry:    {}", last.timestamp);
    }

    // Count by action type
    let mut action_counts: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::new();
    for entry in &entries {
        *action_counts.entry(&entry.action.action_type).or_insert(0) += 1;
    }
    println!("  Action types:");
    for (action, count) in &action_counts {
        println!("    {action}: {count}");
    }

    Ok(())
}

/// Read a JSONL receipt log into a vec of receipts.
fn read_receipts(file: &str) -> Result<Vec<Receipt>> {
    let content = fs::read_to_string(file)?;
    let receipts: Vec<Receipt> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(serde_json::from_str)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(receipts)
}

/// Load a producer signing key from a hex (32-byte secret) file.
fn load_secret_key(path: &str) -> Result<SigningKey> {
    let key_hex = fs::read_to_string(path)?.trim().to_string();
    let key_bytes: [u8; 32] = hex::decode(&key_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Load a producer public key from a `.pub` multibase file or a hex public key.
fn load_public_key(path: &str) -> Result<VerifyingKey> {
    let key_str = fs::read_to_string(path)?.trim().to_string();
    let key_bytes: [u8; 32] = if key_str.starts_with('z') {
        KeyPair::decode_multibase_pubkey(&key_str)
            .map_err(|e| anyhow::anyhow!("invalid multibase public key: {e}"))?
    } else {
        hex::decode(&key_str)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?
    };
    VerifyingKey::from_bytes(&key_bytes).map_err(|e| anyhow::anyhow!("invalid public key: {e}"))
}

const LOCAL_ANCHOR_HONESTY: &str = "Note: a local anchor is producer-controlled — it has NO independent \
third-party\n      witness (no split-view protection). It is tamper-evident and offline-\n      verifiable; for independent attestation use Rekor anchoring (ADR-0011/0012).";

/// Anchor newly-added receipts to a local append-only anchor log (ADR-0013).
pub fn anchor_local(
    log_file: &str,
    anchor_file: &str,
    key_path: Option<&str>,
    producer_did: Option<String>,
) -> Result<()> {
    let receipts = read_receipts(log_file)?;
    if receipts.is_empty() {
        bail!("receipt log is empty: {log_file}");
    }

    let mut anchorlog = if Path::new(anchor_file).exists() {
        LocalAnchorLog::from_jsonl(&fs::read_to_string(anchor_file)?)?
    } else {
        LocalAnchorLog::new()
    };

    let start_seq = receipts[0].chain.sequence_number;
    let next_first = anchorlog
        .records()
        .last()
        .map(|r| r.last_seq + 1)
        .unwrap_or(start_seq);
    if next_first < start_seq {
        bail!("anchor log references receipts before the start of this log");
    }
    let start_idx = (next_first - start_seq) as usize;
    if start_idx >= receipts.len() {
        println!(
            "Nothing new to anchor: all {} receipts already covered (through seq {}).",
            receipts.len(),
            next_first.saturating_sub(1)
        );
        return Ok(());
    }
    let batch = &receipts[start_idx..];

    let signing_key = match key_path {
        Some(p) => Some(load_secret_key(p)?),
        None => None,
    };
    let anchored_at = Utc::now().timestamp();
    let index = anchorlog.next_index();
    let prev = anchorlog.last_record_hash();

    let record = build_record_from_receipts(
        batch,
        index,
        &prev,
        anchored_at,
        signing_key.as_ref(),
        producer_did,
    )?;

    let (first, last, root, signed) = (
        record.first_seq,
        record.last_seq,
        record.root.clone(),
        record.signature.is_some(),
    );
    anchorlog.append(record);
    fs::write(anchor_file, anchorlog.to_jsonl()?)?;

    println!("Local anchor written: {anchor_file}");
    println!("  Record index:   {index}");
    println!(
        "  Receipts:       seq {first}..={last} ({} leaves)",
        last - first + 1
    );
    println!("  Merkle root:    {root}");
    println!(
        "  Signed:         {}",
        if signed {
            "yes (producer Ed25519)"
        } else {
            "NO — pass --key to sign"
        }
    );
    println!();
    println!("{LOCAL_ANCHOR_HONESTY}");
    Ok(())
}

/// Verify a receipt log against a local anchor log (ADR-0013), fully offline.
pub fn verify_local(log_file: &str, anchor_file: &str, key_path: Option<&str>) -> Result<()> {
    let receipts = read_receipts(log_file)?;
    if receipts.is_empty() {
        bail!("receipt log is empty: {log_file}");
    }
    if receipts[0].chain.sequence_number != 0 {
        bail!("verify-local expects the receipt log to start at sequence 0");
    }

    // First, the existing receipt-chain integrity guarantee.
    let leaves: Vec<[u8; 64]> = receipts.iter().map(receipt_leaf).collect();
    let rlog = ReceiptLog::from_entries(receipts);
    match rlog.verify_integrity() {
        Ok(()) => println!("Receipt chain integrity:  VALID ({} entries)", rlog.len()),
        Err(e) => println!("Receipt chain integrity:  BROKEN ({e})"),
    }

    // Then the local-anchor inclusion + chain verification.
    let anchorlog = LocalAnchorLog::from_jsonl(&fs::read_to_string(anchor_file)?)?;
    let pubkey = match key_path {
        Some(p) => Some(load_public_key(p)?),
        None => None,
    };

    match verify_local_anchor(&leaves, &anchorlog, pubkey.as_ref()) {
        Ok(v) => {
            println!("Local anchor chain:       VALID");
            println!("  Records verified:       {}", v.records_verified);
            println!("  Receipts covered:       {}", v.receipts_covered);
            println!(
                "  Producer signatures:    {}",
                if pubkey.is_some() {
                    "ALL VALID"
                } else {
                    "not checked (pass --key)"
                }
            );
            println!();
            println!("Verified fully offline — no network, public key only.");
            println!("{LOCAL_ANCHOR_HONESTY}");
            Ok(())
        }
        Err(e) => {
            println!("Local anchor chain:       BROKEN");
            println!("  {e}");
            bail!("local anchor verification failed");
        }
    }
}
