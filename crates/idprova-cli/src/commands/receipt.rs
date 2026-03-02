use anyhow::Result;
use idprova_core::receipt::{Receipt, ReceiptLog};
use std::fs;

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
    let mut action_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for entry in &entries {
        *action_counts.entry(&entry.action.action_type).or_insert(0) += 1;
    }
    println!("  Action types:");
    for (action, count) in &action_counts {
        println!("    {action}: {count}");
    }

    Ok(())
}
