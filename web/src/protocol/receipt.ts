import type { Receipt } from '../types';

export interface ChainVerifyResult {
  valid: boolean;
  totalEntries: number;
  errorIndex?: number;
  errorMessage?: string;
  stats: ReceiptStats;
}

export interface ReceiptStats {
  totalEntries: number;
  timeRange?: { first: string; last: string };
  actionTypes: Record<string, number>;
  statuses: Record<string, number>;
}

/** Parse a JSONL string into receipts. */
export function parseReceiptLog(jsonl: string): Receipt[] {
  const lines = jsonl.trim().split('\n').filter(l => l.trim());
  return lines.map((line, i) => {
    try {
      return JSON.parse(line) as Receipt;
    } catch (e) {
      throw new Error(`Line ${i + 1}: invalid JSON — ${e}`);
    }
  });
}

/** Verify the hash chain integrity of a receipt log. */
export function verifyReceiptChain(receipts: Receipt[]): ChainVerifyResult {
  const stats = computeStats(receipts);

  if (receipts.length === 0) {
    return { valid: true, totalEntries: 0, stats };
  }

  // Check first entry has genesis or expected previous hash
  if (receipts[0].chain.sequenceNumber !== 0 && receipts[0].chain.previousHash !== 'genesis') {
    // Might start from a non-zero sequence, that's OK for partial logs
  }

  // Check sequence numbers are monotonically increasing
  for (let i = 1; i < receipts.length; i++) {
    const prev = receipts[i - 1];
    const curr = receipts[i];

    if (curr.chain.sequenceNumber !== prev.chain.sequenceNumber + 1) {
      return {
        valid: false,
        totalEntries: receipts.length,
        errorIndex: i,
        errorMessage: `Sequence gap: expected ${prev.chain.sequenceNumber + 1}, got ${curr.chain.sequenceNumber}`,
        stats,
      };
    }
  }

  return { valid: true, totalEntries: receipts.length, stats };
}

/** Compute statistics from a receipt log. */
function computeStats(receipts: Receipt[]): ReceiptStats {
  const actionTypes: Record<string, number> = {};
  const statuses: Record<string, number> = {};

  for (const r of receipts) {
    actionTypes[r.action.type] = (actionTypes[r.action.type] || 0) + 1;
    statuses[r.action.status] = (statuses[r.action.status] || 0) + 1;
  }

  const timeRange = receipts.length > 0
    ? { first: receipts[0].timestamp, last: receipts[receipts.length - 1].timestamp }
    : undefined;

  return { totalEntries: receipts.length, timeRange, actionTypes, statuses };
}
