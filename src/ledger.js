// Ledger — คลังใบเสร็จในเครื่อง (JSONL) + กันซ้ำตาม id (idempotent แบบเดียวกับ sovereign-offgrid)
import fs from 'node:fs';
import path from 'node:path';

export function appendReceipt(ledgerPath, envelope) {
  fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
  const seen = listReceipts(ledgerPath);
  if (seen.some((r) => r.id === envelope.id)) {
    return { ok: false, duplicate: true, id: envelope.id };
  }
  fs.appendFileSync(ledgerPath, JSON.stringify(envelope) + '\n', 'utf8');
  return { ok: true, duplicate: false, id: envelope.id };
}

export function listReceipts(ledgerPath) {
  if (!fs.existsSync(ledgerPath)) return [];
  return fs.readFileSync(ledgerPath, 'utf8')
    .split('\n')
    .filter((l) => l.trim().length > 0)
    .map((l) => JSON.parse(l));
}
