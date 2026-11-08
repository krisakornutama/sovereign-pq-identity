// เครื่องมือพื้นฐานของไลบรารี: canonical JSON / hash / ID / ตัวตรวจรูปแบบ
import { createHash } from 'node:crypto';

export const enc = new TextEncoder();

// Canonical JSON — เรียงคีย์แล้วไม่มีช่องว่าง → ทุกเครื่องกำเนิด bytes เดียวกัน
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
}

export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

export function newReceiptId() {
  return 'pqri_' + createHash('sha256').update(enc.encode(String(Date.now()) + String(process.hrtime.bigint()))).digest('hex').slice(0, 16);
}

// ตรวจชนิดข้อมูลเบื้องต้น
export function isIso(v) { return typeof v === 'string' && !Number.isNaN(Date.parse(v)); }
export function b64ok(v) { return typeof v === 'string' && v.length > 0 && Buffer.from(v, 'base64').length > 0; }
