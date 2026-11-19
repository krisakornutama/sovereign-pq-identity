// 🧾 ตัวเชื่อม ledger → เอกสารบัญชี (v2.0 · Q-08)
// แฟ้ม export = JSONL 3 ชนิดบรรทัด (รูปเดียวกับซองสตรีม v1.8): หัว (header) / เอกสาร (doc หนึ่งบรรทัดต่อใบเสร็จ) / ท้าย (footer)
//
// เสถียร: แฟ้มไร้เวลาสร้างภายในเนื้อหาล้วน — คลังใบเสร็จชุดเดิม export ซ้ำกี่ครั้งก็ได้**ไบต์ตรงกันเป๊ะ**
//   (เวลาอ้างอิงมาจาก issued_at ของใบเสร็จเอง — แฟ้มบัญชีจึงเทียบกันข้ามเครื่อง/ข้ามวัน export ได้)
//
// สาย hash ผูกหัวถึงท้ายทุกบรรทัด:
//   h_i = SHA-256('sovereign-accounting-chain/v1' ‖ 0x00 ‖ h_(i-1) ‖ 0x00 ‖ canonical(บรรทัดที่ตัด h_prev/hash ออก))
//   บรรทัดแรก (header) ผูกต่อจากหัวว่าง (0x00×64) — แก้ใบใด/ตัดใบ/สลับลำดับ/แก้ยอดรวม = สายพังทันที
//
// ข้ออ้างที่พิสูจน์ได้: ทุก doc ฝัง**ซองใบเสร็จต้นฉบับเต็ม** (ลายเซ็นครบทุกชั้นของโปรไฟล์ · pk ฝังในใบ) —
//   ปลายทาง (ส่วนบัญชี/ภาษีของ sovereign-origin) ตรวจลายเซ็นใหม่ได้เองโดยไร้กุญแจ · ตัวตนยังนิรนามตามใบเดิม
// โมดูลนี้ pure logic ล้วน (แฟ้มอ่าน/เขียนเกิดที่ cli.js) — canonical JSON เรียงคีย์จาก util.js
import { canonical, sha256Hex } from './util.js';
import { verifyReceipt } from './receipt.js';

export const ACCOUNTING_FORMAT = 'sovereign.accounting-ledger.v1';
export const ACCOUNTING_VERSION = 1;
export const ACCOUNTING_HEAD_NULL = '0'.repeat(64); // จุดเริ่มสาย (ยังไม่มีบรรทัด)
const ACCOUNTING_DOMAIN = 'sovereign-accounting-chain/v1';
const HEX64 = /^[0-9a-f]{64}$/;

// ยอดรวมบัญชี: รวมได้เฉพาะเมื่อ**ทุกใบ**มี payload.total_thb เป็นตัวเลข — มิฉะนั้นคืน null (ปลายทางรวมเอง)
export function totalThbOf(envelopes) {
  if (!Array.isArray(envelopes) || envelopes.length === 0) return 0;
  let sum = 0;
  for (const e of envelopes) {
    const t = e && e.payload ? e.payload.total_thb : undefined;
    if (typeof t !== 'number' || !Number.isFinite(t)) return null;
    sum += t;
  }
  return Number(sum.toFixed(2));
}

// hash หนึ่งบรรทัดของสาย: H(โดเมน ‖ 0x00 ‖ h_prev ‖ 0x00 ‖ canonical(เนื้อบรรทัด))
export function accountingRowHash(head, body) {
  return sha256Hex(Buffer.concat([
    Buffer.from(ACCOUNTING_DOMAIN, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(head, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonical(body), 'utf8'),
  ]));
}

// ผูกบรรทัดเข้าสาย — เติม h_prev + hash ให้บรรทัด (hash จากเนื้อบรรทัดไร้ h_prev/hash — มาตรฐานเดียวทั้งสาย)
function chainLine(head, body) {
  const h = accountingRowHash(head, body);
  return { ...body, h_prev: head, hash: h };
}

// สร้างแฟ้ม export ทั้งแฟ้ม — envelopes เรียงตามลำดับในคลังต้นทาง (ใบซ้ำ id = ปฏิเสธ คลังควร idempotent อยู่แล้ว)
export function buildAccountingExport(envelopes, { generator, source } = {}) {
  if (!Array.isArray(envelopes)) throw new Error('คลังใบเสร็จต้องเป็น array');
  const seen = new Set();
  for (const e of envelopes) {
    if (!e || typeof e !== 'object' || !e.id || !e.issued_at || !e.payload) {
      throw new Error('ซองใบเสร็จไม่ครบ (ต้องมี id/issued_at/payload) — ปฏิเสธ export แฟ้มต้นทางไม่สมบูรณ์');
    }
    if (seen.has(e.id)) throw new Error('คลังมีใบเสร็จซ้ำ id: ' + e.id + ' — ปฏิเสธ export (ตรวจต้นทางก่อน)');
    seen.add(e.id);
  }
  const lines = [];
  let head = ACCOUNTING_HEAD_NULL;
  lines.push(chainLine(head, {
    line: 'header',
    format: ACCOUNTING_FORMAT,
    version: ACCOUNTING_VERSION,
    generator: generator || null,
    source: source || null,
    receipts_count: envelopes.length,
  }));
  head = lines[0].hash;
  envelopes.forEach((e, i) => {
    lines.push(chainLine(head, {
      line: 'doc',
      seq: i + 1,
      receipt_id: e.id,
      issued_at: e.issued_at,
      receipt: e, // ซองต้นฉบับเต็ม (ลายเซ็นครบ) — ปลายทางตรวจลายเซ็นใหม่ได้เอง
      receipt_sha256: sha256Hex(canonical(e)), // ผูกกลับซองต้นฉบับแบบ bytes เดียว
    }));
    head = lines[lines.length - 1].hash;
  });
  lines.push(chainLine(head, {
    line: 'footer',
    receipts_count: envelopes.length,
    total_thb: totalThbOf(envelopes),
  }));
  return lines;
}

// แยกแฟ้ม export จากข้อความ JSONL — คืน array ของ object (บรรทัดว่างข้าม)
export function parseAccountingExport(text) {
  const lines = [];
  for (const raw of String(text).split('\n')) {
    if (raw.trim().length === 0) continue;
    try { lines.push(JSON.parse(raw)); } catch { throw new Error('บรรทัดไม่ใช่ JSON: ' + raw.slice(0, 40) + '…'); }
  }
  if (lines.length === 0) throw new Error('แฟ้มว่าง — ไม่ใช่แฟ้มเอกสารบัญชีของระบบนี้');
  return lines;
}

// ตรวจแฟ้ม export ทั้งแฟ้ม (สาย hash หัวถึงท้าย + โครง + จำนวน/ยอด ตรงกันทุกชั้น) — ไร้กุญแจ
export function verifyAccountingExport(lines) {
  const problems = [];
  if (!Array.isArray(lines) || lines.length === 0) return { ok: false, problems: ['ไม่มีบรรทัดให้ตรวจ'], head: null, docs: 0, total_thb: null };
  const first = lines[0], last = lines[lines.length - 1];
  if (!first || first.line !== 'header') problems.push('บรรทัดแรกไม่ใช่ header');
  if (!last || last.line !== 'footer') problems.push('บรรทัดท้ายไม่ใช่ footer');
  if (first && first.h_prev !== ACCOUNTING_HEAD_NULL) problems.push('หัวสายแรกไม่ผูกจุดเริ่ม (h_prev ผิด)');

  const docs = [];
  let head = ACCOUNTING_HEAD_NULL;
  lines.forEach((l, i) => {
    if (!l || typeof l !== 'object') { problems.push('บรรทัดที่ ' + (i + 1) + ' ไม่ใช่ object'); return; }
    const { h_prev, hash, ...body } = l;
    if (l.h_prev !== head) { problems.push('บรรทัดที่ ' + (i + 1) + ' h_prev ไม่ตรงหัวก่อนหน้า (คาด ' + head.slice(0, 12) + '… แต่ได้ ' + String(l.h_prev).slice(0, 12) + '…) — ลำดับถูกสลับ/ตัดทอน'); }
    if (typeof hash !== 'string' || !HEX64.test(hash)) { problems.push('บรรทัดที่ ' + (i + 1) + ' hash หาย/รูปผิด'); return; }
    const expect = accountingRowHash(l.h_prev, body);
    if (expect !== hash) { problems.push('บรรทัดที่ ' + (i + 1) + ' hash ไม่ตรงเนื้อหา (บรรทัดถูกแก้)'); }
    head = hash;
    if (l.line === 'doc') docs.push(l);
  });

  // โครงเอกสาร: seq เรียง 1..N · ซองครบและตรงกับสำเนาบรรทัด
  docs.forEach((d, i) => {
    if (d.seq !== i + 1) problems.push('ใบที่ ' + (i + 1) + ' seq ไม่เรียง (' + String(d.seq) + ')');
    if (!d.receipt_id || !d.issued_at || !d.receipt) { problems.push('ใบที่ ' + (i + 1) + ' ข้อมูลไม่ครบ (receipt_id/issued_at/receipt)'); return; }
    if (d.receipt_id !== d.receipt.id) problems.push('ใบที่ ' + (i + 1) + ' receipt_id ไม่ตรงซองที่ฝัง (' + d.receipt_id + ' เทียบ ' + d.receipt.id + ')');
    if (d.issued_at !== d.receipt.issued_at) problems.push('ใบที่ ' + (i + 1) + ' issued_at ไม่ตรงซองที่ฝัง');
    if (d.receipt_sha256 !== undefined && !HEX64.test(String(d.receipt_sha256))) problems.push('ใบที่ ' + (i + 1) + ' receipt_sha256 รูปผิด');
  });

  if (first && first.format !== ACCOUNTING_FORMAT) problems.push('format ไม่ใช่แฟ้มเอกสารบัญชีของระบบนี้');
  if (first && first.version !== ACCOUNTING_VERSION) problems.push('version ไม่ตรงรูปแบบแฟ้ม (' + first.version + ' เทียบ ' + ACCOUNTING_VERSION + ')');
  const n = docs.length;
  if (first && first.receipts_count !== n) problems.push('header ประกาศ ' + first.receipts_count + ' ใบ แต่มีเอกสารจริง ' + n + ' ใบ');
  if (last && last.line === 'footer') {
    if (last.receipts_count !== n) problems.push('footer ประกาศ ' + last.receipts_count + ' ใบ แต่มีเอกสารจริง ' + n + ' ใบ');
    if (last.total_thb !== totalThbOf(docs.map((d) => d.receipt))) problems.push('footer ยอดรวมไม่ตรงผลรวมของเอกสารในแฟ้ม');
  }
  return { ok: problems.length === 0, problems, head: last && last.hash ? last.hash : head, docs: n, total_thb: last && last.line === 'footer' ? last.total_thb : null };
}

// ตรวจลายเซ็นซองที่ฝังในแฟ้ม export ใหม่ทั้งหมด — ไร้กุญแจ (pk ฝังในใบ) · สมบูรณ์ต้องผ่านทุกชั้นของโปรไฟล์
export function verifyAccountingSignatures(lines) {
  const checked = [];
  const invalid = [];
  for (const l of lines || []) {
    if (!l || l.line !== 'doc' || !l.receipt) continue;
    const v = verifyReceipt(l.receipt);
    // ชั้น SLH แสดงตามรุ่นที่ใบประกาศเอง (128s/128f) — ใบสองชั้นไม่มีฟิลด์นี้
    const slhField = v.slh_layer || null;
    checked.push({ seq: l.seq, receipt_id: l.receipt_id, valid: v.valid, ed25519: v.ed25519, ml_dsa44: v.ml_dsa44, ...(slhField ? { slh_layer: slhField, [slhField]: v[slhField] } : {}) });
    if (!v.valid) invalid.push({ seq: l.seq, receipt_id: l.receipt_id, problems: v.problems });
  }
  return { checked, invalid };
}
