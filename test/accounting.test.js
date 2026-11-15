// ทดสอบตัวเชื่อม ledger → เอกสารบัญชี (v2.0 · Q-08) — โครงแฟ้มเสถียร + สาย hash หัวถึงท้าย + ตรวจลายเซ็นซองฝังครบ
// ทุกเคสใช้ใบเสร็จที่เซ็นจริง (สองลายเซ็น — ไม่แตะ SLH เพื่อคุมเวลาชุดเทส) · แฟ้ม export สร้างจาก logic ล้วนในหน่วยความจำ
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildAccountingExport, verifyAccountingExport, verifyAccountingSignatures,
  parseAccountingExport, accountingRowHash, totalThbOf,
  ACCOUNTING_FORMAT, ACCOUNTING_VERSION, ACCOUNTING_HEAD_NULL,
} from '../src/accounting.js';
import { canonical } from '../src/util.js';
import { createIdentity } from '../src/identity.js';
import { signReceipt } from '../src/receipt.js';

// ตัวตนจริง + ใบเสร็จที่เซ็นจริง (สองลายเซ็น)
const id = createIdentity({ label: 'บัญชีทดสอบ' });
const mkReceipt = (payload) => signReceipt(id, payload);

const receipts = [
  mkReceipt({ type: 'sale', customer: 'ร้านตัวอย่าง', items: [{ sku: 'PKY-5KG', qty: 1, price_thb: 120 }], total_thb: 120.0 }),
  mkReceipt({ type: 'sale', customer: 'ร้านตัวอย่าง', items: [{ sku: 'SEED-A', qty: 2, price_thb: 40 }], total_thb: 80.0 }),
  mkReceipt({ type: 'service', customer: 'ลูกค้าสถาบัน', note: 'ค่าติดตั้ง', total_thb: 1500.5 }),
  mkReceipt({ type: 'note', note: 'บันทึกไร้ยอด — ใบล่าสุดไม่มี total_thb' }), // ให้ total_thb รวมไม่ได้ = null
];

test('บัญชี Q-08: โครงแฟ้ม export ครบ — หัว/เอกสาร/ท้าย · ทุกบรรทัดผูกสาย · ฝังซองต้นฉบับเต็ม · ยอดรวมตรง', () => {
  const lines = buildAccountingExport(receipts.slice(0, 3), { generator: 'sovereign-pq-identity', source: 'data/receipts.jsonl' });
  assert.equal(lines.length, 5); // header + 3 เอกสาร + footer
  const [head, d1, d2, d3, foot] = lines;
  assert.equal(head.line, 'header');
  assert.equal(head.format, ACCOUNTING_FORMAT);
  assert.equal(head.version, ACCOUNTING_VERSION);
  assert.equal(head.generator, 'sovereign-pq-identity');
  assert.equal(head.source, 'data/receipts.jsonl');
  assert.equal(head.receipts_count, 3);
  assert.equal(head.h_prev, ACCOUNTING_HEAD_NULL);
  for (const l of lines) { assert.match(l.hash, /^[0-9a-f]{64}$/); assert.match(l.h_prev, /^[0-9a-f]{64}$/); }
  assert.equal(d1.line, 'doc'); assert.equal(d1.seq, 1); assert.equal(d2.seq, 2); assert.equal(d3.seq, 3);
  assert.equal(d1.receipt_id, receipts[0].id);
  assert.equal(d1.issued_at, receipts[0].issued_at);
  assert.equal(d1.receipt.id, receipts[0].id); // ซองต้นฉบับเต็มฝังอยู่จริง (ลายเซ็นครบ)
  assert.ok(d1.receipt.signatures.ed25519.sig_b64.length > 0);
  assert.ok(d1.receipt.signatures.ml_dsa44.sig_b64.length > 0);
  assert.match(d1.receipt_sha256, /^[0-9a-f]{64}$/);
  assert.equal(foot.line, 'footer');
  assert.equal(foot.receipts_count, 3);
  assert.equal(foot.total_thb, 1700.5); // 120 + 80 + 1500.5
  const v = verifyAccountingExport(lines);
  assert.equal(v.ok, true, JSON.stringify(v.problems));
  assert.equal(v.docs, 3);
  assert.equal(v.total_thb, 1700.5);
});

test('บัญชี Q-08: เสถียรจริง — export จากคลังชุดเดิมซ้ำ = ไบต์ตรงกันเป๊ะ (ไร้เวลาสร้างภายใน) · ใบไร้ total_thb → ยอดรวม null', () => {
  const a = buildAccountingExport(receipts, { generator: 'g', source: 's' });
  const b = buildAccountingExport(receipts, { generator: 'g', source: 's' });
  const textA = a.map((l) => JSON.stringify(l)).join('\n');
  const textB = b.map((l) => JSON.stringify(l)).join('\n');
  assert.equal(textA, textB); // เสถียร: คลังเดิม → แฟ้มเดิม (เทียบข้ามวัน/ข้ามเครื่องได้)
  const v = verifyAccountingExport(b);
  assert.equal(v.ok, true, JSON.stringify(v.problems));
  assert.equal(v.total_thb, null); // ใบล่าสุดไม่มี total_thb → ระบบไม่เดา ส่ง null
  assert.equal(totalThbOf(receipts.slice(0, 3)), 1700.5);
  // หัวใจสาย: hash ใบกลางคำนวณด้วยมือตรงรูป H(โดเมน ‖ 0x00 ‖ h_prev ‖ 0x00 ‖ canonical เนื้อบรรทัด)
  const mid = a[2];
  const { h_prev, hash, ...body } = mid;
  assert.equal(accountingRowHash(h_prev, body), hash);
});

test('บัญชี Q-08: โจมตีจับได้ทุกชนิด — แก้ payload ใบกลาง / ตัดใบหนึ่งออก / สลับลำดับใบ', () => {
  const base = buildAccountingExport(receipts.slice(0, 3), { generator: 'g', source: 's' });

  // 1) แก้ payload ใบกลาง (โจมตียอดบัญชี) — hash บรรทัดพัง + ยอดรวม footer ไม่ตรงอีกชั้น
  const tampered = JSON.parse(JSON.stringify(base));
  tampered[2].receipt.payload.total_thb = 99999.0;
  const v1 = verifyAccountingExport(tampered);
  assert.equal(v1.ok, false);
  assert.ok(v1.problems.some((p) => /hash ไม่ตรงเนื้อหา/.test(p)), JSON.stringify(v1.problems));
  assert.ok(v1.problems.some((p) => /ยอดรวมไม่ตรง/.test(p)), JSON.stringify(v1.problems));

  // 2) ตัดใบหนึ่งออก (ปิดยอดที่ระบุ) — จำนวนประกาศไม่ตรง + สายไม่ต่อ
  const truncated = JSON.parse(JSON.stringify(base));
  truncated.splice(2, 1);
  const v2 = verifyAccountingExport(truncated);
  assert.equal(v2.ok, false);
  assert.ok(v2.problems.some((p) => /header ประกาศ 3/.test(p) || /footer ประกาศ 3/.test(p)), JSON.stringify(v2.problems));
  assert.ok(v2.problems.some((p) => /h_prev ไม่ตรงหัวก่อนหน้า|seq ไม่เรียง/.test(p)), JSON.stringify(v2.problems));

  // 3) สลับลำดับสองใบ — seq กระโดด + h_prev พัง
  const swapped = JSON.parse(JSON.stringify(base));
  const tmp = swapped[1]; swapped[1] = swapped[2]; swapped[2] = tmp;
  const v3 = verifyAccountingExport(swapped);
  assert.equal(v3.ok, false);
  assert.ok(v3.problems.some((p) => /h_prev ไม่ตรงหัวก่อนหน้า/.test(p)), JSON.stringify(v3.problems));
});

test('บัญชี Q-08: ยอดรวมบัญชีตามกฎ — ทุกใบมี total_thb เลข = รวมได้ · ใบใดไม่ใช่เลข = null (ไม่เดา) · ทศนิยมตรง', () => {
  assert.equal(totalThbOf([mkReceipt({ total_thb: 0.1 }), mkReceipt({ total_thb: 0.2 })]), 0.3);
  assert.equal(totalThbOf([{ id: 'x', issued_at: 't', payload: { total_thb: '120' } }]), null); // สตริง = ไม่รวม
  assert.equal(totalThbOf([{ id: 'x', issued_at: 't', payload: { amount: 50 } }]), null); // ไร้ total_thb
  assert.equal(totalThbOf([]), 0);
  const lines = buildAccountingExport([{ id: 'x', issued_at: 't', payload: { total_thb: 50 } }], { generator: 'g' });
  assert.equal(lines[lines.length - 1].total_thb, 50);
});

test('บัญชี Q-08: ข้ออ้างพิสูจน์ได้ด้วยตัวเอง — ตรวจลายเซ็นซองฝังใหม่ทุกใบ (ไร้กุญแจ) · ซองถูกแก้ = จับได้', () => {
  const lines = buildAccountingExport(receipts.slice(0, 3), { generator: 'g', source: 's' });
  const sigs = verifyAccountingSignatures(lines);
  assert.equal(sigs.checked.length, 3);
  assert.ok(sigs.checked.every((c) => c.valid === true && c.ed25519 === true && c.ml_dsa44 === true), JSON.stringify(sigs.checked));
  assert.equal(sigs.invalid.length, 0);
  // แก้ payload ในซองที่ฝัง (แม้แต่งยอดเพียงตำแหน่งเดียว) → ลายเซ็นต้องพัง
  const bad = JSON.parse(JSON.stringify(lines));
  bad[2].receipt.payload.total_thb = 1.0;
  const sigs2 = verifyAccountingSignatures(bad);
  assert.equal(sigs2.checked[1].valid, false);
  assert.equal(sigs2.invalid.length, 1);
  assert.ok(sigs2.invalid[0].problems.length > 0);
});

test('บัญชี Q-08: คลังว่าง export ได้จริง — สาย = หัว+ท้ายล้วน · head ตรง · ใบซ้ำ/ซองไม่ครบ = ปฏิเสธตั้งแต่สร้าง', () => {
  const lines = buildAccountingExport([], { generator: 'g', source: 'data/receipts.jsonl' });
  assert.equal(lines.length, 2);
  assert.equal(lines[0].receipts_count, 0);
  assert.equal(lines[1].receipts_count, 0);
  assert.equal(lines[1].total_thb, 0);
  const v = verifyAccountingExport(lines);
  assert.equal(v.ok, true, JSON.stringify(v.problems));
  assert.equal(v.docs, 0);
  assert.equal(v.head, lines[1].hash);
  // ใบซ้ำ id — คลัง idempotent อยู่แล้ว export ต้องไม่ผลิตเอกสารซ้ำ
  const r = mkReceipt({ total_thb: 10 });
  assert.throws(() => buildAccountingExport([r, JSON.parse(JSON.stringify(r))], { generator: 'g' }), /ใบเสร็จซ้ำ id/);
  // ซองไม่ครบ (payload หาย)
  assert.throws(() => buildAccountingExport([{ id: 'x', issued_at: 't' }], { generator: 'g' }), /ซองใบเสร็จไม่ครบ/);
  // แฟ้มว่าง/แฟ้มไม่ใช่ JSON — แยกแฟ้มไม่ได้
  assert.throws(() => parseAccountingExport(''), /แฟ้มว่าง/);
  assert.throws(() => parseAccountingExport('not json'), /ไม่ใช่ JSON/);
});
