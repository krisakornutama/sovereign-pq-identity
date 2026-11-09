// ชุดทดสอบระบบตัวตน + ใบเสร็จกันควอนตัม — ทุกเคสใช้ข้อมูลสาธิตล้วน ตามกฎความปลอดภัยของโครงการ
import test from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity } from '../src/identity.js';
import { signReceipt, verifyReceipt, coreBytes } from '../src/receipt.js';
import { canonical } from '../src/util.js';

test('canonical เรียงคีย์ได้เสถียร (bytes เดียวทุกเครื่อง)', () => {
  const a = { b: 1, a: { d: 2, c: 3 } };
  const b = { a: { c: 3, d: 2 }, b: 1 };
  assert.equal(canonical(a), canonical(b));
});

test('ยืนยันตัวตน Ed25519 + ML-DSA-44 ทั้งคู่', () => {
  const id1 = createIdentity({ label: 't1' });
  const id2 = createIdentity({ label: 't2' });
  assert.equal(id1.id.startsWith('sps_'), true);
  assert.notEqual(id1.id, id2.id); // ตัวตนในแต่ละคู่กุญแจต้องต่างกัน
  assert.equal(Buffer.from(id1.keys.ml_dsa44.pk_b64, 'base64').length, 1312);
  assert.equal(Buffer.from(id1.keys.ml_dsa44.sk_b64, 'base64').length, 2560);
});

test('เซ็นใบเสร็จ → ตรวจผ่านทั้งสองลายเซ็น', () => {
  const id = createIdentity({ label: 't-sign' });
  const env = signReceipt(id, { demo: true, total_thb: 120.5 });
  const v = verifyReceipt(env);
  assert.equal(v.valid, true);
  assert.equal(v.ed25519, true);
  assert.equal(v.ml_dsa44, true);
});

test('ปลอมแปลง payload 1 บิต → ทั้งสองลายเซ็นต้องพัง', () => {
  const id = createIdentity({ label: 't-tamper' });
  const env = signReceipt(id, { demo: true, total_thb: 1 });
  const fake = JSON.parse(JSON.stringify(env));
  fake.payload.total_thb = 99;
  const v = verifyReceipt(fake);
  assert.equal(v.valid, false);
  assert.equal(v.ed25519, false);
  assert.equal(v.ml_dsa44, false);
});

test('ตัดลายเซ็น ML-DSA ออก → ระบบไม่ตอบรับ', () => {
  const id = createIdentity({ label: 't-drop' });
  const env = signReceipt(id, { demo: true });
  delete env.signatures.ml_dsa44;
  const v = verifyReceipt(env);
  assert.equal(v.valid, false);
  assert.equal(v.ed25519, true);
  assert.equal(v.ml_dsa44, false);
  assert.equal(v.problems.some((p) => p.includes('ML-DSA')), true);
});

test('เอาลายเซ็นมาจากใบอื่นมาแปะ → ไม่ผ่าน', () => {
  const a = createIdentity({ label: 't-swap' });
  const b = createIdentity({ label: 't-swap' });
  const ea = signReceipt(a, { n: 1 });
  const eb = signReceipt(b, { n: 1 });
  const mixed = JSON.parse(JSON.stringify(ea));
  mixed.signatures.ml_dsa44 = eb.signatures.ml_dsa44;
  assert.equal(verifyReceipt(mixed).valid, false);
});

test('id/issued_at อยู่ใน core bytes ที่เซ็น และลายเซ็นไม่หลุดเข้าฟีเจอร์เอง', () => {
  const id = createIdentity({ label: 't-core' });
  const env = signReceipt(id, { demo: true });
  const bytes = coreBytes(env);
  const text = Buffer.from(bytes).toString('utf8');
  assert.equal(text.includes('"id":"'), true);
  assert.equal(text.includes('signatures'), false);
  assert.equal(text.includes('alg_profile'), true);
});

test('context ต้องตรงเดิมเป๊ะ (โดเมนแยก) → ML-DSA verify ไม่ผ่าน', () => {
  // โดม別: เซ็นในเน้ schema เดิมแต่ verify เอา context สายที่ไม่ตรง → ต้อง fail
  const id = createIdentity({ label: 't-ctx' });
  const env = signReceipt(id, { demo: true });
  const v = verifyReceipt(env);
  assert.equal(v.valid, true);
  // หากบุกรุกแก้ "alg_profile" เพื่อเปลี่ยน bytes — ตรวจต้องพังทันที
  const bad = JSON.parse(JSON.stringify(env));
  bad.alg_profile = 'sovereign.ed25519+ml_dsa44.v2';
  assert.equal(verifyReceipt(bad).valid, false);
});
