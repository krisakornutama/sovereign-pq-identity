// ชุดทดสอบระบบตัวตน + ใบเสร็จกันควอนตัม — ทุกเคสใช้ข้อมูลสาธิตล้วน ตามกฎความปลอดภัยของโครงการ
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createIdentity, ALG_PROFILE, ALG_PROFILE_SLH } from '../src/identity.js';
import { signReceipt, verifyReceipt, coreBytes } from '../src/receipt.js';
import { rotateIdentity, identityAgeDays, appendAnchor, loadAnchors } from '../src/rotate.js';
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

// ==== v1.4: ลายเซ็นชั้นที่สาม SLH-DSA-128s (FIPS 205) + ระบบหมุนกุญแจ ====

test('v1.4: keygen --slh → กุญแจสามชั้นครบ (SLH pk 32 B sk 64 B) และ id ต่างจากโปรไฟล์สองชั้น', () => {
  const dual = createIdentity({ label: 't-slh' });
  const triple = createIdentity({ label: 't-slh', withSlh: true });
  assert.equal(triple.alg_profile, ALG_PROFILE_SLH);
  assert.equal(triple.keys.slh_dsa128s === undefined, false);
  assert.equal(Buffer.from(triple.keys.slh_dsa128s.pk_b64, 'base64').length, 32);
  assert.equal(Buffer.from(triple.keys.slh_dsa128s.sk_b64, 'base64').length, 64);
  assert.equal(dual.alg_profile, ALG_PROFILE); // โปรไฟล์เดิมไม่ถูกแตะ
  assert.notEqual(triple.id, dual.id);          // กุญแจสาธารณะชุดต่างกัน = หมายเลขตัวตนต่างกันแน่นอน
});

test('v1.4: ใบเสร็จสามชั้น → ตรวจผ่านครบ (Ed25519 + ML-DSA-44 + SLH-DSA)', () => {
  const triple = createIdentity({ label: 't-triple', withSlh: true });
  const env = signReceipt(triple, { demo: true, total_thb: 210 });
  const v = verifyReceipt(env);
  assert.equal(v.valid, true);
  assert.equal(v.ed25519, true);
  assert.equal(v.ml_dsa44, true);
  assert.equal(v.slh_dsa128s, true);
});

test('v1.4: ลบลายเซ็น SLH-DSA ออกจากใบสามชั้น → ระบบไม่ตอบรับ (ใบไม่สมบูรณ์)', () => {
  const triple = createIdentity({ label: 't-drop-slh', withSlh: true });
  const env = signReceipt(triple, { demo: true });
  delete env.signatures.slh_dsa128s;
  const v = verifyReceipt(env);
  assert.equal(v.valid, false);
  assert.equal(v.ed25519, true);
  assert.equal(v.ml_dsa44, true);
  assert.equal(v.slh_dsa128s, false);
  assert.equal(v.problems.some((p) => p.includes('SLH-DSA')), true);
});

test('v1.4: ปลอม payload ในใบสามชั้น → ทั้งสามลายเซ็นพังพร้อมกัน', () => {
  const triple = createIdentity({ label: 't-tamper3', withSlh: true });
  const env = signReceipt(triple, { total: 1 });
  const fake = JSON.parse(JSON.stringify(env));
  fake.payload.total = 999;
  const v = verifyReceipt(fake);
  assert.equal(v.valid, false);
  assert.equal(v.ed25519, false);
  assert.equal(v.ml_dsa44, false);
  assert.equal(v.slh_dsa128s, false);
});

test('v1.4: ลายเซ็น SLH จากตัวตนอื่นมาแปะ → ไม่ผ่าน', () => {
  const a = createIdentity({ label: 't-swap3', withSlh: true });
  const b = createIdentity({ label: 't-swap3', withSlh: true });
  const ea = signReceipt(a, { n: 1 });
  const eb = signReceipt(b, { n: 1 });
  const mixed = JSON.parse(JSON.stringify(ea));
  mixed.signatures.slh_dsa128s = eb.signatures.slh_dsa128s;
  const v = verifyReceipt(mixed);
  assert.equal(v.valid, false);
  assert.equal(v.slh_dsa128s, false);
});

test('v1.4: หมุนกุญแจ → ตัวตนใหม่ · ใบเก่ายังตรวจผ่าน · anchors มีแต่กุญแจสาธารณะ', () => {
  const tmpAnchorFile = 'build/test-anchors.jsonl';
  fs.rmSync(tmpAnchorFile, { force: true });
  const old = createIdentity({ label: 't-rot' });
  const envOld = signReceipt(old, { demo: true });
  const { next, anchor } = rotateIdentity(old, { withSlh: true });
  assert.notEqual(next.id, old.id);
  assert.equal(next.alg_profile, ALG_PROFILE_SLH);  // --slh อัปเกรดสามชั้นได้พร้อมกัน
  assert.equal(next.label, old.label);              // ชื่อเรียกในเครื่องคงเดิม
  // ใบเสร็จที่ออกสมัยกุญแจเก่า: ยังตรวจผ่านสมบูรณ์ (pk ฝังในใบ) — นี่คือหลักที่หมุนได้เลย
  assert.equal(verifyReceipt(envOld).valid, true);
  // anchors: เก็บกุญแจสาธารณะเก่าเป๊ะ และแฟ้มไม่มีกุญแจลับเลย
  assert.equal(anchor.id_old, old.id);
  assert.equal(anchor.id_new, next.id);
  assert.equal(anchor.pks_old.ed25519_pk_b64, old.keys.ed25519.pk_b64);
  const text = JSON.stringify(anchor);
  assert.equal(text.includes('sk_b64'), false); // ลาดตระเวน: ห้ามกุญแจลับหลุดลงสายสกุล
  appendAnchor(tmpAnchorFile, anchor);
  const loaded = loadAnchors(tmpAnchorFile);
  assert.equal(loaded.length, 1);
  assert.equal(loaded[0].id_old, old.id);
  fs.rmSync(tmpAnchorFile, { force: true });
});

test('v1.4: อายุตัวตนคำนวณตรง (วันเต็ม) — เกต --if-due ข้ามวันครบกำหนดถึงหมุน', () => {
  const now = new Date('2026-11-09T12:00:00Z');
  const fresh = { id: 'sps_x', created_at: '2026-11-08T12:00:00Z' };   // อายุ 1 วัน
  const aged = { id: 'sps_y', created_at: '2026-08-09T12:00:00Z' };    // อายุ 92 วัน
  const broken = { id: 'sps_z', created_at: undefined };
  assert.equal(identityAgeDays(fresh, now), 1);
  assert.equal(identityAgeDays(aged, now), 92);
  assert.equal(identityAgeDays(aged, now) >= 90, true);  // เกตจะผ่านเงื่อนไข --if-due 90
  assert.throws(() => identityAgeDays(broken, now));     // ไม่มีวันเกิด = ห้ามเดาอายุ
});
