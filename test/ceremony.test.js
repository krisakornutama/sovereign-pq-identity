// ทดสอบแผ่นสายพิธี Groth16 (v1.9 · Q-03) — โครงแฟ้มพิธี + สาย hash หัวถึงท้าย + โจมตีจับหมด (pure logic ล้วน)
// รายละเอียด snarkjs จริง (setup/contribute/merge/verify) ฝังวิ่งใน sandbox 3 เครื่องจำลอง — เทสนี้กวาดโครง+สายเอง
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import {
  newCeremonySheet, appendCeremonyRow, verifyCeremonyChain,
  responseShaMatches, CEREMONY_FORMAT, CEREMONY_VERSION, CHAIN_HEAD_NULL,
} from '../src/ceremony.js';
import { sha256Hex } from '../src/util.js';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-ceremony-'));
test.after(() => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* tmpdir ล้างเองได้ */ } });

const r1csFile = path.join(TMP, 'demo.r1cs');
const potFile = path.join(TMP, 'pot14_final.ptau');
fs.writeFileSync(r1csFile, randomBytes(2048));
fs.writeFileSync(potFile, randomBytes(4096));

const newSheet = () => newCeremonySheet({
  circuit: 'membership_d5',
  profile: 'membership_d5_v1',
  r1csFile,
  potFile,
  potPowers: 14,
  tool: 'snarkjs 0.7.6',
});

test('พิธี Q-03: แผ่นสายพิธีตามกฎเป๊ะ — หัวครบ field · จด sha256 แฟ้มจริง · สายยังว่าง = head จุดเริ่ม', () => {
  const s = newSheet();
  assert.equal(s.format, CEREMONY_FORMAT);
  assert.equal(s.version, CEREMONY_VERSION);
  assert.equal(s.circuit, 'membership_d5');
  assert.equal(s.profile, 'membership_d5_v1');
  assert.equal(s.curve, 'bn254');
  assert.equal(s.tool, 'snarkjs 0.7.6');
  assert.match(s.r1cs_sha256, /^[0-9a-f]{64}$/);
  assert.match(s.pot_sha256, /^[0-9a-f]{64}$/);
  assert.equal(s.r1cs_sha256, sha256Hex(fs.readFileSync(r1csFile)));
  assert.equal(s.pot_sha256, sha256Hex(fs.readFileSync(potFile)));
  assert.equal(s.pot_powers, 14);
  assert.match(s.entropy_policy, /หน่วยความจำ/);
  assert.deepEqual(s.chain, []);
  assert.equal(s.head, CHAIN_HEAD_NULL);
});

test('พิธี Q-03: เติมแถวผูกหน้าหลังเป็นสายยาว — h_prev ผูกหัวเดิม · head ย้ายไปปลายสาย · ตรวจผ่านครบทุกขั้น', () => {
  const s = newSheet();
  const r1 = appendCeremonyRow(s, { step: 'setup', contributor: 'base (จาก pot14)', file: 'w/zkey_0000.zkey', zkey_sha256: sha256Hex(randomBytes(32)), seconds: 10.1 });
  assert.equal(r1.row.h_prev, CHAIN_HEAD_NULL);
  assert.match(s.head, /^[0-9a-f]{64}$/);
  assert.notEqual(s.head, CHAIN_HEAD_NULL);
  const headAfter1 = s.head;
  const r2 = appendCeremonyRow(s, { step: 'contribute', contributor: 'อบาน', contribution_sha256: sha256Hex(randomBytes(32)), zkey_sha256: sha256Hex(randomBytes(32)), seconds: 2.3 });
  assert.equal(r2.row.h_prev, headAfter1);
  const headAfter2 = s.head;
  const r3 = appendCeremonyRow(s, { step: 'verify-seal', contributor: 'โค้งงานพิธี', zkey_sha256: r2.row.zkey_sha256, seconds: 30.8 });
  assert.equal(r3.row.h_prev, headAfter2);
  const v = verifyCeremonyChain(s);
  assert.equal(v.ok, true, JSON.stringify(v.problems));
  assert.equal(v.rows, 3);
  assert.equal(s.chain.length, 3);
});

test('พิธี Q-03: โจมตีจับได้ทุกชนิด — แก้ hash zkey แถวกลาง / ลบแถวท้าย (ตัดทอน) / สลับลำดับแถว', () => {
  // แก้ hash ในแถวกลาง (contribute) — head ปลายสายไม่ตรงที่ประกาศ
  const a = newSheet();
  appendCeremonyRow(a, { step: 'setup', contributor: 'base', zkey_sha256: sha256Hex(randomBytes(32)) });
  appendCeremonyRow(a, { step: 'contribute', contributor: 'อบาน', zkey_sha256: sha256Hex(randomBytes(32)) });
  const bad = JSON.parse(JSON.stringify(a));
  bad.chain[1].zkey_sha256 = 'ff' + bad.chain[1].zkey_sha256.slice(2);
  const va = verifyCeremonyChain(bad);
  assert.equal(va.ok, false);
  assert.ok(va.problems.some((p) => /ปลายสายไม่ตรง/.test(p)), JSON.stringify(va.problems));

  // ตัดแถวท้าย (ลบ verify-seal) — head ประกาศไม่ตรงที่เหลือ
  const b = newSheet();
  appendCeremonyRow(b, { step: 'setup', contributor: 'base', zkey_sha256: sha256Hex(randomBytes(32)) });
  appendCeremonyRow(b, { step: 'verify-seal', contributor: 'โค้งงานพิธี', zkey_sha256: sha256Hex(randomBytes(32)) });
  const truncated = JSON.parse(JSON.stringify(b));
  truncated.chain.pop();
  const vb = verifyCeremonyChain(truncated);
  assert.equal(vb.ok, false);
  assert.ok(vb.problems.some((p) => /ปลายสายไม่ตรง|ตัดทอน/.test(p)) || vb.problems.length > 0);

  // สลับลำดับแถว — h_prev พันธรุปของสายไม่เนียบ
  const c = newSheet();
  appendCeremonyRow(c, { step: 'contribute', contributor: 'อบาน', zkey_sha256: sha256Hex(randomBytes(32)) });
  appendCeremonyRow(c, { step: 'contribute', contributor: 'ชวิตา', zkey_sha256: sha256Hex(randomBytes(32)) });
  const mixed = JSON.parse(JSON.stringify(c));
  const flip = mixed.chain[0]; mixed.chain[0] = mixed.chain[1]; mixed.chain[1] = flip;
  const vc = verifyCeremonyChain(mixed);
  assert.equal(vc.ok, false);
  assert.ok(vc.problems.some((p) => /h_prev/.test(p) || /ปลายสาย/.test(p)), JSON.stringify(vc.problems));
});

test('พิธี Q-03: เข้มเขียนแถว — ชนิดแถวผิด / ไม่มีชื่อผู้ร่วม / hash รูปผิด = ปฏิเสธตั้งแต่เขียน', () => {
  const s = newSheet();
  assert.throws(() => appendCeremonyRow(s, { step: 'vote', contributor: 'ใครสักคน' }), /ชนิดแถว/);
  assert.throws(() => appendCeremonyRow(s, { step: 'setup', contributor: '   ' }), /ชื่อผู้ร่วม/);
  assert.throws(() => appendCeremonyRow(s, { step: 'setup', contributor: 'ใครสักคน', zkey_sha256: 'abc' }), /hex64/);
  assert.throws(() => appendCeremonyRow(s, { step: 'contribute', contributor: 'ใครสักคน', contribution_sha256: 123456 }), /hex64/);
  // แต่งแผ่นปลอมเอง (ไม่ผ่าน appendCeremonyRow) — verify เห็นทันที
  const fake = JSON.parse(JSON.stringify(newSheet()));
  fake.chain = [{ step: 'setup', contributor: '', zkey_sha256: 'xyz' }];
  const vf = verifyCeremonyChain(fake);
  assert.equal(vf.ok, false);
  assert.ok(vf.problems.some((p) => /ชื่อผู้ร่วม|hex64/.test(p)));
});

test('พิธี Q-03: ตรวจเทียบแฟ้มจริง (files:true) — zkey ที่แถวอ้างถือจริงตรง hash · เนื้อแฟ้มถูกแก้ = พัง', () => {
  const zkeyFile = path.join(TMP, 'demo_0000.zkey');
  fs.writeFileSync(zkeyFile, randomBytes(512));
  const s = newSheet();
  appendCeremonyRow(s, { step: 'setup', contributor: 'base (จาก pot14)', file: zkeyFile, zkey_sha256: sha256Hex(fs.readFileSync(zkeyFile)) });
  const v1 = verifyCeremonyChain(s, { files: true });
  assert.equal(v1.ok, true, JSON.stringify(v1.problems));
  // แก้ 1 ไบต์ในแฟ้ม zkey (โจมตีเครื่องโค้งงาน — แผ่นพิธีกลับนี้พาไปเห็นต่าง)
  const buf = fs.readFileSync(zkeyFile);
  buf[7] ^= 0x55;
  fs.writeFileSync(zkeyFile, buf);
  const v2 = verifyCeremonyChain(s, { files: true });
  assert.equal(v2.ok, false);
  assert.ok(v2.problems.some((p) => /ไม่เห็น hash|ถูกเปลี่ยน/.test(p)), JSON.stringify(v2.problems));
  // แฟ้มหายไปจากดิสก์ = ตรวจทดเป็นคำว่าพังชัด
  fs.unlinkSync(zkeyFile);
  const v3 = verifyCeremonyChain(s, { files: true });
  assert.equal(v3.ok, false);
  assert.ok(v3.problems.some((p) => /ไม่อยู่บนดิสก์/.test(p)));
});

test('พิธี Q-03: บัตรแลกแฟ้มระหว่างเครื่อง — responseShaMatches ตรงเป๊ะเมื่อผู้ร่วมส่งบัตร sha256 มาคู่แฟ้ม · แฟ้ม/บัตรไม่ตรงปฏิเสธ', () => {
  const rsp = path.join(TMP, 'response_1.bin');
  fs.writeFileSync(rsp, randomBytes(1200));
  const good = sha256Hex(fs.readFileSync(rsp));
  assert.deepEqual(responseShaMatches(rsp, good), { ok: true, sha: good, reason: null });
  const bad = '00' + good.slice(2);
  const r2 = responseShaMatches(rsp, bad);
  assert.equal(r2.ok, false);
  assert.match(r2.reason, /sha256 ไม่ตรง/);
  const r3 = responseShaMatches(path.join(TMP, 'ไม่มีจริง.bin'), good);
  assert.equal(r3.ok, false);
  assert.match(r3.reason, /ไม่พบแฟ้ม/);
});
