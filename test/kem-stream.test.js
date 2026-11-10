// ทดสอบซองสตรีมแบ่งส่วน (v1.8 · Q-11) — รูปแบบ JSONL: หัว/ชิ้น/ท้าย · สาย hash ครบหัวถึงท้าย · หน่วยความจำคงที่ตามขนาดชิ้น
// ทั้งหมดกลั่นจากแฟ้มจริงใน tmpdir — จบเทสลบทิ้ง ไม่ทิ้งกากใน repo
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { kemKeygen, kemPublicFile, sha256hex, sealBytes, openEnvelope } from '../src/kem.js';
import { sealStreamFile, openStreamFile, readStreamHeader, verifyStreamChain, STREAM_FOOTER_FORMAT, STREAM_FORMAT } from '../src/kem-stream.js';

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'sovereign-kem-stream-'));
test.after(() => { try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* tmpdir ล้างเองได้ */ } });

const owner = kemKeygen();
const ownerPub = kemPublicFile({ label: 'โหนดเปิดสตรีม', pk_b64: owner.pk_b64 });

const linesOf = (f) => fs.readFileSync(f, 'utf8').split('\n').filter((l) => l.length > 0);
const saveLines = (f, lines) => fs.writeFileSync(f, lines.join('\n') + '\n');
const flipB64Char = (s) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1);

test('kem-stream v1.8 (Q-11): ผนึกสตรีม → เปิด ได้ไบต์ตรงเดิมเป๊ะ (แฟ้ม 3 MB · 48 ชิ้น · หน่วยความจำคงที่ตามขนาดชิ้น)', () => {
  const src = path.join(TMP, 'big.dat');
  const content = randomBytes(3 * 1024 * 1024);
  fs.writeFileSync(src, content);
  const sealPath = src + '.seal.json';
  const s = sealStreamFile(src, sealPath, ownerPub, { chunkSize: 65536 });
  assert.equal(s.total_chunks, 48);
  assert.equal(s.total_plaintext, content.length);
  assert.equal(linesOf(sealPath).length, 50); // หัว + 48 ชิ้น + ท้าย
  const opened = openStreamFile(sealPath, path.join(TMP, 'big.open'), owner.sk_b64);
  assert.equal(opened.chunks, 48);
  assert.equal(opened.bytes, content.length);
  assert.equal(fs.readFileSync(path.join(TMP, 'big.open')).equals(content), true);
  assert.equal(opened.plaintext_sha256, sha256hex(content));
  assert.equal(opened.chain_sha256, s.chain_sha256);
});

test('kem-stream: รูปซองตามกฎเป๊ะ — หัวครบ field · ชิ้นอัดแท็กตามดัชนี · ท้ายประกาศสาย/ยอด/จำนวนบรรทัด', () => {
  const src = path.join(TMP, 'two.dat');
  const content = randomBytes(2048);
  fs.writeFileSync(src, content);
  const sealPath = src + '.seal.json';
  sealStreamFile(src, sealPath, ownerPub, { chunkSize: 512 });
  const lines = linesOf(sealPath);
  assert.equal(lines.length, 6); // หัว + 4 ชิ้น + ท้าย
  const header = JSON.parse(lines[0]);
  assert.equal(header.format, STREAM_FORMAT);
  assert.equal(header.version, 2);
  assert.equal(header.profile, ownerPub.profile);
  assert.equal(header.recipient.public_key_sha256, ownerPub.public_key_sha256);
  assert.equal(header.chunk_size, 512);
  assert.equal(header.total_chunks, 4);
  assert.equal(header.total_plaintext, 2048);
  const last = JSON.parse(lines[4]);
  assert.equal(last.i, 3);
  assert.equal(Buffer.from(last.ct_b64, 'base64').length, 512);   // 2048 หาร 512 ลงตัว — ชิ้นสุดท้ายเต็ม
  assert.equal(Buffer.from(last.tag_b64, 'base64').length, 16);   // authTag GCM ตามมาตรฐาน
  const footer = JSON.parse(lines[5]);
  assert.equal(footer.format, STREAM_FOOTER_FORMAT);
  assert.equal(footer.plaintext_sha256, sha256hex(content));
  assert.equal(footer.total_lines, 6);
  const chain = verifyStreamChain(sealPath);                      // โหนดไร้กุญแจตรวจสายได้เต็มสาย
  assert.equal(chain.ok, true);
  assert.equal(chain.total_chunks, 4);
  assert.equal(chain.total_plaintext, 2048);
  assert.equal(chain.chain_sha256, footer.chain_sha256);
  assert.equal(chain.plaintext_sha256, footer.plaintext_sha256);
});

test('kem-stream: โจมตีจับได้ทุกชนิด — แก้ไบต์ชิ้น (GCM) / สลับลำดับชิ้น (ดัชนี) / ตัดท้าย (footer) / แก้ค่าสายท้าย (chain)', () => {
  const src = path.join(TMP, 'atk.dat');
  fs.writeFileSync(src, randomBytes(1000)); // 4 ชิ้น (ชิ้นท้าย 232 ไบต์) ตาม chunkSize 256
  const sealPath = src + '.seal.json';
  sealStreamFile(src, sealPath, ownerPub, { chunkSize: 256 });
  const lines = linesOf(sealPath);
  assert.equal(lines.length, 6); // หัว + 4 ชิ้น (1000 ไบต์ ÷ 256 = 3 ชิ้นเต็ม + 1 ชิ้นสั้น 232) + ท้าย
  const outP = path.join(TMP, 'atk.open');

  // (a) แก้ 1 ตัวอักษรใน ciphertext ของชิ้นที่ 0 — GCM จับที่ถอด / โหนดไร้กุญแจจับที่สาย (ผลต่างกันแต่จับได้เหมือนกัน)
  const a = lines.slice();
  const c0 = JSON.parse(a[1]);
  c0.ct_b64 = flipB64Char(c0.ct_b64);
  a[1] = JSON.stringify(c0);
  saveLines(sealPath, a);
  assert.throws(() => openStreamFile(sealPath, outP, owner.sk_b64), /เปิดไม่ขึ้น/);
  assert.throws(() => verifyStreamChain(sealPath), /สาย hash/);

  // (b) สลับลำดับชิ้น 1 ↔ 2 — ดัชนีที่ติดอยู่ในบรรทัดจับก่อนถอดแม้แต่บิตเดียว
  const b = [lines[0], lines[1], lines[3], lines[2], lines[4], lines[5]];
  saveLines(sealPath, b);
  assert.throws(() => openStreamFile(sealPath, outP, owner.sk_b64), /ลำดับชิ้น/);
  assert.throws(() => verifyStreamChain(sealPath), /ลำดับชิ้น/);

  // (c) ตัดบรรทัดท้าย (footer) — ทั้งเปิดและตรวจสายต้องปฏิเสธว่าซองถูกตัดทอน
  saveLines(sealPath, lines.slice(0, 5)); // คงหัว + 4 ชิ้น ตัดท้ายหาย
  assert.throws(() => verifyStreamChain(sealPath), /ขาดบรรทัดท้าย/);
  assert.throws(() => openStreamFile(sealPath, outP, owner.sk_b64), /ขาดบรรทัดท้าย/);

  // (d) แก้ค่าสายท้าย — ค่าที่ผู้เปิด/ผู้ตรวจคำนวณเองไม่ตรงที่ประกาศ = แฟ้มถูกแก้แน่นอน
  const d = lines.slice();
  const f2 = JSON.parse(d[5]);
  f2.chain_sha256 = 'ff' + f2.chain_sha256.slice(2);
  d[5] = JSON.stringify(f2);
  saveLines(sealPath, d);
  assert.throws(() => verifyStreamChain(sealPath), /สาย hash/);
  assert.throws(() => openStreamFile(sealPath, outP, owner.sk_b64), /สาย hash/);
  const original = lines.slice();
  saveLines(sealPath, original); // คืนของแท้กันเหยงข้ามเทส
  assert.equal(verifyStreamChain(sealPath).ok, true);
});

test('kem-stream: รั้งก่อนงาน — ขนาดชิ้นนอกช่วงปฏิเสธ · กุญแจไม่ใช่คู่ของผู้รับในซองปฏิเสธก่อนถอด', () => {
  const src = path.join(TMP, 'small.dat');
  fs.writeFileSync(src, randomBytes(128));
  assert.throws(() => sealStreamFile(src, path.join(TMP, 'x.seal.json'), ownerPub, { chunkSize: 100 }), /ขนาดชิ้นต้องอยู่ในช่วง/);
  const sealPath = src + '.seal.json';
  sealStreamFile(src, sealPath, ownerPub, { chunkSize: 256 });
  const impostor = kemKeygen();
  assert.throws(() => openStreamFile(sealPath, path.join(TMP, 'x.open'), impostor.sk_b64), /ไม่ใช่คู่ของกุญแจผู้รับ/);
});

test('kem-stream: แฟ้มว่าง 0 ไบต์ — ผนึก/เปิด/ตรวจสายได้ครบ (0 ชิ้น · สายคือหัวล้วน)', () => {
  const src = path.join(TMP, 'empty.dat');
  fs.writeFileSync(src, Buffer.alloc(0));
  const sealPath = src + '.seal.json';
  const s = sealStreamFile(src, sealPath, ownerPub);
  assert.equal(s.total_chunks, 0);
  assert.equal(s.total_plaintext, 0);
  const { header } = readStreamHeader(sealPath);
  assert.equal(header.total_chunks, 0);
  const chain = verifyStreamChain(sealPath);
  assert.equal(chain.ok, true);
  assert.equal(chain.chain_sha256, s.chain_sha256); // สายยาว 0 ชิ้น = h0 จากหัวตรงท้าย
  const opened = openStreamFile(sealPath, path.join(TMP, 'empty.open'), owner.sk_b64);
  assert.equal(opened.bytes, 0);
  assert.equal(opened.chunks, 0);
  assert.equal(fs.statSync(path.join(TMP, 'empty.open')).size, 0);
  assert.equal(opened.plaintext_sha256, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'); // sha256 ของว่าง — ค่าที่ทุกระบบเห็นตรงกัน
});

test('kem-stream: ครอสฟอร์แมต — เนื้อหาก้อนเดียวกัน ซองเดี่ยว (v1.6) กับซองสตรีม (v1.8) เปิดได้ไบต์ตรงกันเป๊ะ', () => {
  const content = randomBytes(5000);
  const bySingle = openEnvelope(sealBytes(content, ownerPub), owner.sk_b64);
  const src = path.join(TMP, 'cross.dat');
  fs.writeFileSync(src, content);
  const sealPath = src + '.seal.json';
  sealStreamFile(src, sealPath, ownerPub, { chunkSize: 1024 });
  const outPath = path.join(TMP, 'cross.open');
  openStreamFile(sealPath, outPath, owner.sk_b64);
  const byStream = fs.readFileSync(outPath);
  assert.equal(bySingle.equals(content), true);
  assert.equal(byStream.equals(content), true);
  assert.equal(bySingle.equals(byStream), true);
});
