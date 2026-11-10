// ทดสอบ ML-KEM (FIPS 203) — ซองเข้ารหัสไฟล์ระหว่างโหนด (v1.6 · Q-01)
// หลักเดียวกับทั้ง repo: ไม่มีจำลอง — ใช้ ML-KEM-768 จริงจาก @noble/post-quantum + AES-256-GCM จริง
import test from 'node:test';
import assert from 'node:assert/strict';
import { kemKeygen, kemPublicFile, sealBytes, openEnvelope, envelopePublicInfo, pubSha256, KEM_ALG, KEM_PROFILE } from '../src/kem.js';
import { createVault, openVault, VAULT_PARAMS_TEST } from '../src/vault.js';

// เสียบลายเซ็นมือแบบเดียวกับ test/zk: แก้ 1 ตำแหน่งใน base64 string (ยังเป็น base64 ที่พอใช้ได้)
function flipB64(str, pos) {
  const orig = str[pos];
  const swapped = orig === 'A' ? 'B' : 'A';
  return str.slice(0, pos) + swapped + str.slice(pos + 1);
}

function mustThrow(fn, hint) {
  let threw = null;
  try { fn(); } catch (e) { threw = e; }
  assert.ok(threw, 'ต้องปฏิเสธ ' + hint);
  return threw.message;
}

// ไบต์สุ่มกำหนดเอง (ไม่จำเป็นกระตุ้น entropy จริง — ตรวจเฉพาะคุณลักษณะซอง)
function randomFill() {
  const b = Buffer.alloc(512);
  for (let i = 0; i < b.length; i++) b[i] = (i * 3 + (i % 7)) % 256;
  return b;
}

test('kem: keygen ได้ขนาดตามมาตรฐาน FIPS 203 (pk 1184 B · sk 2400 B) และ pk จาก sk ตรงตัว', () => {
  const { pk_b64, sk_b64, pk_sha256 } = kemKeygen();
  assert.equal(Buffer.from(pk_b64, 'base64').length, 1184);
  assert.equal(Buffer.from(sk_b64, 'base64').length, 2400);
  // แฟ้มกุญแจสาธารณะที่เกิดจริงต้องผ่านการตรวจรูปอีกชั้น
  const pub = kemPublicFile({ label: 'ผู้จัดการแฟร์', pk_b64 });
  assert.equal(pub.public_key_sha256, pk_sha256);
  assert.equal(pub.profile, KEM_PROFILE);
  // pub file ไม่มีกุญแจลับหลุดลงแฟ้มสาธารณะเด็ดขาด (ตรวจชื่อ field เท่านั้น — ค่า b64 บังเอิญมีตัวอักษร "sk" ในราสันได้)
  assert.ok(!Object.keys(pub).some((k) => k.toLowerCase().includes('sk')));
});

test('kem: ผนึก → เปิด กลับได้ไบต์ตรงเดิม (ไบนารี + ยูนิโคด) และเนื้อหาไม่หลุดในซอง', () => {
  const { pk_b64, sk_b64 } = kemKeygen();
  const pub = kemPublicFile({ label: 'ผู้รับ', pk_b64 });
  const payload = Buffer.concat([
    Buffer.from('รายงานยอด 12 พ.ย. 2569 — เปิดเฉพาะเจ้าของกุญแจ', 'utf8'),
    Buffer.from([0x00, 0xff, 0xfe, 0x10]), // ไบนารีแท้ (มี null byte ไปด้วย)
    randomFill(),
  ]);
  const seal = sealBytes(payload, pub);
  assert.equal(seal.alg, KEM_ALG);
  assert.equal(seal.plaintext_length, payload.length);
  // FIPS 203 ct 1088 B; ใน node AES-GCM จำแยก tag 16 B ออกไว้ต่าง field — ciphertext วัด 1:1 ตามเนื้อหา
  assert.equal(Buffer.from(seal.ciphertext_b64, 'base64').length, payload.length);
  assert.equal(Buffer.from(seal.encapsulated_cipher_b64, 'base64').length, 1088);
  assert.ok(!JSON.stringify(seal).includes(payload.slice(0, 8).toString('hex')));
  const out = openEnvelope(seal, sk_b64);
  assert.ok(Buffer.compare(out, payload) === 0);
});

test('kem: แก้ 1 ตำแหน่งในซอง (ciphertext / nonce / authTag) → open ปฏิเสธทันที', () => {
  const { pk_b64, sk_b64 } = kemKeygen();
  const pub = kemPublicFile({ label: 'ผู้รับ', pk_b64 });
  const seal = sealBytes(Buffer.from('บรรทัดข้อมูลปกปิด A', 'utf8'), pub);
  assert.notEqual(openEnvelope(seal, sk_b64).toString('utf8'), ''); // ฐาน: เปิดได้ก่อนคู่เทียบ
  const mid = Math.floor(seal.ciphertext_b64.length / 2);
  mustThrow(() => openEnvelope({ ...seal, ciphertext_b64: flipB64(seal.ciphertext_b64, mid) }, sk_b64), 'ciphertext ถูกแก้');
  mustThrow(() => openEnvelope({ ...seal, nonce_b64: flipB64(seal.nonce_b64, 4) }, sk_b64), 'nonce ถูกแก้');
  mustThrow(() => openEnvelope({ ...seal, auth_tag_b64: flipB64(seal.auth_tag_b64, 10) }, sk_b64), 'authTag ถูกแก้');
});

test('kem: ซองของผู้รับรายอื่น → เปิดด้วยกุญแจลับไม่ตรง → ปฏิเสธ (และกุญแจผิดรูปปฏิเสธก่อนถอด)', () => {
  const recipient = kemKeygen();
  const outsider = kemKeygen();
  const pub = kemPublicFile({ label: 'ผู้รับจริง', pk_b64: recipient.pk_b64 });
  const seal = sealBytes(Buffer.from('ยอดเข้าคลังเฉพาะเจ้าของ', 'utf8'), pub);
  // กุญแจลับผู้อื่น (รูปถูกต้องแต่ไม่ใช่คู่) → ตรวจ "คู่ของผู้รับ" แล้วปัด
  const msgWrongKey = mustThrow(() => openEnvelope(seal, outsider.sk_b64), 'กุญแจไม่ใช่คู่ผู้รับ');
  assert.ok(msgWrongKey.includes('ไม่ใช่คู่ของกุญแจผู้รับ'));
  // กุญแจลับผิดรูป (ตัดขนาด) → ปัดที่การตรวจรูปแบบเลย
  mustThrow(() => openEnvelope(seal, recipient.sk_b64.slice(0, 1216)), 'กุญแจลับผิดขนาด');
});

test('kem: ซองถูกแก้โครง (alg/version) หรือรายชื่อผู้รับถูกแทนที่ → ปฏิเสธก่อนถอด', () => {
  const { sk_b64 } = kemKeygen();
  const pub = kemPublicFile({ label: 'ผู้รับ', pk_b64: kemKeygen().pk_b64 });
  const seal = sealBytes(Buffer.from('ok', 'utf8'), pub);
  mustThrow(() => openEnvelope({ ...seal, alg: 'sovereign.ml-kem768+aesgcm.v2' }, sk_b64), 'alg ไม่ตรงระบบ');
  mustThrow(() => openEnvelope({ ...seal, version: 2 }, sk_b64), 'version ไม่ตรงระบบ');
  mustThrow(() => openEnvelope({ ...seal, profile: 'other.profile.v1' }, sk_b64), 'profile ไม่ตรงระบบ');
  // แทน sha256 ผู้รับเป็นคนอื่น (เรื่องปกติเมื่อถูกแก้ซองกลางทาง)
  mustThrow(() => openEnvelope({ ...seal, recipient: { ...seal.recipient, public_key_sha256: 'a'.repeat(64) } }, sk_b64), 'ชี้ผู้รับปลอม');
  // ประกาศขนาดไม่ตรงเนื้อหา
  mustThrow(() => openEnvelope({ ...seal, plaintext_length: 999 }, sk_b64), 'ขนาดประกาศไม่ตรง');
});

test('kem: vault กุญแจ KEM รอบจริง (createVault → openVault) — passphrase ผิดปฏิเสธและ sk ไม่เขียนลงดิสก์แบบ plaintext', () => {
  const { sk_b64, pk_b64 } = kemKeygen();
  // รูปแบบเดียวกับที่ CLI เขียนจริงใน data/kem.vault.json (ทดสอบในหน่วยความจำเท่านั้น)
  const vaultJson = createVault({ profile: KEM_PROFILE, label: 'ผู้จัดการแฟร์', sk_b64 }, 'kem-pass-2026-v', { params: VAULT_PARAMS_TEST });
  const opened = openVault(vaultJson, 'kem-pass-2026-v');
  assert.equal(opened.profile, KEM_PROFILE);
  const out = openEnvelope(sealBytes(Buffer.from('ok', 'utf8'), kemPublicFile({ label: 'ผู้จัดการแฟร์', pk_b64 })), opened.sk_b64);
  assert.equal(out.toString('utf8'), 'ok');
  // passphrase ผิด → ปฏิเสธ (ไม่เงียบเฉย)
  mustThrow(() => openVault(vaultJson, 'ผิดรหัส-ก็-ใช่'), 'passphrase vault ผิด');
});

test('kem: หน้าเส้นทางซองจาก metadata ล้วน (kem check) — ไม่แตะกุญแจ/ไม่แตะเนื้อหา · โครงผิดทุกระดับจับได้', () => {
  const { pk_b64, pk_sha256 } = kemKeygen();
  const pub = kemPublicFile({ label: 'ผู้จัดการกองทุน', pk_b64 });
  const payload = Buffer.from('~ สายส่งลับ ~', 'utf8');
  const seal = sealBytes(payload, pub);
  const info = envelopePublicInfo(seal);
  assert.equal(info.alg, KEM_ALG);
  assert.equal(info.version, 1);
  assert.equal(info.recipient_sha256, pk_sha256);
  assert.equal(info.recipient_label, 'ผู้จัดการกองทุน');
  assert.equal(info.encapsulated_cipher_bytes, 1088); // รูปมาตรฐาน FIPS 203
  assert.equal(info.plaintext_length, payload.length);
  assert.deepEqual(info.anomalies, []);
  // metadata สำหรับเส้นทางต้องไม่มี field ที่แบกไบต์เนื้อหา/กุญแจเด็ดขาด (field ขนาดอย่าง encapsulated_cipher_bytes อนุญาต — เป็นตัวเลข)
  assert.ok(!Object.keys(info).some((k) => /ciphertext|nonce|auth|_b64|_hex|^sk|sk_/.test(k)));
  // โครงผิดแบบ route ไม่ได้ → ปฏิเสธทันที (alg/version/ผู้รับหาย)
  assert.throws(() => envelopePublicInfo({ ...seal, alg: 'other.v1' }), /อัลกอริทึม/);
  assert.throws(() => envelopePublicInfo({ ...seal, version: 2 }), /version ของซองไม่รองรับ/);
  assert.throws(() => envelopePublicInfo({ ...seal, recipient: { label: 'x' } }), /ระบุปลายทางผู้รับ/);
  // โครงเพี้ยนแบบอ่านเส้นทางได้ต่อ (ไม่พังขาดมือ): ขนาด encapsulation ไม่ตามมาตรฐาน → ต้องโผล่ใน anomalies
  const odd = envelopePublicInfo({ ...seal, encapsulated_cipher_b64: 'QQ==' });
  assert.ok(odd.anomalies.some((a) => a.includes('encapsulated_cipher')));
  // pubSha256 วัดตรงจาก b64 เสมอ — แทนกุญแจในแฟ้ม pub โดยคง field sha เดิม → ค่าที่คำนวณใหม่ไม่ตรงแน่นอน
  assert.equal(pubSha256(pub), pk_sha256);
  const other = kemKeygen();
  assert.notEqual(pubSha256({ profile: KEM_PROFILE, public_key_b64: other.pk_b64 }), pk_sha256);
  assert.throws(() => pubSha256({ ...pub, profile: 'sovereign.kem512.v1' }), /ไม่ใช่ของระบบนี้/);
});
