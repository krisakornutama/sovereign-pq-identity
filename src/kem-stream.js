// 🧱 ซองสตรีมแบ่งส่วน (chunked envelope) — v1.8 · Q-11
// แก้ข้อจำกัด v1.6 (แฟ้มซองอ่านทั้งก้อนเข้าหน่วยความจำ): แฟ้มซองเดียวเป็น JSONL มี 3 ชนิดบรรทัด
//   หัว   : { version, format, alg, profile, created_at, recipient, chunk_size, total_chunks, total_plaintext, encapsulated_cipher_b64, nonce_prefix_b64 }
//   ชิ้น  : { i, ct_b64, tag_b64 }        — nonce ตั้งจาก nonce_prefix(8 ไบต์) || ดัชนี(4 ไบต์ต่อท้าย) · กุญแจ session เดียวจาก encapsulation ของหัว
//   ท้าย  : { format, chain_sha256, plaintext_sha256, total_lines }
// สาย hash ต่อเนื่อง: h0 = SHA-256(โดเมน ‖ 0x00 ‖ หัว canonical) → h_i = SHA-256(โดเมน ‖ 0x00 ‖ h_(i-1) ‖ 0x00 ‖ ดัชนี(4B) ‖ ไบต์ ciphertext ชิ้น i)
//   → ผนึก/เปิด/ตรวจอ่านรอบเดียว หน่วยความจำ = ขนาดชิ้น (คงที่ไม่ว่าแฟ้มกี่ GB) และโหนดขนส่งตรวจสายได้ครบโดยไม่มีกุญแจ (h ใช้ ciphertext ล้วน)
// แนวของชั้นกันแก้: เนื้อหาจริงกันด้วย GCM (keyed) เสมอ — สาย hash จับการตัดทอน/ย้ายลำดับระหว่างทางให้ผู้ตรวจที่ไร้กุญแจเห็นเอง
// ผู้รับคนเดียวต่อซอง (ตามมาตรฐาน KEM) — ทั้งซองมี encapsulation เดียว
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { KEM_ALG, KEM_PROFILE, KEM_LEN, kemSessionKey, sha256hex } from './kem.js';

export const STREAM_FORMAT = 'sovereign.kem-stream.v1';
export const STREAM_FOOTER_FORMAT = 'sovereign.kem-stream.footer.v1';
const STREAM_DOMAIN = 'sovereign-kem-stream/v1';
export const STREAM_CHUNK_DEFAULT = 65536;                          // 64 KiB ต่อชิ้น (ค่างานทั่วไป)
export const STREAM_CHUNK_MIN = 256;
export const STREAM_CHUNK_MAX = 4 * 1024 * 1024;                    // 4 MiB — กันชิ้นยักษ์กลืนหน่วยความจำเครื่องเล็ก
const HEADER_READ_CAP = 65536;                                      // บรรทัดหัวยาวสุดที่ยอมอ่าน (b64 encapsulation + หน้า ~2 KB)
const READ_BLOCK = 256 * 1024;                                      // บัฟเฟอร์อ่านต่อบล็อก — คงที่ทุกขนาดแฟ้ม

function assertChunkSize(chunkSize) {
  if (!Number.isSafeInteger(chunkSize) || chunkSize < STREAM_CHUNK_MIN || chunkSize > STREAM_CHUNK_MAX) {
    throw new Error('ขนาดชิ้นต้องอยู่ในช่วง ' + STREAM_CHUNK_MIN + '–' + STREAM_CHUNK_MAX + ' ไบต์ (ประกาศมา: ' + chunkSize + ')');
  }
}

function be4(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0, 0);
  return b;
}

function be8(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n), 0);
  return b;
}

function canonicalHeaderBytes(h) {
  // รูป canonical ของหัวเพื่อผูกเข้า h0 — จัด field ตายตัว กันรูปแบบพรีตตี้/พื้นที่ว่างหลอกสาย
  return Buffer.from(JSON.stringify({
    version: 2,
    format: STREAM_FORMAT,
    alg: h.alg,
    profile: h.profile,
    chunk_size: h.chunk_size,
    total_chunks: h.total_chunks,
    total_plaintext: h.total_plaintext,
    recipient: {
      label: (h.recipient && h.recipient.label) || '',
      public_key_sha256: h.recipient && h.recipient.public_key_sha256,
    },
  }), 'utf8');
}

// โมเดล AAD ของชิ้น: ผูกโดเมน + ผู้รับ + ปริมาตรรวม + จำนวนชิ้น + ดัชนี — ย้ายชิ้นข้ามลำดับ/ข้ามซอง = GCM ล้มทันที
function chunkAAD(header, index) {
  return Buffer.concat([
    Buffer.from(STREAM_DOMAIN),
    Buffer.from([0xA0]),
    Buffer.from(header.recipient.public_key_sha256, 'utf8'),
    Buffer.from([0xA0]),
    be4(header.total_chunks),
    be8(header.total_plaintext),
    be4(index),
  ]);
}

function chunkNonce(header, index) {
  const prefix = Buffer.from(header.nonce_prefix_b64 || '', 'base64');
  return Buffer.concat([prefix, be4(index)]);
}

function headerHash(h) {
  return createHash('sha256').update(Buffer.concat([
    Buffer.from(STREAM_DOMAIN),
    Buffer.from([0x00]),
    canonicalHeaderBytes(h),
  ])).digest('hex');
}

function chainStep(prevHex, index, cipherBytes) {
  return createHash('sha256').update(Buffer.concat([
    Buffer.from(STREAM_DOMAIN),
    Buffer.from([0x00]),
    Buffer.from(prevHex, 'hex'),
    Buffer.from([0x00]),
    be4(index),
    cipherBytes,
  ])).digest('hex');
}

// ขนาดเนื้อหาของชิ้น i ตามที่หัวประกาศ (ชิ้นสุดท้ายอาจสั้น)
function expectedPlainLength(header, index) {
  if (header.total_chunks === 0) return 0;
  if (index === header.total_chunks - 1) return header.total_plaintext - (header.total_chunks - 1) * header.chunk_size;
  return header.chunk_size;
}

// ==== ผนึกแฟ้มใหญ่เป็นซองสตรีม — อ่านต้นทางรอบเดียว หน่วยความจำคงที่เสมอ ====
export function sealStreamFile(srcPath, outPath, pubFile, { chunkSize = STREAM_CHUNK_DEFAULT } = {}) {
  assertChunkSize(chunkSize);
  if (!pubFile || pubFile.profile !== KEM_PROFILE || typeof pubFile.public_key_b64 !== 'string') {
    throw new Error('แฟ้มกุญแจสาธารณะไม่ใช่ของระบบนี้ (ต้องออกจาก kem keygen)');
  }
  const pk = Buffer.from(pubFile.public_key_b64, 'base64');
  if (pk.length !== KEM_LEN.publicKey) throw new Error('กุญแจสาธารณะ ML-KEM ผิดรูปแบบ (ไม่ใช่ขนาด ' + KEM_LEN.publicKey + ' ไบต์)');
  if (pubFile.public_key_sha256 && pubFile.public_key_sha256 !== sha256hex(pk)) {
    throw new Error('แฟ้มกุญแจสาธารณะไม่พ้องกันเอง (sha256 ไม่ตรง pk) — ห้ามใช้');
  }
  const stat = fs.existsSync(srcPath) ? fs.statSync(srcPath) : null;
  if (!stat || !stat.isFile()) throw new Error('ไม่พบแฟ้มข้อมูล ' + srcPath);
  const totalPlaintext = stat.size;
  const totalChunks = Math.ceil(totalPlaintext / chunkSize);

  const { cipherText, sharedSecret } = ml_kem768.encapsulate(pk);
  const key = kemSessionKey(sharedSecret);
  const noncePrefix = randomBytes(8);
  const header = {
    version: 2,
    format: STREAM_FORMAT,
    alg: KEM_ALG,
    profile: KEM_PROFILE,
    created_at: new Date().toISOString(),
    recipient: {
      label: pubFile.label || 'recipient',
      public_key_sha256: pubFile.public_key_sha256 || sha256hex(pk),
    },
    chunk_size: chunkSize,
    total_chunks: totalChunks,
    total_plaintext: totalPlaintext,
    encapsulated_cipher_b64: Buffer.from(cipherText).toString('base64'),
    nonce_prefix_b64: noncePrefix.toString('base64'),
  };
  let h = headerHash(header);

  const outFd = fs.openSync(outPath, 'w');
  const srcFd = fs.openSync(srcPath, 'r');
  const plainDigest = createHash('sha256');
  const piece = Buffer.alloc(chunkSize);
  try {
    fs.writeSync(outFd, JSON.stringify(header) + '\n');
    for (let i = 0; i < totalChunks; i++) {
      const want = expectedPlainLength(header, i);
      let filled = 0;
      while (filled < want) {
        const got = fs.readSync(srcFd, piece, filled, want - filled, null);
        if (got <= 0) break;
        filled += got;
      }
      if (filled !== want) throw new Error('แฟ้มต้นทางเปลี่ยนขนาดระหว่างผนึก (ชิ้นที่ ' + i + ' อ่านได้ ' + filled + ' จาก ' + want + ' ไบต์) — รันผนึกใหม่');
      const slice = piece.subarray(0, filled);
      plainDigest.update(slice);
      const nonce = chunkNonce(header, i);
      const cipher = createCipheriv('aes-256-gcm', key, nonce);
      cipher.setAAD(chunkAAD(header, i));
      const ct = Buffer.concat([cipher.update(slice), cipher.final()]);
      h = chainStep(h, i, ct); // สายบันทึกไบต์จริงของบรรทัดนี้ก่อนเขียนเสมอ
      fs.writeSync(outFd, JSON.stringify({ i, ct_b64: ct.toString('base64'), tag_b64: cipher.getAuthTag().toString('base64') }) + '\n');
    }
    const footer = {
      format: STREAM_FOOTER_FORMAT,
      chain_sha256: h,
      plaintext_sha256: plainDigest.digest('hex'),
      total_lines: totalChunks + 2,
    };
    fs.writeSync(outFd, JSON.stringify(footer) + '\n');
  } catch (e) {
    try { fs.closeSync(outFd); } catch { /* ปิดซ้ำไม่เป็นไร */ }
    try { fs.unlinkSync(outPath); } catch { /* ล้างซองเขียนครึ่งทิ้ง */ }
    try { fs.closeSync(srcFd); } catch { /* ปิดซ้ำไม่เป็นไร */ }
    throw e;
  }
  fs.closeSync(outFd);
  fs.closeSync(srcFd);
  return {
    out: outPath,
    chunk_size: chunkSize,
    total_chunks: totalChunks,
    total_plaintext: totalPlaintext,
    chain_sha256: h,
    created_at: header.created_at,
    recipient: { label: header.recipient.label, public_key_sha256: header.recipient.public_key_sha256 },
  };
}

// ==== อ่าน/ตรวจบรรทัดหัว (strict) — ทุกพาธเปิดใช้ เป็นจุดแยกรูปแบบซองเดี่ยว/ซองสตรีมของระบบ ====
export function readStreamHeader(sealPath) {
  const fd = fs.openSync(sealPath, 'r');
  const buf = Buffer.alloc(HEADER_READ_CAP);
  try {
    let total = 0;
    let nl = -1;
    while (total < buf.length) {
      const got = fs.readSync(fd, buf, total, buf.length - total);
      if (got <= 0) break;
      total += got;
      nl = buf.subarray(0, total).indexOf(0x0A);
      if (nl >= 0) break;
    }
    if (nl < 0) throw new Error('บรรทัดหัวของซองสตรีมยาวลิบพิกัด (' + total + ' ไบต์ไม่เจอจุดคั่นบรรทัด) — ไม่ใช่ซองของระบบนี้');
    let header;
    try { header = JSON.parse(buf.subarray(0, nl).toString('utf8')); } catch {
      throw new Error('บรรทัดหัวของซองสตรีมไม่ใช่ JSON ที่อ่านได้ — แฟ้มเสียหายหรือไม่ใช่ซอง');
    }
    if (!header || header.format !== STREAM_FORMAT) {
      throw new Error('แฟ้มนี้ไม่ใช่ซองสตรีมของระบบนี้ (format ไม่ตรง)');
    }
    if (header.version !== 2) throw new Error('version ของซองสตรีมไม่รองรับ: ' + JSON.stringify(header.version) + ' — ปฏิเสธเส้นทาง');
    if (header.alg !== KEM_ALG || header.profile !== KEM_PROFILE) throw new Error('ซองสตรีมไม่ใช่อัลกอริทึมของระบบนี้ (alg/profile ไม่ตรง)');
    const rec = header.recipient;
    if (!rec || typeof rec.public_key_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(rec.public_key_sha256)) {
      throw new Error('ซองสตรีมไม่ระบุปลายทางผู้รับ (public_key_sha256) — เส้นทางไม่ได้');
    }
    if (Buffer.from(header.nonce_prefix_b64 || '', 'base64').length !== 8) throw new Error('nonce_prefix ผิดรูปแบบ (ต้อง 8 ไบต์)');
    assertChunkSize(header.chunk_size);
    if (!Number.isSafeInteger(header.total_plaintext) || header.total_plaintext < 0) {
      throw new Error('total_plaintext ผิดรูปแบบ (ต้องเป็นจำนวนเต็ม ≥ 0)');
    }
    if (header.total_chunks !== Math.ceil(header.total_plaintext / header.chunk_size)) {
      throw new Error('ประกาศจำนวนชิ้นในหัวไม่ตรงเนื้อหา (total_chunks × chunk_size ไม่ครอบ total_plaintext) — ซองถูกแก้หรือคนละต้นทาง');
    }
    return { header, header_bytes: nl, total_bytes: fs.fstatSync(fd).size };
  } finally {
    fs.closeSync(fd);
  }
}

// หน้าเส้นทางซองสตรีม (metadata ล้วน สำหรับ kem check) — เรียกหลัง readStreamHeader ผ่านแล้วเท่านั้น
export function streamHeaderInfo(header, total_bytes = 0) {
  const encCipher = Buffer.from(header.encapsulated_cipher_b64 || '', 'base64');
  const anomalies = [];
  if (encCipher.length !== KEM_LEN.cipherText) {
    anomalies.push('encapsulated_cipher ผิดขนาด (' + encCipher.length + ' ไบต์ — มาตรฐาน FIPS 203 คือ ' + KEM_LEN.cipherText + ') — เปิดไม่ขึ้นทุกโหนด');
  }
  if (Buffer.from(header.nonce_prefix_b64 || '', 'base64').length !== 8) anomalies.push('nonce_prefix ผิดขนาด (ต้อง 8 ไบต์)');
  return {
    format: header.format,
    version: header.version,
    alg: header.alg,
    profile: header.profile,
    created_at: header.created_at || '(ไม่ระบุ)',
    recipient_label: (header.recipient && header.recipient.label) || '(ไม่มีชื่อ)',
    recipient_sha256: header.recipient && header.recipient.public_key_sha256,
    chunk_size: header.chunk_size,
    total_chunks: header.total_chunks,
    total_plaintext: header.total_plaintext,
    total_bytes,
    encapsulated_cipher_bytes: encCipher.length,
    anomalies,
  };
}

// ---- หัวใจสตรีม: ไล่บรรทัดทีละบรรทัดแบบ sync — หน่วยความจำคงที่ (256 KiB บัฟเฟอร์เท่านั้น) ----
function* iterateSealLines(sealPath) {
  const fd = fs.openSync(sealPath, 'r');
  const buf = Buffer.alloc(READ_BLOCK);
  let rem = Buffer.alloc(0);
  try {
    for (; ; ) {
      let nl = rem.indexOf(0x0A);
      while (nl >= 0) {
        yield rem.subarray(0, nl);
        rem = rem.subarray(nl + 1);
        nl = rem.indexOf(0x0A);
      }
      const got = fs.readSync(fd, buf, 0, buf.length);
      if (got <= 0) break;
      rem = rem.length === 0 ? Buffer.from(buf.subarray(0, got)) : Buffer.concat([rem, buf.subarray(0, got)]);
    }
    if (rem.length > 0) yield rem; // บรรทัดท้ายไม่มี \n ปิดก็ถือว่าบรรทัด
  } finally {
    fs.closeSync(fd);
  }
}

function parseChunkLine(raw, i) {
  let line;
  try { line = JSON.parse(raw.toString('utf8')); } catch {
    throw new Error('บรรทัดชิ้นที่ ' + i + ' ไม่ใช่ JSON ที่อ่านได้ — สายซองถูกบิดเบือนระหว่างทาง');
  }
  if (!line || !Number.isInteger(line.i) || line.i !== i || typeof line.ct_b64 !== 'string' || typeof line.tag_b64 !== 'string') {
    const seen = line && Number.isInteger(line.i) ? ' (พบ i=' + line.i + ')' : ' (บรรทัดไม่ติดป้ายดัชนี)';
    throw new Error('ลำดับชิ้นผิดที่ควรเป็นชิ้นที่ ' + i + seen + ' — ซองถูกตัดทอนหรือย้ายชิ้น');
  }
  return line;
}

function parseFooter(raw) {
  let line;
  try { line = JSON.parse(raw.toString('utf8')); } catch {
    throw new Error('บรรทัดท้าย (footer) ไม่ใช่ JSON ที่อ่านได้ — แฟ้มถูกตัดขาดกลางบรรทัด');
  }
  const hexOk = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
  if (!line || line.format !== STREAM_FOOTER_FORMAT || !hexOk(line.chain_sha256) || !hexOk(line.plaintext_sha256)) {
    throw new Error('โครงบรรทัดท้าย (footer) ไม่ตรงตามระบบ — ไม่ใช่ผลการผนึกของเรา');
  }
  return line;
}

function expectFooterAfter(it, message) {
  const raw = it.next();
  if (raw.done || raw.value === undefined || raw.value.length === 0) throw new Error(message);
  return raw.value;
}

// ==== ตรวจสาย hash ครบหัวถึงท้าย — โหนดขนส่งใช้ได้เลย ไม่ต้องมีกุญแจตัวใดเลย ====
export function verifyStreamChain(sealPath) {
  const { header } = readStreamHeader(sealPath);
  let h = headerHash(header);
  const it = iterateSealLines(sealPath);
  it.next(); // ข้ามหัว (ตรวจแล้วใน readStreamHeader)
  for (let i = 0; i < header.total_chunks; i++) {
    const raw = expectFooterAfter(it, 'แฟ้มซองสตรีมถึงจุดหมดกลางคันก่อนครบรอบชิ้น — หัวประกาศ ' + header.total_chunks + ' ชิ้น');
    const line = parseChunkLine(raw, i);
    const ct = Buffer.from(line.ct_b64, 'base64');
    const tag = Buffer.from(line.tag_b64 || '', 'base64');
    if (tag.length !== 16) throw new Error('authTag ของชิ้นที่ ' + i + ' ผิดรูปแบบ (ต้อง 16 ไบต์) — ซองถูกแก้');
    const want = expectedPlainLength(header, i);
    if (ct.length !== want) throw new Error('ชิ้นที่ ' + i + ' ผิดขนาด (ควร ' + want + ' ไบต์ พบ ' + ct.length + ') — เนื้อหาโดนตัดทอนหรือแก้ไข');
    h = chainStep(h, i, ct);
  }
  const footerRaw = expectFooterAfter(it, 'แฟ้มซองสตรีมขาดบรรทัดท้าย (footer) — ถูกตัดทอนระหว่างทาง');
  const footer = parseFooter(footerRaw);
  const rest = it.next();
  if (!rest.done && rest.value !== undefined && rest.value.length > 0) {
    throw new Error('มีบรรทัดเกินหลังบรรทัดท้าย (footer) — แฟ้มถูกประกอบใหม่หรือแนบซองอื่นต่อ');
  }
  if (footer.chain_sha256 !== h) {
    throw new Error('สาย hash (chain) ไม่ตรงค่าที่ประกาศท้าย — ' + (header.total_chunks > 0 ? 'ลำดับหรือไบต์ในรอบถูกแก้แน่นอน' : 'หัวซองถูกแก้แน่นอน'));
  }
  if (footer.total_lines !== header.total_chunks + 2) {
    throw new Error('จำนวนบรรทัดประกาศในท้ายไม่ตรง (' + footer.total_lines + ' เทียบ ' + (header.total_chunks + 2) + ') — ซองถูกแก้โครง');
  }
  return { ok: true, total_chunks: header.total_chunks, total_plaintext: header.total_plaintext, chain_sha256: h, plaintext_sha256: footer.plaintext_sha256 };
}

// ==== เปิดซองสตรีมเป็นแฟ้มจริง — อ่านรอบเดียว (สาย + ถอด + เขียนสตรีมพร้อมกัน) หน่วยความจำคงที่ ====
export function openStreamFile(sealPath, outPath, skB64) {
  const { header } = readStreamHeader(sealPath);
  const sk = Buffer.from(skB64 || '', 'base64');
  if (sk.length !== KEM_LEN.secretKey) throw new Error('กุญแจลับ ML-KEM ผิดรูปแบบ (ไม่ใช่ขนาด ' + KEM_LEN.secretKey + ' ไบต์)');
  if (header.recipient.public_key_sha256 !== sha256hex(Buffer.from(ml_kem768.getPublicKey(sk)))) {
    throw new Error('กุญแจลับไม่ใช่คู่ของกุญแจผู้รับในซอง (sha256 ไม่ตรง) — ซองนี้ไม่ได้ส่งถึงเรา');
  }
  let sharedSecret;
  try {
    sharedSecret = ml_kem768.decapsulate(Buffer.from(header.encapsulated_cipher_b64, 'base64'), sk);
  } catch {
    throw new Error('ถอด encapsulation ไม่ได้ — ซองผิดรูปแบบ FIPS 203');
  }
  const key = kemSessionKey(sharedSecret);

  const tmpOut = outPath + '.part';
  const outFd = fs.openSync(tmpOut, 'w');
  let h = headerHash(header);
  const plainDigest = createHash('sha256');
  let plainSha;
  try {
    const it = iterateSealLines(sealPath);
    it.next(); // หัว
    for (let i = 0; i < header.total_chunks; i++) {
      const raw = it.next();
      if (raw.done || raw.value === undefined || raw.value.length === 0) {
        throw new Error('แฟ้มซองสตรีมถึงจุดหมดกลางคันก่อนครบรอบชิ้น — หัวประกาศ ' + header.total_chunks + ' ชิ้น');
      }
      const line = parseChunkLine(raw.value, i);
      const ct = Buffer.from(line.ct_b64, 'base64');
      const tag = Buffer.from(line.tag_b64 || '', 'base64');
      if (tag.length !== 16) throw new Error('authTag ของชิ้นที่ ' + i + ' ผิดรูปแบบ (ต้อง 16 ไบต์) — ซองถูกแก้');
      h = chainStep(h, i, ct);
      let plain;
      try {
        const decipher = createDecipheriv('aes-256-gcm', key, chunkNonce(header, i));
        decipher.setAAD(chunkAAD(header, i));
        decipher.setAuthTag(tag);
        plain = Buffer.concat([decipher.update(ct), decipher.final()]);
      } catch {
        throw new Error('ชิ้นที่ ' + i + ' เปิดไม่ขึ้น (GCM authTag ไม่ตรง) — เนื้อหาหรือลำดับถูกแก้');
      }
      if (plain.length !== expectedPlainLength(header, i)) {
        throw new Error('ไบต์ที่ถอดได้ของชิ้นที่ ' + i + ' ไม่ตรงที่ประกาศ (' + plain.length + ') — ปฏิเสธ');
      }
      plainDigest.update(plain);
      fs.writeSync(outFd, plain);
    }
    const footer = parseFooter(expectFooterAfter(it, 'แฟ้มซองสตรีมขาดบรรทัดท้าย (footer) — ถูกตัดทอนระหว่างทาง'));
    const rest = it.next();
    if (!rest.done && rest.value !== undefined && rest.value.length > 0) {
      throw new Error('มีบรรทัดเกินหลังบรรทัดท้าย (footer) — แฟ้มถูกประกอบใหม่หรือแนบซองอื่นต่อ');
    }
    if (footer.chain_sha256 !== h) {
      throw new Error('สาย hash (chain) ไม่ตรงค่าที่ประกาศท้าย — ' + (header.total_chunks > 0 ? 'ลำดับหรือไบต์ในรอบถูกแก้แน่นอน' : 'หัวซองถูกแก้แน่นอน'));
    }
    plainSha = plainDigest.digest('hex');
    if (footer.plaintext_sha256 !== plainSha) {
      throw new Error('sha256 ของเนื้อหาที่ถอดได้ไม่ตรงที่ประกาศท้าย — เส้นทางส่งมาคนละก้อน ปฏิเสธ');
    }
    fs.fsyncSync(outFd);
    fs.closeSync(outFd);
  } catch (e) {
    try { fs.closeSync(outFd); } catch { /* ปิดซ้ำไม่เป็นไร */ }
    try { fs.unlinkSync(tmpOut); } catch { /* ล้างแฟ้มครึ่งโดนทิ้ง */ }
    throw e;
  }
  try { fs.unlinkSync(outPath); } catch { /* แฟ้มปลายทางเดิม (ถูกยอมเขียนทับแล้ว) — ลบก่อนย้ายครอบ (Windows ห้าม rename ทับไฟล์ที่มีอยู่) */ }
  fs.renameSync(tmpOut, outPath);
  return { bytes: header.total_plaintext, chunks: header.total_chunks, plaintext_sha256: plainSha, chain_sha256: h };
}
