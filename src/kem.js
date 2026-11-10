// 🧬 ML-KEM (FIPS 203) — ซองเข้ารหัสไฟล์ไฮบริดระหว่างโหนด (v1.6 · Q-01)
// อัลกอริทึม: ML-KEM-768 (pk 1184 B · ct 1088 B · sharedSecret 32 B) + AES-256-GCM
// หลัก: ผู้ส่งต้องมีแต่ "กุญแจสาธารณะ" ของผู้รับ — เปิดข้างในได้เฉพาะเจ้าของกุญแจลับเครื่องเดียว
//       กุญแจ session คือ SHA-256(โดเมน "sovereign-kem/v1" ‖ sharedSecret) — ผูกโดเมนใช้งาน กันการปะปนข้ามระบบ
// รูปแบบไบต์ในแฟ้ม (b64/hex) ถือกันตามขอบเขตอื่นใน repo: ไบต์ key/แฟ้ม = base64 (เอียงกับ vault/identity) · hash = hex
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

export const KEM_ALG = 'sovereign.ml-kem768+aesgcm.v1';
export const KEM_PROFILE = 'sovereign.kem768.v1';
const KEM_DOMAIN = 'sovereign-kem/v1';

// ขนาดตาม FIPS 203 Table 3 (ML-KEM-768) — ใช้ตรวจรูปแบบแฟ้มก่อนถอดเสมอ (หน่วย: ไบต์ / ตัว(Base64))
export const KEM_LEN = { publicKey: 1184, secretKey: 2400, cipherText: 1088 };
const LEN = KEM_LEN; // ชื่อเรียกในแฟ้มนี้

export function sha256hex(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

// กุญแจ session จาก sharedSecret — เรียกร่วมกันทั้งซองเดี่ยว (v1.6) และซองสตรีม (v1.8) เพื่อโดเมนเดียวกันเสมอ
export function kemSessionKey(sharedSecret) {
  return sessionKey(sharedSecret);
}

function sessionKey(sharedSecret) {
  return createHash('sha256').update(Buffer.concat([Buffer.from(KEM_DOMAIN), Buffer.from(sharedSecret)])).digest();
}

function fromB64(b64, bytes, what) {
  if (typeof b64 !== 'string' || b64.length !== Math.ceil(bytes / 3) * 4) {
    throw new Error(`${what} ผิดรูปแบบ (ไม่ใช่ขนาด ML-KEM-768: ${bytes} ไบต์ base64)`);
  }
  const buf = Buffer.from(b64, 'base64');
  if (buf.length !== bytes) throw new Error(`${what} ผิดรูปแบบ (ถอดแล้วไม่ครบ ${bytes} ไบต์)`);
  return buf;
}

// เกิดกุญแจ KEM ชุดใหม่ (สุ่มในไลบรารี noble — entropy ไม่ถูกบันทึกทุกชนิด)
export function kemKeygen() {
  const { secretKey, publicKey } = ml_kem768.keygen();
  const pk = Buffer.from(publicKey);
  // กันคลาดเคลื่อนชั้นลึก: กุญแจลับต้องให้กุญแจสาธารณะกลับมาตรงตัวเสมอ
  if (!Buffer.from(ml_kem768.getPublicKey(secretKey)).equals(pk)) {
    throw new Error('กุญแจ KEM ไม่พ้องกันเอง (pk ที่ได้จาก sk ไม่ตรง) — ปฏิเสธการเกิดกุญแจ');
  }
  return {
    pk_b64: pk.toString('base64'),
    sk_b64: Buffer.from(secretKey).toString('base64'),
    pk_sha256: sha256hex(pk),
  };
}

// แฟ้มกุญแจสาธารณะ (kem-pub.json) — แจกได้ทุกทาง: public ล้วน ไม่มีข้อมูลลับ
export function kemPublicFile({ label, pk_b64, created_at } = {}) {
  const pk = fromB64(pk_b64, LEN.publicKey, 'กุญแจสาธารณะ ML-KEM');
  return {
    version: 1,
    profile: KEM_PROFILE,
    label: label || 'recipient',
    public_key_b64: pk.toString('base64'),
    public_key_sha256: sha256hex(pk),
    created_at: created_at || new Date().toISOString(),
  };
}

// ผนึกไบต์ใด ๆ ส่งถึงเจ้าของกุญแจใน pub file — คืน "ซอง" (object) เขียนลงแฟ้ม .seal.json ได้เลย
export function sealBytes(plaintext, toPubFile) {
  if (!(plaintext instanceof Uint8Array || Buffer.isBuffer(plaintext))) {
    throw new Error('ข้อมูลที่จะผนึกต้องเป็น bytes (Buffer/Uint8Array)');
  }
  const pub = toPubFile || {};
  if (!pub.public_key_b64 || pub.profile !== KEM_PROFILE) {
    throw new Error('แฟ้มกุญแจสาธารณะไม่ใช่ของระบบนี้ (ต้องออกจาก kem keygen)');
  }
  const pk = fromB64(pub.public_key_b64, LEN.publicKey, 'กุญแจสาธารณะ ML-KEM');
  if (pub.public_key_sha256 && pub.public_key_sha256 !== sha256hex(pk)) {
    throw new Error('แฟ้มกุญแจสาธารณะไม่พ้องกันเอง (sha256 ไม่ตรง pk) — ห้ามใช้');
  }
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(pk);
  const key = sessionKey(sharedSecret);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    version: 1,
    alg: KEM_ALG,
    profile: KEM_PROFILE,
    created_at: new Date().toISOString(),
    recipient: {
      label: pub.label || 'recipient',
      public_key_sha256: pub.public_key_sha256 || sha256hex(pk),
    },
    encapsulated_cipher_b64: Buffer.from(cipherText).toString('base64'),
    nonce_b64: nonce.toString('base64'),
    auth_tag_b64: cipher.getAuthTag().toString('base64'),
    ciphertext_b64: ct.toString('base64'),
    plaintext_length: Buffer.byteLength(plaintext),
  };
}

// เปิดซองด้วยกุญแจลับของเจ้าของ — กุญแจผิด รูปแบบผิด หรือไบต์ใดถูกแก้ = ปฏิเสธทันที
export function openEnvelope(envelope, skB64) {
  if (!envelope || envelope.alg !== KEM_ALG || envelope.version !== 1 || envelope.profile !== KEM_PROFILE) {
    throw new Error('ซองไม่ตรงรูปแบบของระบบนี้ (alg/version/profile ไม่ตรง) — ปฏิเสธ');
  }
  const sk = fromB64(skB64, LEN.secretKey, 'กุญแจลับ ML-KEM');
  const encCipher = fromB64(envelope.encapsulated_cipher_b64, LEN.cipherText, 'encapsulated cipher (FIPS 203)');
  const nonce = Buffer.from(envelope.nonce_b64 || '', 'base64');
  if (nonce.length !== 12) throw new Error('nonce ของซองผิดรูปแบบ (ต้อง 12 ไบต์)');
  const authTag = Buffer.from(envelope.auth_tag_b64 || '', 'base64');
  if (authTag.length !== 16) throw new Error('authTag ของซองผิดรูปแบบ (ต้อง 16 ไบต์)');
  const ct = Buffer.from(envelope.ciphertext_b64 || '', 'base64');
  if (ct.length === 0) throw new Error('เนื้อหาเข้ารหัสในซองว่างเปล่า');
  // ตรวจก่อนถอดว่ากุญแจลับเป็นคู่ของผู้รับตาม sha256 ที่ผนึกไว้ — error ชี้เป้าได้ชัดกว่า GCM ทั่วไป
  if (envelope.recipient.public_key_sha256 !== sha256hex(Buffer.from(ml_kem768.getPublicKey(sk)))) {
    throw new Error('กุญแจลับไม่ใช่คู่ของกุญแจผู้รับในซอง (sha256 ไม่ตรง) — ซองนี้ไม่ได้ส่งถึงเรา');
  }
  let sharedSecret;
  try {
    sharedSecret = ml_kem768.decapsulate(encCipher, sk);
  } catch {
    throw new Error('ถอด encapsulation ไม่ได้ — ซองผิดรูปแบบ FIPS 203');
  }
  const decipher = createDecipheriv('aes-256-gcm', sessionKey(sharedSecret), nonce);
  decipher.setAuthTag(authTag);
  let plain;
  try {
    plain = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new Error('เปิดซองไม่ได้ — ซองไม่ผูกกับกุญแจนี้ หรือเนื้อหาถูกแก้ (GCM authTag ไม่ตรง)');
  }
  if (envelope.plaintext_length !== undefined && plain.length !== envelope.plaintext_length) {
    throw new Error('ประกาศขนาดเนื้อหาในซองไม่ตรงจริง — ปฏิเสธ');
  }
  return plain;
}

// ==== สายส่งมาตรฐาน (v1.7 · Q-02) — หน้าเส้นทางซองจาก metadata ล้วน ====
// ที่หมาย: โหนดขนส่งระหว่างกัน route แฟ้มได้โดยไม่มีกุญแจและไม่ผ่าน GCM แม้บิตเดียว — ไม่มีทางรั่วเนื้อหา
// ยืนยัน "ซองนี้ไปหาใคร" ด้วย public_key_sha256 คือการแมตช์แฟ้มกุญแจสาธารณะที่เครื่องถืออยู่เท่านั้น
export function envelopePublicInfo(envelope) {
  if (!envelope || typeof envelope !== 'object') {
    throw new Error('แฟ้มนี้ไม่ใช่ซอง sovereign (ไม่มีโครง JSON ของซอง)');
  }
  if (envelope.alg !== KEM_ALG) {
    throw new Error('ซองไม่ใช่อัลกอริทึมของระบบนี้ (alg: ' + JSON.stringify(envelope.alg) + ')');
  }
  if (envelope.version !== 1) {
    throw new Error('version ของซองไม่รองรับ: ' + JSON.stringify(envelope.version) + ' — ปฏิเสธเส้นทาง');
  }
  if (!envelope.recipient || typeof envelope.recipient.public_key_sha256 !== 'string' || envelope.recipient.public_key_sha256.length !== 64) {
    throw new Error('ซองไม่ระบุปลายทางผู้รับ (public_key_sha256) — เส้นทางไม่ได้');
  }
  const encCipher = Buffer.from(envelope.encapsulated_cipher_b64 || '', 'base64');
  const nonce = Buffer.from(envelope.nonce_b64 || '', 'base64');
  const authTag = Buffer.from(envelope.auth_tag_b64 || '', 'base64');
  const ct = Buffer.from(envelope.ciphertext_b64 || '', 'base64');
  const anomalies = [];
  if (encCipher.length !== LEN.cipherText) anomalies.push('encapsulated_cipher ผิดขนาด (' + encCipher.length + ' ไบต์ — มาตรฐาน FIPS 203 คือ ' + LEN.cipherText + ') — เปิดไม่ขึ้นทุกโหนด');
  if (nonce.length !== 12) anomalies.push('nonce ผิดขนาด (' + nonce.length + ' ไบต์ — มาตรฐาน 12)');
  if (authTag.length !== 16) anomalies.push('authTag ผิดขนาด (' + authTag.length + ' ไบต์ — มาตรฐาน 16)');
  if (ct.length === 0) anomalies.push('เนื้อหาเข้ารหัส (ciphertext) ว่างเปล่า');
  return {
    alg: envelope.alg,
    version: envelope.version,
    profile: envelope.profile || '',
    created_at: envelope.created_at || '(ไม่ระบุ)',
    recipient_label: envelope.recipient.label || '(ไม่มีชื่อ)',
    recipient_sha256: envelope.recipient.public_key_sha256,
    plaintext_length: typeof envelope.plaintext_length === 'number' ? envelope.plaintext_length : null,
    envelope_bytes: Buffer.byteLength(JSON.stringify(envelope)),
    encapsulated_cipher_bytes: encCipher.length,
    anomalies,
  };
}

// sha256 ของกุญแจสาธารณะจากแฟ้ม pub — คำนวณตรงจาก b64 (ไม่เชื่อ field ประกาศลอย) สำหรับเทียบเส้นทาง kem check
export function pubSha256(pubFile) {
  if (!pubFile || pubFile.profile !== KEM_PROFILE || typeof pubFile.public_key_b64 !== 'string') {
    throw new Error('แฟ้มกุญแจสาธารณะไม่ใช่ของระบบนี้ (ต้องออกจาก kem keygen)');
  }
  return sha256hex(Buffer.from(pubFile.public_key_b64, 'base64'));
}
