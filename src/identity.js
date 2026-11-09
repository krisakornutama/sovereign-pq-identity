// ตัวตนแบบนิรนาม — Ed25519 (ระบบปัจจุบัน) + ML-DSA-44 (FIPS 204, กันควอนตัม) + SLH-DSA-128s (FIPS 205, ชั้นเสริม v1.4)
// กุญแจทั้งชุดเกิดและอยู่บนเครื่องนี้ — ต้องไม่ออกจากเครื่องตามหลักโครงการ
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { slh_dsa_shake_128s } from '@noble/post-quantum/slh-dsa.js';
import { generateKeyPairSync } from 'node:crypto';
import { concatBytes } from '@noble/hashes/utils.js';
import { sha256Hex, enc, b64ok } from './util.js';

export const ALG_PROFILE = 'sovereign.ed25519+ml_dsa44.v1';                 // สองชั้น — ค่าเริ่มต้น เข้ากันได้กับ v1.0–v1.3
export const ALG_PROFILE_SLH = 'sovereign.ed25519+ml_dsa44+slh_dsa128s.v1'; // สามชั้น (v1.4 — ลายเซ็นชุดเสริม)

// ML-DSA-44 ตาม FIPS 204: pk = 1312 bytes, sk = 2560 bytes
export const ML_DSA_PK_LEN = ml_dsa44.lengths.publicKey;
export const ML_DSA_SK_LEN = ml_dsa44.lengths.secretKey;

// SLH-DSA-SHAKE-128s ตาม FIPS 205: pk = 32 bytes, sk = 64 bytes, sig = 7,856 bytes
export const SLH_PK_LEN = slh_dsa_shake_128s.lengths.publicKey;
export const SLH_SK_LEN = slh_dsa_shake_128s.lengths.secretKey;
export const SLH_SIG_LEN = slh_dsa_shake_128s.lengths.signature;

export function createIdentity({ label = 'anonymous', withSlh = false } = {}) {
  const ed = generateKeyPairSync('ed25519');
  const edSk = ed.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const edPk = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  const pq = ml_dsa44.keygen();
  const pqSk = Buffer.from(pq.secretKey).toString('base64');
  const pqPk = Buffer.from(pq.publicKey).toString('base64');

  const keys = {
    ed25519: { pk_b64: edPk, sk_b64: edSk },
    ml_dsa44: { pk_b64: pqPk, sk_b64: pqSk },
  };
  // หมายเลขตัวตนนิรนาม: hash ของกุญแจสาธารณะ "ทุกดอกในโปรไฟล์" — โปรไฟล์ต่างกัน = เลขต่างกันแน่นอน
  const pubParts = [Buffer.from(edPk, 'base64'), Buffer.from(pqPk, 'base64')];
  let algProfile = ALG_PROFILE;
  if (withSlh) {
    const slh = slh_dsa_shake_128s.keygen();
    keys.slh_dsa128s = {
      pk_b64: Buffer.from(slh.publicKey).toString('base64'),
      sk_b64: Buffer.from(slh.secretKey).toString('base64'),
    };
    pubParts.push(Buffer.from(slh.publicKey));
    algProfile = ALG_PROFILE_SLH;
  }
  const idHash = sha256Hex(concatBytes(...pubParts));
  const id = 'sps_' + idHash.slice(0, 20);

  return {
    version: 1,
    alg_profile: algProfile,
    id,
    label,
    created_at: new Date().toISOString(),
    keys,
  };
}

// โหลดจากแฟ้ม — ตรวจความยาวกุญแจตามโปรไฟล์ก่อนใช้เสมอ (ชำรุด = ปฏิเสธทันที)
export function loadIdentity(identityJson) {
  const err = (m) => { throw new Error('รูปแบบตัวตนไม่ถูกต้อง: ' + m); };
  if (!identityJson || typeof identityJson !== 'object') err('ไม่ใช่ object');
  const triple = identityJson.alg_profile === ALG_PROFILE_SLH;
  if (identityJson.alg_profile !== ALG_PROFILE && !triple) err('alg_profile ต่างจากระบบนี้');
  if (b64ok(identityJson.keys?.ed25519?.pk_b64) === false || !identityJson.keys?.ed25519?.sk_b64) err('กุญแจ Ed25519 ขาด');
  const pqPk = Buffer.from(identityJson.keys?.ml_dsa44?.pk_b64 || '', 'base64');
  const pqSk = Buffer.from(identityJson.keys?.ml_dsa44?.sk_b64 || '', 'base64');
  if (pqPk.length !== ML_DSA_PK_LEN) err(`ML-DSA public key ความยาว ${pqPk.length} ≠ ${ML_DSA_PK_LEN}`);
  if (pqSk.length !== ML_DSA_SK_LEN) err(`ML-DSA secret key ความยาว ${pqSk.length} ≠ ${ML_DSA_SK_LEN}`);
  if (triple) {
    const slhPk = Buffer.from(identityJson.keys?.slh_dsa128s?.pk_b64 || '', 'base64');
    const slhSk = Buffer.from(identityJson.keys?.slh_dsa128s?.sk_b64 || '', 'base64');
    if (slhPk.length !== SLH_PK_LEN) err(`SLH-DSA public key ความยาว ${slhPk.length} ≠ ${SLH_PK_LEN}`);
    if (slhSk.length !== SLH_SK_LEN) err(`SLH-DSA secret key ความยาว ${slhSk.length} ≠ ${SLH_SK_LEN}`);
  }
  if (!identityJson.id?.startsWith('sps_')) err('id ขาดรูปแบบ sps_*');
  return identityJson;
}

// ก่อเกิด public identity — ส่วนที่ใช้อ้างอิงโดยที่ไม่เปิดเผยตัวตน (สลิปอ้างหมายเลขนี้เท่านั้น)
export function publicView(identity) {
  const out = { id: identity.id, alg_profile: identity.alg_profile, ed25519_pk_b64: identity.keys.ed25519.pk_b64, ml_dsa44_pk_b64: identity.keys.ml_dsa44.pk_b64 };
  if (identity.keys.slh_dsa128s) out.slh_dsa128s_pk_b64 = identity.keys.slh_dsa128s.pk_b64;
  return out;
}

export { enc };
