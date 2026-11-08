// ตัวตนแบบนิรนาม — Ed25519 (ระบบปัจจุบัน) + ML-DSA-44 (FIPS 204, กันควอนตัม)
// กุญแจทั้งคู่เกิดและอยู่บนเครื่องนี้ — ต้องไม่ออกจากเครื่องตามหลักโครงการ
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { generateKeyPairSync } from 'node:crypto';
import { concatBytes } from '@noble/hashes/utils.js';
import { sha256Hex, enc, b64ok } from './util.js';

export const ALG_PROFILE = 'sovereign.ed25519+ml_dsa44.v1';

// ML-DSA-44 โดยตรงตาม FIPS 204: pk = 1312 bytes, sk = 2560 bytes
export const ML_DSA_PK_LEN = ml_dsa44.lengths.publicKey;
export const ML_DSA_SK_LEN = ml_dsa44.lengths.secretKey;

export function createIdentity({ label = 'anonymous' } = {}) {
  const ed = generateKeyPairSync('ed25519');
  const edSk = ed.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  const edPk = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

  const pq = ml_dsa44.keygen();
  const pqSk = Buffer.from(pq.secretKey).toString('base64');
  const pqPk = Buffer.from(pq.publicKey).toString('base64');

  // หมายเลขตัวตนนิรนาม: hash ของกุญแจสาธารณะคู่ → ไม่เก็บชื่อจริง (label ตั้งเอง อยู่ในเครื่องเท่านั้น)
  const idHash = sha256Hex(concatBytes(
    Buffer.from(edPk, 'base64'),
    Buffer.from(pqPk, 'base64'),
  ));
  const id = 'sps_' + idHash.slice(0, 20);

  return {
    version: 1,
    alg_profile: ALG_PROFILE,
    id,
    label,
    created_at: new Date().toISOString(),
    keys: {
      ed25519: { pk_b64: edPk, sk_b64: edSk },
      ml_dsa44: { pk_b64: pqPk, sk_b64: pqSk },
    },
  };
}

// โหลดจากแฟ้ม — ตรวจความยาวกุญแจก่อนใช้เสมอ (ชำรุด = ปฏิเสธทันที)
export function loadIdentity(identityJson) {
  const err = (m) => { throw new Error('รูปแบบตัวตนไม่ถูกต้อง: ' + m); };
  if (!identityJson || typeof identityJson !== 'object') err('ไม่ใช่ object');
  if (identityJson.alg_profile !== ALG_PROFILE) err('alg_profile ต่างจากระบบนี้');
  if (b64ok(identityJson.keys?.ed25519?.pk_b64) === false || !identityJson.keys?.ed25519?.sk_b64) err('กุญแจ Ed25519 ขาด');
  const pqPk = Buffer.from(identityJson.keys?.ml_dsa44?.pk_b64 || '', 'base64');
  const pqSk = Buffer.from(identityJson.keys?.ml_dsa44?.sk_b64 || '', 'base64');
  if (pqPk.length !== ML_DSA_PK_LEN) err(`ML-DSA public key ความยาว ${pqPk.length} ≠ ${ML_DSA_PK_LEN}`);
  if (pqSk.length !== ML_DSA_SK_LEN) err(`ML-DSA secret key ความยาว ${pqSk.length} ≠ ${ML_DSA_SK_LEN}`);
  if (!identityJson.id?.startsWith('sps_')) err('id ขาดรูปแบบ sps_*');
  return identityJson;
}

// ก่อเกิด public identity — ส่วนที่ใช้อ้างอิงโดยที่ไม่เปิดเผยตัวตน (สลิปอ้างหมายเลขนี้เท่านั้น)
export function publicView(identity) {
  return { id: identity.id, alg_profile: identity.alg_profile, ed25519_pk_b64: identity.keys.ed25519.pk_b64, ml_dsa44_pk_b64: identity.keys.ml_dsa44.pk_b64 };
}

export { enc };
