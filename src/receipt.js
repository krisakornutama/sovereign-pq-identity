// ใบเสร็จสองลายเซ็น — Ed25519 (ตรวจได้ทุกเครื่องวันนี้) + ML-DSA-44 (กันควอนตัมล้วนแน่แท้ FIPS 204)
// หลัก: verify ต้องผ่าน "ทั้งสอง" ถึงนับว่ารายการสมบูรณ์ — ขาดตัวใดตัวหนึ่งไม่ตอบรับ
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { canonical, newReceiptId, enc } from './util.js';
import { ML_DSA_PK_LEN } from './identity.js';
import { edSign, edVerifyB64, readEdPriv } from './ed25519.js';

// ลายเซ็น ML-DSA ใช้ context (domain separation) แยกใช้งานจากคนอื่น
const PQ_CONTEXT = enc.encode('sovereign-pq-receipt/v1');
export const ALG_PROFILE = 'sovereign.ed25519+ml_dsa44.v1';

// bytes ที่ถูกเซ็น = canonical JSON ของแกน (id/issued_at/payload/alg_profile) ตัดลายเซ็นออก
export function coreBytes(envelope) {
  const { id, issued_at, payload, alg_profile } = envelope;
  return enc.encode(canonical({ id, issued_at, payload, alg_profile }));
}

export function signReceipt(identity, payload, { issued_at } = {}) {
  const envelope = {
    id: newReceiptId(),
    issued_at: issued_at || new Date().toISOString(),
    payload,
    alg_profile: ALG_PROFILE,
  };
  const bytes = coreBytes(envelope);

  // 1) Ed25519 (node:crypto)
  const edSig = edSign(readEdPriv(identity.keys.ed25519.sk_b64), bytes);

  // 2) ML-DSA-44 (FIPS 204) — context ต้องตรงกับตอน verify
  const pqSig = ml_dsa44.sign(bytes, Buffer.from(identity.keys.ml_dsa44.sk_b64, 'base64'), { context: PQ_CONTEXT });

  envelope.signatures = {
    ed25519: { pk_b64: identity.keys.ed25519.pk_b64, sig_b64: edSig.toString('base64') },
    ml_dsa44: { pk_b64: identity.keys.ml_dsa44.pk_b64, sig_b64: Buffer.from(pqSig).toString('base64') },
  };
  return envelope;
}

export function verifyReceipt(envelope) {
  const out = { valid: false, ed25519: false, ml_dsa44: false, problems: [] };
  if (!envelope || typeof envelope !== 'object') { out.problems.push('ไม่ใช่ object'); return out; }
  if (!envelope.id || !envelope.issued_at || envelope.payload === undefined) {
    out.problems.push('แกนของใบเสร็จขาด (id/issued_at/payload)');
    return out;
  }
  if (envelope.alg_profile && envelope.alg_profile !== ALG_PROFILE) out.problems.push('alg_profile ไม่ตรงระบบนี้');

  const bytes = coreBytes(envelope);
  const sigs = envelope.signatures || {};

  // 1) Ed25519
  if (!sigs.ed25519?.pk_b64 || !sigs.ed25519?.sig_b64) {
    out.problems.push('ไม่มีลายเซ็น Ed25519');
  } else {
    try {
      out.ed25519 = edVerifyB64(sigs.ed25519.pk_b64, bytes, Buffer.from(sigs.ed25519.sig_b64, 'base64'));
      if (!out.ed25519) out.problems.push('ลายเซ็น Ed25519 ไม่ตรงข้อมูล');
    } catch (e) { out.problems.push('Ed25519 ตรวจไม่สำเร็จ: ' + e.message); }
  }

  // 2) ML-DSA-44
  if (!sigs.ml_dsa44?.pk_b64 || !sigs.ml_dsa44?.sig_b64) {
    out.problems.push('ไม่มีลายเซ็น ML-DSA-44');
  } else {
    try {
      const pk = Buffer.from(sigs.ml_dsa44.pk_b64, 'base64');
      if (pk.length !== ML_DSA_PK_LEN) {
        out.problems.push(`ML-DSA pk ความยาว ${pk.length} ≠ ${ML_DSA_PK_LEN}`);
      } else {
        out.ml_dsa44 = ml_dsa44.verify(Buffer.from(sigs.ml_dsa44.sig_b64, 'base64'), bytes, pk, { context: PQ_CONTEXT });
        if (!out.ml_dsa44) out.problems.push('ลายเซ็น ML-DSA-44 ไม่ตรงข้อมูล');
      }
    } catch (e) { out.problems.push('ML-DSA ตรวจไม่สำเร็จ: ' + e.message); }
  }

  out.valid = out.ed25519 === true && out.ml_dsa44 === true;
  return out;
}
