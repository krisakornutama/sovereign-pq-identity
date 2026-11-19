// ใบเสร็จสองลายเซ็นตามโปรไฟล์:  Ed25519 + ML-DSA-44 (เดิม · FIPS 204) และเมื่อโปรไฟล์สามชั้นเพิ่ม SLH-DSA (FIPS 205 · 128s หรือ 128f)
// หลัก: verify ต้องผ่าน "ทุกชั้นของโปรไฟล์" ถึงนับว่ารายการสมบูรณ์ — ขาดตัวใดตัวหนึ่งไม่ตอบรับ
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { canonical, newReceiptId, enc } from './util.js';
import { ALG_PROFILE, ALG_PROFILE_SLH, ALG_PROFILE_SLH_FAST, ML_DSA_PK_LEN, slhVariantForProfile } from './identity.js';
import { edSign, edVerifyB64, readEdPriv } from './ed25519.js';

// ลายเซ็น ML-DSA/SLH-DSA ใช้ context (domain separation) เดียวกันแยกใช้งานจากคนอื่น
const PQ_CONTEXT = enc.encode('sovereign-pq-receipt/v1');
// โปรไฟล์ลายเซ็นอยู่ที่เดียว (identity.js) — re-export ให้คงรูป API เดิมของ receipt.js
export { ALG_PROFILE, ALG_PROFILE_SLH, ALG_PROFILE_SLH_FAST } from './identity.js';
// รุ่น SLH ที่ตรวจพบในใบ (null = ใบสองชั้น) — ให้ผู้เรียกอ่านชื่อชั้นได้โดยไม่ต้องเดา
export { slhVariantForProfile };

// bytes ที่ถูกเซ็น = canonical JSON ของแกน (id/issued_at/payload/alg_profile) ตัดลายเซ็นออก
export function coreBytes(envelope) {
  const { id, issued_at, payload, alg_profile } = envelope;
  return enc.encode(canonical({ id, issued_at, payload, alg_profile }));
}

export function signReceipt(identity, payload, { issued_at } = {}) {
  const slhVariant = slhVariantForProfile(identity.alg_profile);
  const envelope = {
    id: newReceiptId(),
    issued_at: issued_at || new Date().toISOString(),
    payload,
    alg_profile: identity.alg_profile,
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

  // 3) SLH-DSA ชั้นเสริมของโปรไฟล์สามชั้น (128s หรือ 128f ตาม alg_profile) — เซ็น bytes แกนเดียวกัน ผูกโดเมนเดียวกัน
  if (slhVariant) {
    const slhKeys = identity.keys[slhVariant.keyField];
    if (!slhKeys?.sk_b64) throw new Error(`ตัวตนโปรไฟล์ ${identity.alg_profile} ขาดกุญแจ ${slhVariant.keyField}`);
    const slhSig = slhVariant.impl.sign(bytes, Buffer.from(slhKeys.sk_b64, 'base64'), { context: PQ_CONTEXT });
    envelope.signatures[slhVariant.keyField] = {
      pk_b64: slhKeys.pk_b64,
      sig_b64: Buffer.from(slhSig).toString('base64'),
    };
  }
  return envelope;
}

export function verifyReceipt(envelope) {
  const out = { valid: false, ed25519: false, ml_dsa44: false, problems: [] };
  if (!envelope || typeof envelope !== 'object') { out.problems.push('ไม่ใช่ object'); return out; }
  if (!envelope.id || !envelope.issued_at || envelope.payload === undefined) {
    out.problems.push('แกนของใบเสร็จขาด (id/issued_at/payload)');
    return out;
  }
  const slhVariant = slhVariantForProfile(envelope.alg_profile);
  if (slhVariant) {
    out[slhVariant.keyField] = false; // แสดงชั้นเสริมตามโปรไฟล์ของใบเสร็จ
    out.slh_layer = slhVariant.keyField;
  }
  if (envelope.alg_profile && envelope.alg_profile !== ALG_PROFILE && !slhVariant) out.problems.push('alg_profile ไม่ตรงระบบนี้');

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

  // 3) SLH-DSA — เมื่อใบเป็นโปรไฟล์สามชั้น ต้องมีและผ่านด้วย (ขาด = ใบไม่สมบูรณ์)
  // ผู้ตรวจเลือกรุ่นจาก alg_profile ในใบเอง ไม่มีตารางตายตัว — ใบ 128s เก่ายังตรวจด้วยอิมพลีเมนต์เดิมเสมอ
  if (slhVariant) {
    const layer = sigs[slhVariant.keyField];
    if (!layer?.pk_b64 || !layer?.sig_b64) {
      out.problems.push(`ไม่มีลายเซ็น ${slhVariant.label}`);
    } else {
      try {
        const pk = Buffer.from(layer.pk_b64, 'base64');
        if (pk.length !== slhVariant.impl.lengths.publicKey) {
          out.problems.push(`${slhVariant.label} pk ความยาว ${pk.length} ≠ ${slhVariant.impl.lengths.publicKey}`);
        } else {
          out[slhVariant.keyField] = slhVariant.impl.verify(Buffer.from(layer.sig_b64, 'base64'), bytes, pk, { context: PQ_CONTEXT });
          if (!out[slhVariant.keyField]) out.problems.push(`ลายเซ็น ${slhVariant.label} ไม่ตรงข้อมูล`);
        }
      } catch (e) { out.problems.push(`${slhVariant.label} ตรวจไม่สำเร็จ: ` + e.message); }
    }
  }

  const slhOk = slhVariant ? out[slhVariant.keyField] === true : true;
  out.valid = out.ed25519 === true && out.ml_dsa44 === true && slhOk;
  return out;
}
