// ระบบหมุนเวียนกุญแจ (v1.4) — เกิดตัวตนใหม่แทนชุดเดิม แล้วลงสายสกุล "กุญแจสาธารณะ" ที่ปลดใช้แล้ว
// หลักยืนยันที่ทำให้การหมุนปลอดภัย: ใบเสร็จเก่าฝังกุญแจสาธารณะไว้ในตัวเอง (pk_b64 คู่กับลายเซ็น) —
// ฉะนั้นหมุนกุญแจวันไหน ใบเดิมก็ยังตรวจผ่านได้ด้วยตัวเอง โดยไม่ต้องถือกุญแจใหม่ของผู้เซ็น
// แฟ้ม anchors เก็บแต่กุญแจสาธารณะล้วน (ไม่มี sk) — data/ ทั้งหมดอยู่นอก git
import fs from 'node:fs';
import nodePath from 'node:path';
import { createIdentity, publicView } from './identity.js';

// อายุตัวตนเป็นจำนวนวันเต็ม — คำนวณจากเวลาจริงของเครื่อง (created_at เป็น ISO เสมอ)
export function identityAgeDays(identity, now = new Date()) {
  const born = new Date(identity.created_at == null ? NaN : identity.created_at);
  if (Number.isNaN(born.getTime())) throw new Error('ตัวตนไม่มี created_at ที่อ่านได้ — หมุนกุญแจตามกำหนดอายุไม่ได้');
  return Math.floor((now.getTime() - born.getTime()) / 86_400_000);
}

// หมุนกุญแจ: สร้างตัวตนใหม่ (withSlh = เพิ่มชั้น SLH-DSA ขึ้นเป็นโปรไฟล์สามชั้น) + รายการปลดอายุของกุญแจเก่า
// คืน { next, anchor } — ผู้เรียกบันทึก vault ใหม่และแนบ anchor ลงแฟ้มสายสกุลเอง (ฟังก์ชันนี้ไม่แตะแฟ้ม)
export function rotateIdentity(oldIdentity, { withSlh = false, now = new Date() } = {}) {
  if (!oldIdentity || !oldIdentity.id) throw new Error('ตัวตนเดิมไม่ครบ (ไม่มี id) — หมุนกุญแจไม่ได้');
  const next = createIdentity({ label: oldIdentity.label, withSlh });
  const pksOld = publicView(oldIdentity);
  const anchor = {
    id_old: oldIdentity.id,
    id_new: next.id,
    alg_profile_old: oldIdentity.alg_profile,
    alg_profile_new: next.alg_profile,
    pks_old: {
      ed25519_pk_b64: pksOld.ed25519_pk_b64,
      ml_dsa44_pk_b64: pksOld.ml_dsa44_pk_b64,
      ...(pksOld.slh_dsa128s_pk_b64 ? { slh_dsa128s_pk_b64: pksOld.slh_dsa128s_pk_b64 } : {}),
    },
    old_created_at: oldIdentity.created_at,
    retired_at: now.toISOString(),
    reason: 'rotate',
  };
  return { next, anchor };
}

// แฟ้มสายสกุลกุญแจ (JSONL ต่อท้ายเสมอ เหมือนคลังใบเสร็จ) — สาธารณะทั้งแฟ้ม
export function loadAnchors(anchorsPath) {
  if (!fs.existsSync(anchorsPath)) return [];
  return fs.readFileSync(anchorsPath, 'utf8')
    .split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
}

export function appendAnchor(anchorsPath, anchor) {
  fs.mkdirSync(nodePath.dirname(anchorsPath), { recursive: true });
  fs.appendFileSync(anchorsPath, JSON.stringify(anchor) + '\n', 'utf8');
}
