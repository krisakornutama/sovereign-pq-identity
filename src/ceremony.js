// 🎪 พิธี Groth16 หลายเครื่องจริง (multi-party ceremony chain) — v1.9 · Q-03
// แผ่นสายพิธี (ceremony sheet) = แฟ้ม JSON เดียวที่นำทางพิธีทั้งสาย:
//   หัว      : circuit/profile/curve/tool · pot (powers + sha256) · r1cs_sha256 · entropy_policy
//   สาย (chain) : หนึ่งแถวต่อหนึ่งขั้นจริง (setup / challenge-export / contribute / verify+seal)
//                 แต่ละแถวถือ h_prev = head ของสายก่อนแถวนี้ → สอดแทรก/ตัดทอน/สลับลำดับแถว = ตรวจจับได้
//   head    : hash ปลายสาย (ต้องตรงค่าที่คำนวณจากแถวทั้งหมดเสมอ)
// กฎสาย hash: H = SHA-256(โดเมน ‖ 0x00 ‖ h_prev ‖ 0x00 ‖ canonical(แถว)) — canonical เรียงคีย์ (util.js)
//        ทุกแถวจับ hash ทั้งหมดของแถว (ชื่อผู้ร่วม + hash zkey + hash challenge + เวลา) — แก้สิ่งใด = สายพังทันที
// ความปลอดภัยของพิธี: entropy สุ่มด้วย crypto.randomBytes ในหน่วยความจำ (CLI) — แฟ้มพิธีจด "ชื่อผู้ร่วม + sha256" เท่านั้น
//   แฟ้มขนส่งระหว่างเครื่อง: challenge/response + บัตร sha256 (`--expect-sha` ตรวจก่อนรวมเข้าสายเสมอ)
// โมดูลนี้ pure logic ล้วน (ไม่แตะ snarkjs) — ผูกการเรียก snarkjs อยู่ที่ cli.js (กิ่ง zk ceremony)
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { canonical, sha256Hex } from './util.js';

export const CEREMONY_FORMAT = 'sovereign.ceremony-chain.v1';
export const CEREMONY_VERSION = 1;
const CHAIN_DOMAIN = 'sovereign-ceremony-chain/v1';
export const CHAIN_HEAD_NULL = '0'.repeat(64); // จุดเริ่มสาย (ยังไม่มีแถว)

const HEX64 = /^[0-9a-f]{64}$/;
export const CEREMONY_STEPS = ['setup', 'challenge-export', 'contribute', 'verify-seal']; // ชนิดแถวตามกฎ

function sha256File(file) {
  return sha256Hex(fs.readFileSync(file));
}

// สร้างแผ่นสายพิธีใหม่ (เครื่องโค้งงานพิธี) — r1csFile/potFile ต้องมีจริงบนดิสก์ (จด hash ล้วน)
export function newCeremonySheet({ circuit, profile, r1csFile, potFile, potPowers, tool }) {
  for (const [name, f] of [['r1cs', r1csFile], ['pot', potFile]]) {
    if (!f || !fs.existsSync(f)) throw new Error('ไม่พบแฟ้ม ' + name + ': ' + f + ' — พิธีต้องเริ่มจากแฟ้มจริง');
  }
  return {
    format: CEREMONY_FORMAT,
    version: CEREMONY_VERSION,
    circuit,
    profile: profile || null,
    curve: 'bn254',
    tool: tool || null,
    created_at: new Date().toISOString(),
    r1cs_file: r1csFile,
    r1cs_sha256: sha256File(r1csFile),
    pot_file: potFile,
    pot_powers: potPowers || 14,
    pot_sha256: sha256File(potFile),
    entropy_policy: 'entropy ของทุกผู้ร่วมสุ่มจาก node:crypto.randomBytes ในหน่วยความจำและใช้แล้วทิ้งทันที — แฟ้มพิธีจดเฉพาะชื่อผู้ร่วมและ sha256 ห้ามบันทึก entropy ทางใด',
    work_zkey: null, // พาธแฟ้ม zkey บนเครื่องโค้งงาน (สถานะเครื่องฐาน — เครื่องผู้ร่วมไม่ต้องมี)
    chain: [],
    head: CHAIN_HEAD_NULL,
  };
}

// hash หนึ่งแถวของสาย: H(โดเมน ‖ 0x00 ‖ h_prev ‖ 0x00 ‖ canonical(เนื้อแถว))
export function ceremonyRowHash(head, body) {
  return sha256Hex(Buffer.concat([
    Buffer.from(CHAIN_DOMAIN, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(head, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonical(body), 'utf8'),
  ]));
}

// เติมแถวเข้าสาย — h_prev ผูกต่อจากหัวสายเดิม (หน้าถึงหลังติดกันเป็นเส้นยาว); คืนแถวที่เพิ่มและหัวใหม่ของสาย
// hash แถวคำนวณจาก "เนื้อแถวโดยไม่มี h_prev" — verify ตัด key เดิมก่อน hash (มาตรฐานเดียวทั้งสาย)
export function appendCeremonyRow(sheet, body) {
  if (!body || typeof body !== 'object') throw new Error('แถวต้องเป็น object');
  if (body.h_prev !== undefined) throw new Error('h_prev ห้ามปรุงเอง — ระบบผูกต่อจากหัวสายให้เอง');
  if (!CEREMONY_STEPS.includes(body.step)) throw new Error('ชนิดแถวไม่ตามกฎพิธี: ' + String(body.step));
  if (!body.contributor || typeof body.contributor !== 'string' || body.contributor.trim().length === 0) {
    throw new Error('แต่ละแถวต้องมีชื่อผู้ร่วม (contributor) — ไม่ยอมจดแถวไร้ชื่อ');
  }
  if (!body.ts) body.ts = new Date().toISOString();
  if (body.zkey_sha256 !== undefined && !HEX64.test(body.zkey_sha256)) throw new Error('zkey_sha256 ผิดรูป (ต้อง hex64)');
  if (body.contribution_sha256 !== undefined && !HEX64.test(body.contribution_sha256)) throw new Error('contribution_sha256 ผิดรูป (ต้อง hex64)');
  const row = { h_prev: sheet.head, ...body };
  const h = ceremonyRowHash(sheet.head, body);
  sheet.chain.push(row);
  sheet.head = h;
  return { row, head: h };
}

// ตรวจแผ่นสายพิธีทั้งแผ่น — ไร้กุญแจ (แค่ตรวจ hash) · options.files = true จะเทียบแฟ้มจริงที่ row.file ชี้
export function verifyCeremonyChain(sheet, options = {}) {
  const problems = [];
  if (!sheet || typeof sheet !== 'object') return { ok: false, problems: ['ไม่ใช่ object'], head: null, rows: 0 };
  if (sheet.format !== CEREMONY_FORMAT) problems.push('format ไม่ใช่แผ่นสายพิธีของระบบนี้');
  if (sheet.version !== CEREMONY_VERSION) problems.push('version ไม่ตรงรูปแบบแฟ้มพิธี (' + sheet.version + ' เทียบ ' + CEREMONY_VERSION + ')');
  if (!sheet.circuit || typeof sheet.circuit !== 'string' || sheet.circuit.trim().length === 0) problems.push('circuit หาย/ว่าง');
  if (sheet.curve !== 'bn254') problems.push('curve ผิด (ต้อง bn254 ตาม Groth16 ของด้านนี้)');
  for (const [n, h] of [['r1cs_sha256', sheet.r1cs_sha256], ['pot_sha256', sheet.pot_sha256]]) {
    if (!HEX64.test(String(h || ''))) problems.push(n + ' ไม่ใช่ hex64');
  }
  if (!Array.isArray(sheet.chain)) { problems.push('chain ไม่ใช่ array'); return { ok: false, problems, head: null, rows: 0 }; }

  let head = CHAIN_HEAD_NULL;
  sheet.chain.forEach((row, i) => {
    if (!row || typeof row !== 'object') { problems.push('แถวที่ ' + i + ' ไม่ใช่ object'); return; }
    if (!CEREMONY_STEPS.includes(row.step)) problems.push('แถวที่ ' + i + ' ชนิดผิด: ' + String(row.step));
    if (!row.contributor || String(row.contributor).trim().length === 0) problems.push('แถวที่ ' + i + ' ไม่มีชื่อผู้ร่วม');
    for (const f of ['zkey_sha256', 'contribution_sha256']) {
      if (row[f] !== undefined && !HEX64.test(String(row[f]))) problems.push('แถวที่ ' + i + ' ' + f + ' ไม่ใช่ hex64');
    }
    if (row.h_prev !== head) { problems.push('แถวที่ ' + i + ' h_prev ไม่ตรงหัวก่อนหน้า (ควร ' + head.slice(0, 12) + '…) แต่ได้ ' + String(row.h_prev).slice(0, 12) + '… — สายพิธีถูกตัดทอน/สลับลำดับ'); }
    const { h_prev, ...body } = row;
    let h;
    try { h = ceremonyRowHash(h_prev, body); } catch (e) { problems.push('แถวที่ ' + i + ' hash ไม่สำเร็จ: ' + e.message.slice(0, 72)); return; }
    head = h;
    if (options.files && row.step === 'setup' && row.file) {
      if (!fs.existsSync(row.file)) problems.push('แถวที่ ' + i + ' แฟ้มพาธแฟ้ม ' + row.file + ' ไม่อยู่บนดิสก์');
      else if (sha256File(row.file) !== String(row.zkey_sha256)) problems.push('แถวที่ ' + i + ' แฟ้มบนดิสก์ไม่ตรง hash ที่ประกาศ (zkey ถูกเปลี่ยน)');
    }
  });
  if (sheet.head !== head) problems.push('ปลายสายไม่ตรง (ประกาศ ' + String(sheet.head || '').slice(0, 12) + '… คำนวณเองได้ ' + head.slice(0, 12) + '…) — แผ่นพิธีถูกแก้ไข');
  return { ok: problems.length === 0, problems, head, rows: sheet.chain.length };
}

// ตรวจบัตรแลกแฟ้มตอบกลับของผู้ร่วม (response file) ก่อน merge — ผู้ร่วมต้องส่ง sha256 มาคู่แฟ้มเสมอ
export function responseShaMatches(responseFile, expectSha) {
  if (!fs.existsSync(responseFile)) return { ok: false, reason: 'ไม่พบแฟ้ม response' };
  const sha = sha256File(responseFile);
  return { ok: sha === expectSha, sha, reason: sha === expectSha ? null : 'sha256 ไม่ตรงที่ผู้ร่วมประกาศ (ต่างกันที่ ' + sha.slice(0, 12) + '… เทียบ ' + String(expectSha).slice(0, 12) + '…)' };
}
