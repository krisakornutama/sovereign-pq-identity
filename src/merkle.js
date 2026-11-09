// ต้นไม้ Merkle ของสมาชิก — ใช้ Poseidon (BN254) เหมือนกับวงจรเป๊ะ
// แยกโดเมนด้วยแท็ก: leaf = P([secret, TAG_LEAF, 0]) · node = P([left, right, TAG_NODE]) · nullifier = P([secret, epoch, TAG_NULL])
// วงจร balance (v1.3) ใช้ต้นไม้เดียวกัน: ใบยอด = P([balance, blinding, TAG_BAL]) · nullifier ยอด = P([blinding, epoch, TAG_NULL_BAL])
// ทุกค่าอยู่ในช่วง BN254 p = 21888…617 (F.p) — การคำนวณฝั่ง JS ให้ได้ค่าตรงกับวงจรทุกขั้น

const _tags = { NODE: 0n, LEAF: 1n, NULL: 2n, BAL: 10n, NULL_BAL: 11n };

export const MERKLE_DEPTH = 4;      // โปรไฟล์ฐาน — ตรงวงจร membership.circom (Membership(4) = 16 ใบ)
export const MAX_MEMBERS = 2 ** MERKLE_DEPTH;
export const DEEP_DEPTH = 5;        // โปรไฟล์ลึก (v1.5) — ตรงวงจร *_d5.circom (Membership(5) = 32 ใบ)

let _poseidonCache = null;

// โหลด Poseidon (circomlibjs — พารามิเตอร์ตรงกับวงจร circomlib)
// คืน object: leafOf / nodeOf / nullifierOf / balanceLeafOf / balanceNullifierOf / F (field BN254 ไว้เทียบค่าตรง ๆ) / raw
export async function loadPoseidon() {
  if (_poseidonCache) return _poseidonCache;
  // circomlibjs เป็น CommonJS — ดึงผ่าน createRequire เพื่อความเสถียรกับ ESM
  const { createRequire } = await import('node:module');
  const require = createRequire(import.meta.url);
  const { buildPoseidon } = require('circomlibjs');
  const poseidon = await buildPoseidon();
  const toBig = (limbs) => poseidon.F.toObject(limbs); // Montgomery limbs → BigInt ปกติ

  _poseidonCache = {
    F: poseidon.F,
    p: poseidon.F.p,
    leafOf: (secretBig) => toBig(poseidon([secretBig, _tags.LEAF, 0n])),
    nodeOf: (left, right) => toBig(poseidon([left, right, _tags.NODE])),
    nullifierOf: (secretBig, epochBig) => toBig(poseidon([secretBig, epochBig, _tags.NULL])),
    balanceLeafOf: (balanceBig, blindingBig) => toBig(poseidon([balanceBig, blindingBig, _tags.BAL])),
    balanceNullifierOf: (blindingBig, epochBig) => toBig(poseidon([blindingBig, epochBig, _tags.NULL_BAL])),
    raw: poseidon,
  };
  return _poseidonCache;
}

// สุ่มกุญแจลับสมาชิก — 248 บิต (ต่ำกว่าโมดูลัส BN254 p ที่ยาว 254 บิต)
export function newMemberSecret(randomBytesFn) {
  const buf = randomBytesFn(31); // 248 บิต < BN254 p (254 บิต)
  return BigInt('0x' + Buffer.from(buf).toString('hex'));
}

// ต้นไม้คงเส้นคงวา: ลำดับใบ = ลำดับสมาชิก (ใบขาดช่วง ๆ ห้าม) — เติมช่องว่างด้วย 0
export function buildTree(commitments, poseidon, { depth = MERKLE_DEPTH } = {}) {
  const capacity = 2 ** depth;
  const leaves = commitments.map((c) => BigInt(c));
  if (leaves.length > capacity) {
    throw new Error(`สมาชิกเกินความจุแผนผัง (${leaves.length} > ${capacity}) — ปักรากโปรไฟล์ลึกขึ้น: zk tree --deep (D=5 = 32 ช่อง)`);
  }
  while (leaves.length < capacity) leaves.push(0n); // padding — ใบสมัครเว้นช่องว่าง

  const levels = [leaves];
  for (let d = 0; d < depth; d++) {
    const prev = levels[d];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) {
      next.push(poseidon.nodeOf(prev[i], prev[i + 1]));
    }
    levels.push(next);
  }
  return { depth, levels, root: levels[depth][0] };
}

// เส้นทางพิสูจน์สมาชิกอันดับ j — รูปร่างตรงกับวงจร (ทุกขั้น: sibling + บิตทิศทาง)
export function pathFor(tree, index) {
  const { depth, levels } = tree;
  if (index < 0 || index >= levels[0].length) throw new Error('อันดับสมาชิกใหญ่กว่า/น้อยกว่าต้นไม้');
  const elements = [];
  const indices = [];
  let idx = index;
  for (let d = 0; d < depth; d++) {
    const isRight = idx % 2 === 1;        // 1 = ฉันอยู่ขวา (ต้องส่งพี่น้องฝั่งซ้าย)
    const sibIdx = isRight ? idx - 1 : idx + 1;
    elements.push(levels[d][sibIdx]);
    indices.push(isRight ? 1 : 0);
    idx = Math.floor(idx / 2);
  }
  return { elements, indices };
}

// มุมมอง commitment สำหรับแฟ้ม JSON — เลขจำนวนใหญ่รูปแบบ string decimal
export function commitmentView(commitments) {
  return commitments.map((c, i) => ({ index: i, commitment: c.toString() }));
}

// ความจุตามโปรไฟล์ที่ปักในแฟ้มราก (field depth) — แฟ้มรากรุ่นเก่าไม่มี field นี้ = โปรไฟล์ฐาน (16)
export function capacityFromRootFile(rootJson) {
  const d = Number(rootJson?.depth);
  return Number.isInteger(d) && d >= 1 && d <= 12 ? 2 ** d : MAX_MEMBERS;
}

// ความลึกจากแฟ้มราก — แฟ้มเสีย/ไม่มี field = โปรไฟล์ฐาน (ให้ทำงานต่อได้อย่างเดิมเสมอ)
export function depthFromRootFile(rootJson) {
  const d = Number(rootJson?.depth);
  return Number.isInteger(d) && d >= 1 && d <= 12 ? d : MERKLE_DEPTH;
}
