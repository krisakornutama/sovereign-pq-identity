// ZK-SNARK pipeline — ครบชุด: พยาน (witness) → บทพิสูจน์ (Groth16) → ตรวจ (snarkjs)
// ตัวตนซ่อน: ผู้พิสูจน์ไม่ส่งกุญแจใดออกจากวงจร — ผู้ตรวจเห็นเพียง (root, epoch, nullifier, proof)
import fs from 'node:fs';
import nodePath from 'node:path';
import os from 'node:os';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');

// แฟ้มส่งอ้างอิงวงจร (เก็บใน repo — โหนดตรวจจำเป็นต้องมี vkey เท่านั้น)
// โปรไฟล์ฐาน D=4 (16 ช่อง) — v1.2
export const ARTIFACTS = {
  wasm: 'artifacts/membership.wasm',
  zkey: 'artifacts/membership.zkey',
  vkey: 'artifacts/membership_vkey.json',
};

// โปรไฟล์ลึก D=5 (32 ช่อง) — v1.5: แฟ้มชุดของตัวเอง แยกชัดจากโปรไฟล์ฐาน (ใบเก่าตรวจด้วย vkey ชุดเดิมได้ตลอด)
export const ARTIFACTS_DEEP = {
  wasm: 'artifacts/membership_d5.wasm',
  zkey: 'artifacts/membership_d5.zkey',
  vkey: 'artifacts/membership_d5_vkey.json',
};

// ชื่อวงจรที่ลงในแฟ้มใบพิสูจน์ (field circuit) — ผู้ตรวจเลือก vkey จากฟิลด์นี้เอง
export const CIRCUIT = {
  membership: 'membership_v1',
  membershipDeep: 'membership_d5_v1',
  balance: 'balance_v1',
  balanceDeep: 'balance_d5_v1',
};

export function artifactsReadySet(arts, base = process.cwd()) {
  return Object.values(arts).every((f) => fs.existsSync(nodePath.join(base, f)));
}

export function artifactsReady(base = process.cwd()) {
  return artifactsReadySet(ARTIFACTS, base);
}

export function artifactsReadyDeep(base = process.cwd()) {
  return artifactsReadySet(ARTIFACTS_DEEP, base);
}

// แฟ้มวงจร balance threshold (วงจรที่ 2 — พิสูจน์ "ยอด ≥ threshold" โดยไม่เปิดยอดจริง)
// โปรไฟล์ลึก D=5 (32 ใบ) — v1.5
export const ARTIFACTS_BALANCE = {
  wasm: 'artifacts/balance.wasm',
  zkey: 'artifacts/balance.zkey',
  vkey: 'artifacts/balance_vkey.json',
};

export const ARTIFACTS_BALANCE_DEEP = {
  wasm: 'artifacts/balance_d5.wasm',
  zkey: 'artifacts/balance_d5.zkey',
  vkey: 'artifacts/balance_d5_vkey.json',
};

export function artifactsReadyBalance(base = process.cwd()) {
  return artifactsReadySet(ARTIFACTS_BALANCE, base);
}

export function artifactsReadyBalanceDeep(base = process.cwd()) {
  return artifactsReadySet(ARTIFACTS_BALANCE_DEEP, base);
}

// ส่งสัญญาณเข้าวงจร: ต้องเป็น string-decimal ทั้งหมด (รูปแบบที่ witness WASM อ่าน)
export function witnessInputs({ secret, path, root, epoch }) {
  return {
    identitySecret: BigInt(secret).toString(10),
    pathElements: path.elements.map((e) => BigInt(e).toString(10)),
    pathIndices: path.indices.map((b) => Number(b)),
    merkleRoot: BigInt(root).toString(10),
    epochNonce: BigInt(epoch).toString(10),
  };
}

// พิสูจน์ — คืน { proof, publicSignals } ตามรูปแบบใบพิสูจน์ของ snarkjs ({pi_a, pi_b, pi_c})
// artifacts: null = โปรไฟล์ฐาน D=4 · ARTIFACTS_DEEP = โปรไฟล์ลึก D=5 (v1.5 — ต้นไม้ 32 ช่อง)
export async function proveMembership({ secret, path, root, epoch, artifacts = null }) {
  const arts = artifacts || ARTIFACTS;
  if (!artifactsReadySet(arts)) throw new Error('ยังไม่มีแฟ้มวงจรใน artifacts/ — ดูวิธีสร้างใน README หัวข้อ "การสร้างแฟ้มวงจร"');
  const inputs = witnessInputs({ secret, path, root, epoch });
  const tmp = fs.mkdtempSync(nodePath.join(os.tmpdir(), 'spq-wtns-'));
  try {
    const wtnsPath = nodePath.join(tmp, 'w.wtns');
    await snarkjs.wtns.calculate(inputs, arts.wasm, wtnsPath);
    const out = await snarkjs.groth16.prove(arts.zkey, wtnsPath, null, null);
    // ลำดับ publicSignals ของ snarkjs: [nullifierHash (output), merkleRoot, epochNonce]
    const [sigNullifier, sigRoot, sigEpoch] = out.publicSignals;
    if (sigRoot !== BigInt(root).toString(10)) throw new Error('root ใน publicSignals ไม่ตรงข้อมูลส่งเข้า');
    if (sigEpoch !== BigInt(epoch).toString(10)) throw new Error('epoch ใน publicSignals ไม่ตรงข้อมูลส่งเข้า');
    return { proof: out.proof, publicSignals: { nullifierHash: sigNullifier, merkleRoot: sigRoot, epochNonce: sigEpoch } };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// ส่งสัญญาณเข้าวงจร balance: string-decimal ทั้งหมด (รูปแบบที่ witness WASM อ่าน)
export function balanceWitnessInputs({ balance, blinding, path, root, epoch, threshold }) {
  return {
    balance: BigInt(balance).toString(10),
    blinding: BigInt(blinding).toString(10),
    pathElements: path.elements.map((e) => BigInt(e).toString(10)),
    pathIndices: path.indices.map((b) => Number(b)),
    merkleRoot: BigInt(root).toString(10),
    epochNonce: BigInt(epoch).toString(10),
    threshold: BigInt(threshold).toString(10),
  };
}

// พิสูจน์ว่า "ยอด ≥ threshold" — ยอดจริงและตำแหน่งใบในต้นไม้คือความลับทั้งหมด
// (ยอดต่ำกว่า threshold วงจรปฏิเสธที่ witness เอง — ไม่มี proof ให้หลอกได้)
// artifacts: null = โปรไฟล์ฐาน D=4 · ARTIFACTS_BALANCE_DEEP = โปรไฟล์ลึก D=5 (v1.5)
export async function proveBalance({ balance, blinding, path, root, epoch, threshold, artifacts = null }) {
  const arts = artifacts || ARTIFACTS_BALANCE;
  if (!artifactsReadySet(arts)) throw new Error('ยังไม่มีแฟ้มวงจร balance ใน artifacts/ — ดูวิธีสร้างใน README หัวข้อ "การสร้างแฟ้มวงจร"');
  const inputs = balanceWitnessInputs({ balance, blinding, path, root, epoch, threshold });
  const tmp = fs.mkdtempSync(nodePath.join(os.tmpdir(), 'spq-wtns-'));
  try {
    const wtnsPath = nodePath.join(tmp, 'w.wtns');
    await snarkjs.wtns.calculate(inputs, arts.wasm, wtnsPath);
    const out = await snarkjs.groth16.prove(arts.zkey, wtnsPath, null, null);
    // ลำดับ publicSignals ของ snarkjs: [nullifierHash (output), merkleRoot, epochNonce, threshold]
    const [sigNullifier, sigRoot, sigEpoch, sigThreshold] = out.publicSignals;
    if (sigRoot !== BigInt(root).toString(10)) throw new Error('root ใน publicSignals ไม่ตรงข้อมูลส่งเข้า');
    if (sigEpoch !== BigInt(epoch).toString(10)) throw new Error('epoch ใน publicSignals ไม่ตรงข้อมูลส่งเข้า');
    if (sigThreshold !== BigInt(threshold).toString(10)) throw new Error('threshold ใน publicSignals ไม่ตรงข้อมูลส่งเข้า');
    return { proof: out.proof, publicSignals: { nullifierHash: sigNullifier, merkleRoot: sigRoot, epochNonce: sigEpoch, threshold: sigThreshold } };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// ตรวจ — โหนดปลายทางไม่ต้องถือ zkey หรือกุญแจสมาชิกใด ๆ — ใช้ vkey ล้วน
// vkeyPath: null = โปรไฟล์ฐาน D=4 · ระบุแฟ้มเฉพาะ = โปรไฟล์ลึก/อื่น
export async function verifyMembership({ proof, publicSignals, vkeyPath = null }) {
  const vkeyFile = vkeyPath || ARTIFACTS.vkey;
  const vkey = JSON.parse(fs.readFileSync(vkeyFile, 'utf8'));
  const proofRaw = { pi_a: proof.pi_a, pi_b: proof.pi_b, pi_c: proof.pi_c };
  // ลำดับที่ snarkjs/vkey ต้องการ: [nullifierHash, merkleRoot, epochNonce]
  const signals = [publicSignals.nullifierHash, publicSignals.merkleRoot, publicSignals.epochNonce];
  return Boolean(await snarkjs.groth16.verify(vkey, signals, proofRaw));
}

// ตรวจใบพิสูจน์ยอด — โหนดตรวจใช้ vkey ล้วน (ไม่รู้ตัวตน ไม่รู้ยอดจริง)
// vkeyPath: null = โปรไฟล์ฐาน D=4 · ระบุแฟ้มเฉพาะ = โปรไฟล์ลึก/อื่น
export async function verifyBalance({ proof, publicSignals, vkeyPath = null }) {
  const vkeyFile = vkeyPath || ARTIFACTS_BALANCE.vkey;
  const vkey = JSON.parse(fs.readFileSync(vkeyFile, 'utf8'));
  const proofRaw = { pi_a: proof.pi_a, pi_b: proof.pi_b, pi_c: proof.pi_c };
  // ลำดับที่ snarkjs/vkey ต้องการ: [nullifierHash, merkleRoot, epochNonce, threshold]
  const signals = [publicSignals.nullifierHash, publicSignals.merkleRoot, publicSignals.epochNonce, publicSignals.threshold];
  return Boolean(await snarkjs.groth16.verify(vkey, signals, proofRaw));
}

// รูปแบบแฟ้มใบพิสูจน์ยอดนิรนาม — ข้ออ้างเดียวที่ประกาศ: ยอด ≥ threshold (ไม่มียอดจริงหลุดลงแฟ้ม)
// circuit: 'balance_v1' (D=4) หรือ 'balance_d5_v1' (D=5 v1.5) — ผู้ตรวจใช้ฟิลด์นี้เลือก vkey เอง
export function balanceReceipt({ proof, publicSignals, epoch, threshold, circuit = 'balance_v1' }) {
  const rootHex = '0x' + BigInt(publicSignals.merkleRoot).toString(16);
  const nullHex = '0x' + BigInt(publicSignals.nullifierHash).toString(16);
  return {
    receiptId: 'pqri_thr_' + BigInt(publicSignals.nullifierHash).toString(16).slice(0, 8),
    authMode: 'zk-snark-groth16',
    circuit,
    issued_at: new Date().toISOString(),
    epochNonce: String(epoch),
    threshold: String(threshold),
    zkProof: {
      pi_a: proof.pi_a.map(String),
      pi_b: proof.pi_b.map((r) => r.map(String)),
      pi_c: proof.pi_c.map(String),
    },
    publicSignals: {
      merkleRoot: rootHex,
      nullifierHash: nullHex,
      epochNonce: String(epoch),
      threshold: String(threshold),
    },
  };
}

// รูปแบบแฟ้มใบเสร็จนิรนาม (anon receipt)
// circuit: 'membership_v1' (D=4) หรือ 'membership_d5_v1' (D=5 v1.5)
export function anonReceipt({ proof, publicSignals, epoch, rootView, circuit = 'membership_v1' }) {
  const rootHex = '0x' + BigInt(publicSignals.merkleRoot).toString(16);
  const nullHex = '0x' + BigInt(publicSignals.nullifierHash).toString(16);
  return {
    receiptId: 'pqri_anon_' + BigInt(publicSignals.nullifierHash).toString(16).slice(0, 8),
    authMode: 'zk-snark-groth16',
    circuit,
    issued_at: new Date().toISOString(),
    epochNonce: String(epoch),
    zkProof: {
      pi_a: proof.pi_a.map(String),
      pi_b: proof.pi_b.map((r) => r.map(String)),
      pi_c: proof.pi_c.map(String),
    },
    publicSignals: {
      merkleRoot: rootHex,
      nullifierHash: nullHex,
      epochNonce: String(epoch),
    },
    group: rootView ? { members: rootView.members } : undefined,
  };
}

// คลัง nullifier ฝั่งผู้ตรวจ — กันการใช้สิทธิ์รอบเดิมซ้ำ (double-claim)
export function loadNullifierLedger(ledgerPath) {
  if (!fs.existsSync(ledgerPath)) return [];
  return fs.readFileSync(ledgerPath, 'utf8')
    .split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
}

export function isNullifierSpent(ledger, nullifier, epoch, root) {
  return ledger.some((e) => e.nullifier === nullifier && e.epoch === Number(epoch) && e.root === root);
}

export function appendNullifier(ledgerPath, entry) {
  fs.mkdirSync(nodePath.dirname(ledgerPath), { recursive: true });
  fs.appendFileSync(ledgerPath, JSON.stringify(entry) + '\n', 'utf8');
}
