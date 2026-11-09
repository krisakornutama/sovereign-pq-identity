// ZK-SNARK pipeline — ครบชุด: พยาน (witness) → บทพิสูจน์ (Groth16) → ตรวจ (snarkjs)
// ตัวตนซ่อน: ผู้พิสูจน์ไม่ส่งกุญแจใดออกจากวงจร — ผู้ตรวจเห็นเพียง (root, epoch, nullifier, proof)
import fs from 'node:fs';
import nodePath from 'node:path';
import os from 'node:os';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');

// แฟ้มส่งอ้างอิงวงจร (เก็บใน repo — โหนดตรวจจำเป็นต้องมี vkey เท่านั้น)
export const ARTIFACTS = {
  wasm: 'artifacts/membership.wasm',
  zkey: 'artifacts/membership.zkey',
  vkey: 'artifacts/membership_vkey.json',
};

export function artifactsReady(base = process.cwd()) {
  return Object.values(ARTIFACTS).every((f) => fs.existsSync(nodePath.join(base, f)));
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
export async function proveMembership({ secret, path, root, epoch }) {
  if (!artifactsReady()) throw new Error('ยังไม่มีแฟ้มวงจรใน artifacts/ — ดูวิธีสร้างใน README หัวข้อ "การสร้างแฟ้มวงจร"');
  const inputs = witnessInputs({ secret, path, root, epoch });
  const tmp = fs.mkdtempSync(nodePath.join(os.tmpdir(), 'spq-wtns-'));
  try {
    const wtnsPath = nodePath.join(tmp, 'w.wtns');
    await snarkjs.wtns.calculate(inputs, ARTIFACTS.wasm, wtnsPath);
    const out = await snarkjs.groth16.prove(ARTIFACTS.zkey, wtnsPath, null, null);
    // ลำดับ publicSignals ของ snarkjs: [nullifierHash (output), merkleRoot, epochNonce]
    const [sigNullifier, sigRoot, sigEpoch] = out.publicSignals;
    if (sigRoot !== BigInt(root).toString(10)) throw new Error('root ใน publicSignals ไม่ตรงข้อมูลส่งเข้า');
    if (sigEpoch !== BigInt(epoch).toString(10)) throw new Error('epoch ใน publicSignals ไม่ตรงข้อมูลส่งเข้า');
    return { proof: out.proof, publicSignals: { nullifierHash: sigNullifier, merkleRoot: sigRoot, epochNonce: sigEpoch } };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

// ตรวจ — โหนดปลายทางไม่ต้องถือ zkey หรือกุญแจสมาชิกใด ๆ — ใช้ vkey ล้วน
export async function verifyMembership({ proof, publicSignals, vkeyPath = ARTIFACTS.vkey }) {
  const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
  const proofRaw = { pi_a: proof.pi_a, pi_b: proof.pi_b, pi_c: proof.pi_c };
  // ลำดับที่ snarkjs/vkey ต้องการ: [nullifierHash, merkleRoot, epochNonce]
  const signals = [publicSignals.nullifierHash, publicSignals.merkleRoot, publicSignals.epochNonce];
  return Boolean(await snarkjs.groth16.verify(vkey, signals, proofRaw));
}

// รูปแบบแฟ้มใบเสร็จนิรนาม (anon receipt)
export function anonReceipt({ proof, publicSignals, epoch, rootView }) {
  const rootHex = '0x' + BigInt(publicSignals.merkleRoot).toString(16);
  const nullHex = '0x' + BigInt(publicSignals.nullifierHash).toString(16);
  return {
    receiptId: 'pqri_anon_' + BigInt(publicSignals.nullifierHash).toString(16).slice(0, 8),
    authMode: 'zk-snark-groth16',
    circuit: 'membership_v1',
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
