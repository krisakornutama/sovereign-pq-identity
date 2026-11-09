#!/usr/bin/env node
// พิธีกรรม Groth16 หลายฝ่าย (multi-party ceremony chain) — v1.5
//
// รัน: node scripts/ceremony.mjs          (สายพิธีปฐม: วงจร D=5 ทั้งสอง — contribute 2 ฝ่าย)
//
// สายพิธีต่อวงจร:
//   1) groth16 setup   — snarkjs.zKey.newZKey(r1cs, pot)              → แฟ้ม zkey ฐาน
//   2) contribute ×N   — snarkjs.zKey.contribute(prev, next, name, e)  → entropy สุ่มแยกทุกฝ่าย
//   3) zkey verify     — snarkjs.zKey.verifyFromR1cs(r1cs, pot, final) → ต้องได้ "ZKey Ok!"
//   4) export vkey     — snarkjs.zKey.exportVerificationKey(final)     → artifacts/<circuit>_vkey.json
//
// กฎความปลอดภัยของพิธี (โปรเจกต์นี้):
//   - entropy ของผู้ร่วมทุกฝ่าย = crypto.randomBytes(32) สุ่มในหน่วยความจำ ใช้แล้วทิ้งทันที
//     ห้ามบันทึกทางใดทางหนึ่ง — log ได้เฉพาะชื่อผู้ร่วม + sha256 ของแฟ้ม zkey
//   - แฟ้มระหว่างทางอยู่ใน build/ (นอก git ทั้งหมด); เข้า repo เฉพาะ artifacts สุดท้าย + ceremony.json
//   - ผู้สนใจต่อสายพิธีเพิ่มความเหลือเกิน: ต่อจาก artifacts/<circuit>.zkey ด้วย
//     npx snarkjs zkey contribute ... --name="<ชื่อคุณ>" — สายยิ่งยาว ความเชื่อมั่นยิ่งแตกหักยาก
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

const require = createRequire(import.meta.url);
const snarkjs = require('snarkjs');
const here = path.dirname(fileURLToPath(import.meta.url));
const snarkjsVersion = JSON.parse(fs.readFileSync(path.join(here, '..', 'node_modules', 'snarkjs', 'package.json'), 'utf8')).version;

const POT = 'build/pot14_final.ptau';        // Powers of Tau phase-2 prepared (สร้างเครื่องนี้ v1.2 — นอก git)
const PARTIES = ['local-a', 'local-b'];       // ชื่อผู้ร่วมพิธีชุดปฐม (entropy สุ่มแยกทุกครั้งที่รัน)
const WORK = 'build/ceremony';
const CIRCUITS = [
  { id: 'membership_d5', name: 'membership (โปรไฟล์ลึก D=5 — 32 ช่อง)', profile: 'membership_d5_v1' },
  { id: 'balance_d5',    name: 'balance threshold (โปรไฟล์ลึก D=5 — 32 ใบ)', profile: 'balance_d5_v1' },
];

const sha256 = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const bytes = (f) => fs.statSync(f).size;
const fmtB = (n) => n.toLocaleString('en-US');
const secs = (t0) => ((performance.now() - t0) / 1000).toFixed(1);
const bigintReplacer = (_k, v) => (typeof v === 'bigint' ? v.toString() : v);

const logg = {  // logger ตามสัญญาของ snarkjs (เอาต์พุตจริงของ snarkjs ออกทางนี้)
  info: (m) => console.log('   ·', m),
  error: (m) => console.error('   !', m),
  warn: (m) => console.warn('   …', m),
  debug: () => {},
};
const silent = { info: () => {}, error: console.error, warn: () => {}, debug: () => {} };

fs.mkdirSync(WORK, { recursive: true });
fs.mkdirSync('artifacts', { recursive: true });

const manifest = {
  protocol: 'groth16',
  curve: 'bn254',
  tool: 'snarkjs ' + snarkjsVersion,
  created_at: new Date().toISOString(),
  pot: {
    powers: 14,
    file: POT,
    sha256: sha256(POT),
    note: 'Powers of Tau เตรียม phase2 จากพิธีเครื่องนี้เอง (v1.2) — แฟ้มอยู่ใน build/ นอก git; zkey ของพิธีนี้เกิดบนฐาน pot14 ชุดเดียวกัน',
  },
  entropy_policy: 'entropy ของทุกฝ่ายสุ่มจาก node:crypto.randomBytes(32) ในหน่วยความจำและลบทิ้งทันทีเมื่อขั้นจบ — ไม่มีการบันทึกทางใด (log เฉพาะชื่อผู้ร่วม + sha256)',
  circuits: [],
};

console.log('🎪 พิธีกรรม Groth16 — pot14_final · ผู้ร่วม: ' + PARTIES.join(', '));
for (const c of CIRCUITS) {
  console.log(`\n=== ${c.id} (${c.name}) ===`);
  const profileBase = ['membership', 'balance'].find((p) => c.id.startsWith(p)) + '_d5_v1';
  const entry = { circuit: `circuits/${c.id}.circom`, profile: profileBase, name: c.name, started_at: new Date().toISOString(), chain: [] };

  const r1cs = path.join('build', c.id + '.r1cs');
  if (!fs.existsSync(r1cs)) throw new Error(`ไม่พบแฟ้ม r1cs: ${r1cs} — คอมไพล์วงจรก่อน (ดู README หัวข้อ "การสร้างแฟ้มวงจร")`);

  // 0) ขนาดวงจรจริงจากแฟ้ม r1cs
  const cir = await snarkjs.r1cs.info(r1cs, silent);
  entry.shape = { nConstraints: cir.nConstraints, nVars: cir.nVars, nPubInputs: cir.nPubInputs, nPrvInputs: cir.nPrvInputs, nOutputs: cir.nOutputs, nLabels: cir.nLabels };
  console.log(`   รูปทรง r1cs: ${fmtB(cir.nConstraints)} constraints · ${fmtB(cir.nVars)} vars`);

  const tAll = performance.now();

  // 1) โครง zkey (groth16 setup — ฐานพิธี)
  const t0 = performance.now();
  const step0 = path.join(WORK, c.id + '_0000.zkey');
  await snarkjs.zKey.newZKey(r1cs, POT, step0, logg);
  entry.chain.push({ step: 'setup (groth16 setup)', contributor: 'base (จาก pot14)', zkey_sha256: sha256(step0), seconds: Number(secs(t0)) });
  console.log(`   setup จบ (${secs(t0)} s) — sha256 zkey: ${sha256(step0).slice(0, 16)}…`);

  // 2) contribute ทีละฝ่าย — entropy ใหม่สำหรับทุกฝ่าย ใช้แล้วทิ้ง
  let prev = step0;
  for (const party of PARTIES) {
    const next = path.join(WORK, `${c.id}_contrib_${party}.zkey`);
    const t1 = performance.now();
    const entropy = crypto.randomBytes(32).toString('hex');  // อยู่ในหน่วยความจำเท่านั้น
    await snarkjs.zKey.contribute(prev, next, party, entropy, logg);
    entry.chain.push({ step: 'contribute', contributor: party, zkey_sha256: sha256(next), seconds: Number(secs(t1)) });
    console.log(`   contribute [${party}] จบ (${secs(t1)} s) — sha256 zkey: ${sha256(next).slice(0, 16)}…`);
    prev = next;
  }

  // 3) ตรวจสายพิธีกับ r1cs + pot — ต้องได้ "ZKey Ok!"
  const t2 = performance.now();
  const ok = await snarkjs.zKey.verifyFromR1cs(r1cs, POT, prev, logg);
  if (!ok) throw new Error(`zkey verify ไม่ผ่าน — หยุดพิธี ${c.id}`);
  entry.verified = true;
  entry.chain.push({ step: 'verify (zkey vs r1cs+pot)', contributor: 'snarkjs (ในเครื่องผู้รันพิธี)', result: ok ? 'ZKey Ok!' : 'FAILED', seconds: Number(secs(t2)) });
  console.log(`   verify: ZKey Ok! (${secs(t2)} s)`);

  // 4) export vkey + ส่งของเข้า artifacts/ (แชร์ที่ตรวจสอบได้)
  const vkey = await snarkjs.zKey.exportVerificationKey(prev, logg);
  const vkeyOut = `artifacts/${c.id}_vkey.json`;
  fs.writeFileSync(vkeyOut, JSON.stringify(vkey, bigintReplacer, 2));
  const zkeyOut = `artifacts/${c.id}.zkey`;
  fs.copyFileSync(prev, zkeyOut);
  const wasmSrc = path.join('build', `${c.id}_js`, `${c.id}.wasm`);
  const wasmOut = `artifacts/${c.id}.wasm`;
  fs.copyFileSync(wasmSrc, wasmOut);
  entry.artifacts = {
    zkey: { file: zkeyOut, bytes: bytes(zkeyOut), sha256: sha256(zkeyOut) },
    wasm: { file: wasmOut, bytes: bytes(wasmOut), sha256: sha256(wasmOut) },
    vkey: { file: vkeyOut, bytes: bytes(vkeyOut), sha256: sha256(vkeyOut), note: 'ผู้ตรวจถือแฟ้มนี้เท่านั้นก็ตรวจได้' },
  };
  entry.total_seconds = Number(((performance.now() - tAll) / 1000).toFixed(1));
  console.log(`   artifacts: ${zkeyOut} (${fmtB(bytes(zkeyOut))} B) · ${wasmOut} (${fmtB(bytes(wasmOut))} B) · ${vkeyOut}`);
  manifest.circuits.push(entry);
}

manifest.notes = [
  'พิธีนี้รันในเครื่องเดียว: ผู้ร่วมทุกชื่อในสายคือกระบวนการเดียวกันที่ entropy สุ่มแยกกัน — โครงสายรองรับผู้ร่วมจริง (ต่างเครื่อง) ได้ทุกจุดต่อขยาย',
  'ใบรับรองสาย = แฟ้มนี้ (ชื่อผู้ร่วม + sha256 ทุกขั้น) · แฟ้ม entropy ไม่มีอยู่ในโลกนี้',
];
fs.writeFileSync('artifacts/ceremony.json', JSON.stringify(manifest, bigintReplacer, 2) + '\n');
console.log('\n✓ พิธีจบตรงกันทวี — แฟ้มพิธีอยู่ที่ artifacts/ceremony.json · entropy ทางใดทางหนึ่งไม่ถูกเขียนลงดิสก์เลย');
