#!/usr/bin/env node
// สายสร้างแฟ้มวงจรครบชุดต่อระดับ D (Q-04 · v2.2)
// generate (.circom) → compile (circom) → Groth16 setup/contribute/verify (snarkjs) → copy ไป artifacts/
//
// ใช้งาน:
//   node scripts/build-depth.mjs 6              สร้างชุด D=6 ทั้งสองวงจร (membership + balance)
//   node scripts/build-depth.mjs 6 membership   เฉพาะวงจรเดียว
//   node scripts/build-depth.mjs 7 --force      ออกพิธีใหม่แทนแฟ้ม D นั้น (entropy ใหม่ทั้งชุด)
//
// กฎความปลอดภัย (ตาม AGENTS.md ของ repo):
//   - entropy ของ zkey contribute สุ่มในหน่วยความจำ — ไม่บันทึก ไม่พิมพ์ ไม่ส่งไปที่ใดทั้งสิ้น
//   - แฟ้ม D=4 และ D=5 ที่ commit ไว้ (โปรไฟล์ฐาน/ลึก v1.5) ห้ามถูกแทน — สคริปต์ปฏิเสธ D ≤ 5 เด็ดขาด
//   - ptau ใช้ของเดิม build/pot14_final.ptau (ไม่ผลิตซ้ำ) — ความถูกต้องของ zkey ตรวจด้วย snarkjs zkey verify ตอนจบ
//   - ตรวจจำนวน constraints ≤ 2^14 ก่อน setup เสมอ (pot14 รับได้สูงสุด 2^14)
//   - แฟ้มที่ commit ได้ตามกฎ repo = wasm/zkey/vkey ใน artifacts/ (~2 MB/วงจร) — build/ กับ .tools/ gitignored ทั้งชั้น
import fs from 'node:fs';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';

const CIRCOM = '.tools/circom.exe';
const PTAU = 'build/pot14_final.ptau';
const CONSTRAINT_MAX = 2 ** 14; // pot14 รองรับสูงสุด
const KINDS = ['membership', 'balance'];
const D_MIN_BUILD = 6; // D=4/5 แฟ้ม commit ไว้ — ห้ามแตะ (ย้อนเข้ากันได้: ใบเก่าตรวจด้วย vkey เดิมตลอด)

const argv = process.argv.slice(2);
const force = argv.includes('--force');
const kinds = KINDS.filter((k) => argv.includes(k));
const d = Number(argv.find((a) => /^\d+$/.test(a)));
if (!Number.isInteger(d) || d < 4 || d > 12) {
  console.error('ใช้งาน: node scripts/build-depth.mjs <D> [--force] [membership] [balance]   (D ≥ ' + D_MIN_BUILD + ')');
  process.exit(1);
}
if (d < D_MIN_BUILD) {
  console.error('ปฏิเสธ D=' + d + ' — แฟ้ม D=4/D=5 commit ไว้แล้วและกำลังใช้ตรวจใบเก่า (ห้ามแทน · ดู AGENTS.md)');
  process.exit(1);
}
const useKinds = kinds.length ? kinds : KINDS;

const mb = (n) => (n / (1024 * 1024)).toFixed(2) + ' MB';
const existsAll = (files) => files.every((f) => fs.existsSync(f));

// ── อ่านจำนวน constraints จากแฟ้ม .r1cs (parse header เอง — ไม่พึ่ง lib เพิ่ม) ──
function r1csInfo(file) {
  const buf = fs.readFileSync(file);
  const fieldSize = buf.subarray(0, 4).toString('latin1') !== 'r1cs' ? 0 : 0; // magic ที่ 0-3
  void fieldSize;
  let off = 12; // magic(4) + version(4) + nSections(4)
  while (off + 12 <= buf.length) {
    const type = buf.readUInt32LE(off);
    const size = Number(buf.readBigUInt64LE(off + 4));
    if (type === 1) {
      const fsz = buf.readUInt32LE(off + 12);
      const p = off + 12;
      return {
        nWires: buf.readUInt32LE(p + 4 + fsz),
        nPubOut: buf.readUInt32LE(p + 8 + fsz),
        nPubIn: buf.readUInt32LE(p + 12 + fsz),
        nPrvIn: buf.readUInt32LE(p + 16 + fsz),
        nConstraints: buf.readUInt32LE(p + 28 + fsz),
      };
    }
    off += 12 + size;
  }
  throw new Error('อ่าน header ของ ' + file + ' ไม่ได้');
}

const run = (cmd, args, label) => {
  const t = Date.now();
  const r = spawnSync(cmd, args, { stdio: 'inherit', shell: cmd === 'npx' });
  if (r.status !== 0) {
    console.error('\nล้มที่ขั้น "' + label + '" (exit ' + r.status + ') — หยุดก่อนแตะ artifacts');
    process.exit(1);
  }
  return Date.now() - t;
};

if (!fs.existsSync(PTAU)) {
  console.error('ไม่พบ ' + PTAU + ' — สร้างก่อนตาม README หัวข้อ "การสร้างแฟ้มวงจร" (powersoftau 2^14)');
  process.exit(1);
}

const summary = [];
const tAll = Date.now();

for (const kind of useKinds) {
  const name = kind + '_d' + d; // รูปแฟ้ม D≥6: membership_d6.* ตาม precedent d5
  const cir = 'circuits/' + name + '.circom';
  const outArtifacts = ['artifacts/' + name + '.wasm', 'artifacts/' + name + '.zkey', 'artifacts/' + name + '_vkey.json'];

  console.log('\n══════ ' + kind + ' D=' + d + ' (' + name + ') ══════');
  const tKind = Date.now();
  if (existsAll(outArtifacts) && !force) {
    console.error('มีแฟ้มใน artifacts/ อยู่แล้ว — ปฏิเสธเพื่อกันแทนชุดที่ใช้งานจริง (ใช้ --force เพื่อออกพิธีใหม่)');
    process.exit(1);
  }

  // 1) generate .circom (deterministic — แฟ้มมีอยู่แล้วก็ตรวจย้อนตัวเอง)
  run('node', ['scripts/gen-circuits.mjs', String(d)], 'generate ' + cir);

  // 2) compile → build/<name>_js/<name>.wasm + build/<name>.r1cs
  const tCompile = run(CIRCOM, [cir, '--wasm', '--r1cs', '-o', 'build', '-l', 'node_modules'], 'compile');
  const wasmBuild = 'build/' + name + '_js/' + name + '.wasm';
  const r1csBuild = 'build/' + name + '.r1cs';
  if (!fs.existsSync(wasmBuild) || !fs.existsSync(r1csBuild)) {
    console.error('compile แล้วไม่เจอ ' + wasmBuild + ' / ' + r1csBuild);
    process.exit(1);
  }

  // 3) ตรวจ constraints ≤ 2^14 ก่อน setup เสมอ
  const info = r1csInfo(r1csBuild);
  console.log('  constraints: ' + info.nConstraints + ' (wires ' + info.nWires + ' · pubOut ' + info.nPubOut
    + ' · pubIn ' + info.nPubIn + ' · prvIn ' + info.nPrvIn + ') — ขีด pot14 = ' + CONSTRAINT_MAX);
  if (info.nConstraints > CONSTRAINT_MAX) {
    console.error('เกินขีด pot14 (' + info.nConstraints + ' > ' + CONSTRAINT_MAX + ') — ต้องใช้ ptau ใหญ่ขึ้น ห้าม setup ต่อ');
    process.exit(1);
  }

  // 4) Groth16 setup + contribute + verify — entropy สุ่มในหน่วยความจำ (ห้ามบันทึก/พิมพ์)
  const tSetup = run('npx', ['snarkjs', 'groth16', 'setup', r1csBuild, PTAU, 'build/' + name + '_0000.zkey'], 'groth16 setup');
  const entropy = crypto.randomBytes(48).toString('hex'); // ใช้แล้วทิ้ง — ไม่ลงไฟล์ ไม่ลง log
  const tContribute = run('npx', ['snarkjs', 'zkey', 'contribute', 'build/' + name + '_0000.zkey', 'build/' + name + '_final.zkey',
    '--name=local', '-v', '-e=' + entropy], 'zkey contribute');
  const tVerify = run('npx', ['snarkjs', 'zkey', 'verify', r1csBuild, PTAU, 'build/' + name + '_final.zkey'], 'zkey verify');
  const tVkey = run('npx', ['snarkjs', 'zkey', 'export', 'verificationkey', 'build/' + name + '_final.zkey', 'artifacts/' + name + '_vkey.json'], 'export vkey');

  // 5) copy ไป artifacts/
  fs.copyFileSync(wasmBuild, outArtifacts[0]);
  fs.copyFileSync('build/' + name + '_final.zkey', outArtifacts[1]);
  const tKindEnd = Date.now();
  const sizes = outArtifacts.slice(0, 2).map((f) => mb(fs.statSync(f).size)).join(' · ');
  summary.push(kind + ' D=' + d + ': wasm+zkey ' + sizes + ' (vkey ' + mb(fs.statSync(outArtifacts[2]).size)
    + ') · constraints ' + info.nConstraints + ' · เวลารวม ' + ((tKindEnd - tKind) / 1000).toFixed(1) + ' s'
    + ' (compile ' + (tCompile / 1000).toFixed(1) + ' · setup ' + (tSetup / 1000).toFixed(1)
    + ' · contribute ' + (tContribute / 1000).toFixed(1) + ' · verify ' + (tVerify / 1000).toFixed(1) + ')');
}

console.log('\n─── สรุป ───');
for (const s of summary) console.log('  ' + s);
console.log('ทั้งหมด ' + ((Date.now() - tAll) / 1000).toFixed(1) + ' s — ต่อด้วยเทสจริง: node cli.js zk tree --depth ' + d + ' → zk prove → zk verify');
