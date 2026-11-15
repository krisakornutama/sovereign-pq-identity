#!/usr/bin/env node
// ตัวกำเนิดวงจรแบบพารามิเตอร์ (Q-04 · v2.2) — สร้าง .circom สำหรับ D ใดก็ได้จากแฟ้มต้นฉบับ
//
// หลัก: แหล่งความจริงเดียว = วงจรต้นฉบับใน repo (circuits/membership.circom · circuits/balance.circom)
//  generator แค่แทนพารามิเตอร์ D บรรทัด `component main … = Membership(4)` — โค้ดหลักเหมือนกันทุกบิต
//  แฟ้ม D=4 (ฐาน) และ D=5 ที่ commit ไว้เดิมไม่ถูกเขียนทับ — แฟ้ม generate มีแต่ D ใหม่ (D>=6)
// ย้อนเข้ากันได้: ใบเดิมทุกรูปตรวจด้วย vkey เดิมตลอด — generator ไม่แตะ artifacts ที่มี
//
// ใช้งาน:
//   node scripts/gen-circuits.mjs 6            สร้าง circuits/membership_d6.circom + circuits/balance_d6.circom
//   node scripts/gen-circuits.mjs 6 --recheck  พิสูจน์ย้อน: generate D=5 ต้องตรงแฟ้ม *_d5.circom ที่ commit ไว้
//                                              ทุกบรรทัดโค้ด (ไม่นับคอมเมนต์) — จบด้วย exit 0 เท่านั้น
//   node scripts/gen-circuits.mjs --list       แสดงระดับที่มีแฟ้มวงจร + artifacts พร้อมจริง
import fs from 'node:fs';

const D_MAX = 12; // ขีดของแผนผังที่ระบบยอมรับ (ตรง depthFromRootFile ใน src/merkle.js)

// ตัวจับบรรทัด main ของแต่ละวงจร (ตรงลิเทอรัลในแฟ้มต้นฉบับ — เบี่ยงเมื่อแฟ้มต้นฉบับถูกแก้ = หยุดทันที)
const SOURCES = [
  {
    kind: 'membership',
    src: 'circuits/membership.circom',
    mainLine: 'component main { public [merkleRoot, epochNonce] } = Membership(4);',
    makeMain: (d) => `component main { public [merkleRoot, epochNonce] } = Membership(${d});`,
    makeHead: (d) => [
      '// วงจร Anonymous Membership Verification — ZK-SNARK (Groth16) · โปรไฟล์ลึก D=' + d,
      '// generate จากต้นฉบับ membership.circom ด้วย scripts/gen-circuits.mjs — โค้ดหลักเหมือนต้นฉบับทุกบิต ต่างเฉพาะพารามิเตอร์ D',
      '// ห้ามแก้แฟ้มนี้ด้วยมือ — แก้ที่ต้นฉบับแล้วรัน generator ใหม่ (พิสูจน์ย้อนด้วย --recheck)',
      '//',
    ],
  },
  {
    kind: 'balance',
    src: 'circuits/balance.circom',
    mainLine: 'component main { public [merkleRoot, epochNonce, threshold] } = BalanceThreshold(4, 64);',
    makeMain: (d) => `component main { public [merkleRoot, epochNonce, threshold] } = BalanceThreshold(${d}, 64);`,
    makeHead: (d) => [
      '// วงจร Balance Threshold — ZK-SNARK (Groth16) · โปรไฟล์ลึก D=' + d,
      '// generate จากต้นฉบับ balance.circom ด้วย scripts/gen-circuits.mjs — โค้ดหลักเหมือนต้นฉบับทุกบิต ต่างเฉพาะพารามิเตอร์ D',
      '// ห้ามแก้แฟ้มนี้ด้วยมือ — แก้ที่ต้นฉบับแล้วรัน generator ใหม่ (พิสูจน์ย้อนด้วย --recheck)',
      '//',
    ],
  },
];

const isCommentLine = (l) => l.trim().startsWith('//');

function generateOne(spec, d) {
  const text = fs.readFileSync(spec.src, 'utf8');
  const lines = text.split('\n');
  const idx = lines.findIndex((l) => l.trim() === spec.mainLine);
  if (idx < 0) throw new Error('ไม่พบบรรทัด main ที่คาดไว้ใน ' + spec.src + ' — แฟ้มต้นฉบับถูกแก้? (เส้น: ' + spec.mainLine + ')');
  // ตัดคอมเมนต์หัวแฟ้ม (ก้อนแรกของบรรทัดคอมเมนต์/ว่างต่อเนื่อง) ออก แล้ววางหัวใหม่ + แทนบรรทัด main
  let first = 0;
  while (first < lines.length && (isCommentLine(lines[first]) || lines[first].trim() === '')) first++;
  const body = lines.slice(first).map((l) => (l.trim() === spec.mainLine ? spec.makeMain(d) : l));
  const out = [...spec.makeHead(d), ...body].join('\n');
  return { out };
}

function d5CodeLines(spec) {
  // แฟ้ม *_d5.circom ที่ commit ไว้ — คืนบรรทัดโค้ด (ไม่ใช่คอมเมนต์/ว่าง) เทียบกับ generate
  const file = 'circuits/' + spec.kind + '_d5.circom';
  return fs.readFileSync(file, 'utf8').split('\n').filter((l) => !isCommentLine(l) && l.trim() !== '');
}

// ── --list ──────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
if (argv.includes('--list')) {
  console.log('ระดับที่มีแฟ้มวงจร + artifacts พร้อมจริง:');
  for (const spec of SOURCES) {
    const rows = [];
    for (let d = 4; d <= D_MAX; d++) {
      const cir = d === 4 ? 'circuits/' + spec.kind + '.circom' : 'circuits/' + spec.kind + '_d' + d + '.circom';
      const suf = d === 4 ? '' : '_d' + d;
      const wasm = 'artifacts/' + spec.kind + suf + '.wasm';
      const zkey = 'artifacts/' + spec.kind + suf + '.zkey';
      const vkey = 'artifacts/' + spec.kind + suf + '_vkey.json';
      const ready = [wasm, zkey, vkey].every((f) => fs.existsSync(f));
      rows.push('D=' + d + ': วงจร' + (fs.existsSync(cir) ? '✓' : '—') + ' · artifacts' + (ready ? '✓' : '—'));
    }
    console.log('  ' + spec.kind + ': ' + rows.join('  ·  '));
  }
  process.exit(0);
}

// ── --recheck: พิสูจน์ย้อน D=5 ──────────────────────────────────────────────
if (argv.includes('--recheck')) {
  let ok = true;
  for (const spec of SOURCES) {
    const { out } = generateOne(spec, 5);
    const d5 = d5CodeLines(spec);
    const genFree = out.split('\n').filter((l) => !isCommentLine(l) && l.trim() !== '');
    if (genFree.length !== d5.length) {
      console.error('FAIL ' + spec.kind + ': จำนวนบรรทัดโค้ดไม่ตรง (gen ' + genFree.length + ' vs d5 ' + d5.length + ')');
      ok = false;
      continue;
    }
    for (let i = 0; i < d5.length; i++) {
      if (genFree[i] !== d5[i]) {
        console.error('FAIL ' + spec.kind + ' บรรทัดโค้ดที่ ' + (i + 1) + ':\n  gen: ' + genFree[i] + '\n  d5 : ' + d5[i]);
        ok = false;
        break;
      }
    }
    if (ok) console.log('PASS ' + spec.kind + ': generate D=5 ตรงแฟ้ม ' + spec.kind + '_d5.circom ทุกบรรทัดโค้ด (ไม่นับคอมเมนต์)');
  }
  process.exit(ok ? 0 : 1);
}

// ── สร้างแฟ้มระดับ D ────────────────────────────────────────────────────────
const d = Number(argv[0]);
if (!Number.isInteger(d) || d < 4 || d > D_MAX) {
  console.error('ใช้งาน: node scripts/gen-circuits.mjs <D>  (4 ≤ D ≤ ' + D_MAX + ') หรือ --recheck / --list');
  process.exit(1);
}

for (const spec of SOURCES) {
  const target = 'circuits/' + spec.kind + '_d' + d + '.circom';
  if (d === 4) {
    console.log('SKIP ' + spec.kind + ' D=4 — แฟ้มต้นฉบับ ' + spec.src + ' คือโปรไฟล์ฐาน (ไม่สร้างซ้ำ)');
    continue;
  }
  if (fs.existsSync(target)) {
    // แฟ้มมีอยู่แล้ว = regenerate ตรวจย้อนกลับตัวเอง (ต้องได้เนื้อหาเดิม — generator deterministic)
    const { out } = generateOne(spec, d);
    const old = fs.readFileSync(target, 'utf8');
    if (old !== out) { console.error('FAIL ' + target + ' — regenerate ได้เนื้อหาไม่ตรงของเดิม (แฟ้มถูกแก้มือ?)'); process.exit(1); }
    console.log('OK ' + target + ' — มีอยู่แล้ว ตรงกับ generate ใหม่พอดี');
    continue;
  }
  const { out } = generateOne(spec, d);
  fs.writeFileSync(target, out);
  console.log('สร้าง ' + target + '  (' + out.length + ' chars)');
}
console.log('เสร็จ — ต่อด้วย: node scripts/build-depth.mjs ' + d);
