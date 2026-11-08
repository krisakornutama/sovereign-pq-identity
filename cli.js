#!/usr/bin/env node
// Sovereign PQ Identity — CLI ทุกคำสั่งทำงานในเครื่อง (offline 100%)
import fs from 'node:fs';
import { createIdentity, loadIdentity, publicView } from './src/identity.js';
import { signReceipt, verifyReceipt } from './src/receipt.js';
import { appendReceipt, listReceipts } from './src/ledger.js';

const IDENT = 'data/identity.json';
const LEDGER = 'data/receipts.jsonl';
const C = { g: (s) => `\x1b[32m${s}\x1b[0m`, y: (s) => `\x1b[33m${s}\x1b[0m`, r: (s) => `\x1b[31m${s}\x1b[0m`, b: (s) => `\x1b[36m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m` };

const [cmd, ...rest] = process.argv.slice(2);

function loadOrCreateIdentity() {
  if (fs.existsSync(IDENT)) {
    return loadIdentity(JSON.parse(fs.readFileSync(IDENT, 'utf8')));
  }
  const id = createIdentity({ label: 'demo' });
  fs.mkdirSync('data', { recursive: true });
  fs.writeFileSync(IDENT, JSON.stringify(id, null, 2));
  console.log(C.y('⚠ ไม่พบตัวตนเดิม — สร้างกุญแจคู่ใหม่ให้อัตโนมัติที่ ' + IDENT));
  return id;
}

function showVerify(v) {
  const mark = (b) => (b ? C.g('✓ ผ่าน') : C.r('✗ ไม่ผ่าน'));
  console.log(`  Ed25519   : ${mark(v.ed25519)}`);
  console.log(`  ML-DSA-44 : ${mark(v.ml_dsa44)}`);
  console.log(`  สรุป      : ${v.valid ? C.g('✓ ใบเสร็จถูกต้อง (ทั้งสองลายเซ็นตรวจผ่าน)') : C.r('✗ ใบเสร็จไม่สมบูรณ์')}`);
  for (const p of v.problems) console.log(C.dim('    • ' + p));
}

if (cmd === 'keygen') {
  const label = rest.join(' ') || 'sovereign';
  if (fs.existsSync(IDENT) && !process.argv.includes('--force')) {
    console.error(C.r('แฟ้มตัวตนมีอยู่แล้ว — ใช้ --force เพื่อทับ (กุญแจเดิมจะหาย)'));
    process.exit(1);
  }
  fs.mkdirSync('data', { recursive: true });
  fs.writeFileSync(IDENT, JSON.stringify(createIdentity({ label }), null, 2));
  const id = loadIdentity(JSON.parse(fs.readFileSync(IDENT, 'utf8')));
  console.log(C.g('✓ กุญแจคู่ Ed25519 + ML-DSA-44 สร้างที่ ' + IDENT));
  console.log('  หมายเลขตัวตนนิรนาม: ' + C.b(id.id) + C.dim('  (ไม่ผูกชื่อจริง — อ้างหมายเลขนี้อย่างเดียว)'));
  console.log(C.y('  ⚠ แฟ้มนี้คือกุญแจบ้านของคุณ: ห้าม commit · หายแล้วอ่านกลับไม่ได้'));
} else if (cmd === 'demo') {
  const id = loadOrCreateIdentity();
  const payload = {
    type: 'sale',
    customer: 'สาธิตในเครื่อง',
    items: [{ sku: 'PKY-5KG', name: 'ปุ๋ยอินทรีย์ 5 กก.', qty: 1, price_thb: 120 }],
    total_thb: 120.0,
    demo: true,
  };
  const env = signReceipt(id, payload);
  appendReceipt(LEDGER, env);
  const v = verifyReceipt(env);
  console.log(C.g('สร้างใบเสร็จสาธิต + เซ็นสองลายเซ็นแล้ว'));
  console.log('  ตัวตน     : ' + C.b(id.id) + C.dim(' (' + id.alg_profile + ')'));
  console.log('  หมายเลขใบ: ' + C.b(env.id));
  console.log('  เวลา     : ' + env.issued_at);
  console.log('  ยอด      : ฿' + payload.total_thb.toFixed(2));
  console.log('  บัญชีในเครื่อง: ' + LEDGER)
  ;
  showVerify(v);
  console.log(C.dim('  (payload ทั้งหมดเป็นข้อมูลสาธิตในเครื่อง ไม่มีข้อมูลจริง)'));
} else if (cmd === 'verify') {
  const file = rest[0];
  if (!file) { console.error('ใช้งาน: node cli.js verify <ใบเสร็จ.json>'); process.exit(1); }
  const v = verifyReceipt(JSON.parse(fs.readFileSync(file, 'utf8')));
  showVerify(v);
  process.exitCode = v.valid ? 0 : 1;
} else if (cmd === 'ledger') {
  const all = listReceipts(LEDGER);
  console.log(C.g(`คลังในเครื่องมี ${all.length} ใบ:`));
  for (const e of all) {
    const v = verifyReceipt(e);
    console.log(`  ${C.b(e.id)}  ${new Date(e.issued_at).toLocaleString('th-TH')}  ฿${(e.payload?.total_thb ?? 0).toFixed(2)}  ${v.valid ? C.g('✓') : C.r('✗')}`);
  }
} else if (cmd === 'selftest') {
  const mk = () => createIdentity({ label: 'selftest' }); // ตัวตนชั่วคราว — ไม่แตะแฟ้ม + คลังจริง
  const id = mk();
  const env = signReceipt(id, { demo: true, total_thb: 210.0 });
  const tampered = JSON.parse(JSON.stringify(env)); tampered.payload.total_thb = 2.1;
  const droppedPq = JSON.parse(JSON.stringify(env)); delete droppedPq.signatures.ml_dsa44;
  const cases = [
    ['เซ็นแล้วตรวจผ่าน (ทั้งสองลายเซ็น)', verifyReceipt(env).valid === true],
    ['แก้ payload → ต้องไม่ผ่าน', verifyReceipt(tampered).valid === false],
    ['ลบลายเซ็น ML-DSA → ต้องไม่ผ่าน', verifyReceipt(droppedPq).valid === false],
    ['ลายเซ็น Ed25519 ตรวจแยกขั้น', verifyReceipt(env).ed25519 === true],
    ['ลายเซ็น ML-DSA-44 ตรวจแยกขั้น', verifyReceipt(env).ml_dsa44 === true],
  ];
  let allOk = true;
  for (const [name, ok] of cases) {
    console.log(`  ${ok ? C.g('✓') : C.r('✗')} ${name}`);
    if (!ok) allOk = false;
  }
  process.exitCode = allOk ? 0 : 1;
} else {
  console.log(`Sovereign PQ Identity — การใช้งาน:
  node cli.js keygen "ชื่อเรียกเครื่องของฉัน"   สร้างตัวตน Ed25519 + ML-DSA-44 ในเครื่อง
  node cli.js demo                            จำลองขาย → เซ็นสองลายเซ็น → ตรวจ → ลงคลังในเครื่อง
  node cli.js verify <ใบเสร็จ.json>            ตรวจใบเสร็จ (exit 0 เมื่อผ่านทั้งคู่)
  node cli.js ledger                          อ่านคลังใบเสร็จในเครื่อง + ตรวจแต่ละใบ
  node cli.js selftest                        เทสต์ตัวเอง 5 เคส (ข้อมูลสาธิตล้วน)`);
}
