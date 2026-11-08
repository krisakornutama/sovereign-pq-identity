#!/usr/bin/env node
// Sovereign PQ Identity — CLI ทุกคำสั่งทำงานในเครื่อง (offline 100%)
// กุญแจจริงถูกเก็บใน Vault เข้ารหัส Argon2id + AES-256-GCM โดยดั้งเดิม
import fs from 'node:fs';
import path from 'node:path';
import { createIdentity, loadIdentity, publicView } from './src/identity.js';
import { signReceipt, verifyReceipt } from './src/receipt.js';
import { appendReceipt, listReceipts } from './src/ledger.js';
import { createVault, openVault, vaultSummary } from './src/vault.js';
import { readPassphrase, passphraseFromEnv } from './src/password.js';
import { canonical } from './src/util.js';

const IDENT = 'data/identity.json';
const VAULT = 'data/identity.vault.json';
const LEDGER = 'data/receipts.jsonl';
const C = { g: (s) => `\x1b[32m${s}\x1b[0m`, y: (s) => `\x1b[33m${s}\x1b[0m`, r: (s) => `\x1b[31m${s}\x1b[0m`, b: (s) => `\x1b[36m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m` };

const [cmd, ...rest] = process.argv.slice(2);

async function getPassphrase(confirm = false) {
  if (passphraseFromEnv()) return passphraseFromEnv();
  const p1 = await readPassphrase('  ตั้ง passphrase (ต่ำสุด 8 ตัว): ');
  if (p1.length < 8) { console.error(C.r('  ✗ passphrase สั้นเกินไป')); process.exit(1); }
  if (confirm) {
    const p2 = await readPassphrase('  พิมพ์ซ้ำอีกครั้ง: ');
    if (p1 !== p2) { console.error(C.r('  ✗ สองรอบไม่ตรงกัน — ยกเลิก ไม่ได้เขียนแฟ้มใด ๆ')); process.exit(1); }
  }
  return p1;
}

async function openVaultFile() {
  if (!fs.existsSync(VAULT)) return null;
  let passphrase = passphraseFromEnv();
  if (!passphrase) passphrase = await readPassphrase('  passphrase ของ vault: ');
  try {
    const identity = openVault(JSON.parse(fs.readFileSync(VAULT, 'utf8')), passphrase);
    return loadIdentity(identity);
  } catch (e) {
    console.error(C.r('  ✗ ' + e.message));
    process.exit(1);
  }
}

// โหลดตัวตนเพื่อทำงาน: vault ก่อนเสมอ → ถ้าไม่มี plaintext (แจ้งเตือนว่าควร migrate) → ถ้าไม่มีเลยสร้างใหม่ใน vault
async function loadOrCreateIdentity() {
  const fromVault = await openVaultFile();
  if (fromVault) return { identity: fromVault, source: 'vault' };

  if (fs.existsSync(IDENT)) {
    console.log(C.y('⚠ ยังใช้แฟ้ม plaintext (' + IDENT + ') — แนะนำ run: node cli.js vault create'));
    return { identity: loadIdentity(JSON.parse(fs.readFileSync(IDENT, 'utf8'))), source: 'plain' };
  }

  console.log(C.y('⚠ ยังไม่มีตัวตน — สร้างใหม่ + เก็บเข้า Vault เข้ารหัส'));
  console.log(C.dim('  (จำ passphrase ให้ดี — ลืม = อ่านกุญแจกลับไม่ได้)'));
  const passphrase = await getPassphrase(false);
  const id = createIdentity({ label: 'sovereign' });
  fs.mkdirSync('data', { recursive: true });
  fs.writeFileSync(VAULT, JSON.stringify(createVault(id, passphrase), null, 2));
  console.log(C.g('  ✓ ตัวตนถูกเก็บใน vault แล้ว (Argon2id + AES-256-GCM)'));
  return { identity: id, source: 'new-vault' };
}

function showVerify(v) {
  const mark = (b) => (b ? C.g('✓ ผ่าน') : C.r('✗ ไม่ผ่าน'));
  console.log(`  Ed25519   : ${mark(v.ed25519)}`);
  console.log(`  ML-DSA-44 : ${mark(v.ml_dsa44)}`);
  console.log(`  สรุป      : ${v.valid ? C.g('✓ ใบเสร็จถูกต้อง (ทั้งสองลายเซ็นตรวจผ่าน)') : C.r('✗ ใบเสร็จไม่สมบูรณ์')}`);
  for (const p of v.problems) console.log(C.dim('    • ' + p));
}

function writeVaultFile(identity, passphrase) {
  fs.mkdirSync(path.dirname(VAULT), { recursive: true });
  fs.writeFileSync(VAULT, JSON.stringify(createVault(identity, passphrase), null, 2));
}

if (cmd === 'keygen') {
  const label = rest.join(' ') || 'sovereign';
  if (fs.existsSync(VAULT) || fs.existsSync(IDENT)) {
    console.error(C.r('ตัวตนมีอยู่แล้ว — ลบแฟ้มเดิมก่อนถ้าตั้งใจสร้างใหม่ (ระวัง: กุญแจเดิมจะหาย)'));
    process.exit(1);
  }
  console.log('สร้างกุญแจคู่ Ed25519 + ML-DSA-44 แล้วเก็บเข้า Vault เข้ารหัส');
  console.log(C.dim('(จำ passphrase ให้ดี — ลืมแล้วอ่านกุญแจกลับไม่ได้)'));
  fs.mkdirSync('data', { recursive: true });
  const passphrase = await getPassphrase(true);
  const id = createIdentity({ label });
  writeVaultFile(id, passphrase);
  console.log(C.g('✓ กุญแจคู่สร้างเสร็จ + เก็บใน vault: ' + VAULT));
  console.log('  หมายเลขตัวตนนิรนาม: ' + C.b(id.id) + C.dim('  (ไม่ผูกชื่อจริง — อ้างหมายเลขนี้อย่างเดียว)'));
  console.log('  KDF: Argon2id ' + JSON.stringify(vaultSummary(JSON.parse(fs.readFileSync(VAULT, 'utf8'))).params));
  console.log(C.y('  ⚠ passphrase ไม่ถูกบันทึกที่ไหน: ลืม = ไม่มีทางกู้คืน'));
} else if (cmd === 'demo') {
  const { identity: id, source } = await loadOrCreateIdentity();
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
  const keyNote = source === 'plain' ? '' : ' (กุญแจถอดออกจาก vault ในหน่วยความจำเท่านั้น)';
  console.log(C.g('สร้างใบเสร็จสาธิต + เซ็นสองลายเซ็นแล้ว' + keyNote));
  console.log('  ตัวตน     : ' + C.b(id.id) + C.dim(' (' + id.alg_profile + ')'));
  console.log('  หมายเลขใบ: ' + C.b(env.id));
  console.log('  เวลา     : ' + env.issued_at);
  console.log('  ยอด      : ฿' + payload.total_thb.toFixed(2));
  console.log('  คลังในเครื่อง: ' + LEDGER);
  showVerify(v);
  console.log(C.dim('  (payload ทั้งหมดเป็นข้อมูลสาธิตในเครื่อง ไม่มีข้อมูลจริง)'));
} else if (cmd === 'verify') {
  const file = rest[0];
  if (!file) { console.error('ใช้งาน: node cli.js verify <แฟ้มใบเสร็จ.json>'); process.exit(1); }
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
} else if (cmd === 'vault') {
  const sub = rest[0] || 'help';
  if (sub === 'create') {
    if (!fs.existsSync(IDENT)) { console.error(C.r('ไม่พบแฟ้ม plaintext ' + IDENT + ' — สร้างด้วย keygen หรือไม่ต้อง migrate (กุญแจสร้างใหม่เก็บ vault อัตโนมัติแล้ว)')); process.exit(1); }
    const identity = loadIdentity(JSON.parse(fs.readFileSync(IDENT, 'utf8')));
    console.log('ย้ายกุญแจจากแฟ้ม plaintext → vault เข้ารหัส (แฟ้ม plaintext จะยังอยู่ จนสร้าง vault สำเร็จ)');
    const passphrase = await getPassphrase(true);
    writeVaultFile(identity, passphrase);
    // ทดสอบว่าเปิดกลับได้จริงก่อนอวยวัด
    openVault(JSON.parse(fs.readFileSync(VAULT, 'utf8')), passphrase);
    console.log(C.g('✓ เตรียมเสร็จ: vault ' + VAULT + ' ตรวจเปิดกลับผ่าน'));
    console.log(C.y('  ✍ ต่อไป: ลบแฟ้ม plaintext เอง หรือ run: node cli.js vault remove-plain'));
  } else if (sub === 'open') {
    const id = await openVaultFile();
    if (!id) { console.error(C.r('ยังไม่มี vault — รัน keygen หรือ vault create ก่อน')); process.exit(1); }
    console.log(C.g('✓ เปิด vault ได้จริง (กุญแจอยู่ในหน่วยความจำเฉพาะกระบวนการนี้)'));
    console.log('  ตัวตน : ' + C.b(id.id) + '  ·  KDF: ' + vaultSummary(JSON.parse(fs.readFileSync(VAULT, 'utf8'))).kdf);
    console.log(C.dim('  กุญแจ public: Ed25519 ' + id.keys.ed25519.pk_b64.slice(0, 12) + '… / ML-DSA-44 ' + id.keys.ml_dsa44.pk_b64.slice(0, 12) + '…'));
  } else if (sub === 'remove-plain') {
    if (!fs.existsSync(VAULT)) { console.error(C.r('ยังไม่มี vault — ห้ามลบ plaintext อย่างเดียว (ห้ามแห้งข้ามแน่)')); process.exit(1); }
    const pass = await getPassphrase(false) || passphraseFromEnv();
    openVault(JSON.parse(fs.readFileSync(VAULT, 'utf8')), pass); // ตรวจว่า vault เปิดได้จริงก่อนลบ
    fs.rmSync(IDENT);
    console.log(C.g('✓ ลบแฟ้ม plaintext แล้ว — กุญแจอยู่ใน vault เข้ารหัสเท่านั้น'));
  } else {
    console.log([
      'คำสั่ง vault:',
      '  node cli.js vault create      ย้ายกุญแจจากแฟ้ม plaintext → vault เข้ารหัส',
      '  node cli.js vault open        ทดสอบว่า vault เปิดได้ด้วย passphrase จริง',
      '  node cli.js vault remove-plain ลบแฟ้ม plaintext หลัง vault พร้อม',
    ].join('\n'));
  }
} else if (cmd === 'selftest') {
  // ทุกเคสใช้ข้อมูลจำลองล้วน — ไม่แตะแฟ้ม + คลังจริง
  const id = createIdentity({ label: 'selftest' });
  const env = signReceipt(id, { demo: true, total_thb: 210.0 });
  const tampered = JSON.parse(JSON.stringify(env)); tampered.payload.total_thb = 2.1;
  const droppedPq = JSON.parse(JSON.stringify(env)); delete droppedPq.signatures.ml_dsa44;
  const vaultJson = createVault({ ...id, keys: { ...id.keys } }, 'test-passphrase-8', { params: { m: 1024, t: 1, p: 1 } });
  const cases = [
    ['เซ็นแล้วตรวจผ่าน (ทั้งสองลายเซ็น)', verifyReceipt(env).valid === true],
    ['แก้ payload → ต้องไม่ผ่าน', verifyReceipt(tampered).valid === false],
    ['ลบลายเซ็น ML-DSA → ต้องไม่ผ่าน', verifyReceipt(droppedPq).valid === false],
    ['ลายเซ็น Ed25519 ตรวจแยกขั้น', verifyReceipt(env).ed25519 === true],
    ['ลายเซ็น ML-DSA-44 ตรวจแยกขั้น', verifyReceipt(env).ml_dsa44 === true],
    ['vault: เข้ารหัส→ถอดรหัส กลับได้ตรง', canonical(openVault(vaultJson, 'test-passphrase-8')) === canonical(id)],
    ['vault: passphrase ผิด → ต้องปฏิเสธ', (() => { try { openVault(vaultJson, 'wrong-passphrase'); return false; } catch { return true; } })()],
  ];
  let allOk = true;
  for (const [name, ok] of cases) {
    console.log(`  ${ok ? C.g('✓') : C.r('✗')} ${name}`);
    if (!ok) allOk = false;
  }
  process.exitCode = allOk ? 0 : 1;
} else {
  console.log(`Sovereign PQ Identity — การใช้งาน:

  กุญแจ (ครั้งแรก):
  node cli.js keygen "ชื่อเรียกเครื่อง"      สร้างตัวตน Ed25519 + ML-DSA-44 + Vault เข้ารหัส Argon2id

  ใช้งานประจำ:
  node cli.js demo                          จำลองขาย → เซ็นสองลายเซ็น → ตรวจ → ลงคลัง (ถอดกุญแจจาก vault ขึ้นหน่วยความจำเท่านั้น)
  node cli.js verify <แฟ้มใบเสร็จ.json>     ตรวจใบเสร็จ (exit 0 เมื่อผ่านทั้งคู่)
  node cli.js ledger                        อ่านคลังใบเสร็จในเครื่อง + ตรวจแต่ละใบ
  node cli.js selftest                      ทดสอบตัวเอง 7 เคส (ข้อมูลสาธิตล้วน)

  vault:
  node cli.js vault create                  ย้ายกุญแจ plaintext เก่า → vault (migrate)
  node cli.js vault open                    ทดสอบเปิด vault
  node cli.js vault remove-plain            ลบ plaintext หลัง vault พร้อม

  สำหรับ automation (หลีกเลี่ยง prompt): กำหนด SOVEREIGN_PASSPHRASE=... ก่อนคำสั่ง`);
}
