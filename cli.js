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
import { loadPoseidon, buildTree, pathFor, newMemberSecret, MAX_MEMBERS } from './src/merkle.js';
import { rotateIdentity, identityAgeDays, loadAnchors, appendAnchor } from './src/rotate.js';
import { proveMembership, verifyMembership, anonReceipt, loadNullifierLedger, isNullifierSpent, appendNullifier, artifactsReady, proveBalance, verifyBalance, balanceReceipt, artifactsReadyBalance } from './src/zk.js';
import { randomBytes } from 'node:crypto';

const IDENT = 'data/identity.json';
const VAULT = 'data/identity.vault.json';
const LEDGER = 'data/receipts.jsonl';
const MEMBERS = 'data/members.json';          // สาธารณะ: ชื่อเรียก + commitment (ไม่มีกุญแจลับ) — data/ ทั้งหมดอยู่นอก git
const MVAULT = 'data/membership.vault.json';  // เข้ารหัส: กุญแจลับสมาชิก (Argon2id + AES-256-GCM เดียวกับกุญแจตัวตน)
const NULLIFIER_LEDGER = 'data/nullifiers.jsonl'; // คลังฝั่งผู้ตรวจ — nullifier ที่ใช้แล้ว (กัน double-claim, ทั้งสองวงจร)
const BVAULT = 'data/balances.vault.json';       // คลังใบยอด (แฟ้มที่ 2): ยอดจริง + blinding เข้ารหัสแยกจากคลังสมาชิก
const ISSUED = 'data/issued_balances.json';      // ทะเบียนสาธารณะ: commitment ใบยอดล้วน (ไม่มียอด ไม่มีตัวตน)
const BROOT = 'data/balances_root.json';         // รากต้นไม้ใบยอดที่ issuer ประกาศให้ผู้ตรวจ
const ANCHORS = 'data/anchors.jsonl';            // สายสกุลกุญแจสาธารณะหลังหมุน (public ล้วน — แฟ้มนี้ไม่มีกุญแจลับ)
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
  if (v.slh_dsa128s !== undefined) console.log(`  SLH-DSA   : ${mark(v.slh_dsa128s)}`);
  const layers = v.slh_dsa128s === undefined ? 'ทั้งสองลายเซ็น' : 'ลายเซ็นครบสามชั้น';
  console.log(`  สรุป      : ${v.valid ? C.g('✓ ใบเสร็จถูกต้อง (' + layers + 'ตรวจผ่าน)') : C.r('✗ ใบเสร็จไม่สมบูรณ์')}`);
  for (const p of v.problems) console.log(C.dim('    • ' + p));
}

function writeVaultFile(identity, passphrase) {
  fs.mkdirSync(path.dirname(VAULT), { recursive: true });
  fs.writeFileSync(VAULT, JSON.stringify(createVault(identity, passphrase), null, 2));
}

if (cmd === 'keygen') {
  const slhFlag = rest.includes('--slh');
  const labelWords = rest.filter((a) => a !== '--slh');
  const label = labelWords.join(' ') || 'sovereign';
  if (fs.existsSync(VAULT) || fs.existsSync(IDENT)) {
    console.error(C.r('ตัวตนมีอยู่แล้ว — ลบแฟ้มเดิมก่อนถ้าตั้งใจสร้างใหม่ (ระวัง: กุญแจเดิมจะหาย — ถ้าแค่ต้องการเปลี่ยนกุญแจ ใช้ node cli.js rotate แทน)'));
    process.exit(1);
  }
  console.log(slhFlag
    ? 'สร้างกุญแจ **สามชั้น** Ed25519 + ML-DSA-44 (FIPS 204) + SLH-DSA-128s (FIPS 205) แล้วเก็บเข้า Vault เข้ารหัส'
    : 'สร้างกุญแจคู่ Ed25519 + ML-DSA-44 แล้วเก็บเข้า Vault เข้ารหัส' + C.dim('  (อยากได้ชั้นที่สาม: เพิ่ม --slh)'));
  console.log(C.dim('(จำ passphrase ให้ดี — ลืมแล้วอ่านกุญแจกลับไม่ได้)'));
  fs.mkdirSync('data', { recursive: true });
  const passphrase = await getPassphrase(true);
  const id = createIdentity({ label, withSlh: slhFlag });
  writeVaultFile(id, passphrase);
  console.log(C.g('✓ กุญแจสร้างเสร็จ + เก็บใน vault: ' + VAULT));
  console.log('  หมายเลขตัวตนนิรนาม: ' + C.b(id.id) + C.dim('  (ไม่ผูกชื่อจริง — อ้างหมายเลขนี้อย่างเดียว)'));
  console.log('  โปรไฟล์ลายเซ็น: ' + C.b(id.alg_profile));
  console.log('  KDF: Argon2id ' + JSON.stringify(vaultSummary(JSON.parse(fs.readFileSync(VAULT, 'utf8'))).params));
  console.log(C.y('  ⚠ passphrase ไม่ถูกบันทึกที่ไหน: ลืม = ไม่มีทางกู้คืน'));
} else if (cmd === 'rotate') {
  // หมุนกุญแจ — เกิดกุญแจใหม่ใน vault เดิม · ลงสายสกุลกุญแจสาธารณะ · ใบเสร็จเก่ายังตรวจได้เพราะ pk ฝังในใบเอง
  const slhFlag = rest.includes('--slh');
  const dueIdx = rest.indexOf('--if-due');
  let dueDays = null;
  if (dueIdx >= 0) {
    dueDays = Number(rest[dueIdx + 1]);
    if (!Number.isFinite(dueDays) || dueDays < 0) { console.error(C.r('ใช้งาน: rotate --if-due <จำนวนวันเต็ม> (เช่น 90)')); process.exit(1); }
  }
  const current = await openVaultFile();
  if (!current) { console.error(C.r('ยังไม่มี vault — รัน node cli.js keygen ก่อน')); process.exit(1); }
  const age = identityAgeDays(current);
  if (dueDays !== null && age < dueDays) {
    console.log(C.g('✓ ยังไม่ถึงกำหนด — ตัวตน ' + current.id + ' อายุ ' + age + ' วัน < ' + dueDays + ' วัน ไม่เขียนแฟ้มใด'));
    console.log(C.dim('  (automation: กำหนด SOVEREIGN_PASSPHRASE แล้วข้ามวันครบกำหนดครั้งต่อไปจะหมุนโดยไม่ถาม)'));
    process.exit(0);
  }
  const passphrase = await getPassphrase(false);
  const { next, anchor } = rotateIdentity(current, { withSlh: slhFlag });
  appendAnchor(ANCHORS, anchor);
  writeVaultFile(next, passphrase); // แฟ้มเดิมถูกเขียนทับด้วยตัวตนใหม่ในชั้นเหล็ก — passphrase เดิมใช้ต่อได้
  console.log(C.g('✓ หมุนกุญแจสำเร็จ — ตัวตนใหม่: ' + C.b(next.id)));
  console.log('  สายสกุล   : ' + anchor.id_old + ' → ' + anchor.id_new + C.dim('  (ลง ' + ANCHORS + ' แล้ว — กุญแจสาธารณะที่ปลดอายุเท่านั้น ไม่มีกุญแจลับ)'));
  console.log('  โปรไฟล์  : ' + anchor.alg_profile_old + ' → ' + anchor.alg_profile_new + (slhFlag && anchor.alg_profile_old !== anchor.alg_profile_new ? C.dim('  (อัปเกรดเพิ่มชั้น SLH-DSA)') : ''));
  console.log(C.dim('  ใบเสร็จเก่าทุกใบยังตรวจผ่านได้ตามเดิม — ตรวจสอบอยู่ในตัวใบเสร็จเอง (pk ฝังคู่ลายเซ็น)'));
  console.log(C.dim('  ระวังจุดเปลี่ยน: คำสั่งที่ถอด vault ต่อจากนี้ใช้ passphrase เดิมกับกุญแจใหม่ทั้งชุด'));
} else if (cmd === 'anchors') {
  const list = loadAnchors(ANCHORS);
  if (!list.length) { console.log('ยังไม่มีประวัติการหมุนกุญแจ — แฟ้ม ' + ANCHORS + ' ยังไม่ได้สร้าง'); process.exit(0); }
  console.log(C.g('สายสกุลกุญแจ (ทุกชุดปลดอายุแล้ว — สาธารณะล้วน):'));
  for (const [i, a] of list.entries()) {
    console.log(`  [${i}] ${C.b(a.id_old)} → ${C.b(a.id_new)}  ${a.alg_profile_old} → ${a.alg_profile_new}`);
    console.log(`      ใช้งานระยะ: ${a.old_created_at} → ${a.retired_at}  (${a.reason})`);
  }
  console.log(C.dim('  ใบเสร็จที่ออกสมัยกุญแจเก่า: ตรวจได้ตลอดอายุแฟ้ม — pk ฝังในตัวใบเสร็จเอง'));
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
  const layerWord = id.keys.slh_dsa128s ? 'สามลายเซ็น' : 'สองลายเซ็น';
  console.log(C.g('สร้างใบเสร็จสาธิต + เซ็น' + layerWord + 'แล้ว' + keyNote));
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
} else if (cmd === 'zk') {
  await zkNamespace(rest);
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
  node cli.js keygen --slh "ชื่อเรียกเครื่อง" เหมือนบรรทัดบน + ลายเซ็นชั้นที่สาม SLH-DSA-128s (FIPS 205)

  ใช้งานประจำ:
  node cli.js demo                          จำลองขาย → เซ็นตามโปรไฟล์ (สองชั้น หรือสามชั้นเมื่อ --slh) → ตรวจ → ลงคลัง
  node cli.js verify <แฟ้มใบเสร็จ.json>     ตรวจใบเสร็จ (exit 0 เมื่อผ่านครบทุกชั้น)
  node cli.js ledger                        อ่านคลังใบเสร็จในเครื่อง + ตรวจแต่ละใบ
  node cli.js selftest                      ทดสอบตัวเอง 7 เคส (ข้อมูลสาธิตล้วน)

  หมุนเวียนกุญแจ:
  node cli.js rotate [--slh] [--if-due <วัน>]  เกิดกุญแจใหม่แทนชุดเดิม + ลงสายสกุลกุญแจสาธารณะ (ใบเสร็จเก่ายังตรวจได้)
  node cli.js anchors                          อ่านสายสกุลกุญแจที่ปลดอายุแล้ว (สาธารณะล้วน)

  vault:
  node cli.js vault create                  ย้ายกุญแจ plaintext เก่า → vault (migrate)
  node cli.js vault open                    ทดสอบเปิด vault
  node cli.js vault remove-plain            ลบ plaintext หลัง vault พร้อม

  สำหรับ automation (หลีกเลี่ยง prompt): กำหนด SOVEREIGN_PASSPHRASE=... ก่อนคำสั่ง

  ZK-SNARK (นิรนามแท้ — เฟส 2):
  node cli.js zk enroll "ชื่อสมาชิก"          ลงทะเบียนสมาชิก (กุญแจลับเข้า vault, ลง commitment สาธารณะ)
  node cli.js zk list                         อ่านทะเบียน (เห็น commitment เท่านั้น ไม่มีตัวตน)
  node cli.js zk tree                         คำนวณรากสมาชิก + เขียน data/members_root.json
  node cli.js zk prove "ชื่อสมาชิก" [epoch]   พิสูจน์นิรนาม → แฟ้มใบพิสูจน์ data/zk-receipt-<epoch>.json
  node cli.js zk verify <แฟ้มใบพิสูจน์.json>  ฝั่งโหนดตรวจ: vkey ล้วน + กัน nullifier ซ้ำ (exit 0 = ผ่าน)

  node cli.js zk issue "ชื่อ" <สตางค์>      ออกใบยอด (ยอดจริงถูกเก็บในคลังเข้ารหัสแฟ้มที่ 2)
  node cli.js zk issue-list                 อ่านทะเบียนใบยอด (เห็น commitment เท่านั้น ไม่มียอด)
  node cli.js zk balance-tree               คำนวณรากใบยอด + เขียน data/balances_root.json
  node cli.js zk prove-bal "ชื่อ" <threshold> [epoch]  พิสูจน์ "ยอด ≥ threshold" → data/zk-balance-<epoch>.json
  node cli.js zk verify-bal <แฟ้ม.json>     ฝั่งโหนดตรวจยอด: vkey ล้วน + กัน nullifier ซ้ำ (exit 0 = ผ่าน)

  สำหรับ automation (หลีกเลี่ยง prompt): กำหนด SOVEREIGN_MEMBER_PASS=... สำหรับ vault สมาชิก · SOVEREIGN_BALANCE_PASS=... สำหรับคลังใบยอด (แฟ้มแยก passphrase แยกกัน)`);
}

// ==== ZK-SNARK Anonymous Membership — ตัวจัดการคำสั่ง (เฟส 2) ====
// (เส้นทางแฟ้มทะเบียน/คลังสมาชิกประกาศอยู่บนหัวไฟล์ — รวมชุดเดียวกับแฟ้มกุญแจตัวตน)

function todayEpoch() {
  const d = new Date();
  return Number(`${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, '0')}${String(d.getUTCDate()).padStart(2, '0')}`);
}

async function zkNamespace(rest) {
  const sub = rest[0] || 'help';

  // แฟ้มทะเบียนสมาชิกสาธารณะ
  const readMembersPublic = () => (fs.existsSync(MEMBERS) ? JSON.parse(fs.readFileSync(MEMBERS, 'utf8')) : []);
  const writeMembersPublic = (arr) => { fs.mkdirSync('data', { recursive: true }); fs.writeFileSync(MEMBERS, JSON.stringify(arr, null, 2)); };

  // เปิด vault สมาชิก — คืน { data, passphrase } เพื่อใช้ passphrase เดิมบันทึกต่อได้ทันที (จะถามแค่ครั้งเดียว)
  const openMemberVault = async (needCreate) => {
    let passphrase = process.env.SOVEREIGN_MEMBER_PASS || '';
    if (!passphrase) passphrase = await readPassphrase(needCreate ? '  ตั้ง passphrase สมาชิก (ต่ำสุด 8 ตัว): ' : '  passphrase สมาชิก: ');
    if (needCreate && passphrase.length < 8) { console.error(C.r('  ✗ passphrase สั้นเกินไป (ต่ำสุด 8 ตัว)')); process.exit(1); }
    if (needCreate && !fs.existsSync(MVAULT)) {
      fs.mkdirSync('data', { recursive: true });
      fs.writeFileSync(MVAULT, JSON.stringify(createVault({ members: [] }, passphrase), null, 2));
      console.log(C.g('  ✓ คลังสมาชิกสร้างใหม่ (เข้ารหัสแบบเดียวกับกุญแจตัวตน: Argon2id + AES-256-GCM)'));
    }
    try {
      if (!fs.existsSync(MVAULT)) { console.error(C.r('ยังไม่มี ' + MVAULT + ' — รัน node cli.js zk enroll ก่อน')); process.exit(1); }
      const data = openVault(JSON.parse(fs.readFileSync(MVAULT, 'utf8')), passphrase);
      if (!data || !Array.isArray(data.members)) throw new Error('โครงแฟ้มคลังสมาชิกไม่ตรง (members ต้องเป็น array)');
      return { data, passphrase };
    } catch (e) {
      console.error(C.r('  ✗ ' + e.message));
      process.exit(1);
    }
  };

  // ดึงกุญแจลับของสมาชิกตามชื่อเรียก — จาก vault เข้ารหัสเท่านั้น ไม่มีทางอื่น
  const openMemberByLabel = async (label) => {
    const { data } = await openMemberVault(false);
    const member = data.members.find((m) => m.label === label);
    if (!member || !member.secret) { console.error(C.r('ไม่พบกุญแจของสมาชิก "' + label + '" ใน ' + MVAULT + ' — รัน node cli.js zk enroll ก่อน')); process.exit(1); }
    return member;
  };

  const saveMemberVault = (data, passphrase) => {
    fs.writeFileSync(MVAULT, JSON.stringify(createVault(data, passphrase), null, 2));
  };

  // ==== วงจรที่ 2: Balance Threshold — คลังใบยอด (แฟ้มเข้ารหัสแฟ้มที่สอง แยก passphrase) ====
  const BAL_MAX = 18446744073709551615n; // 2^64-1 — ช่วงจำนวนเต็มที่วงจรนี้ตรวจได้ (LessEqThan(64))

  const readIssuedPublic = () => (fs.existsSync(ISSUED) ? JSON.parse(fs.readFileSync(ISSUED, 'utf8')) : []);
  const writeIssuedPublic = (arr) => { fs.mkdirSync('data', { recursive: true }); fs.writeFileSync(ISSUED, JSON.stringify(arr, null, 2)); };

  const openBalanceVault = async (needCreate) => {
    let passphrase = process.env.SOVEREIGN_BALANCE_PASS || '';
    if (!passphrase) passphrase = await readPassphrase(needCreate ? '  ตั้ง passphrase คลังใบยอด (ต่ำสุด 8 ตัว): ' : '  passphrase คลังใบยอด: ');
    if (needCreate && passphrase.length < 8) { console.error(C.r('  ✗ passphrase สั้นเกินไป (ต่ำสุด 8 ตัว)')); process.exit(1); }
    if (needCreate && !fs.existsSync(BVAULT)) {
      fs.mkdirSync('data', { recursive: true });
      fs.writeFileSync(BVAULT, JSON.stringify(createVault({ balances: [] }, passphrase), null, 2));
      console.log(C.g('  ✓ คลังใบยอดสร้างใหม่ (เข้ารหัส Argon2id + AES-256-GCM — แยกจากคลังสมาชิก)'));
    }
    try {
      if (!fs.existsSync(BVAULT)) { console.error(C.r('ยังไม่มี ' + BVAULT + ' — รัน node cli.js zk issue ก่อน')); process.exit(1); }
      const data = openVault(JSON.parse(fs.readFileSync(BVAULT, 'utf8')), passphrase);
      if (!data || !Array.isArray(data.balances)) throw new Error('โครงแฟ้มคลังใบยอดไม่ตรง (balances ต้องเป็น array)');
      return { data, passphrase };
    } catch (e) {
      console.error(C.r('  ✗ ' + e.message));
      process.exit(1);
    }
  };

  const saveBalanceVault = (data, passphrase) => {
    fs.writeFileSync(BVAULT, JSON.stringify(createVault(data, passphrase), null, 2));
  };

  if (sub === 'enroll') {
    const label = rest[1] || '';
    if (!label) { console.error(C.r('ใช้งาน: node cli.js zk enroll "ชื่อสมาชิก"')); process.exit(1); }
    const pub = readMembersPublic();
    if (pub.some((m) => m.label === label)) { console.error(C.r('ชื่อสมาชิก "' + label + '" ลงทะเบียนแล้ว')); process.exit(1); }
    const createNew = !fs.existsSync(MVAULT);
    const needBe = pub.length + 1;
    if (needBe > MAX_MEMBERS) { console.error(C.r('สมาชิกเต็มความจุวงจร (' + MAX_MEMBERS + ' คน) — ต้องออกวงจรลึกขึ้น')); process.exit(1); }

    const { data: vaultData, passphrase } = await openMemberVault(createNew);
    // กุญแจลับ 31 ไบต์ (< BN254 p) — ถูกเก็บใน vault เข้ารหัสแบบเดียวกับกุญแจตัวตน
    const secretBig = newMemberSecret(randomBytes);
    const poseidon = await loadPoseidon();
    const commitment = poseidon.leafOf(secretBig);
    vaultData.members.push({ label, secret: secretBig.toString(16) });
    saveMemberVault(vaultData, passphrase);
    pub.push({ label, commitment: commitment.toString(), enrolled_at: new Date().toISOString() });
    writeMembersPublic(pub);
    console.log(C.g(`✓ ลงทะเบียนสมาชิก "${label}" สำเร็จ (อันดับ ${pub.length - 1})`));
    console.log('  commitment (สาธารณะ): ' + C.b(commitment.toString(16).slice(0, 20) + '…'));
    console.log(C.dim('  (กุญแจลับอยู่ใน ' + MVAULT + ' — แฟ้มทะเบียนไม่มีข้อมูลลับ)'));
    console.log(C.y('  ✍ ต่อไป: node cli.js zk tree  แล้วส่ง data/members.json ให้ผู้ตรวจ (ห้ามส่งแฟ้ม vault)'));
  } else if (sub === 'list') {
    const pub = readMembersPublic();
    console.log(C.g(`ทะเบียนสมาชิก ${pub.length}/${MAX_MEMBERS}:`));
    for (const [i, m] of pub.entries()) {
      console.log(`  [${i}] ${C.b(m.label)}  commitment: 0x${BigInt(m.commitment).toString(16).slice(0, 20)}…`);
    }
    console.log(C.dim('  (commitment คือ hash ของกุญแจลับ — ตรวจสลิปไม่ปรากฏตัวตน)'));
  } else if (sub === 'tree') {
    const pub = readMembersPublic();
    if (pub.length === 0) { console.error(C.r('ยังไม่มีสมาชิก — enroll ก่อน')); process.exit(1); }
    const poseidon = await loadPoseidon();
    const tree = buildTree(pub.map((m) => BigInt(m.commitment)), poseidon);
    const rootHex = '0x' + tree.root.toString(16);
    fs.mkdirSync('data', { recursive: true });
    fs.writeFileSync('data/members_root.json', JSON.stringify({ root: rootHex, members: pub.length, depth: tree.depth, generated_at: new Date().toISOString(), labels: pub.map((m) => m.label) }, null, 2));
    console.log(C.g('✓ รากสมาชิก (merkleRoot): ' + C.b(rootHex.slice(0, 26) + '…')));
    console.log('  สมาชิก ' + pub.length + ' จากความจุสูงสุด ' + MAX_MEMBERS + ' (ช่องว่างเติมด้วยค่า 0 ครบทุกชั้น — หมายเหตุการผูกกลุ่มจริงอยู่ใน README)');
    console.log(C.dim('  แฟ้มราก: data/members_root.json — ผู้ตรวจถือแฟ้มนี้เท่านั้น'));
  } else if (sub === 'prove') {
    const label = rest[1] || '';
    if (!label) { console.error(C.r('ใช้งาน: node cli.js zk prove "ชื่อสมาชิก" [epoch=YYYYMMDD]')); process.exit(1); }
    const epoch = rest[2] ? Number(rest[2]) : todayEpoch();
    if (!fs.existsSync('data/members_root.json')) { console.error(C.r('ยังไม่มี data/members_root.json — รัน: node cli.js zk tree')); process.exit(1); }
    const pub = readMembersPublic();
    if (!artifactsReady()) { console.error(C.r('ยังไม่มีแฟ้มวงจรใน artifacts/ — ดู README หัวข้อ "การสร้างแฟ้มวงจร"')); process.exit(1); }
    const idx = pub.findIndex((m) => m.label === label);
    if (idx < 0) { console.error(C.r('ไม่พบสมาชิก "' + label + '" — รัน node cli.js zk list ดูชื่อที่ลงทะเบียนไว้')); process.exit(1); }
    const member = await openMemberByLabel(label);
    const secretBig = BigInt('0x' + member.secret);
    const poseidon = await loadPoseidon();
    // กันคลาดเคลื่อนระหว่าง vault กับทะเบียน: กุญแจต้องแฮชออกมาตรง commitment ที่ประกาศไว้เสมอ
    if (poseidon.leafOf(secretBig) !== BigInt(pub[idx].commitment)) {
      console.error(C.r('กุญแจใน ' + MVAULT + ' ไม่ตรงกับ commitment ใน ' + MEMBERS + ' — ข้อมูลเหลื่อมกัน ปฏิเสธพิสูจน์'));
      process.exit(1);
    }
    const tree = buildTree(pub.map((m) => BigInt(m.commitment)), poseidon);
    const path = pathFor(tree, idx);
    console.log('พิสูจน์นิรนาม (กุญแจลับอยู่ในหน่วยความจำระหว่างคำนวณเท่านั้น)…');
    const { proof, publicSignals } = await proveMembership({ secret: secretBig, path, root: tree.root, epoch: BigInt(epoch) });
    const rootView = { members: pub.length };
    const rec = anonReceipt({ proof, publicSignals, epoch, rootView });
    fs.mkdirSync('data', { recursive: true });
    const file = 'data/zk-receipt-' + epoch + '.json';
    fs.writeFileSync(file, JSON.stringify(rec, null, 2));
    console.log(C.g('✓ พิสูจน์สำเร็จ → ' + file));
    console.log('  ใบพิสูจน์  : ' + C.b(rec.receiptId) + '  ·  epoch: ' + epoch);
    console.log('  nullifier : ' + C.b(rec.publicSignals.nullifierHash.slice(0, 18) + '…') + C.dim('  (ผู้ตรวจบันทึกไว้กันซ้ำ — ไม่ออกตัวตน)'));
    console.log('  ราก       : ' + rec.publicSignals.merkleRoot.slice(0, 18) + '…');
    console.log(C.dim('  โหนดตรวจ: node cli.js zk verify ' + file));
    // snarkjs ฝาก worker ไว้ใน event loop — จบกระบวนการชัด ๆ
    process.exit(0);
  } else if (sub === 'verify') {
    const file = rest[1] || '';
    if (!file) { console.error(C.r('ใช้งาน: node cli.js zk verify <แฟ้มใบพิสูจน์.json>')); process.exit(1); }
    if (!fs.existsSync(file)) { console.error(C.r('ไม่พบแฟ้ม ' + file)); process.exit(1); }
    const rec = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!rec.zkProof || rec.authMode !== 'zk-snark-groth16' || rec.circuit !== 'membership_v1') { console.error(C.r('แฟ้มไม่ใช่ใบพิสูจน์ ZK วงจร membership ของระบบนี้')); process.exit(1); }
    // ลำดับ publicSignals ของ vkey: [nullifierHash, merkleRoot, epochNonce]
    const signals = [
      BigInt(rec.publicSignals.nullifierHash).toString(10),
      BigInt(rec.publicSignals.merkleRoot).toString(10),
      String(BigInt(rec.publicSignals.epochNonce)),
    ];
    const proof = { pi_a: rec.zkProof.pi_a, pi_b: rec.zkProof.pi_b, pi_c: rec.zkProof.pi_c };
    const ok = await verifyMembership({ proof, publicSignals: { nullifierHash: signals[0], merkleRoot: signals[1], epochNonce: signals[2] } });
    if (!ok) {
      console.error(C.r('✗ ใบพิสูจน์ไม่ผ่าน (proof ไม่เที่ยงตามวงจร)'));
      process.exit(1);
    }
    // กันการใช้สิทธิ์ซ้ำ — คลัง nullifier ฝั่งผู้ตรวจ
    const ledger = loadNullifierLedger(NULLIFIER_LEDGER);
    const nul = String(BigInt(rec.publicSignals.nullifierHash));
    const epoch = String(BigInt(rec.publicSignals.epochNonce));
    const root = String(BigInt(rec.publicSignals.merkleRoot));
    if (isNullifierSpent(ledger, nul, Number(epoch), root)) {
      console.error(C.r('✗ สิทธิ์รอบนี้ถูกใช้ไปแล้ว (nullifier ซ้ำ) — ปฏิเสธแม้ proof ยังถูกต้องตามวงจร'));
      process.exit(1);
    }
    appendNullifier(NULLIFIER_LEDGER, { nullifier: nul, epoch: Number(epoch), root, circuit: 'membership_v1', verified_at: new Date().toISOString(), receiptId: rec.receiptId });
    console.log(C.g('✓ ใบพิสูจน์ถูกต้อง (vkey ตรวจผ่าน · กุญแจเจ้าของไม่ถูกเปิดเผย)'));
    console.log('  nullifier : ' + rec.publicSignals.nullifierHash.slice(0, 18) + '…  → บันทึกกันซ้ำแล้ว (' + ledger.length + ' รายการ)');
    console.log(C.dim('  margin: ใบเดียวกันรอบเดียวกันใช้ซ้ำไม่ได้อีก — epoch ใหม่คือสิทธิ์ใหม่'));
    process.exit(0); // snarkjs ฝาก worker ค้าง — ต้องจบชัด
  } else if (sub === 'issue') {
    // ออกใบยอด — ยอดจริงถูกเก็บใน vault เข้ารหัสเท่านั้น; ทะเบียนสาธารณะมีแต่ commitment
    const label = rest[1] || '';
    const amountStr = rest[2] || '';
    if (!label || !amountStr) { console.error(C.r('ใช้งาน: node cli.js zk issue "ชื่อ" <ยอดเป็นสตางค์>')); process.exit(1); }
    let amountBig;
    try { amountBig = BigInt(amountStr); } catch { console.error(C.r('ยอดต้องเป็นจำนวนเต็ม (สตางค์)')); process.exit(1); }
    if (amountBig < 1n || amountBig > BAL_MAX) { console.error(C.r('ยอดต้องอยู่ในช่วงจำนวนเต็ม 64 บิต (1 … 18,446,744,073,709,551,615 สตางค์)')); process.exit(1); }
    const createNew = !fs.existsSync(BVAULT);
    const { data: balVault, passphrase } = await openBalanceVault(createNew);
    if (balVault.balances.some((b) => b.label === label)) { console.error(C.r('ใบยอด "' + label + '" มีอยู่แล้ว — ใบใหม่ใช้ชื่อเรียกต่างกัน')); process.exit(1); }
    if (balVault.balances.length + 1 > MAX_MEMBERS) { console.error(C.r('ใบยอดเต็มความจุวงจร (' + MAX_MEMBERS + ' ใบ) — ต้องออกวงจรลึกขึ้น')); process.exit(1); }
    const poseidon = await loadPoseidon();
    const blindingBig = newMemberSecret(randomBytes); // เหลื่อมสุ่มประจำใบ (248 บิต < BN254 p)
    const leaf = poseidon.balanceLeafOf(amountBig, blindingBig);
    const index = balVault.balances.length;
    balVault.balances.push({ label, index, balance: amountBig.toString(10), blinding: blindingBig.toString(16), leaf: leaf.toString(10) });
    saveBalanceVault(balVault, passphrase);
    const pub = readIssuedPublic();
    pub.push({ index, commitment: leaf.toString(), issued_at: new Date().toISOString() });
    writeIssuedPublic(pub);
    console.log(C.g(`✓ ออกใบยอด "${label}" สำเร็จ (ใบยอดที่ ${index})`));
    console.log('  commitment (สาธารณะ): ' + C.b('0x' + leaf.toString(16).slice(0, 20) + '…'));
    console.log(C.dim('  (ทะเบียนไม่มีตัวเลขยอด — ยอดจริง + เหลื่อมสุ่มอยู่ใน ' + BVAULT + ' เข้ารหัสเท่านั้น)'));
    console.log(C.y('  ✍ ต่อไป: node cli.js zk balance-tree  แล้วประกาศรากให้ผู้ตรวจ (ห้ามส่งแฟ้มคลังใบยอด)'));
  } else if (sub === 'issue-list') {
    const pub = readIssuedPublic();
    console.log(C.g(`ทะเบียนใบยอด ${pub.length}/${MAX_MEMBERS}:`));
    for (const c of pub) console.log(`  [ใบยอดที่ ${c.index}]  commitment: 0x${BigInt(c.commitment).toString(16).slice(0, 20)}…`);
    console.log(C.dim('  (commitment คือ hash ของ (ยอด, เหลื่อมสุ่ม) — ตรวจสลิปไม่ปรากฏทั้งตัวตนและยอด)'));
  } else if (sub === 'balance-tree') {
    const pub = readIssuedPublic();
    if (pub.length === 0) { console.error(C.r('ยังไม่มีใบยอด — รัน node cli.js zk issue ก่อน')); process.exit(1); }
    const poseidon = await loadPoseidon();
    // โหนดต้นไม้ใช้แท็กเดียวกับวงจร membership (TAG_NODE = 0) — วงจร balance สร้างต้นไม้แบบเดียวกันเป๊ะ
    const tree = buildTree(pub.map((c) => BigInt(c.commitment)), poseidon);
    const rootHex = '0x' + tree.root.toString(16);
    fs.mkdirSync('data', { recursive: true });
    fs.writeFileSync(BROOT, JSON.stringify({ root: rootHex, cards: pub.length, depth: tree.depth, generated_at: new Date().toISOString() }, null, 2));
    console.log(C.g('✓ รากใบยอด (merkleRoot): ' + C.b(rootHex.slice(0, 26) + '…')));
    console.log('  ' + pub.length + ' ใบจากความจุ ' + MAX_MEMBERS + ' (ช่องว่างเติมด้วยค่า 0 ครบทุกชั้น)');
    console.log(C.dim('  แฟ้มราก: ' + BROOT + ' — issuer ต้องประกาศรากนี้ให้ผู้ตรวจถือค้างไว้ (ใบนอกรากนี้ = ผู้ตรวจปฏิเสธ)'));
  } else if (sub === 'prove-bal') {
    const label = rest[1] || '';
    const thrStr = rest[2] || '';
    if (!label || !thrStr) { console.error(C.r('ใช้งาน: node cli.js zk prove-bal "ชื่อ" <threshold สตางค์> [epoch]')); process.exit(1); }
    let thresholdBig;
    try { thresholdBig = BigInt(thrStr); } catch { console.error(C.r('threshold ต้องเป็นจำนวนเต็ม (สตางค์)')); process.exit(1); }
    if (thresholdBig < 1n || thresholdBig > BAL_MAX) { console.error(C.r('threshold ต้องอยู่ในช่วงจำนวนเต็ม 64 บิต')); process.exit(1); }
    const epoch = rest[3] ? Number(rest[3]) : todayEpoch();
    if (!fs.existsSync(BROOT)) { console.error(C.r('ยังไม่มี ' + BROOT + ' — รัน: node cli.js zk balance-tree')); process.exit(1); }
    if (!artifactsReadyBalance()) { console.error(C.r('ยังไม่มีแฟ้มวงจร balance ใน artifacts/ — ดู README หัวข้อ "การสร้างแฟ้มวงจร"')); process.exit(1); }
    const pub = readIssuedPublic();
    const { data: balVault } = await openBalanceVault(false);
    const card = balVault.balances.find((b) => b.label === label);
    if (!card) { console.error(C.r('ไม่พบใบยอด "' + label + '" ใน ' + BVAULT + ' — รัน node cli.js zk issue ก่อน')); process.exit(1); }
    const balanceBig = BigInt(card.balance);
    const blindingBig = BigInt('0x' + card.blinding);
    const leafBig = BigInt(card.leaf);
    const poseidon = await loadPoseidon();
    // กันคลาดเคลื่อนระหว่างคลังใบยอดกับทะเบียน: (ยอด, เหลื่อม) ต้องแฮชออกมาตรง leaf ในคลัง และตรง commitment ที่ประกาศ
    if (poseidon.balanceLeafOf(balanceBig, blindingBig) !== leafBig) {
      console.error(C.r('ข้อมูลใน ' + BVAULT + ' ไม่ตรงกันเอง (ยอด + เหลื่อมสุ่ม ≠ leaf) — ปฏิเสธพิสูจน์'));
      process.exit(1);
    }
    if (Number.isInteger(card.index) === false || !pub[card.index] || BigInt(pub[card.index].commitment) !== leafBig) {
      console.error(C.r('ใบยอดใน ' + BVAULT + ' ไม่ตรงกับ commitment ใน ' + ISSUED + ' — ข้อมูลเหลื่อมกัน ปฏิเสธพิสูจน์'));
      process.exit(1);
    }
    const tree = buildTree(pub.map((c) => BigInt(c.commitment)), poseidon);
    const path = pathFor(tree, card.index);
    if (balanceBig < thresholdBig) {
      console.error(C.r(`✗ ยอดของ "${label}" ต่ำกว่า threshold ที่ประกาศ (${thresholdBig} สตางค์) — วงจรไม่ยอมพิสูจน์ข้ออ้างลวง`));
      process.exit(1);
    }
    console.log(`พิสูจน์ "ยอด ≥ ${thresholdBig} สตางค์" (ยอดจริงอยู่ในวงจรเท่านั้น ไม่กลายเป็นข้อมูลสาธารณะ)…`);
    const { proof, publicSignals } = await proveBalance({ balance: balanceBig, blinding: blindingBig, path, root: tree.root, epoch: BigInt(epoch), threshold: thresholdBig });
    const rec = balanceReceipt({ proof, publicSignals, epoch, threshold: thresholdBig });
    fs.mkdirSync('data', { recursive: true });
    const file = 'data/zk-balance-' + epoch + '.json';
    fs.writeFileSync(file, JSON.stringify(rec, null, 2));
    console.log(C.g('✓ พิสูจน์สำเร็จ → ' + file));
    console.log('  ใบพิสูจน์  : ' + C.b(rec.receiptId) + '  ·  ข้ออ้าง: ยอด ≥ ' + thresholdBig + ' สตางค์  ·  epoch: ' + epoch);
    console.log('  nullifier : ' + C.b(rec.publicSignals.nullifierHash.slice(0, 18) + '…') + C.dim('  (ผู้ตรวจบันทึก — ไม่รู้ว่าใคร ไม่รู้ยอด)'));
    console.log('  ราก       : ' + rec.publicSignals.merkleRoot.slice(0, 18) + '…');
    console.log(C.dim('  โหนดตรวจ: node cli.js zk verify-bal ' + file));
    process.exit(0); // snarkjs ฝาก worker ค้าง — ต้องจบชัด
  } else if (sub === 'verify-bal') {
    const file = rest[1] || '';
    if (!file) { console.error(C.r('ใช้งาน: node cli.js zk verify-bal <แฟ้มใบพิสูจน์ยอด.json>')); process.exit(1); }
    if (!fs.existsSync(file)) { console.error(C.r('ไม่พบแฟ้ม ' + file)); process.exit(1); }
    const rec = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!rec.zkProof || rec.authMode !== 'zk-snark-groth16' || rec.circuit !== 'balance_v1') { console.error(C.r('แฟ้มไม่ใช่ใบพิสูจน์ ZK วงจร balance ของระบบนี้')); process.exit(1); }
    // ลำดับ publicSignals ของ vkey: [nullifierHash, merkleRoot, epochNonce, threshold]
    const signals = [
      BigInt(rec.publicSignals.nullifierHash).toString(10),
      BigInt(rec.publicSignals.merkleRoot).toString(10),
      String(BigInt(rec.publicSignals.epochNonce)),
      String(BigInt(rec.publicSignals.threshold)),
    ];
    const proof = { pi_a: rec.zkProof.pi_a, pi_b: rec.zkProof.pi_b, pi_c: rec.zkProof.pi_c };
    const ok = await verifyBalance({ proof, publicSignals: { nullifierHash: signals[0], merkleRoot: signals[1], epochNonce: signals[2], threshold: signals[3] } });
    if (!ok) {
      console.error(C.r('✗ ใบพิสูจน์ยอดไม่ผ่าน (proof ไม่เที่ยงตามวงจร)'));
      process.exit(1);
    }
    // กันการใช้สิทธิ์ซ้ำ — คลัง nullifier ฝั่งผู้ตรวจ (ค่าโดเมนของวงจรนี้แยกจากวงจรสมาชิกผ่านแท็ก 11)
    const ledger = loadNullifierLedger(NULLIFIER_LEDGER);
    const nul = String(BigInt(rec.publicSignals.nullifierHash));
    const epoch = String(BigInt(rec.publicSignals.epochNonce));
    const root = String(BigInt(rec.publicSignals.merkleRoot));
    if (isNullifierSpent(ledger, nul, Number(epoch), root)) {
      console.error(C.r('✗ สิทธิ์ยอดรอบนี้ถูกใช้ไปแล้ว (nullifier ซ้ำ) — ปฏิเสธแม้ proof ยังถูกต้องตามวงจร'));
      process.exit(1);
    }
    appendNullifier(NULLIFIER_LEDGER, { nullifier: nul, epoch: Number(epoch), root, circuit: 'balance_v1', verified_at: new Date().toISOString(), receiptId: rec.receiptId });
    console.log(C.g('✓ ใบพิสูจน์ยอดถูกต้อง (vkey ตรวจผ่าน · ทั้งตัวตนและยอดจริงไม่ถูกเปิดเผย)'));
    console.log('  ข้ออ้าง    : ยอด ≥ ' + signals[3] + ' สตางค์ (มัดจำใน proof เท่านั้น)');
    console.log('  nullifier : ' + rec.publicSignals.nullifierHash.slice(0, 18) + '…  → บันทึกกันซ้ำแล้ว (' + ledger.length + ' รายการ)');
    console.log(C.dim('  margin: ใบเดียวกันรอบเดียวกันใช้ซ้ำไม่ได้ — และผู้ตรวจตรวจได้โดยไม่ถือแฟ้มคลังใบยอดเลย'));
    process.exit(0); // snarkjs ฝาก worker ค้าง — ต้องจบชัด
  } else {
    console.log([
      'คำสั่ง zk (ZK-SNARK):',
      '  — วงจรที่ 1: Anonymous Membership —',
      '  node cli.js zk enroll "ชื่อ"  ลงทะเบียนสมาชิก',
      '  node cli.js zk list           ดูทะเบียนสมาชิก',
      '  node cli.js zk tree           คำนวณรากสมาชิก',
      '  node cli.js zk prove "ชื่อ"   พิสูจน์นิรนาม',
      '  node cli.js zk verify <file>  ฝั่งโหนดตรวจ',
      '',
      '  — วงจรที่ 2: Balance Threshold —',
      '  node cli.js zk issue "ชื่อ" <สตางค์>          ออกใบยอด (ยอดจริงเข้าคลังเข้ารหัสแฟ้มที่สอง)',
      '  node cli.js zk issue-list                    ดูทะเบียนใบยอด',
      '  node cli.js zk balance-tree                  คำนวณรากใบยอด',
      '  node cli.js zk prove-bal "ชื่อ" <threshold>   พิสูจน์ "ยอด ≥ threshold" (ไม่เปิดยอด)',
      '  node cli.js zk verify-bal <file>             ฝั่งโหนดตรวจยอด',
      '',
      '  สิทธิ์ 1 คน / 1 รอบ (epoch) — nullifier กันการใช้ซ้ำ โดยไม่เผยว่าใคร และไม่เผยยอดจริง',
      '  ครั้งแรก: ต้องมีแฟ้มวงจรใน artifacts/ — วิธีสร้างอยู่ใน README หัวข้อ "การสร้างแฟ้มวงจร"',
    ].join('\n'));
  }
}
