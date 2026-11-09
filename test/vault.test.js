// ทดสอบ Vault — เข้ารหัส Argon2id + AES-256-GCM (ใช้พารามิเตอร์เบาเพื่อความเร็วเทสต์เท่านั้น)
import test from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity } from '../src/identity.js';
import { createVault, openVault, vaultSummary } from '../src/vault.js';
import { signReceipt, verifyReceipt } from '../src/receipt.js';

const PARAMS_FAST = { m: 1024, t: 1, p: 1 };
const PASS = 'correct-horse-8';

test('vault: ตัวตนเข้ารหัส→ถอดรหัสกลับได้ตรงกัน', () => {
  const identity = createIdentity({ label: 't-vault' });
  const vault = createVault(identity, PASS, { params: PARAMS_FAST });
  assert.equal(vault.kdf, 'argon2id');
  assert.equal(vault.version, 1);
  const opened = openVault(vault, PASS);
  assert.deepEqual(opened, identity);
});

test('vault: passphrase ผิด → ปฏิเสธ (ไม่เงียบเฉย)', () => {
  const identity = createIdentity({ label: 't-vault-wrong' });
  const vault = createVault(identity, PASS, { params: PARAMS_FAST });
  assert.throws(() => openVault(vault, 'wrong-passphrase-'));
});

test('vault: แฟ้มถูกแก้ 1 บิต (ciphertext) → authTag ตรวจไม่ผ่าน', () => {
  const identity = createIdentity({ label: 't-vault-tamper' });
  const vault = createVault(identity, PASS, { params: PARAMS_FAST });
  const bit = Buffer.from(vault.ciphertext_b64, 'base64');
  bit[0] ^= 0x01;
  const tampered = { ...vault, ciphertext_b64: bit.toString('base64') };
  assert.throws(() => openVault(tampered, PASS));
});

test('vault: ต้องมีพารามิเตอร์ Argon2id ในแฟ้ม (ตรวจสอบได้ตลอดอายุแฟ้ม)', () => {
  const identity = createIdentity({ label: 't-vault-params' });
  const vault = createVault(identity, PASS, { params: { m: 2048, t: 2, p: 1 } });
  const s = vaultSummary(vault);
  assert.equal(s.kdf, 'argon2id');
  assert.equal(s.params.m, 2048);
  assert.equal(s.params.t, 2);
});

test('vault → signReceipt: ถอดกุญแจจาก vault แล้วเซ็นได้ + ตรวจผ่านทั้งคู่', () => {
  const identity = createIdentity({ label: 't-vault-sign' });
  const vault = createVault(identity, PASS, { params: PARAMS_FAST });
  const opened = openVault(vault, PASS);
  const env = signReceipt(opened, { demo: true, total_thb: 99 });
  assert.equal(verifyReceipt(env).valid, true);
});

test('vault: passphrase สั้นเกิน 8 ตัว → ปฏิเสธตั้งแต่ตอนสร้าง', () => {
  const identity = createIdentity({ label: 't-vault-short' });
  assert.throws(() => createVault(identity, 'abc12', { params: PARAMS_FAST }));
});
