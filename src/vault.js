// 🔐 Local Key Vault — กุญแจ secret ไม่เก็บเป็นแฟ้ม plaintext อีกต่อไป
// ชั้นเข้ารหัส: Argon2id (KDF, จาก @noble/hashes · RFC 9106) + AES-256-GCM (node:crypto)
// หลัก: passphrase ของคุณ = กุญแจเท่านั้น · ถอดออกจากแฟ้มเข้าหน่วยความจำชั่วคราวเวลาเซ็นสลิปเท่านั้น
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { argon2id } from '@noble/hashes/argon2.js';
import { canonical } from './util.js';

export const VAULT_VERSION = 1;
export const VAULT_KDF = 'argon2id';

// ตัวอ้างอิงปรับแต่งได้: ผู้ใช้ทั่วไปใช้พารามิเตอร์แน่นกว่า; ทดสอบใช้ตัวเบาเพื่อความเร็ว
export const VAULT_PARAMS_STRONG = { m: 65536, t: 3, p: 1 };  // 64 MiB · 3 รอบ (ค่าเริ่มต้นบนเดสก์ท็อป)
export const VAULT_PARAMS_TEST   = { m: 1024,  t: 1, p: 1 };  // เฉพาะ unit test

function deriveKey(passphraseBytes, salt, params) {
  return argon2id(passphraseBytes, salt, { ...params, dkLen: 32 });
}

// เข้ารหัส identity object → vault JSON (รวมเวลาสร้างแฟ้ม)
export function createVault(identity, passphrase, { params = VAULT_PARAMS_STRONG, created_at } = {}) {
  if (!passphrase || passphrase.length < 8) throw new Error('passphrase ต้องยาวอย่างน้อย 8 ตัวอักษร');
  const enc = new TextEncoder();
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = deriveKey(enc.encode(passphrase), salt, params);

  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const plaintext = enc.encode(canonical(identity)); // canonical = bytes เสถียร เทียบได้ทุกเครื่อง
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    version: VAULT_VERSION,
    kdf: VAULT_KDF,
    params,
    salt_b64: salt.toString('base64'),
    iv_b64: iv.toString('base64'),
    tag_b64: tag.toString('base64'),
    ciphertext_b64: ciphertext.toString('base64'),
    created_at: created_at || new Date().toISOString(),
  };
}

// ถอดรหัส vault → identity object (passphrase ผิด / แฟ้มถูกแก้ = ปฏิเสธทันที)
export function openVault(vault, passphrase) {
  if (!vault || vault.version !== VAULT_VERSION || vault.kdf !== VAULT_KDF) {
    throw new Error('แฟ้ม vault ไม่ตรงรูปแบบของระบบนี้');
  }
  const dec = new TextDecoder();
  const salt = Buffer.from(vault.salt_b64, 'base64');
  const iv = Buffer.from(vault.iv_b64, 'base64');
  const tag = Buffer.from(vault.tag_b64, 'base64');
  const ciphertext = Buffer.from(vault.ciphertext_b64, 'base64');
  const key = deriveKey(new TextEncoder().encode(passphrase), salt, vault.params);

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let plaintext;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    throw new Error('ถอดรหัสไม่ได้ — passphrase ผิด หรือแฟ้มถูกแก้ (GCM authTag ไม่ตรง)');
  }
  return JSON.parse(dec.decode(plaintext));
}

// ตรวจทานคุณลักษณะแฟ้ม vault (ที่จะระงิงเอาไว้ในเพย์โหลดพังกระเบียนต่าง ๆ)
export function vaultSummary(vault) {
  return { version: vault.version, kdf: vault.kdf, params: vault.params, created_at: vault.created_at };
}
