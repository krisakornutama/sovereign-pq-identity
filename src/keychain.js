// OS Keychain Integration (Q-06) — เก็บ passphrase ใน Credential Store ของระบบปฏิบัติการ
// Windows: Credential Manager · macOS: Keychain Access · Linux: Secret Service (libsecret)
// ใช้ keytar (Node.js native addon) — ไม่แตะรูปแบบ vault · คง Argon2id + AES-256-GCM เดิมทุกอย่าง
import keytar from 'keytar';

const SERVICE = 'sovereign-pq-identity';
const ACCOUNTS = {
  identity: 'identity-passphrase',
  membership: 'membership-passphrase',
  balance: 'balance-passphrase',
  kem: 'kem-passphrase',
};

/**
 * ตรวจสอบว่า keychain ใช้งานได้บนระบบนี้หรือไม่
 * @returns {Promise<boolean>}
 */
export async function isKeychainAvailable() {
  try {
    // พยายามอ่าน (จะคืน null ถ้าไม่มี) — ถ้า throw = ระบบไม่รองรับ
    await keytar.getPassword(SERVICE, 'probe');
    return true;
  } catch {
    return false;
  }
}

/**
 * บันทึก passphrase ลง keychain
 * @param {'identity'|'membership'|'balance'|'kem'} vaultType
 * @param {string} passphrase
 * @returns {Promise<void>}
 */
export async function setPassphrase(vaultType, passphrase) {
  const account = ACCOUNTS[vaultType];
  if (!account) throw new Error('ประเภท vault ไม่รู้จัก: ' + vaultType);
  await keytar.setPassword(SERVICE, account, passphrase);
}

/**
 * อ่าน passphrase จาก keychain
 * @param {'identity'|'membership'|'balance'|'kem'} vaultType
 * @returns {Promise<string|null>} passphrase หรือ null ถ้ายังไม่มี
 */
export async function getPassphrase(vaultType) {
  const account = ACCOUNTS[vaultType];
  if (!account) throw new Error('ประเภท vault ไม่รู้จัก: ' + vaultType);
  return await keytar.getPassword(SERVICE, account);
}

/**
 * ลบ passphrase จาก keychain
 * @param {'identity'|'membership'|'balance'|'kem'} vaultType
 * @returns {Promise<boolean>} true ถ้าลบสำเร็จ (มีอยู่เดิม), false ถ้าไม่มี
 */
export async function deletePassphrase(vaultType) {
  const account = ACCOUNTS[vaultType];
  if (!account) throw new Error('ประเภท vault ไม่รู้จัก: ' + vaultType);
  return await keytar.deletePassword(SERVICE, account);
}

/**
 * แสดงรายการ passphrase ที่เก็บอยู่ใน keychain (สำหรับ debug/admin)
 * @returns {Promise<Record<string, boolean>>} object แสดงว่ามี passphrase อยู่หรือไม่
 */
export async function listStoredPassphrases() {
  const result = {};
  for (const [type, account] of Object.entries(ACCOUNTS)) {
    result[type] = Boolean(await keytar.getPassword(SERVICE, account));
  }
  return result;
}

/**
 * ล้าง passphrase ทั้งหมดของ sovereign-pq-identity
 * @returns {Promise<void>}
 */
export async function clearAllPassphrases() {
  for (const account of Object.values(ACCOUNTS)) {
    await keytar.deletePassword(SERVICE, account);
  }
}