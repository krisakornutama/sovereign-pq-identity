// โปรแกรมรับ passphrase โดยซ่อนการพิมพ์ (raw mode) — ทำงานบนเทอร์มินาลทุกรุ่น
// เส้นทางแท้: ผู้พิมพ์เห็นเส้นจิ่นของตัวเองเท่านั้น ค่านี้ไม่ถูกจับในแฟ้ม / log ใด ๆ
// Q-06: รองรับ OS keychain (Windows Credential Manager / macOS Keychain / Linux Secret Service)
import { getPassphrase as keychainGet, isKeychainAvailable } from './keychain.js';

export async function readPassphrase(prompt, { useKeychain = false, vaultType = 'identity' } = {}) {
  // 1) ลองอ่านจาก keychain ก่อน (ถ้าขอใช้ และระบบรองรับ)
  if (useKeychain) {
    const available = await isKeychainAvailable();
    if (available) {
      const fromKeychain = await keychainGet(vaultType);
      if (fromKeychain) return fromKeychain;
      // ไม่มีใน keychain → ตกมาลงไปอ่านจาก env/prompt ต่อ
    }
  }

  // 2) ลองอ่านจาก environment variable (automation)
  const fromEnv = process.env.SOVEREIGN_PASSPHRASE;
  if (fromEnv) return fromEnv;

  // 3) ถามผู้ใช้ในเทอร์มินัล (interactive)
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const chars = [];
    const isTTY = process.stdin.isTTY;
    if (isTTY) { try { process.stdin.setRawMode(true); } catch { /* ข้ามถ้าระบบไม่รองรับ raw */ } }
    process.stdin.resume();
    const onData = (buf) => {
      for (const ch of buf) {
        if (ch === 0x0d || ch === 0x0a) { finish(); return; }        // Enter → หยุดทันที ไม่อ่านต่อ
        if (ch === 0x03) { process.exit(1); }                        // Ctrl-C
        if (ch === 0x7f || ch === 0x08) { chars.pop(); if (isTTY) process.stdout.write('\b \b'); continue; }
        if (ch >= 0x20 && ch <= 0x7e || ch >= 0xa0) { chars.push(ch); if (isTTY) process.stdout.write('*'); }
      }
    };
    const finish = () => {
      process.stdin.removeListener('data', onData);
      process.stdin.pause();
      if (isTTY) { try { process.stdin.setRawMode(false); } catch { /* ignore */ } }
      process.stdout.write('\n');
      resolve(Buffer.from(chars).toString('utf8'));
    };
    process.stdin.on('data', onData);
  });
}

// ทางเลือกสำหรับ automation: อ่าน passphrase จากตัวแปรสภาพแวดล้อมแทนการพิมพ์
export function passphraseFromEnv() {
  return process.env.SOVEREIGN_PASSPHRASE || null;
}

/**
 * บันทึก passphrase ลง OS keychain (สำหรับ CLI `keychain set`)
 * @param {'identity'|'membership'|'balance'|'kem'} vaultType
 * @param {string} passphrase
 */
export async function storePassphraseInKeychain(vaultType, passphrase) {
  const { setPassphrase } = await import('./keychain.js');
  return setPassphrase(vaultType, passphrase);
}

/**
 * ลบ passphrase จาก OS keychain (สำหรับ CLI `keychain delete`)
 * @param {'identity'|'membership'|'balance'|'kem'} vaultType
 */
export async function deletePassphraseFromKeychain(vaultType) {
  const { deletePassphrase } = await import('./keychain.js');
  return deletePassphrase(vaultType);
}

/**
 * แสดงสถานะ passphrase ใน keychain (สำหรับ CLI `keychain list`)
 */
export async function listKeychainPassphrases() {
  const { listStoredPassphrases } = await import('./keychain.js');
  return listStoredPassphrases();
}
