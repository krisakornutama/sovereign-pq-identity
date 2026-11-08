// โปรแกรมรับ passphrase โดยซ่อนการพิมพ์ (raw mode) — ทำงานบนเทอร์มินาลทุกรุ่น
// เส้นทางแท้: ผู้พิมพ์เห็นเส้นจิ่นของตัวเองเท่านั้น ค่านี้ไม่ถูกจับในแฟ้ม / log ใด ๆ
export function readPassphrase(prompt) {
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
