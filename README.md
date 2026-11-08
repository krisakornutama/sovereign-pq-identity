<div align="center">

### 🛡️ Sovereign PQ Identity
**POST-QUANTUM IDENTITY + DUAL-SIGNED RECEIPTS** — ตัวตนนิรนามที่ทำงานเครื่องใดก็ได้ **กุญแจเกิดและอยู่ในเครื่องคุณ · ตรวจได้ครบโดยไม่มีคลาวด์ทั้งชุด**

ร่วมกันแปลงสลิป/บันทึกออกเป็นลายเซ็น*สองชั้น* — **Ed25519** (ตรวจได้ทุกเครื่องวันนี้) + **ML-DSA-44 (FIPS 204)** (ลายเซ็นกันควอนตัมตามมาตรฐาน NIST) เครื่องอื่นตรวจย้อนได้เสมอ

[![Standard](https://img.shields.io/badge/Standard-FIPS_204_ML--DSA-fbbf24?style=for-the-badge&labelColor=030712)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
[![Zero Cloud](https://img.shields.io/badge/Cloud-ZERO-34d399?style=for-the-badge&labelColor=030712)](.)
[![Tests](https://img.shields.io/badge/Tests-14_passing-22d3ee?style=for-the-badge&labelColor=030712)](#-ผลการทดสอบจากเครื่องจริง)
[![Node](https://img.shields.io/badge/Node.js-%E2%89%A520-43853d?style=for-the-badge&labelColor=030712)](./package.json)

</div>

---

## ⚡ ติดตั้งและลองใน 2 นาที

```bash
git clone https://github.com/krisakornutama/sovereign-pq-identity.git
cd sovereign-pq-identity
npm install
node cli.js keygen "ชื่อเรียกเครื่อง"   # สร้างตัวตน + เก็บกุญแจใน Vault เข้ารหัส (ตั้ง passphrase ตอนถาม)
node cli.js demo        # จำลองขาย → ถอดกุญแจจาก vault → เซ็นสองลายเซ็น → ตรวจ → ลงคลัง
node cli.js selftest    # ทดสอบการบุกรุก 7 เคส (สลิป + vault)
npm test                # ชุดทดสอบเต็ม 14 เคส (ไม่ใช้เน็ต)
```

**เอาต์พุตจริงตอนรัน `node cli.js demo` (คัดจากเครื่องที่สร้างระบบนี้เอง):**

```
สร้างใบเสร็จสาธิต + เซ็นสองลายเซ็นแล้ว
  ตัวตน     : sps_86889d83f2f32d7ef2a7  (sovereign.ed25519+ml_dsa44.v1)
  หมายเลขใบ: pqri_7f590bc1ae771ab6
  เวลา     : 2026-11-08T09:33:08.585Z
  ยอด      : ฿120.00
  บัญชีในเครื่อง: data/receipts.jsonl
  Ed25519   : ✓ ผ่าน
  ML-DSA-44 : ✓ ผ่าน
  สรุป      : ✓ ใบเสร็จถูกต้อง (ทั้งสองลายเซ็นตรวจผ่าน)
  (payload ทั้งหมดเป็นข้อมูลสาธิตในเครื่อง ไม่มีข้อมูลจริง)
```

---

## 💎 ทำอะไรได้บ้าง

| # | ระบบ | ทำหน้าที่อะไร |
|---|---|---|
| 🪪 | **ตัวตนนิรนาม (`sps_*`)** | สร้างคู่กุญแจ **Ed25519 + ML-DSA-44** แล้ว hash เป็นหมายเลขตัวตน (`sps_xxxx…`) — ไม่ผูกชื่อจริง อ้างธุรกรรมด้วยหมายเลขนี้เพียงอย่างเดียว |
| ✍️ | **ใบเสร็จสองลายเซ็น (`pqri_*`)** | bytes เดียวกันถูกเซ็นโดยกุญแจ 2 อัลกอริทึม — verify ต้องผ่าน **ทั้งคู่** ขาดตัวใดตัวหนึ่งถือว่าใบเสร็จไม่สมบูรณ์ |
| 🌐 | **ตรวจย้อนจากเครื่องอื่นได้** | bytes ที่ถูกเซ็นคือ canonical JSON (เรียงคีย์แบบเสถียร) — verifier อีกเครื่องคำนวณซ้ำแล้วได้ผลลัพธ์เดียวกันเสมอ |
| 💾 | **คลังใบเสร็จท้องถิ่น** | แฟ้ม JSONL + กันซ้ำตาม `id` (ยื่นใบเดิมซ้ำไม่เกิดรายการใหม่ — ระบบเดียวแบบ `sovereign-offgrid`) |
| 🔒 | **Domain separation** | ลายเซ็น ML-DSA ผูก context `"sovereign-pq-receipt/v1"` — ลายเซ็นจากระบบอื่นใช้ต่อในแฟ้มของระบบนี้ไม่ได้ |
| 🛡 | **Local Key Vault** | กุญแจ secret **ไม่เก็บ plaintext** — เก็บเป็น vault เข้ารหัส **Argon2id (RFC 9106) + AES-256-GCM** ถอดขึ้นหน่วยความจำเฉพาะตอนเซ็นสลิปเท่านั้น |

---

## 🚀 วิธีใช้งานครบชุด

```bash
# 1) สร้างตัวตนของเครื่องคุณ (กุญแจเกิดในแฟ้ม data/identity.json)
node cli.js keygen "ชื่อเรียกเครื่องนี้อย่างเดียว"

# 2) ออกใบเสร็จจำลอง + ตรวจทันที (เห็นกระบวนการเต็ม)
node cli.js demo

# 3) ตรวจแฟ้มใบเสร็จไฟล์ใดก็ได้ (exit 0 เมื่อผ่านทั้งคู่ลายเซ็น)
node cli.js verify <แฟ้มใบเสร็จ.json>

# 4) อ่านคลังใบเสร็จในเครื่อง + ตรวจทีละใบ
node cli.js ledger
```

**ใช้เป็นไลบรารีจากโค้ดคุณเอง:**

```js
import { createIdentity } from './src/identity.js';
import { signReceipt, verifyReceipt } from './src/receipt.js';

const identity = createIdentity({ label: 'แม่ค้าที่ 1' });
const receipt = signReceipt(identity, { type: 'sale', total_thb: 210 });

// ใบเสร็จนี้ถูกเซ็นด้วย Ed25519 และ ML-DSA-44 — ใครถือแฟ้มก็ตรวจความจริงด้วยตัวเองได้
const v = verifyReceipt(receipt); // → { valid: true, ed25519: true, ml_dsa44: true }
```

**โครงใบเสร็จจริงในคลัง (ตัดความยาว base64 เพื่ออ่านง่าย — ความยาวในวงเล็บคือจำนวนจริง):**

```json
{
  "id": "pqri_7f590bc1ae771ab6",
  "issued_at": "2026-11-08T09:33:08.585Z",
  "payload": { "type": "sale", "demo": true, "total_thb": 120.0 },
  "alg_profile": "sovereign.ed25519+ml_dsa44.v1",
  "signatures": {
    "ed25519":  { "pk_b64": "…44 bytes SPKI (60 chars)", "sig_b64": "…64 bytes (88 chars)" },
    "ml_dsa44": { "pk_b64": "…1,312 bytes (1,750 chars)", "sig_b64": "…2,420 bytes (3,228 chars)" }
  }
}
```

---

## 🏛️ สถาปัตยกรรม — ทำไมต้อง "สองลายเซ็น"

```mermaid
flowchart LR
  A["🪪 Identity<br/>Ed25519 + ML-DSA-44"] -->|"เซ็น core bytes เดียวกัน<br/>(canonical JSON)"| B["📝 Receipt<br/>สองลายเซ็นพร้อมกัน"]
  B --> C[("💾 Ledger<br/>data/receipts.jsonl<br/>dedupe ตาม id")]
  B --> D["✅ Verifier<br/>ต้องผ่านทั้งสองลายเซ็น"]
  D --> E["🖥 ตรวจได้ทุกเครื่องวันนี้<br/>(Ed25519)"]
  D --> F["🛡 ปลอดภัยแม้เข้ายุคควอนตัม<br/>(ML-DSA · FIPS 204)"]
```

**เหตุผลเชิงความเสี่ยง (Harvest-now-decrypt-later ที่มาคู่ใบเสร็จ):** สลิปที่เก็บไว้ยาว ๆ วันหนึ่งอาจถูกแกะ Ed25519 ได้ด้วยเครื่องควอนตัม — ถ้ายังใช้ลายเซ็นชั้นเดียว สลิปจะถูกปลอมแปลงภายหลังได้อย่างเงียบ ๆ ระบบสองลายเซ็นนี้จึงเป็นการเตือนความปลอดภัยตั้งแต่ต้นวันธุรกรรม — ทั้งยังตรวจย้อนระยะยาวได้เสมอ (ความยาวกุญแจตรงมาตรฐาน FIPS 204: pk = 1,312 bytes · sk = 2,560 bytes · sig = 2,420 bytes)

---

## 🔐 Local Key Vault — กุญแจไม่เก็บ plaintext อีกต่อไป

กุญแจ secret ถูกเข้ารหัสด้วย **Argon2id** (KDF กัน brute-force ตาม RFC 9106 · m=64 MiB t=3 p=1) → กุญแจ AES-256-GCM ปกป้องแฟ้ม vault — **passphrase ไม่ถูกเก็บที่ใดเลย** — ถอดกุญแจขึ้นหน่วยความจำชั่วคราวเฉพาะขณะเซ็นสลิปแล้วทิ้งพร้อมโปรแกรมปิด

```bash
# กรณีมีตัวตนแบบ plaintext เก่า (จาก v1.0) — migrate:
node cli.js vault create        # ย้ายกุญแจ → vault + ตรวจเปิดกลับก่อนสำเร็จ
node cli.js vault remove-plain   # ลบแฟ้ม plaintext (ตรวจว่า vault ยังเปิดได้ก่อนลบเสมอ)

# ทดสอบเปิด vault ได้จริง (ขึ้น public view เท่านั้น ไม่โชว์ secret)
node cli.js vault open
```

**เอาต์พุตจริงจากการ migrate บนเครื่องสร้างระบบ:**

```
$ node cli.js vault create
ย้ายกุญแจจากแฟ้ม plaintext → vault เข้ารหัส (แฟ้ม plaintext จะยังอยู่ จนสร้าง vault สำเร็จ)
✓ เตรียมเสร็จ: vault data/identity.vault.json ตรวจเปิดกลับผ่าน
  ✍ ต่อไป: ลบแฟ้ม plaintext เอง หรือ run: node cli.js vault remove-plain

$ node cli.js vault open
✓ เปิด vault ได้จริง (กุญแจอยู่ในหน่วยความจำเฉพาะกระบวนการนี้)
  ตัวตน : sps_86889d83f2f32d7ef2a7  ·  KDF: argon2id
  กุญแจ public: Ed25519 MCowBQYDK2Vw… / ML-DSA-44 Aq1AcVZ4+H8g…

$ node cli.js vault remove-plain
✓ ลบแฟ้ม plaintext แล้ว — กุญแจอยู่ใน vault เข้ารหัสเท่านั้น
```

**สิ่งพิสูจน์แล้วจากการทดสอบ 1 จุดดี ๆ:** หลังลบแฟ้ม plaintext ทิ้งแล้ว ใบเสร็จ**เก่า**ที่เคยเซ็นไว้ยังตรวจผ่าน ✓ ทุกใบ — เพราะกุญแจสาธารณะถูกฝังในตัวใบเสร็จเอง (ใครถือแฟ้มสลิปตรวจได้ตลอดอายุไฟล์ ไม่จำเป็นต้องถือกุญแจของผู้เซ็น)

> 💡 Automation ล้วน: กำหนด `SOVEREIGN_PASSPHRASE=...` (เฉพาะเซสชัน) แล้วคำสั่งทุกตัวไม่ถาม prompt — เหมาะ CI / สคริปต์เบื้องหลัง (ระวัง log แฟ้มประวัติคำสั่ง).

**ข้อแตกต่างตรวจสอบมาแล้วจากโค้ดจริง:**

- ปลอม payload แม้ 1 บิต → ทั้งสองลายเซ็นพังพร้อมกัน (bytes เดาไม่ได้)
- ลบลายเซ็น ML-DSA ออก → verify ปฏิเสธ (ไม่ยอมรับ Ed25519 เฉพาะ)
- สลับลายเซ็นจากใบอื่นมาแปะ → verify ปฏิเสธ (pk ต้องจับคู่ sk จริงของตัวเอง)
- เปลี่ยน `alg_profile` → canonical bytes เปลี่ยน → verify ปฏิเสธทันที

---

## ✅ ผลการทดสอบจากเครื่องจริง

```
$ npm test
✔ canonical เรียงคีย์ได้เสถียร (bytes เดียวทุกเครื่อง)
✔ ยืนยันตัวตน Ed25519 + ML-DSA-44 ทั้งคู่
✔ เซ็นใบเสร็จ → ตรวจผ่านทั้งสองลายเซ็น
✔ ปลอมแปลง payload 1 บิต → ทั้งสองลายเซ็นต้องพัง
✔ ตัดลายเซ็น ML-DSA ออก → ระบบไม่ตอบรับ
✔ เอาลายเซ็นมาจากใบอื่นมาแปะ → ไม่ผ่าน
✔ id/issued_at อยู่ใน core bytes ที่เซ็น และลายเซ็นไม่หลุดเข้าฟีเจอร์เอง
✔ context ต้องตรงเดิม → ML-DSA verify ไม่ผ่าน
✔ vault: ตัวตนเข้ารหัส→ถอดรหัสกลับได้ตรงกัน
✔ vault: passphrase ผิด → ปฏิเสธ (ไม่เงียบมันเอง)
✔ vault: แฟ้มถูกแก้ 1 บิต (ciphertext) → authTag ตรวจไม่ผ่าน
✔ vault: มีพารามิเตอร์ Argon2id ในแฟ้ม (ตรวจสอบได้ตลอด)
✔ vault → signReceipt: ถอดกุญแจจาก vault แล้วเซ็นได้ + ตรวจผ่านทั้งคู่
✔ vault: passphrase สั้นเกิน 8 ตัว → ปฏิเสธตั้งแต่ตอนสร้าง

ℹ tests 14 · pass 14 · fail 0
```

```
$ node cli.js selftest
  ✓ เซ็นแล้วตรวจผ่าน (ทั้งสองลายเซ็น)
  ✓ แก้ payload → ต้องไม่ผ่าน
  ✓ ลบลายเซ็น ML-DSA → ต้องไม่ผ่าน
  ✓ ลายเซ็น Ed25519 ตรวจแยกขั้น
  ✓ ลายเซ็น ML-DSA-44 ตรวจแยกขั้น
  ✓ vault: เข้ารหัส→ถอดรหัส กลับได้ตรง
  ✓ vault: passphrase ผิด → ต้องปฏิเสธ
```

---

## 🏢 อยู่ตรงไหนในผังระบบ Sovereign

repo นี้คือ**ชั้นตรวจสอบอัตลักษณ์**ที่วางแผนเพื่อต่อกับโครงอื่นทั้งชุด — แทนที่จะแตะระบบเดิมโดยตรง มันทำงานเป็น**ไลบรารีเดี่ยว ๆ** แล้วคุณเลือกเวลาต่อยอดได้เองในอนาคต

| โปรเจกต์ | ความสัมพันธ์ |
|---|---|
| 🏠 [`sovereign-origin`](https://github.com/krisakornutama/sovereign-origin) — **ระบบหลัก** | แอป desktop ประจำบ้าน (ขาย · บัญชี · ภาษี · ฟาร์ม) — อนาคตรับ ledger จาก repo นี้ไป export เป็นเอกสารทางบัญชี |
| 🌿 [`sovereign-offgrid`](https://github.com/krisakornutama/sovereign-offgrid) | POS ออฟไลน์เซ็น Ed25519 แล้ววันนี้ — ไลบรารีของ repo นี้นำไป**อัปเกรดสลิปเป็นสองลายเซ็นตั้งแต่ต้นทาง**ได้เลย |
| 📡 [`project-sovereign`](https://github.com/krisakornutama/project-sovereign) | เว็บสาธารณะ + ระบบหลังบ้าน self-hosted — โครงพื้นฐานที่เชื่อมทุก repo |
| 🧠 [`sovereign-rule-engine`](https://github.com/krisakornutama/sovereign-rule-engine) | Rule engine Merkle + CRDT — ใช้ตัวตน/ลายเซ็นจาก repo นี้ตั้งกฎสิทธิ์ได้โดยตรง |

---

## 🧭 โรดแม็ปตามชั้นเป้าหมายจริง

| เฟส | งาน | สถานะ |
|---|---|---|
| ✅ **เสร็จแล้ววันนี้** | ตัวตนนิรนาม + สองลายเซ็น (Ed25519 + ML-DSA-44) + คลัง idempotent + **Local Key Vault (Argon2id + AES-256-GCM)** + ทดสอบ 14/14 | พร้อมใช้ |
| 🧩 **เฟส 2** | **ZK จริง: พิสูจน์โดยไม่เปิดเผยข้อมูล** (ZK-SNARK / ZK-STARK — ยืนยันสิทธิ์โดยไม่ต้องบอกว่าคุณคือใคร) | วางแผนถัดไป |
| 🧊 **เฟส 3** | ลายเซ็นชุดเสริม (SLH-DSA / Falcon) + ระบบหมุนเวียนกุญแจอัตโนมัติ | วางแผน |
| 🔊 **เฟส 4** | เข้ารหัสแบบด้าน ML-KEM (FIPS 203) สำหรับแฟ้มที่ส่งระหว่างโหนด | วางแผน |

---

## ⚠️ ความจริงระยะตรง — อ่านก่อนใช้จริง

- 🔏 **กุญแจ secret เก็บใน vault เข้ารหัสตั้งแต่ v1.1** — หากยังใช้แฟ้ม plaintext เก่า (v1.0) ให้ migrate ด้วย `node cli.js vault create` ตามด้วย `vault remove-plain` ทันที — ระบบขอ passphrase แบบพิมพ์ซ่อนอักษร · **ลืม passphrase = ไม่มีทางกู้คืนกุญแจ** (ตามหลัก vault: กุญแจเสีย ตัวตนต้องสร้างใหม่) ทางต่อยอดถัดไป: เชื่อม OS keychain (macOS Keychain / Windows DPAPI / Linux Secret Service)
- 🌐 **บนเบราว์เซอร์ (Web Crypto) ยังไม่รองรับ ML-DSA** — ระบบนี้วิ่งบน Node.js เป็นหลัก ส่วนฝั่งเบราว์เซอร์จะต้องใส่ไลบรารี JS/WASM อีกชั้น (จะเพิ่มเป็นเวอร์ชันเสริม)
- 🧪 **สำหรับภารกิจระดับธนาคาร/การแพทย์** — โค้ดระบบนี้เป็นระบบนำพิสูจน์แนวทาง; ก่อนนำไปใช้ระดับ production จริง ควรให้ผู้เชี่ยวชาญตรวจโค้ด (code audit) หรือใช้ liboqs เวอร์ชันที่ผ่านการตรวจแทน
- 🧾 ทุกชิ้นรันในเครื่อง · **ไม่ส่งข้อมูลจากเครื่องออกไปที่ไหน** — `npm install` ต้องเน็ตครั้งเดียวตอนติดตั้ง; หลังจากนั้นระบบทำงาน offline 100%

---

## 👤 ผู้พัฒนา

**กฤษกรณ์ อุตมะ (Krisakorn Utama)** — System Architect
> ออกแบบและพัฒนาระบบ Electron / Next.js + Node.js ทั้งชุด — ข้อมูลทุกชุดรออยู่ในเครื่องของคุณเอง ตามหลัก sovereignty
> แผนการพัฒนาทั้งหมดดูได้ที่ [project-sovereign](https://github.com/krisakornutama/project-sovereign)

<div align="center">

**⭐ ถ้าระบบนี้ช่วยงานคุณได้ กด Star เป็นกำลังใจให้การพัฒนา 🫶**

</div>
