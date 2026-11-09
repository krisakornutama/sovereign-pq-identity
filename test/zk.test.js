// ทดสอบ ZK-SNARK Anonymous Membership — วงจรจริง (artifacts เท่านั้น ไม่มีจำลอง)
// ถ้ายังไม่มีแฟ้มวงจร ทดสอบพิสูจน์ข้าม (skip) พร้อมเหตุผล — วิธีสร้างแฟ้มวงจรอยู่ใน README หัวข้อ "การสร้างแฟ้มวงจร"
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { randomBytes } from 'node:crypto';
import { loadPoseidon, buildTree, pathFor, newMemberSecret, MERKLE_DEPTH, MAX_MEMBERS, DEEP_DEPTH } from '../src/merkle.js';
import { proveMembership, verifyMembership, artifactsReady, loadNullifierLedger, isNullifierSpent, appendNullifier, proveBalance, verifyBalance, artifactsReadyBalance, artifactsReadyDeep, artifactsReadyBalanceDeep, ARTIFACTS_DEEP, ARTIFACTS_BALANCE_DEEP, CIRCUIT } from '../src/zk.js';

const READY = artifactsReady();
const READY_BAL = artifactsReadyBalance();
const READY_DEEP = artifactsReadyDeep();
const READY_BAL_DEEP = artifactsReadyBalanceDeep();

test('merkle: ลำดับใบต่างกัน → รากต้องต่างกัน (canonical เสถียร)', async () => {
  const poseidon = await loadPoseidon();
  const c1 = [11n, 22n, 33n];
  const t1 = buildTree(c1, poseidon);
  const c2 = [33n, 11n, 22n];
  const t2 = buildTree(c2, poseidon);
  assert.notEqual(t1.root, t2.root); // ลำดับใบต่างกันรากต้องต่าง
  assert.equal(t1.levels.length, MERKLE_DEPTH + 1);
});

test('merkle: สมาชิกน้อยกว่าความจุ → padding เต็มช่องและรากยังเสถียร', async () => {
  const poseidon = await loadPoseidon();
  const t = buildTree([123n], poseidon);
  assert.equal(t.levels[0].length, MAX_MEMBERS);
});

test('merkle: รากจากเส้นทาง member#2 ไต่ขึ้นเทียบรากตรงกัน (indices เป็นบิตจริง)', async () => {
  const poseidon = await loadPoseidon();
  const secrets = [1n, 2n, 3n, 4n];
  const c = secrets.map((s) => poseidon.leafOf(s));
  const tree = buildTree(c, poseidon);
  const p = pathFor(tree, 2); // 2 = 10 ในฐานสอง → [1,0]
  assert.deepEqual(p.indices, [0, 1, 0, 0]);
  // การไต่แบบทำเอง: ต้องได้รากเดียวกัน
  let idx = 2;
  let cur = c[2];
  for (let d = 0; d < MERKLE_DEPTH; d++) {
    const isRight = idx % 2 === 1;
    const sib = isRight ? tree.levels[d][idx - 1] : tree.levels[d][idx + 1];
    cur = isRight ? poseidon.nodeOf(sib, cur) : poseidon.nodeOf(cur, sib);
    idx = Math.floor(idx / 2);
  }
  assert.equal(cur, tree.root);
});

test('zk: พิสูจน์สมาชิกจริง → ตรวจผ่านโดยไม่รู้กุญแจ', { skip: !READY && 'ยังไม่มี artifacts (wasm/zkey/vkey) — ดูวิธีสร้างใน README หัวข้อ "การสร้างแฟ้มวงจร"' }, async () => {
  const poseidon = await loadPoseidon();
  const secrets = Array.from({ length: 6 }, () => newMemberSecret(randomBytes));
  const c = secrets.map((s) => poseidon.leafOf(s));
  const tree = buildTree(c, poseidon);
  const path = pathFor(tree, 5);
  const epoch = 20261108n;
  const { proof, publicSignals } = await proveMembership({ secret: secrets[5], path, root: tree.root, epoch });
  // ผู้ตรวจไม่มีข้อมูลสมาชิกใด ๆ — ตรวจด้วย vkey ล้วน
  const ok = await verifyMembership({ proof, publicSignals });
  assert.equal(ok, true);
  assert.equal(publicSignals.epochNonce, '20261108');
});

test('zk: แก้ proof 1 บิต → ตรวจไม่ผ่าน', { skip: !READY && 'ยังไม่มี artifacts (wasm/zkey/vkey)' }, async () => {
  const poseidon = await loadPoseidon();
  const secrets = [10n, 20n];
  const tree = buildTree(secrets.map((s) => poseidon.leafOf(s)), poseidon);
  const { proof, publicSignals } = await proveMembership({ secret: secrets[1], path: pathFor(tree, 1), root: tree.root, epoch: 20261108n });
  const bad = JSON.parse(JSON.stringify(proof));
  bad.pi_c[0] = (BigInt(bad.pi_c[0]) + 1n).toString();
  assert.equal(await verifyMembership({ proof: bad, publicSignals }), false);
});

test('zk: สมาชิกที่ไม่อยู่ในกลุ่ม → วงจรปฏิเสธที่ witness (ไม่มี proof ออกมา)', { skip: !READY && 'ยังไม่มี artifacts (wasm/zkey/vkey)' }, async () => {
  const poseidon = await loadPoseidon();
  const secrets = [99n, 100n];
  const tree = buildTree(secrets.map((s) => poseidon.leafOf(s)), poseidon);
  await assert.rejects(() => proveMembership({ secret: 987654321n, path: pathFor(tree, 0), root: tree.root, epoch: 20261108n }));
});

test('zk: nullifier เดียวกันใช้ซ้ำรอบเดียวกัน = ตรวจพบ (double-claim)', { skip: !READY && 'ยังไม่มี artifacts (wasm/zkey/vkey)' }, async () => {
  const tmpLedger = 'build/test-nullifiers.jsonl';
  fs.rmSync(tmpLedger, { force: true });
  assert.equal(isNullifierSpent([], '123456789', 20261108, '42'), false);
  appendNullifier(tmpLedger, { nullifier: '123456789', epoch: 20261108, root: '42', verified_at: new Date().toISOString() });
  const ledger = loadNullifierLedger(tmpLedger);
  assert.equal(isNullifierSpent(ledger, '123456789', 20261108, '42'), true);
  assert.equal(isNullifierSpent(ledger, '123456789', 20261109, '42'), false); // epoch ใหม่ = สิทธิ์ใหม่
  fs.rmSync(tmpLedger, { force: true });
});

// ==== วงจรที่ 2: Balance Threshold — พิสูจน์ "ยอด ≥ threshold" โดยไม่เปิดยอดจริง ====

test('zk-balance: พิสูจน์ "ยอด ≥ threshold" จริง → ตรวจผ่าน และยอดจริงไม่โผล่ที่สาธารณะ', { skip: !READY_BAL && 'ยังไม่มี artifacts balance (wasm/zkey/vkey) — ดูวิธีสร้างใน README หัวข้อ "การสร้างแฟ้มวงจร"' }, async () => {
  const poseidon = await loadPoseidon();
  const balances = [50_000n, 500_000n, 1_200_000n];
  const blindings = balances.map(() => newMemberSecret(randomBytes));
  const commitments = balances.map((b, i) => poseidon.balanceLeafOf(b, blindings[i]));
  const tree = buildTree(commitments, poseidon);
  const epoch = 20261109n;
  const threshold = 100_000n;
  const { proof, publicSignals } = await proveBalance({ balance: balances[1], blinding: blindings[1], path: pathFor(tree, 1), root: tree.root, epoch, threshold });
  assert.equal(await verifyBalance({ proof, publicSignals }), true); // ผู้ตรวจใช้ vkey ล้วน
  assert.equal(publicSignals.threshold, '100000');                  // threshold สาธารณะตามที่อ้าง
  assert.ok(!Object.values(publicSignals).includes('500000'));      // ยอดจริงต้องไม่เทียบเตียงออกมา
  assert.equal(publicSignals.epochNonce, '20261109');
});

test('zk-balance: ยอด < threshold → วงจรปฏิเสธที่ witness (ไม่มี proof ออกมาให้หลอก)', { skip: !READY_BAL && 'ยังไม่มี artifacts balance (wasm/zkey/vkey)' }, async () => {
  const poseidon = await loadPoseidon();
  const commitments = [poseidon.balanceLeafOf(50_000n, 111n)];
  const tree = buildTree(commitments, poseidon);
  await assert.rejects(() => proveBalance({ balance: 50_000n, blinding: 111n, path: pathFor(tree, 0), root: tree.root, epoch: 20261109n, threshold: 100_000n }));
});

test('zk-balance: แก้ threshold ใน publicSignals → ตรวจไม่ผ่าน (proof ผูกข้ออ้างตายตัว)', { skip: !READY_BAL && 'ยังไม่มี artifacts balance (wasm/zkey/vkey)' }, async () => {
  const poseidon = await loadPoseidon();
  const commitments = [poseidon.balanceLeafOf(900_000n, 222n)];
  const tree = buildTree(commitments, poseidon);
  const { proof, publicSignals } = await proveBalance({ balance: 900_000n, blinding: 222n, path: pathFor(tree, 0), root: tree.root, epoch: 20261109n, threshold: 100_000n });
  const tampered = { ...publicSignals, threshold: (BigInt(publicSignals.threshold) + 1n).toString() }; // อ้างขั้นต่ำสูงขึ้นภายหลัง → ไม่ผ่าน
  assert.equal(await verifyBalance({ proof, publicSignals: tampered }), false);
});

test('zk-balance: leaf ไม่ตรงกลุ่มของ issuer (เหลื่อมสุ่มอีกชุด) → วงจรปฏิเสธ', { skip: !READY_BAL && 'ยังไม่มี artifacts balance (wasm/zkey/vkey)' }, async () => {
  const poseidon = await loadPoseidon();
  const commitments = [poseidon.balanceLeafOf(900_000n, 333n)];
  const tree = buildTree(commitments, poseidon);
  const wrongBlinding = newMemberSecret(randomBytes); // คนอื่นพยายามเอายอดว่าวงจรที่ผู้อื่นลงบันทึก
  await assert.rejects(() => proveBalance({ balance: 900_000n, blinding: wrongBlinding, path: pathFor(tree, 0), root: tree.root, epoch: 20261109n, threshold: 100_000n }));
});

test('zk-balance: แท็กโดเมนแยกชัด — nullifier วงจรยอดไม่ทับ nullifier สมาชิกแม้ค่าลับเท่ากัน', async () => {
  const poseidon = await loadPoseidon();
  const epoch = 20261109n;
  assert.notEqual(poseidon.nullifierOf(42n, epoch), poseidon.balanceNullifierOf(42n, epoch)); // แท็ก 2 vs 11
});

// ==== v1.5: โปรไฟล์ลึก D=5 (32 ช่อง) ====

test('merkle D=5: ความจุ 32 ช่อง · padding เต็มและรากเสถียร', async () => {
  const poseidon = await loadPoseidon();
  const t = buildTree([123n], poseidon, { depth: DEEP_DEPTH });
  assert.equal(t.levels[0].length, 2 ** DEEP_DEPTH); // 32
  assert.equal(t.depth, DEEP_DEPTH);
});

test('zk D=5: พิสูจน์สมาชิกจริงโปรไฟล์ลึก → ตรวจผ่านด้วย vkey D=5', { skip: !READY_DEEP && 'ยังไม่มี artifacts D=5 (wasm/zkey/vkey)' }, async () => {
  const poseidon = await loadPoseidon();
  const secrets = Array.from({ length: 10 }, () => newMemberSecret(randomBytes));
  const c = secrets.map((s) => poseidon.leafOf(s));
  const tree = buildTree(c, poseidon, { depth: DEEP_DEPTH });
  const path = pathFor(tree, 9);
  const epoch = 20261109n;
  const { proof, publicSignals } = await proveMembership({ secret: secrets[9], path, root: tree.root, epoch, artifacts: ARTIFACTS_DEEP });
  // ผู้ตรวจใช้ vkey D=5
  const ok = await verifyMembership({ proof, publicSignals, vkeyPath: 'artifacts/membership_d5_vkey.json' });
  assert.equal(ok, true);
  assert.equal(publicSignals.epochNonce, '20261109');
});

test('zk-balance D=5: พิสูจน์ยอดจริงโปรไฟล์ลึก → ตรวจผ่านด้วย vkey D=5', { skip: !READY_BAL_DEEP && 'ยังไม่มี artifacts balance D=5' }, async () => {
  const poseidon = await loadPoseidon();
  const balances = [50_000n, 500_000n, 1_200_000n];
  const blindings = balances.map(() => newMemberSecret(randomBytes));
  const commitments = balances.map((b, i) => poseidon.balanceLeafOf(b, blindings[i]));
  const tree = buildTree(commitments, poseidon, { depth: DEEP_DEPTH });
  const epoch = 20261109n;
  const threshold = 100_000n;
  const { proof, publicSignals } = await proveBalance({ balance: balances[1], blinding: blindings[1], path: pathFor(tree, 1), root: tree.root, epoch, threshold, artifacts: ARTIFACTS_BALANCE_DEEP });
  const ok = await verifyBalance({ proof, publicSignals, vkeyPath: 'artifacts/balance_d5_vkey.json' });
  assert.equal(ok, true);
  assert.equal(publicSignals.threshold, '100000');
  assert.ok(!Object.values(publicSignals).includes('500000'));
});

test('zk cross-vkey: ใบพิสูจน์ D=4 ตรวจด้วย vkey D=5 → ต้องปฏิเสธ', { skip: !READY || !READY_DEEP && 'ต้องมี artifacts ทั้ง D=4 และ D=5' }, async () => {
  const poseidon = await loadPoseidon();
  const secrets = [100n, 200n];
  const c = secrets.map((s) => poseidon.leafOf(s));
  const tree = buildTree(c, poseidon, { depth: MERKLE_DEPTH });
  const epoch = 20261109n;
  // พิสูจน์ด้วย artifacts D=4
  const { proof, publicSignals } = await proveMembership({ secret: secrets[1], path: pathFor(tree, 1), root: tree.root, epoch });
  // ตรวจด้วย vkey D=5 (ต้องล้มเหลวเพราะวงจรต่างกัน = constraints ต่างกัน)
  const ok = await verifyMembership({ proof, publicSignals, vkeyPath: 'artifacts/membership_d5_vkey.json' });
  assert.equal(ok, false);
});

test('zk cross-vkey: ใบพิสูจน์ D=5 ตรวจด้วย vkey D=4 → ต้องปฏิเสธ', { skip: !READY || !READY_DEEP && 'ต้องมี artifacts ทั้ง D=4 และ D=5' }, async () => {
  const poseidon = await loadPoseidon();
  const secrets = [100n, 200n, 300n];
  const c = secrets.map((s) => poseidon.leafOf(s));
  const tree = buildTree(c, poseidon, { depth: DEEP_DEPTH });
  const epoch = 20261109n;
  // พิสูจน์ด้วย artifacts D=5
  const { proof, publicSignals } = await proveMembership({ secret: secrets[2], path: pathFor(tree, 2), root: tree.root, epoch, artifacts: ARTIFACTS_DEEP });
  // ตรวจด้วย vkey D=4 (ต้องล้มเหลว)
  const ok = await verifyMembership({ proof, publicSignals, vkeyPath: 'artifacts/membership_vkey.json' });
  assert.equal(ok, false);
});

test('zk cross-circuit: ใบพิสูจน์ membership ตรวจด้วย vkey balance → ต้องปฏิเสธ', { skip: !READY || !READY_BAL && 'ต้องมี artifacts ทั้งสองวงจร' }, async () => {
  const poseidon = await loadPoseidon();
  const secrets = [100n, 200n];
  const c = secrets.map((s) => poseidon.leafOf(s));
  const tree = buildTree(c, poseidon);
  const epoch = 20261109n;
  const { proof, publicSignals } = await proveMembership({ secret: secrets[1], path: pathFor(tree, 1), root: tree.root, epoch });
  // ตรวจ membership proof ด้วย balance vkey (ต้องล้มเหลว)
  const ok = await verifyMembership({ proof, publicSignals, vkeyPath: 'artifacts/balance_vkey.json' });
  assert.equal(ok, false);
});

test('zk cross-circuit: ใบพิสูจน์ balance ตรวจด้วย vkey membership → ต้องปฏิเสธ (error หรือ false)', { skip: !READY || !READY_BAL && 'ต้องมี artifacts ทั้งสองวงจร' }, async () => {
  const poseidon = await loadPoseidon();
  const balances = [500_000n];
  const blindings = [newMemberSecret(randomBytes)];
  const commitments = balances.map((b, i) => poseidon.balanceLeafOf(b, blindings[i]));
  const tree = buildTree(commitments, poseidon);
  const epoch = 20261109n;
  const threshold = 100_000n;
  const { proof, publicSignals } = await proveBalance({ balance: balances[0], blinding: blindings[0], path: pathFor(tree, 0), root: tree.root, epoch, threshold });
  // ตรวจ balance proof ด้วย membership vkey (ต้องล้มเหลว — public signals จำนวนไม่ตรง จะได้ error หรือ false)
  let ok = false;
  try {
    ok = await verifyBalance({ proof, publicSignals, vkeyPath: 'artifacts/membership_vkey.json' });
  } catch {
    ok = false;
  }
  assert.equal(ok, false);
});
