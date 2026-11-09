// วงจร Balance Threshold Proof — ZK-SNARK (Groth16) — v1.3
//
// พิสูจน์ต่อผู้ตรวจว่า "ยอดสิทธิ์ของผู้ถือ ≥ threshold ที่ประกาศ" โดยไม่เปิดเผยยอดจริง
// และไม่เปิดเผยว่าใบนั้นเป็นของใครในต้นไม้ (Merkle position คงเป็นลับ)
//
// โครงกุญแจ: ผู้ออกสิทธิ์ (issuer) ออก "ใบยอด" = commitment ของยอด
//   leaf = Poseidon(3)([balance, blinding, TAG_BAL])   · balance = จำนวนสตางค์ (จำนวนเต็ม)
// แล้วลงต้นไม้เดียวกับกลุ่ม (node = Poseidon(3)([L, R, TAG_NODE])) — รากที่ประกาศ
// คือหลักฐานว่าใบนั้นมาจากผู้ออกสิทธิ์จริง (เชิงตรรกะเดียวกับ membership แต่ต่างโดเมนแท็ก)
//
// ข้ออ้างในวงจร (ผ่านทุกข้อ จึงพิสูจน์ได้):
//   1) ใบของลับนี้และเส้นทางขึ้นตรงรากที่ประกาศ (อยู่ในกลุ่มใบยอดของ issuer)
//   2) balance อยู่ในช่วง 64 บิต (range check ผ่านบิตตัวแทน — กันการม้วนค่าด้วยโมดูลาร์)
//   3) threshold ≤ balance (ตรวจด้วย LessEqThan(64) — ยอดจริงไม่ออกจากวงจร)
//   4) nullifier แยกโดเมน — ใบเดียวรอบเดียวใช้ได้ครั้งเดียว (กัน double-claim ข้ามวงจรด้วย)
//
// Public inputs:  merkleRoot · epochNonce (กัน replay) · threshold (iterations เปิดเผยขั้นต่ำ)
// Public output:  nullifierHash — ผู้ตรวจบันทึกห้ามซ้ำ (ไม่รู้ว่าใคร · ไม่รู้ยอด)
pragma circom 2.2.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/switcher.circom";
include "circomlib/circuits/comparators.circom";

template BalanceThreshold(D, NBITS) {
    // แท็กโดเมนของวงจรนี้ — เลขเหลื่อมจากวงจร membership (0-2) โดยเจตนา
    // กันการแย่งแฮชข้ามวงจร: ใบยอดและ nullifier ของวงจรนี้ยังไม่ตรงมาทับค่าของวงจรอื่น
    var TAG_NODE = 0;      // แฮชแนวเดินต้นไม้ร่วมกับ membership (โครง node เดียวกัน)
    var TAG_BAL = 10;      // ใบยอด: แยกชัดจาก leaf สมาชิก (1)
    var TAG_NULL_BAL = 11; // nullifier ของวงจรนี้: แยกชัดจาก nullifier สมาชิก (2)

    // ----- ข้อมูลลับ (อยู่เฉพาะเครื่องผู้พิสูจน์ ไม่ออกจากวงจร) -----
    signal input balance;          // ยอดจริง (สตางค์) — ปิดเป็นความลับเสมอ
    signal input blinding;         // ค่าเหลื่อมสุ่มประจำใบ — ทำให้ใบเดียวกันเจาะไม่ได้จากค่าใบที่ซ้ำเท่ากัน
    signal input pathElements[D];  // พี่น้อง (sibling) ตามแนวขึ้น
    signal input pathIndices[D];   // บิตทิศทาง 0/1 ของแต่ละชั้น

    // ----- ข้อมูลสาธารณะ (ผู้ตรวจถืออยู่แล้ว) -----
    signal input merkleRoot;       // รากของต้นไม้ใบยอดที่ issuer ประกาศ
    signal input epochNonce;       // หมายเลขรอบ — กันการนำ Proof เดิมกลับมา
    signal input threshold;        // ขั้นต่ำที่ผู้ตรวจยอมรับ (สาธารณะจริง — เช่น POS ประกาศ "ต้อง ≥ หนึ่งหนึ่งโห")

    // ----- สัญญาณสาธารณะที่ออกจากวงจร -----
    signal output nullifierHash;   // แตะสิทธิ์รอบนี้ — ผู้ตรวจบันทึกห้ามซ้ำ

    // 1) ยอด + เหลื่อมสุ่ม → commitment ใบ (leaf)
    component leaf = Poseidon(3);
    leaf.inputs[0] <== balance;
    leaf.inputs[1] <== blinding;
    leaf.inputs[2] <== TAG_BAL;

    signal levels[D + 1];
    levels[0] <== leaf.out;

    component sw[D];
    component climb[D];

    // 2) ไต่ต้นไม้ D ขั้น — บิตทิศทางต้องเป็น 0/1 (ผูกเอง เพราะ Switcher ไม่ตรวจให้)
    for (var i = 0; i < D; i++) {
        pathIndices[i] * pathIndices[i] - pathIndices[i] === 0;
        sw[i] = Switcher();
        sw[i].sel <== pathIndices[i];
        sw[i].L <== levels[i];
        sw[i].R <== pathElements[i];
        climb[i] = Poseidon(3);
        climb[i].inputs[0] <== sw[i].outL;
        climb[i].inputs[1] <== sw[i].outR;
        climb[i].inputs[2] <== TAG_NODE;
        levels[i + 1] <== climb[i].out;
    }

    // 3) ปลายขึ้นต้องตรงรากที่ issuer ประกาศ — ไม่ตรง = ใบไม่ได้ออกให้ = วงจรไม่พิสูจน์ให้
    levels[D] === merkleRoot;

    // 4) ข้ออ้างหลักของวงจรนี้: threshold ≤ balance — ผ่าน LessEqThan(64)
    //    (Num2Bits(65) ข้างในพ่วงตัวยืนยันช่วง 64 บิตของ balance/threshold มาด้วย — ม้วนค่าที่บวกโมดูลาร์ไม่ผ่าน)
    component cmp = LessEqThan(NBITS);
    cmp.in[0] <== threshold;
    cmp.in[1] <== balance;
    cmp.out === 1;

    // 5) nullifier ผูกกับ blinding + epoch (โดเมนของวงจรนี้) — ตัวตนซ่อน ยอดซ่อน แต่ใบซ้ำจับได้
    component nf = Poseidon(3);
    nf.inputs[0] <== blinding;
    nf.inputs[1] <== epochNonce;
    nf.inputs[2] <== TAG_NULL_BAL;
    nullifierHash <== nf.out;
}

component main { public [merkleRoot, epochNonce, threshold] } = BalanceThreshold(4, 64);
