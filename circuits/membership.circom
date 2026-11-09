// วงจร Anonymous Membership Verification — ZK-SNARK (Groth16)
//
// พิสูจน์ได้ว่า "ผู้ถือสิทธิ์อยู่ในกลุ่มสมาชิกที่ได้รับอนุมัติ" โดยไม่เปิดเผยกุญแจ
// เฉพาะตัว (identitySecret) และไม่เปิดเผยตำแหน่งในแผนผัง (Merkle path)
//
// ใช้แฮช Poseidon (SNARK-friendly) — ทุกขั้นเป็น Poseidon(3) ล้วน:
//   leaf      = Poseidon(3)([identitySecret, TAG_LEAF, 0])
//   node      = Poseidon(3)([outL, outR, TAG_NODE])   (outL/outR จาก Switcher ตามบิตทิศทาง)
//   nullifier = Poseidon(3)([identitySecret, epochNonce, TAG_NULL])
//
// Public inputs:  merkleRoot (รากที่ประกาศสาธารณะแล้ว), epochNonce (หมายเลขรอบ กัน replay)
// Public output:  nullifierHash — ผู้ตรวจเก็บไว้ ห้ามใช้ซ้ำ (ไม่รู้ว่าใคร แต่รู้ว่ากลุ่มใด)
pragma circom 2.2.0;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/switcher.circom";

template Membership(D) {
    // แท็กโดเมนแยกหน้าที่ชัดเจน: กันการนำแฮชจากขั้นหนึ่งไปแปะอีกขั้น
    var TAG_NODE = 0;
    var TAG_LEAF = 1;
    var TAG_NULL = 2;

    // ----- ข้อมูลลับ (อยู่เฉพาะเครื่องผู้พิสูจน์ ไม่ออกจากวงจร) -----
    signal input identitySecret;     // กุญแจลับประจำตัว (< BN254 p — ซ้อนใน vault เข้ารหัส)
    signal input pathElements[D];    // ค่าพี่น้อง (sibling) ตามแนวขึ้น
    signal input pathIndices[D];     // บิตทิศทาง 0/1 ว่าโหนดตัวเองอยู่ซ้าย/ขวาในแต่ละชั้น

    // ----- ข้อมูลสาธารณะ (โหนดตรวจควรถืออยู่แล้ว) -----
    signal input merkleRoot;         // รากของต้นไม้สมาชิก ที่ประกาศแล้วในวันออกสิทธิ์
    signal input epochNonce;         // หมายเลขรอบ — กันการนำ Proof จากรอบเก่ากลับมาซ้ำ

    // ----- สัญญาณสาธารณะที่ออกจากวงจร -----
    signal output nullifierHash;     // = ตัวเลขอ้างสิทธิ์รอบนี้ (ผู้ตรวจบันทึกห้ามซ้ำ)

    // 1) กุญแจตัวตน → commitment ใบ (leaf)
    component leaf = Poseidon(3);
    leaf.inputs[0] <== identitySecret;
    leaf.inputs[1] <== TAG_LEAF;
    leaf.inputs[2] <== 0;

    signal levels[D + 1];
    levels[0] <== leaf.out;

    component sw[D];
    component climb[D];

    // 2) ไต่ต้นไม้ D ขั้น — แต่ละขั้นเลือกจุดพี่น้องตามบิตทิศทาง
    for (var i = 0; i < D; i++) {
        // บิตทิศทางตั้งเองต้องเป็น 0/1 (Switcher ไม่ตรวจให้ — ต้องผูกเอง)
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

    // 3) ปลายขึ้นต้องตรงรากประกาศ — ไม่ตรง = ไม่อยู่ในกลุ่ม = วงจรไม่พิสูจน์ให้
    levels[D] === merkleRoot;

    // 4) nullifier ผูกกับ identitySecret + epoch — ตัวตนซ่อน แต่รอบซ้ำจับได้
    component nf = Poseidon(3);
    nf.inputs[0] <== identitySecret;
    nf.inputs[1] <== epochNonce;
    nf.inputs[2] <== TAG_NULL;
    nullifierHash <== nf.out;
}

component main { public [merkleRoot, epochNonce] } = Membership(4);
