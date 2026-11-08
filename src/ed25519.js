// Ed25519 — ผ่าน node:crypto (built-in, ไม่มี dependency ที่กลุ้มรุ่น)
import { createPrivateKey, createPublicKey, sign, verify as verifySig } from 'node:crypto';

export function readEdPriv(sk_b64) {
  return createPrivateKey({ key: Buffer.from(sk_b64, 'base64'), format: 'der', type: 'pkcs8' });
}

export function readEdPub(pk_b64) {
  return createPublicKey({ key: Buffer.from(pk_b64, 'base64'), format: 'der', type: 'spki' });
}

export function edSign(privKeyObject, bytes) {
  return sign(null, bytes, privKeyObject);
}

export function edVerifyB64(pk_b64, bytes, sigBytes) {
  return verifySig(null, bytes, readEdPub(pk_b64), sigBytes);
}
