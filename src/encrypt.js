import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

// UNSAFE: CBC with a fixed IV and no authentication. The same plaintext always
// gives the same ciphertext (leaks equality), and an attacker can flip bits in
// the ciphertext without you noticing.
const STATIC_IV = Buffer.alloc(16, 0);
export function encryptUnsafe(plaintext, key) {
  const cipher = createCipheriv('aes-256-cbc', key, STATIC_IV);
  return Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]).toString('base64');
}

// SAFE: AES-256-GCM. Fresh random 12-byte IV per message, and a 16-byte auth
// tag so any tampering makes decryption throw.
// Output layout: iv (12) | tag (16) | ciphertext, base64 encoded.
const IV_LEN = 12;
const TAG_LEN = 16;

export function encrypt(plaintext, key) {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_LEN });
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64');
}

export function decrypt(blob, key) {
  const buf = Buffer.from(blob, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', key, buf.subarray(0, IV_LEN), { authTagLength: TAG_LEN });
  decipher.setAuthTag(buf.subarray(IV_LEN, IV_LEN + TAG_LEN));
  return Buffer.concat([decipher.update(buf.subarray(IV_LEN + TAG_LEN)), decipher.final()]).toString('utf8');
}

// UNSAFE: no integrity check. A tampered ciphertext decrypts "successfully" to
// whatever the attacker's bit flips produced.
export function decryptUnsafe(blob, key) {
  const decipher = createDecipheriv('aes-256-cbc', key, STATIC_IV);
  return Buffer.concat([decipher.update(Buffer.from(blob, 'base64')), decipher.final()]).toString('utf8');
}
