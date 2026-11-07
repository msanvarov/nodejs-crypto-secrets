import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { hashPassword, hashPasswordUnsafe, verifyPassword } from '../src/password.js';
import { hashToken, otpCode, resetToken } from '../src/tokens.js';
import { sign, verify, verifyUnsafe } from '../src/jwt.js';
import { decrypt, encrypt, encryptUnsafe } from '../src/encrypt.js';
import { redact, requireSecret } from '../src/config.js';

test('passwords: salted scrypt, unique per hash, verifies correctly', async () => {
  assert.equal(hashPasswordUnsafe('hunter2'), hashPasswordUnsafe('hunter2'), 'unsafe: same input, same hash');

  const a = await hashPassword('hunter2');
  const b = await hashPassword('hunter2');
  assert.notEqual(a, b, 'random salt makes every hash unique');
  assert.match(a, /^scrypt\$32768\$8\$1\$/);
  assert.equal(await verifyPassword('hunter2', a), true);
  assert.equal(await verifyPassword('hunter3', a), false);
  assert.equal(await verifyPassword('hunter2', 'md5$whatever'), false);
});

test('tokens: long, unique, URL-safe; stored as a hash', () => {
  const tokens = new Set(Array.from({ length: 1000 }, resetToken));
  assert.equal(tokens.size, 1000);
  const [t] = tokens;
  assert.match(t, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(hashToken(t), hashToken(t));
  assert.notEqual(hashToken(t), t);
  assert.match(otpCode(), /^\d{6}$/);
});

test('JWT: forged alg=none token fools the unsafe verifier only', () => {
  const secret = randomBytes(32);
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const forged = `${b64({ alg: 'none' })}.${b64({ sub: 'attacker', role: 'admin' })}.`;

  assert.equal(verifyUnsafe(forged, secret).role, 'admin');
  assert.throws(() => verify(forged, secret), /unexpected algorithm/);
});

test('JWT: valid tokens pass; tampered, wrong-key, and expired tokens fail', () => {
  const secret = randomBytes(32);
  const token = sign({ sub: 'alice', role: 'user' }, secret);
  assert.equal(verify(token, secret).sub, 'alice');

  const [h, , s] = token.split('.');
  const tampered = `${h}.${Buffer.from(JSON.stringify({ sub: 'alice', role: 'admin', exp: 9e9 })).toString('base64url')}.${s}`;
  assert.throws(() => verify(tampered, secret), /bad signature/);
  assert.throws(() => verify(token, randomBytes(32)), /bad signature/);
  assert.throws(() => verify(sign({ sub: 'alice' }, secret, { expiresInSec: -1 }), secret), /expired/);
  assert.throws(() => verify('not.a-token', secret), /malformed/);
});

test('encryption: GCM round-trips, uses fresh IVs, and detects tampering', () => {
  const key = randomBytes(32);
  assert.equal(encryptUnsafe('same', key), encryptUnsafe('same', key), 'unsafe: leaks that two messages are equal');

  const c1 = encrypt('card ending 4242', key);
  assert.notEqual(c1, encrypt('card ending 4242', key));
  assert.equal(decrypt(c1, key), 'card ending 4242');

  const bytes = Buffer.from(c1, 'base64');
  bytes[bytes.length - 1] ^= 1; // flip one bit of ciphertext
  assert.throws(() => decrypt(bytes.toString('base64'), key));
  assert.throws(() => decrypt(c1, randomBytes(32)));
});

test('config: missing or weak secrets fail fast; logs are redacted', () => {
  assert.throws(() => requireSecret('JWT_SECRET', { env: {} }), /Missing/);
  assert.throws(() => requireSecret('JWT_SECRET', { env: { JWT_SECRET: 'changeme' } }), /at least 32/);
  const strong = randomBytes(32).toString('base64');
  assert.equal(requireSecret('JWT_SECRET', { env: { JWT_SECRET: strong } }).length, 32);

  assert.deepEqual(
    redact({ user: 'bob', password: 'x', headers: { Authorization: 'Bearer y' }, apiKey: 'z' }),
    { user: 'bob', password: '[REDACTED]', headers: { Authorization: '[REDACTED]' }, apiKey: '[REDACTED]' },
  );
});
