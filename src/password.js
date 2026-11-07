import { createHash, randomBytes, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);

// UNSAFE: fast hash, no salt. Identical passwords give identical hashes, and a
// GPU can try billions of guesses per second against a leaked table.
export const hashPasswordUnsafe = (password) => createHash('sha256').update(password).digest('hex');

// SAFE: scrypt is deliberately slow and memory-hard, with a random salt per user.
// N=2^15, r=8 uses 32 MiB and ~50-100 ms per hash. Raise N as hardware gets faster.
const PARAMS = { N: 2 ** 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const KEY_LEN = 64;

// Parameters are stored with the hash so you can raise them later and still
// verify old hashes.
export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scryptAsync(password.normalize('NFKC'), salt, KEY_LEN, PARAMS);
  return ['scrypt', PARAMS.N, PARAMS.r, PARAMS.p, salt.toString('base64'), key.toString('base64')].join('$');
}

export async function verifyPassword(password, stored) {
  const [alg, N, r, p, salt, hash] = stored.split('$');
  if (alg !== 'scrypt') return false;
  const expected = Buffer.from(hash, 'base64');
  const key = await scryptAsync(password.normalize('NFKC'), Buffer.from(salt, 'base64'), expected.length, {
    N: Number(N), r: Number(r), p: Number(p), maxmem: PARAMS.maxmem,
  });
  // Constant time: `===` stops at the first differing byte, which leaks timing.
  return timingSafeEqual(key, expected);
}
