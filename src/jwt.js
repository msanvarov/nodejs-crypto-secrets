import { createHmac, timingSafeEqual } from 'node:crypto';

// A minimal HS256 JWT, to show the checks a verifier must make.
// In production, use a maintained library (e.g. `jose`) and still pin the algorithm:
//   jwtVerify(token, key, { algorithms: ['HS256'] })

const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const decode = (part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
const hmac = (data, secret) => createHmac('sha256', secret).update(data).digest();

export function sign(payload, secret, { expiresInSec = 900 } = {}) {
  const header = encode({ alg: 'HS256', typ: 'JWT' });
  const body = encode({ ...payload, exp: Math.floor(Date.now() / 1000) + expiresInSec });
  return `${header}.${body}.${hmac(`${header}.${body}`, secret).toString('base64url')}`;
}

// UNSAFE: trusts the token's own header to pick the algorithm. A token with
// {"alg":"none"} and no signature is accepted. Also ignores `exp`, and `!==`
// on strings leaks timing.
export function verifyUnsafe(token, secret) {
  const [header, body, sig] = token.split('.');
  if (decode(header).alg === 'none') return decode(body);
  if (sig !== hmac(`${header}.${body}`, secret).toString('base64url')) throw new Error('bad signature');
  return decode(body);
}

// SAFE: the server decides the algorithm, compares in constant time, and
// enforces expiry.
export function verify(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('malformed token');
  const [header, body, sig] = parts;
  if (decode(header).alg !== 'HS256') throw new Error('unexpected algorithm');
  const expected = hmac(`${header}.${body}`, secret);
  const given = Buffer.from(sig, 'base64url');
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) throw new Error('bad signature');
  const payload = decode(body);
  if (typeof payload.exp !== 'number' || payload.exp <= Date.now() / 1000) throw new Error('token expired');
  return payload;
}
