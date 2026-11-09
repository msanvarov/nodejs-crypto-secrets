// Local demo UI: runs the real unsafe and safe functions from src/ side by side.
// Bound to 127.0.0.1 and guarded so other websites can't drive it.

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createHmac, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { hashPassword, hashPasswordUnsafe, verifyPassword } from '../src/password.js';
import { hashToken, resetToken, resetTokenUnsafe } from '../src/tokens.js';
import { sign, verify, verifyUnsafe } from '../src/jwt.js';
import { decrypt, decryptUnsafe, encrypt, encryptUnsafe } from '../src/encrypt.js';
import { redact, requireSecret } from '../src/config.js';

const MAX_BODY = 64 * 1024;
const INDEX = new URL('./index.html', import.meta.url);

// Per-process keys. They exist only while the demo runs.
const JWT_SECRET = randomBytes(32);
const ENC_KEY = randomBytes(32);

// A tiny "leaked password list". Real cracking lists have billions of entries.
const COMMON_PASSWORDS = `123456 password 123456789 12345678 12345 qwerty 1234567 111111 1234567890 123123
abc123 1234 password1 iloveyou 1q2w3e4r 000000 qwerty123 zaq12wsx dragon sunshine princess letmein 654321
monkey 1qaz2wsx 123321 qwertyuiop superman asdfghjkl trustno1 hunter2 password123 welcome admin login
football baseball master shadow michael jennifer 666666 121212 starwars freedom whatever qazwsx batman
696969 mustang access flower hello charlie aa123456 donald bailey passw0rd 7777777 123qwe killer jordan
hottie loveme zxcvbnm zxcvbn computer soccer harley ranger buster thomas tigger robert hockey daniel
andrew joshua pepper ginger summer ashley nicole hannah jessica matthew cheese chelsea biteme amanda
maggie yankees samsung google ninja azerty solo 1qazxsw2 changeme secret root toor test test123 guest
default pass1234 abcd1234 qwer1234 admin123 welcome1 iloveu lovely 159753 11111111 987654321 1111
2000 222222 555555 888888 123654 147258369 a123456 q1w2e3r4 asdf1234 mypassword letmein1 sunshine1
princess1 football1 monkey1 dragon1 shadow1 master1 michael1 baseball1 superman1 batman1 starwars1
whatever1 freedom1 trustno1! password! Password Password1 P@ssw0rd p@ssword Qwerty123 Welcome1 Admin
admin1 administrator user username love family friends forever angel jesus purple orange banana
chocolate cookie peanut pokemon minecraft fortnite liverpool arsenal chelsea1 barcelona juventus
spiderman ironman marvel matrix hello123 hello1 iloveyou1 secret1 qwerty1 abc12345 1q2w3e 1q2w3e4r5t`
  .split(/\s+/)
  .filter(Boolean);
const CRACK_TABLE = new Map(COMMON_PASSWORDS.map((p) => [hashPasswordUnsafe(p), p]));

const ms = (start) => Math.round((performance.now() - start) * 1000) / 1000;
const b64url = (text) => Buffer.from(text, 'utf8').toString('base64url');
const fromB64url = (part) => Buffer.from(part, 'base64url').toString('utf8');
const attempt = (fn) => {
  try {
    return { ok: true, value: fn() };
  } catch (err) {
    return { ok: false, error: err.message };
  }
};

const handlers = {
  async passwords({ password = '' }) {
    const unsafeHashes = [hashPasswordUnsafe(password), hashPasswordUnsafe(password)];
    let t = performance.now();
    const cracked = CRACK_TABLE.get(unsafeHashes[0]);
    const lookupMs = ms(t);

    const safeHashes = [];
    const hashMs = [];
    for (let i = 0; i < 2; i++) {
      t = performance.now();
      safeHashes.push(await hashPassword(password));
      hashMs.push(Math.round(ms(t)));
    }
    t = performance.now();
    // A precomputed table can't contain salted hashes: each user's salt is new.
    const safeCracked = CRACK_TABLE.has(safeHashes[0]);
    const safeLookupMs = ms(t);
    return {
      unsafe: {
        hashes: unsafeHashes,
        identical: unsafeHashes[0] === unsafeHashes[1],
        cracked: cracked ?? null,
        lookupMs,
        tableSize: CRACK_TABLE.size,
        exploited: cracked !== undefined,
      },
      safe: {
        hashes: safeHashes,
        identical: safeHashes[0] === safeHashes[1],
        hashMs,
        lookupMs: safeLookupMs,
        cracked: safeCracked,
        verified: await verifyPassword(password, safeHashes[0]),
        exploited: safeCracked,
      },
    };
  },

  async tokens() {
    const unsafeTokens = Array.from({ length: 5 }, resetTokenUnsafe);
    const safeTokens = Array.from({ length: 5 }, resetToken);
    return {
      unsafe: { tokens: unsafeTokens, exploited: true },
      safe: { tokens: safeTokens, stored: hashToken(safeTokens[0]), exploited: false },
    };
  },

  // Returns editor contents for the JWT presets that need a real signature.
  async 'jwt-sample'({ kind }) {
    const token =
      kind === 'expired'
        ? sign({ sub: 'alice', role: 'user' }, JWT_SECRET, { expiresInSec: -60 })
        : sign({ sub: 'alice', role: 'user' }, JWT_SECRET);
    const [h, p, s] = token.split('.');
    if (kind === 'tampered') {
      const claims = JSON.parse(fromB64url(p));
      return { header: fromB64url(h), payload: JSON.stringify({ ...claims, role: 'admin' }), signature: s };
    }
    return { header: fromB64url(h), payload: fromB64url(p), signature: s };
  },

  async jwt({ header = '', payload = '', signature = '' }) {
    const token = `${b64url(header)}.${b64url(payload)}.${signature}`;
    // Ground truth, independent of either verifier: was this token issued by
    // the server (HS256, correct HMAC) and is it still valid?
    const [h, p] = token.split('.');
    const legit = (() => {
      try {
        const alg = JSON.parse(header).alg;
        const exp = JSON.parse(payload).exp;
        const expected = createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64url');
        return alg === 'HS256' && signature === expected && typeof exp === 'number' && exp > Date.now() / 1000;
      } catch {
        return false;
      }
    })();
    const side = (fn) => {
      const r = attempt(() => fn(token, JWT_SECRET));
      return r.ok ? { accepted: true, claims: r.value, exploited: !legit } : { accepted: false, error: r.error, exploited: false };
    };
    return { token, legit, unsafe: side(verifyUnsafe), safe: side(verify) };
  },

  async encryption({ plaintext = '' }) {
    // Attack: edit ciphertext block 0 so plaintext block 1 changes the way we
    // want. Here, every digit in block 1 becomes '9'. Without digits we change
    // the first character of block 1 to 'X'.
    const bytes = Buffer.from(plaintext, 'utf8');
    const edits = [];
    for (let i = 16; i < Math.min(bytes.length, 32); i++) if (bytes[i] >= 48 && bytes[i] <= 57) edits.push([i, 57]);
    if (!edits.length && bytes.length > 16) edits.push([16, 88]);

    const u1 = encryptUnsafe(plaintext, ENC_KEY);
    const u2 = encryptUnsafe(plaintext, ENC_KEY);
    const tamperedCbc = Buffer.from(u1, 'base64');
    if (edits.length) for (const [i, want] of edits) tamperedCbc[i - 16] ^= bytes[i] ^ want;
    else tamperedCbc[0] ^= 1; // single block: flip a bit and see what happens
    const unsafeResult = attempt(() => decryptUnsafe(tamperedCbc.toString('base64'), ENC_KEY));

    const g1 = encrypt(plaintext, ENC_KEY);
    const g2 = encrypt(plaintext, ENC_KEY);
    const tamperedGcm = Buffer.from(g1, 'base64');
    tamperedGcm[tamperedGcm.length - 1] ^= 1;
    const safeResult = attempt(() => decrypt(tamperedGcm.toString('base64'), ENC_KEY));

    const unsafeIdentical = u1 === u2;
    return {
      unsafe: {
        ciphertexts: [u1, u2],
        identical: unsafeIdentical,
        targeted: edits.length > 0,
        tamper: unsafeResult.ok ? { accepted: true, text: unsafeResult.value } : { accepted: false, error: unsafeResult.error },
        exploited: unsafeIdentical || unsafeResult.ok,
      },
      safe: {
        ciphertexts: [g1, g2],
        identical: g1 === g2,
        tamper: safeResult.ok ? { accepted: true, text: safeResult.value } : { accepted: false, error: safeResult.error },
        exploited: g1 === g2 || safeResult.ok,
      },
    };
  },

  async secrets({ value = '' }) {
    // UNSAFE pattern: `process.env.JWT_SECRET || 'changeme'`, then log the config.
    const unsafeSecret = value || 'changeme';
    const unsafeConfig = { port: 3000, jwtSecret: unsafeSecret, dbPassword: 's3cr3t' };
    const weak = Buffer.from(unsafeSecret, 'base64').length < 32;

    const r = attempt(() => requireSecret('JWT_SECRET', { env: value ? { JWT_SECRET: value } : {} }));
    const safeConfig = { port: 3000, jwtSecret: value, dbPassword: 's3cr3t' };
    return {
      unsafe: {
        started: true,
        usedSecret: unsafeSecret,
        weak,
        log: `config ${JSON.stringify(unsafeConfig)}`,
        exploited: true,
      },
      safe: {
        started: r.ok,
        ...(r.ok ? { bytes: r.value.length } : { error: r.error }),
        log: `config ${JSON.stringify(redact(safeConfig))}`,
        exploited: false,
      },
    };
  },
};

function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(type.startsWith('application/json') ? JSON.stringify(body) : body);
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw Object.assign(new Error('body too large'), { status: 413 });
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
  } catch {
    throw Object.assign(new Error('invalid JSON'), { status: 400 });
  }
}

export function createDemoServer() {
  const server = http.createServer(async (req, res) => {
    try {
      const port = server.address().port;
      const allowedHosts = [`127.0.0.1:${port}`, `localhost:${port}`];
      // DNS rebinding: a hostile site's domain pointed at 127.0.0.1 still sends its own Host.
      if (!allowedHosts.includes(req.headers.host)) return send(res, 403, { error: 'forbidden host' });
      const origin = req.headers.origin;
      if (origin && !allowedHosts.map((h) => `http://${h}`).includes(origin)) return send(res, 403, { error: 'forbidden origin' });

      const { pathname } = new URL(req.url, 'http://localhost');
      if (req.method === 'GET' && pathname === '/') {
        return send(res, 200, await readFile(INDEX, 'utf8'), 'text/html; charset=utf-8');
      }
      const handler = req.method === 'POST' && pathname.startsWith('/api/') && Object.hasOwn(handlers, pathname.slice(5)) && handlers[pathname.slice(5)];
      if (!handler) return send(res, 404, { error: 'not found' });
      // JSON content type forces a CORS preflight from other origins, which we never answer.
      if (!req.headers['content-type']?.startsWith('application/json')) return send(res, 415, { error: 'expected application/json' });
      send(res, 200, await handler(await readJson(req)));
    } catch (err) {
      send(res, err.status ?? 500, { error: err.status ? err.message : 'internal error' });
      if (!err.status) console.error(err);
    }
  });
  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 4104);
  createDemoServer().listen(port, '127.0.0.1', () => {
    console.log(`Demo running at http://127.0.0.1:${port}`);
    console.log('Warning: this runs deliberately vulnerable code. It only listens on 127.0.0.1.');
  });
}
