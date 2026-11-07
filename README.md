# nodejs-crypto-secrets

[![CI](https://github.com/msanvarov/nodejs-crypto-secrets/actions/workflows/test.yml/badge.svg)](https://github.com/msanvarov/nodejs-crypto-secrets/actions/workflows/test.yml) ![Node](https://img.shields.io/badge/node-%3E%3D22.13-339933?logo=node.js&logoColor=white) ![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen) ![License: MIT](https://img.shields.io/badge/license-MIT-blue)

Getting crypto right in Node.js with nothing but `node:crypto`. Each file in `src/` shows the common mistake next to the fix, and `test/` proves the difference (for example, a forged `alg: none` JWT that the unsafe verifier accepts).

```bash
npm test
```

> [!WARNING]
> Functions ending in `Unsafe` are **intentionally vulnerable** so the tests can show the attack working. Copy the safe versions, never those.

## Project layout

```text
src/
  password.js   sha256 vs salted scrypt
  tokens.js     Math.random vs crypto.randomBytes
  jwt.js        alg-trusting verifier vs pinned HS256
  encrypt.js    AES-CBC with static IV vs AES-256-GCM
  config.js     fail-fast secret loading and log redaction
test/
  crypto.test.js   proves each mistake and each fix
```

## What's covered

| Topic | File | Common mistake | Fix |
| --- | --- | --- | --- |
| Password storage | [src/password.js](src/password.js) | `sha256(password)`, no salt | `scrypt` with a random salt per user, params stored with the hash, `timingSafeEqual` |
| Random tokens | [src/tokens.js](src/tokens.js) | `Math.random()` for reset links, OTPs, session IDs | `randomBytes(32)`, `randomInt`, `randomUUID`; store a hash of the token, not the token |
| JWT verification | [src/jwt.js](src/jwt.js) | Trusting the token's `alg` header (`none` = no signature), skipping `exp`, `===` on signatures | Server pins the algorithm, constant-time compare, expiry enforced |
| Encrypting data | [src/encrypt.js](src/encrypt.js) | AES-CBC with a fixed IV and no integrity check | AES-256-GCM, random 12-byte IV per message, 16-byte auth tag |
| Secrets & config | [src/config.js](src/config.js) | Hardcoded secrets, `"changeme"` defaults, secrets in logs | Load from env, fail fast if missing or short, redact before logging |

## Guidance

### Passwords
- Use a slow, memory-hard function: **scrypt** (built in), **Argon2id**, or bcrypt. Never MD5/SHA-x alone, even with a salt.
- Newer Node versions also include `crypto.argon2` (still experimental). Until it's stable, scrypt is the zero-dependency choice, or use the `argon2` package.
- Store the cost parameters with each hash so you can raise them later and rehash on next login.
- Rate limit login attempts and lock out or slow down after repeated failures. A strong hash doesn't stop online guessing.

### Tokens
- Anything an attacker must not guess (session IDs, reset links, API keys, invite codes) comes from `crypto`, never `Math.random`.
- 32 random bytes is plenty. Store only `sha256(token)` and compare against that, so a database leak doesn't hand out working tokens.
- Make reset tokens single use and short lived (15–60 minutes).

### JWTs
- Pin the accepted algorithm(s) on the server. Never let the token choose.
- Always check `exp`. Check `iss` and `aud` too when you have more than one service.
- HS256 secrets must be long and random (32+ bytes), not a password. Prefer asymmetric keys (ES256/EdDSA) when other services need to verify but not issue tokens.
- JWTs can't be revoked before they expire. Keep them short lived and use refresh tokens, or use plain server-side sessions.
- Don't put sensitive data in the payload. It is only base64, not encrypted.

### Encryption
- Use an AEAD mode: AES-256-GCM or ChaCha20-Poly1305. Never ECB, and never CBC without a MAC.
- Never reuse an IV with the same GCM key. A random 96-bit IV is safe for about 2^32 messages per key; rotate keys before that.
- Pass `authTagLength` when decrypting so truncated tags are rejected.
- Keys come from a secret manager or KMS, not from source code. Encrypt data keys with a KMS master key ("envelope encryption") for anything serious.

### Comparing secrets
- `a === b` returns as soon as a byte differs, which leaks timing. Use `crypto.timingSafeEqual` on equal-length Buffers. For different lengths, compare HMACs or hashes of both values.

### Secrets in config
- Use `node --env-file=.env` locally (built in since Node 20.6) and keep `.env` in `.gitignore`.
- In production, inject env vars from a secret manager (AWS Secrets Manager, GCP Secret Manager, Vault, Doppler, your platform's encrypted variables).
- Scan for committed secrets with GitHub secret scanning or `gitleaks`. If a secret was ever committed, rotate it. Removing it from history is not enough.
- Never log request headers, bodies, or `process.env` without redaction.

## Node.js security series

| Repo | Covers |
| --- | --- |
| [nodejs-injection-defense](https://github.com/msanvarov/nodejs-injection-defense) | Command, SQL, path traversal, prototype pollution, ReDoS |
| [nodejs-http-hardening](https://github.com/msanvarov/nodejs-http-hardening) | Headers, body limits, timeouts, rate limiting, CORS, safe errors |
| [nodejs-supply-chain-security](https://github.com/msanvarov/nodejs-supply-chain-security) | npm config, CI auditing, install-script scanning, permission model |
| **nodejs-crypto-secrets** (you are here) | Password hashing, tokens, JWTs, encryption, secrets |

## Running it

Requires Node.js 22.13 or newer. No `npm install` needed.

```bash
git clone https://github.com/msanvarov/nodejs-crypto-secrets.git
cd nodejs-crypto-secrets
npm test
```

Found a mistake or want to add an example? Issues and pull requests are welcome.

## License

[MIT](LICENSE)
