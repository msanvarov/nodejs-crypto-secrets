import { createHash, randomBytes, randomInt, randomUUID } from 'node:crypto';

// UNSAFE: Math.random is not cryptographically secure. V8's generator state can
// be recovered from a handful of outputs, and then every future token predicted.
export const resetTokenUnsafe = () => Math.random().toString(36).slice(2);

// SAFE: 32 bytes from the OS CSPRNG (256 bits), URL-safe.
export const resetToken = () => randomBytes(32).toString('base64url');

// SAFE: uniform 6-digit code. `randomBytes(n) % 1e6` would be slightly biased.
export const otpCode = () => String(randomInt(0, 1_000_000)).padStart(6, '0');

export const sessionId = () => randomUUID();

// Store only a hash of reset/API tokens, like passwords. If the database leaks,
// the tokens can't be used. A fast hash is fine here because the token is
// random and long, so there is nothing to brute force.
export const hashToken = (token) => createHash('sha256').update(token).digest('hex');
