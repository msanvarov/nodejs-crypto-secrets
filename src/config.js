// Load secrets from the environment and fail at startup, not on the first
// request, if one is missing or too weak.
//
// Locally: `node --env-file=.env app.js` (keep .env out of git).
// Production: inject env vars from your platform's secret manager.

export function requireSecret(name, { minBytes = 32, env = process.env } = {}) {
  const value = env[name];
  if (!value) throw new Error(`Missing required secret: ${name}`);
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length < minBytes) {
    throw new Error(`${name} must be at least ${minBytes} random bytes, base64 encoded. Generate one with:\n` +
      `  node -e "console.log(crypto.randomBytes(${minBytes}).toString('base64'))"`);
  }
  return bytes;
}

// Use when logging config or request data, so secrets never end up in logs.
const SECRET_KEY = /pass(word)?|secret|token|api[-_]?key|authorization|cookie/i;
export function redact(obj) {
  return JSON.parse(JSON.stringify(obj, (key, value) => (SECRET_KEY.test(key) ? '[REDACTED]' : value)));
}
