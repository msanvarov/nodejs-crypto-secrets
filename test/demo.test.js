import { test } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { request } from 'node:http';
import { createDemoServer } from '../demo/server.js';

async function start(t) {
  const server = createDemoServer();
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => server.close());
  return `http://127.0.0.1:${server.address().port}`;
}

const post = (base, route, body, headers = {}) =>
  fetch(`${base}/api/${route}`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });

// fetch won't let us override Host, so use node:http for that check.
const statusWithHost = (base, host) =>
  new Promise((resolve, reject) => {
    request(base, { headers: { host } }, (res) => { res.resume(); resolve(res.statusCode); }).on('error', reject).end();
  });

const DEFAULTS = {
  passwords: { password: 'password123' },
  tokens: {},
  jwt: { header: '{"alg":"none","typ":"JWT"}', payload: '{"sub":"attacker","role":"admin","exp":9999999999}', signature: '' },
  encryption: { plaintext: 'Transfer $100 to account 4242' },
  secrets: { value: 'changeme' },
};

test('demo serves the page and every default attack works on unsafe only', async (t) => {
  const base = await start(t);
  const page = await fetch(base + '/');
  assert.equal(page.status, 200);
  assert.match(await page.text(), /<html/);

  for (const [route, body] of Object.entries(DEFAULTS)) {
    const data = await (await post(base, route, body)).json();
    assert.equal(data.unsafe.exploited, true, `${route}: unsafe should be exploited`);
    assert.equal(data.safe.exploited, false, `${route}: safe should hold`);
  }
});

test('demo JWT samples: a genuine token passes both, an expired one fools only unsafe', async (t) => {
  const base = await start(t);
  const verifyKind = async (kind) => {
    const sample = await (await post(base, 'jwt-sample', { kind })).json();
    return (await post(base, 'jwt', sample)).json();
  };
  const valid = await verifyKind('valid');
  assert.equal(valid.unsafe.accepted && valid.safe.accepted, true);
  assert.equal(valid.unsafe.exploited || valid.safe.exploited, false);
  const expired = await verifyKind('expired');
  assert.equal(expired.unsafe.exploited, true);
  assert.equal(expired.safe.accepted, false);
});

test('demo only answers local, same-origin JSON requests', async (t) => {
  const base = await start(t);
  assert.equal(await statusWithHost(base, 'evil.example'), 403);
  assert.equal((await post(base, 'tokens', {}, { Origin: 'https://evil.example' })).status, 403);
  const wrongType = await fetch(`${base}/api/tokens`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
  assert.equal(wrongType.status, 415);
  assert.equal((await post(base, 'constructor', {})).status, 404);
});
