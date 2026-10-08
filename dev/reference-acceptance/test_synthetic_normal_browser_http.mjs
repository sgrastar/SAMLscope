import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, access, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { fetchStatus, publicDocument, readPublicResponse } from './synthetic_normal_browser_http.mjs';

for (const code of [200, 201, 204, 400, 403, 500]) test(`actual Node Response ${code} uses status/ok properties`, () => {
  const response = new Response(code === 204 ? null : '{}', { status: code, headers: { 'Content-Type': 'application/json' } });
  assert.deepEqual(fetchStatus(response), { status: code, ok: code >= 200 && code < 300, contentType: 'application/json' });
});

for (const code of [200, 201, 400, 500]) test(`public JSON original ${code} is retained before a status-only failure`, async () => {
  const raw = '{ "managementUrl": null, "error": "owned synthetic public response" }';
  const response = new Response(raw, { status: code, headers: { 'Content-Type': 'application/json; charset=utf-8' } });
  const statuses = [], originals = [];
  const call = readPublicResponse(response, async status => statuses.push(status), async bytes => originals.push(bytes));
  if (code < 300) assert.equal((await call).managementUrl, null);
  else await assert.rejects(call, new RegExp(`Owned Suite API status ${code}$`));
  assert.equal(statuses[0].status, code); assert.equal(statuses.length, 1);
  assert.equal(originals.length, 1); assert.equal(originals[0].toString(), raw);
});

test('actual Node Responses omit non-public, duplicate, malformed and HTML bodies before any raw disk retention', async () => {
  const directory = await mkdtemp(resolve(tmpdir(), 'samlscope-public-fetch-guards-'));
  const cases = [
    { raw: '{"managementUrl":"private sentinel"}' },
    { raw: '{"nested":[{"access_token":"private sentinel"}]}' },
    { raw: '{"managementUrl":"private sentinel","managementUrl":null}' },
    { raw: '{"nested":{"management\\u0055rl":"private sentinel","managementUrl":null}}' },
    { raw: '{"Cookie":"private sentinel"}' },
    { raw: '{"nested":{"x":1,"x":2}}' },
    { raw: '{"malformed":' },
    { raw: '<html><input type="password" value="private sentinel"></html>', type: 'text/html' },
    { raw: 'null' },
  ];
  try {
    for (const [index, invalid] of cases.entries()) {
      const path = resolve(directory, `raw-${index}.body`), statuses = [];
      await assert.rejects(readPublicResponse(new Response(invalid.raw, { status: 403,
        headers: { 'Content-Type': invalid.type ?? 'application/json' } }), async status => statuses.push(status), raw => writeFile(path, raw)));
      await assert.rejects(access(path)); assert.equal(statuses[0].status, 403);
    }
    const accepted = resolve(directory, 'public.body'), raw = '{"managementUrl":null,"nested":[{"x":"public\\\"value"}]}';
    await readPublicResponse(new Response(raw, { headers: { 'Content-Type': 'application/json' } }), async () => {}, bytes => writeFile(accepted, bytes));
    assert.equal((await readFile(accepted)).toString(), raw);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('fetch boundary rejects method-shaped mocks and trailing JSON instead of hiding Node Response mistakes', () => {
  assert.throws(() => fetchStatus({ status: () => 200, ok: () => true }));
  assert.throws(() => publicDocument(Buffer.from('{} {}')));
  assert.throws(() => publicDocument(Buffer.from('{"x":NaN}')));
  assert.throws(() => publicDocument(Buffer.from('{"x":1e99999}')));
  assert.throws(() => publicDocument(Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xff,0x22,0x7d])));
  assert.deepEqual(publicDocument(Buffer.from('{"x":[0,-1.2e3,true,false,null,{},[]]}')), { x: [0, -1200, true, false, null, {}, []] });
});

test('bounded actual Node Response cancels oversized public-looking data before disk retention', async () => {
  let saved = false;
  const response = new Response(JSON.stringify({ public: 'x'.repeat(6 * 1024 * 1024) }), { headers: { 'Content-Type': 'application/json' } });
  await assert.rejects(readPublicResponse(response, async () => {}, async () => { saved = true; }));
  assert.equal(saved, false);
});
