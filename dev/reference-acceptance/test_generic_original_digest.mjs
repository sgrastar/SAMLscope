import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bindProtocolOriginals, collectNativeOriginalDigests, validateNativeOriginalDigest, validateM0Guard,
  validateTask, publicJson } from './generic_browser_campaign.mjs';

const RUN = 'run_0123456789ABCDEFGHJKMNPQRS', PLAN = 'plan_0123456789ABCDEFGHJKMNPQRS';
const CASE = 'IIP-SSO01-f-idp-01', OTHER = 'IIP-IDP12-a-idp-01';
const tx = value => `tx_${String(value).padStart(26, '0')}`, action = `action_${'1'.repeat(32)}`;
const task = validateTask({ suiteBaseUrl: 'https://suite.example', runId: RUN, planId: PLAN, caseIds: [CASE],
  targetOrigins: ['https://idp.example'], outputDirectory: '/private/tmp/generic-digest-test' });
const raw = Buffer.from('<p:AuthnRequest xmlns:p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_request"/>');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const capture = overrides => ({ record: { runId: RUN, planId: PLAN, direction: 'OUTBOUND', caseId: CASE,
  actionId: action, bytes: raw.length, sha256: sha(raw), ...overrides }, file: 'request.xml', bytes: raw });
const entry = (number = 1, overrides = {}) => ({ id: tx(number), runId: RUN, direction: 'OUTBOUND',
  correlationId: action, decodedSamlRef: `transcripts/${RUN}/${tx(number)}.saml.xml`, decodedSamlBytes: raw.length,
  samlSummary: { type: 'AuthnRequest', scenario_case_id: CASE }, ...overrides });
const proof = (id = tx(1), overrides = {}) => ({ schema: 'samlscope-transcript-original-digest-v1', runId: RUN,
  txId: id, decodedSamlSha256: sha(raw), decodedSamlBytes: raw.length, ...overrides });

test('actual digest response qualifies missing-summary originals and is fetched once without changing Recorder rows', async () => {
  const rows = [entry()], before = structuredClone(rows), proofs = new Map(), calls = [];
  const read = async id => {
    calls.push(id);
    const response = new Response(JSON.stringify(proof(id)), { headers: { 'content-type': 'application/json' } });
    assert.equal(response.ok, true);
    return response.json();
  };
  assert.equal(bindProtocolOriginals(task, [capture()], rows)[0].transcriptReferences.length, 0);
  await collectNativeOriginalDigests(task, [capture(), capture()], rows, read, null, proofs);
  await collectNativeOriginalDigests(task, [capture()], rows, read, null, proofs);
  assert.deepEqual(calls, [tx(1)]);
  const bound = bindProtocolOriginals(task, [capture()], rows, null, proofs)[0];
  assert.deepEqual(bound.transcriptReferences, [tx(1)]); assert.equal(bound.bindingProofSource, 'native-original-digest-api');
  assert.equal(bound.conformanceConclusionAssigned, false); assert.deepEqual(rows, before);
  assert.equal(JSON.stringify([...proofs.values()]).includes('<p:'), false);
});

test('fabricated summary hashes never replace native proof, and equal-size changed native bytes remain unqualified', async () => {
  const rows = [entry(1, { samlSummary: { type: 'AuthnRequest', scenario_case_id: CASE, decodedSha256: sha(raw) } })];
  assert.equal(bindProtocolOriginals(task, [capture()], rows)[0].transcriptReferences.length, 0);
  const changed = Buffer.from(raw.toString().replace('_request', '_changed'));
  assert.equal(changed.length, raw.length);
  const proofs = await collectNativeOriginalDigests(task, [capture()], rows, async id => proof(id, { decodedSamlSha256: sha(changed) }));
  assert.equal(bindProtocolOriginals(task, [capture()], rows, null, proofs)[0].transcriptReferences.length, 0);
});

test('wrong action, unselected case, wrong type and foreign decoded path are not queried', async () => {
  let calls = 0;
  for (const rows of [[entry(1, { correlationId: 'action_' + '2'.repeat(32) })],
    [entry(1, { samlSummary: { type: 'AuthnRequest', scenario_case_id: OTHER } })],
    [entry(1, { samlSummary: { type: 'EcpPaosResponse', scenario_case_id: CASE } })],
    [entry(1, { decodedSamlRef: `transcripts/${RUN}/${tx(2)}.saml.xml` })]]) {
    await collectNativeOriginalDigests(task, [capture()], rows, async () => { calls++; return proof(); });
  }
  await collectNativeOriginalDigests(task, [capture({ caseId: OTHER })], [entry()], async () => { calls++; return proof(); });
  assert.equal(calls, 0);
});

test('foreign or duplicate Recorder rows and foreign capture identities reject before any digest GET', async () => {
  let calls = 0; const read = async () => { calls++; return proof(); };
  for (const rows of [[entry(1, { runId: 'run_' + '0'.repeat(26) })], [entry(), entry()]]) {
    await assert.rejects(collectNativeOriginalDigests(task, [capture()], rows, read));
  }
  for (const changed of [{ runId: 'run_' + '0'.repeat(26) }, { planId: 'plan_' + '0'.repeat(26) }]) {
    await assert.rejects(collectNativeOriginalDigests(task, [capture(changed)], [entry()], read));
  }
  assert.equal(calls, 0);
});

test('ambiguous actual originals never produce a qualified binding', async () => {
  const rows = [entry(1), entry(2)];
  const proofs = await collectNativeOriginalDigests(task, [capture()], rows, async id => proof(id));
  assert.equal(proofs.size, 2);
  assert.equal(bindProtocolOriginals(task, [capture()], rows, null, proofs)[0].transcriptReferences.length, 0);
});

test('native digest rejects cross-Run/tx, oversized, malformed, additional and credential fields', () => {
  assert.deepEqual(validateNativeOriginalDigest(task, tx(1), proof()), proof());
  for (const changed of [{ runId: 'run_' + '0'.repeat(26) }, { txId: tx(2) }, { schema: 'untrusted' },
    { decodedSamlSha256: 'A'.repeat(64) }, { decodedSamlSha256: 'invented' }, { decodedSamlBytes: 0 },
    { decodedSamlBytes: 4 * 1024 * 1024 + 1 }, { decodedSamlBytes: 1.5 }, { bodyBase64: 'never-export' },
    { nested: { token: 'never-export' } }, { headers: { Cookie: 'never-export' } }]) {
    assert.throws(() => validateNativeOriginalDigest(task, tx(1), proof(tx(1), changed)));
  }
  assert.throws(() => validateNativeOriginalDigest(task, '../' + tx(1), proof()));
  assert.throws(() => publicJson({ Cookie: '<redacted: 32 bytes>' }));
});

test('unavailable non-2xx bodies and non-public proof objects stay omitted with no retry or false promotion', async () => {
  for (const read of [async () => {
    const response = new Response('<html>private login sentinel</html>', { status: 404 });
    if (!response.ok) throw new Error('Original unavailable');
    return response.json();
  }, async () => proof(tx(1), { token: 'private token sentinel' })]) {
    const proofs = new Map(); let calls = 0;
    const counted = async id => { calls++; return read(id); };
    await collectNativeOriginalDigests(task, [capture()], [entry()], counted, null, proofs);
    await collectNativeOriginalDigests(task, [capture()], [entry()], counted, null, proofs);
    assert.equal(calls, 1);
    const retained = JSON.stringify([...proofs.values()]);
    assert.equal(retained.includes('private'), false);
    assert.equal(bindProtocolOriginals(task, [capture()], [entry()], null, proofs)[0].transcriptReferences.length, 0);
  }
});

test('valid stale same-Run M0 evidence cannot request or qualify an old normal original', async () => {
  const oldRaw = Buffer.from(raw.toString().replace('_request', '_old'));
  const currentRaw = Buffer.from(raw.toString().replace('_request', '_new'));
  assert.equal(oldRaw.length, currentRaw.length);
  const normal = (number, nonce, direction) => entry(number, { direction, correlationId: nonce,
    decodedSamlBytes: oldRaw.length,
    samlSummary: direction === 'OUTBOUND' ? { type: 'AuthnRequest', id: nonce }
      : { type: 'Response', normalFlowAccepted: true, inResponseTo: nonce, issuer: 'https://idp.example/idp',
        destination: `https://suite.example/p/${PLAN}/sp/acs/0`, statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success' },
    url: `https://suite.example/p/${PLAN}/sp/acs/0` });
  const rows = [normal(1, '_old', 'OUTBOUND'), normal(2, '_old', 'INBOUND'), normal(3, '_new', 'OUTBOUND'), normal(4, '_new', 'INBOUND')];
  const guard = validateM0Guard(task, { id: RUN, planId: PLAN, status: 'COMPLETED', context: { authnRequestId: '_new' } },
    { plan: { id: PLAN, profile: 'browser_sso_idp', target: { kind: 'IDP', entityId: 'https://idp.example/idp' } } }, rows);
  const oldCapture = { ...capture({ operationKind: 'M0_NORMAL', bytes: oldRaw.length, sha256: sha(oldRaw) }), bytes: oldRaw };
  const calls = [];
  const proofs = await collectNativeOriginalDigests(task, [oldCapture], rows, async id => {
    calls.push(id); return proof(id, { decodedSamlBytes: currentRaw.length, decodedSamlSha256: sha(currentRaw) });
  }, guard);
  assert.deepEqual(calls, [tx(3)], 'only the guard-approved current nonce reference may be queried');
  assert.equal(bindProtocolOriginals(task, [oldCapture], rows, guard, proofs)[0].transcriptReferences.length, 0);
});
