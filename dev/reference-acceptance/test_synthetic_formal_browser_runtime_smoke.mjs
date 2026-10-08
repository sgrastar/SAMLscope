/** Pure owned-harness boundary controls only; no Suite, browser, Docker, or network. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, rm, readFile, symlink } from 'node:fs/promises';
import { resolve } from 'node:path';
import { ownedCookieHeader, ownedSetCookie, publicSamlFixtureHtml, publicSamlRequestBody,
  buildPlanInput, assertSessionProof, assertCaptureProof, assertFormalProof, checkedPortableOriginals,
  exportPortableOriginals, assertResultProof, existingColdCreation, publicFailureDetails, publicTranscriptDocument,
  readFormalPublicResponse, retainSupplementalCaptures, createImmutableEvidenceRecorder, bindNativeProtocolOriginals, SELECTED_CASE } from './synthetic_formal_browser_runtime_smoke.mjs';
import { fetchStatus, readPublicResponse } from './synthetic_normal_browser_http.mjs';
import { collectSelected, validateTask } from './generic_browser_campaign.mjs';

const RUN = 'run_0123456789ABCDEFGHJKMNPQRS', PLAN = 'plan_0123456789ABCDEFGHJKMNPQRS';
const OTHER = 'run_1123456789ABCDEFGHJKMNPQRS', origin = 'http://localhost:18080';
const owned = 'samlscope_owned_formal_session=' + 'a'.repeat(32);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const tx = index => 'tx_' + String(index).padStart(26, '0');
const action = index => 'action_' + String(index).padStart(32, '0');
const decoded = index => Buffer.from(`<${index % 2 ? 'Response' : 'AuthnRequest'} fixture="pure-unit-${index}"/>`);
const form = (changes = {}) => `<form method='post' action='${changes.action ?? `${origin}/p/${PLAN}/sp/acs/0`}'>`
  + `<input type='hidden' name='SAMLResponse' value='${changes.response ?? Buffer.from('<Response/>').toString('base64')}'>`
  + `<input type='hidden' name='RelayState' value='${changes.relay ?? RUN}'>${changes.extra ?? ''}</form>`;
const session = () => ({ contextsCreated: 1, normalContextOrdinal: 1, formalContextOrdinals: [1, 1],
  normalCookiePresent: false, formalCookiePresent: [true, true], formalCookieMatchesNormal: [true, true], credentialOrCookieValuesPersisted: 0 });
const stats = () => ({ normalReplies: 1, formalReplies: 2, newSessions: 1, reusedSessions: 2, missingSessionRejects: 0 });
const bindings = () => Array.from({ length: 6 }, (_, index) => ({ runId: RUN, file: `browser-saml-originals/${String(index).padStart(4, '0')}-${sha(decoded(index))}.xml`,
  bytes: decoded(index).length, sha256: sha(decoded(index)), direction: index % 2 ? 'INBOUND' : 'OUTBOUND', transcriptReferences: [tx(index)],
  bindingState: index < 2 ? 'recorder-hash-and-normal-flow-bound' : 'recorder-hash-and-action-bound',
  ...(index < 2 ? { operationKind: 'M0_NORMAL' } : { caseId: SELECTED_CASE, actionId: action(Math.floor((index - 2) / 2)) }) }));
const native = mode => ({ runId: RUN, planId: PLAN, fixtureMode: mode, approvedSelectedCase: { id: SELECTED_CASE },
  qualificationOutcome: 'VERIFIED', selectedCaseOutcome: mode === 'honor' ? 'SATISFIED' : 'VIOLATED',
  wholeRunConformance: 'NOT_QUALIFIED', canonicalAdoption: false, selectedOutboxActions: 2,
  actualCaseAndRequiredControlsProven: true, actualRequestSignaturesVerified: true, actualResponseAndAssertionSignaturesVerified: true,
  protocolSessionReused: true, normalRequestReference: tx(0), normalResponseReference: tx(1),
  selectedFixturePairs: [0, 1].map(index => ({ fixture: index ? 'non-default-index' : 'default-control', actionId: action(index),
    requestReference: tx(2 + index * 2), responseReference: tx(3 + index * 2) })),
  portableEvidenceReferences: Array.from({ length: 6 }, (_, index) => tx(index)),
  selectedCaseEvidence: [3, 5].map(index => ({ kind: 'transcript', reference: tx(index) })),
  transcriptOriginals: Array.from({ length: 6 }, (_, index) => {
    const xml = decoded(index), raw = index === 0 ? Buffer.alloc(0) : Buffer.from(`public-pure-unit-body-${index}`);
    const query = index === 0 ? `SAMLRequest=public-control&RelayState=${RUN}&SigAlg=public-control&Signature=public-control` : null;
    return { id: tx(index), runId: RUN, direction: index % 2 ? 'INBOUND' : 'OUTBOUND', method: index === 0 ? 'GET' : 'POST',
      url: query ? `http://localhost:18949/sso/${mode}?${query}` : origin + `/p/${PLAN}/sp/acs/0`, rawQuery: query,
      correlationId: index < 2 ? '_normal-unit' : (index % 2 ? '_' : '') + action(Math.floor((index - 2) / 2)),
      bodyRef: index === 0 ? null : `transcripts/${RUN}/${tx(index)}.body`, bodyBytes: raw.length, bodyBase64: raw.toString('base64'),
      computedBodySha256: sha(raw), storedBodySha256: null,
      decodedSamlRef: `transcripts/${RUN}/${tx(index)}.saml.xml`, decodedSamlBytes: xml.length,
      decodedSamlBase64: xml.toString('base64'), computedDecodedSha256: sha(xml) };
  }) });
const proof = (mode = 'honor') => ({ mode, runId: RUN, planId: PLAN, collected: { collectionState: 'COLLECTED', counts: {
  initialNormalFlowSubmissions: 1, normalLoginContexts: 1, fullProfileStartCalls: 1, selectedTargetActions: 2,
  authenticatedContextReuses: 2, freshEmptyContexts: 0, automatedCredentialPosts: 0 } }, bindings: bindings(),
  runtime: native(mode), session: session(), stats: stats() });

test('import is test-safe and plan creation is restricted to the two owned synthetic modes', () => {
  for (const mode of ['honor', 'ignore']) {
    const plan = buildPlanInput(mode);
    assert.equal(plan.name, `Synthetic formal browser runtime ${mode}; no adoption`);
    assert.equal(plan.targetEntityId, `http://host.docker.internal:18946/entity/${mode}`);
    assert.equal(plan.metadataSourceLocation, `http://host.docker.internal:18949/metadata/${mode}`);
    assert.equal(plan.parameters.requestSigningMode, 'REQUIRED');
  }
  assert.throws(() => buildPlanInput('product'), /Only owned/);
});

test('same-created-Run continuation preserves exact mode and refuses existing or foreign M0 state', () => {
  const input = buildPlanInput('honor'), prior = { input, created: { plan: { plan: { id: PLAN } } },
    runCreated: { run: { id: RUN, planId: PLAN, status: 'CREATED', context: {} }, managementUrl: null } };
  assert.equal(existingColdCreation(prior, input).runId, RUN);
  for (const fault of [p => { p.input = buildPlanInput('ignore'); }, p => { p.runCreated.run.planId = 'plan_1123456789ABCDEFGHJKMNPQRS'; },
    p => { p.runCreated.run.status = 'WAITING_BROWSER'; }, p => { p.runCreated.run.context.authnRequestId = '_live-normal'; },
    p => { p.runCreated.managementUrl = 'private-control'; }]) {
    const p = structuredClone(prior); fault(p); assert.throws(() => existingColdCreation(p, input));
  }
});

test('failure diagnostics expose only stage/type/categories and project locations, never raw private text', () => {
  const error = new Error('Operation not permitted; private-cookie-control; raw-login-html-control');
  error.stack += '\n    at own (file:///Users/yuta/Documents/SAMLscope/dev/reference-acceptance/synthetic_formal_browser_runtime_smoke.mjs:300:20)';
  const facts = publicFailureDetails(error, 'browser-launch');
  assert.equal(facts.stage, 'browser-launch'); assert.equal(facts.publicCategories.permissionDenied, true);
  assert.equal(facts.safeProjectStack.at(-1).file, 'dev/reference-acceptance/synthetic_formal_browser_runtime_smoke.mjs');
  assert.equal(JSON.stringify(facts).includes('private-cookie-control'), false);
  assert.equal(JSON.stringify(facts).includes('raw-login-html-control'), false);
});

test('fatal attempts retain hash-checked public captures with explicitly unqualified bindings', async () => {
  const dir = await mkdtemp(resolve('build', 'formal-supplemental-control-'));
  try {
    const bytes = decoded(0), file = `browser-saml-originals/0001-${sha(bytes)}.xml`;
    const capture = { file, bytes, record: { runId: RUN, bytes: bytes.length, sha256: sha(bytes), operationKind: 'M0_NORMAL' } };
    const manifest = await retainSupplementalCaptures([capture], dir);
    assert.deepEqual(await readFile(resolve(dir, file)), bytes);
    assert.equal(manifest[0].conformanceConclusionAssigned, false);
    assert.equal(manifest[0].bindingState, 'original-captured-recorder-unqualified');
    await assert.rejects(retainSupplementalCaptures([{ ...capture, file: '../private-control.xml' }], dir));
    await assert.rejects(retainSupplementalCaptures([{ ...capture, bytes: Buffer.from('mismatched-public-control') }], dir));
  } finally { await rm(dir, { recursive: true }); }
});

test('actual collector cold-M0 then two-fixture event sequence preserves every repeated record immutably', async () => {
  const dir = await mkdtemp(resolve('build', 'formal-record-sequence-control-'));
  try {
    const record = createImmutableEvidenceRecorder(dir), task = validateTask({ suiteBaseUrl: origin, runId: RUN, planId: PLAN,
      targetOrigins: ['http://localhost:18949'], caseIds: [SELECTED_CASE], completeNormalFlow: true, startTests: true, outputDirectory: dir });
    const plan = { plan: { id: PLAN, profile: 'browser_sso_idp', target: { kind: 'IDP', entityId: 'http://localhost:18949/entity/honor' } } };
    let current = { id: RUN, planId: PLAN, status: 'CREATED', context: {} }, transcript = [], started = false, resultExists = false;
    const queue = [0, 1].map(index => ({ state: 'READY', caseId: SELECTED_CASE, actionId: action(index), requiresFreshSession: false,
      startUrl: `${origin}/p/${PLAN}/probe/${action(index)}?run=${RUN}` }));
    const api = async (path, body) => {
      if (path === `/api/runs/${RUN}`) return structuredClone(current);
      if (path === `/api/plans/${PLAN}`) return plan;
      if (path.endsWith('/transcript')) return structuredClone(transcript);
      if (path.endsWith('/campaigns')) return { runId: RUN, cases: 0, classifications: [], campaigns: [] };
      if (path.endsWith('/protocol-evidence')) return { eligibleCases: 0, readyCases: 0, cases: [] };
      if (path.endsWith('/interactions')) return [];
      if (path.endsWith('/active-probe')) return started ? queue[0] ?? { state: 'COMPLETE' } : { state: 'NOT_STARTED' };
      if (path.endsWith('/preflight')) { current.status = 'RUNNING'; return { checks: [{ status: 'PASS' }] }; }
      if (path.endsWith('/evaluate')) { resultExists = true; return { completed: [], remaining: { eligibleCases: 0, readyCases: 0, cases: [] } }; }
      if (path.endsWith('/result.json')) { assert.equal(resultExists, true); return { run: { id: RUN }, requirements: [{ cases: [{ id: SELECTED_CASE }] }] }; }
      if (path.endsWith('/tests/start')) { assert.equal(current.status, 'COMPLETED'); started = true; return { started: true }; }
      throw new Error('Unexpected pure integration API path');
    };
    const browser = {
      normalFlow: async (url, timeout, poll) => {
        current = { ...current, status: 'COMPLETED', context: { authnRequestId: '_owned-normal-control' } };
        transcript = [{ id: tx(0), runId: RUN, direction: 'OUTBOUND', samlSummary: { type: 'AuthnRequest', id: '_owned-normal-control' } },
          { id: tx(1), runId: RUN, direction: 'INBOUND', correlationId: '_owned-normal-control', url: `${origin}/p/${PLAN}/sp/acs/0`,
            samlSummary: { normalFlowAccepted: true, type: 'Response', statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
              issuer: plan.plan.target.entityId, destination: `${origin}/p/${PLAN}/sp/acs/0`, inResponseTo: '_owned-normal-control' } }];
        return { recorded: await poll(), browserPageRetained: false, manualAuthenticationCheckpoints: 0 };
      },
      probe: async (task, status, policy) => { assert.equal(policy, 'authenticated-context'); assert.equal(queue.shift().actionId, status.actionId);
        return { recorded: true, manualAuthenticationCheckpoints: 0 }; },
    };
    const collected = await collectSelected(task, api, browser, record);
    assert.equal(collected.collectionState, 'COLLECTED'); assert.equal(collected.counts.selectedTargetActions, 2);
    assert.equal(collected.counts.initialNormalFlowSubmissions, 1);
    const history = record.history();
    assert.equal(history.filter(row => row.logicalName === 'membership.json').length, 2);
    assert.equal(history.filter(row => row.logicalName === 'steps.json').length, 3);
    assert.equal(new Set(history.map(row => row.file)).size, history.length);
    for (const row of history) { const bytes = await readFile(resolve(dir, row.file)); assert.equal(bytes.length, row.bytes); assert.equal(sha(bytes), row.sha256); }
    await assert.rejects(record('../private-control.json', {}));
    await assert.rejects(record('non-public.json', { token: 'private-control' }));
  } finally { await rm(dir, { recursive: true }); }
});

test('cookie boundary forwards only the strict owned RAM cookie and never unrelated values', () => {
  assert.equal(ownedCookieHeader(`unrelated=private-control; ${owned}; other=do-not-forward`), owned);
  assert.equal(ownedCookieHeader('unrelated=private-control'), null);
  assert.equal(ownedCookieHeader(undefined), null);
  assert.equal(ownedCookieHeader(''), null);
});

test('Transcript boundary omits only the exact owned Recorder redaction and keeps strict public parsing', () => {
  const raw = JSON.stringify([{ runId: RUN, headers: { Cookie: ['samlscope_owned_formal_session=<redacted: 32 bytes>'], Accept: ['public-control'] } }]);
  const result = publicTranscriptDocument(Buffer.from(raw), RUN);
  assert.equal(result.irreversiblyRedactedOwnedCookieHeadersOmitted, 1);
  assert.equal('Cookie' in result.document[0].headers, false);
  assert.deepEqual(result.document[0].headers.Accept, ['public-control']);
  for (const bad of [raw.replace('<redacted: 32 bytes>', 'a'.repeat(32)), raw.replace('32 bytes', '31 bytes'),
    raw.replace('samlscope_owned_formal_session', 'other_cookie'), raw.replace(RUN, OTHER),
    raw.replace('"Cookie":', '"Cookie":null,"Cookie":'),
    raw.replace('"Accept":["public-control"]', '"Authorization":["private-control"]'),
    raw.replace('"headers":', '"nested":'), raw.replace('"Accept":["public-control"]', '"token":"private-control"')])
    assert.throws(() => publicTranscriptDocument(Buffer.from(bad), RUN));
});

test('actual Response Transcript retention never writes raw headers, including rejected private values', async () => {
  const dir = await mkdtemp(resolve('build', 'formal-transcript-public-control-'));
  try {
    const raw = JSON.stringify([{ runId: RUN, headers: { Cookie: ['samlscope_owned_formal_session=<redacted: 32 bytes>'] } }]);
    const saved = resolve(dir, 'public.json'), events = [];
    const make = body => new Response(body, { status: 200, headers: { 'content-type': 'application/json' } });
    await readFormalPublicResponse(make(raw), `/api/runs/${RUN}/transcript`, RUN, facts => events.push(facts),
      async (bytes, facts) => { events.push(facts); await writeFile(saved, bytes); });
    assert.equal((await readFile(saved, 'utf8')).includes('Cookie'), false);
    assert.equal(events[1].rawTranscriptBodyRetained, false);
    const forbidden = resolve(dir, 'forbidden.json');
    await assert.rejects(readFormalPublicResponse(make(raw.replace('<redacted: 32 bytes>', 'a'.repeat(32))),
      `/api/runs/${RUN}/transcript`, RUN, () => {}, bytes => writeFile(forbidden, bytes)));
    await assert.rejects(readFile(forbidden), { code: 'ENOENT' });
    await assert.rejects(readFormalPublicResponse(make('{"managementUrl":"private-control"}'),
      '/api/plans', RUN, () => {}, bytes => writeFile(forbidden, bytes)));
    await assert.rejects(readFile(forbidden), { code: 'ENOENT' });
  } finally { await rm(dir, { recursive: true }); }
});
for (const bad of [owned + '; ' + owned, 'samlscope_owned_formal_session=short', owned + '\r\n',
  'samlscope_owned_formal_session=' + 'A'.repeat(32)]) test('malformed or duplicate owned cookie rejects without echoing values', () => {
  assert.throws(() => ownedCookieHeader(bad), error => error.message === 'Malformed owned session header');
});
test('Set-Cookie permits only the one owned cookie with closed safe attributes', () => {
  assert.equal(ownedSetCookie(`${owned}; Path=/; HttpOnly; SameSite=Lax`), `${owned}; Path=/; HttpOnly; SameSite=Lax`);
  assert.equal(ownedSetCookie(`${owned}; SameSite=Lax; HttpOnly; Path=/`), `${owned}; SameSite=Lax; HttpOnly; Path=/`);
  for (const extra of ['; Domain=example.test', '; Secure', '; HttpOnly', ', other=private-control'])
    assert.throws(() => ownedSetCookie(`${owned}; Path=/; HttpOnly; SameSite=Lax${extra}`), /header omitted/);
});

test('only an original public form to the same Suite and exact owned Run/Plan may execute', () => {
  const normal = form(); assert.ok(publicSamlFixtureHtml(normal, origin, { runId: RUN, planId: PLAN }).includes(`value="${RUN}"`));
  const formal = form({ action: `${origin}/p/${PLAN}/sp/acs/1`, relay: `sp1:${RUN}:action_${'a'.repeat(32)}` });
  assert.ok(publicSamlFixtureHtml(formal, origin, { runId: RUN, planId: PLAN }).includes('/sp/acs/1'));
  for (const bad of [form({ action: `http://foreign.invalid/p/${PLAN}/sp/acs/0` }), form({ action: `${origin}/p/${PLAN}/sp/acs/2` }),
    form({ action: `${origin}/p/${PLAN}/sp/acs/0?token=private-control` }), form({ relay: OTHER }),
    form({ action: `${origin}/p/plan_1123456789ABCDEFGHJKMNPQRS/sp/acs/0` }), form({ response: 'not-base64!' }),
    form({ extra: "<input type='password' name='password' value='private-control'>" }), form({ extra: '<script>document.cookie</script>' }),
    form({ extra: '<iframe src="http://foreign.invalid"></iframe>' }), form().replace('<form ', '<form onsubmit="private-control" '),
    form({ extra: '<img src="http://foreign.invalid/collect">' }), form({ extra: '<link href="http://foreign.invalid/style">' }),
    form({ extra: '<meta http-equiv="refresh" content="0;url=http://foreign.invalid/">' }), form({ extra: '<svg></svg>' })])
    assert.throws(() => publicSamlFixtureHtml(bad, origin, { runId: RUN, planId: PLAN }));
});

test('raw POST body and content type are validated without rebuilding protocol bytes', () => {
  const xml = Buffer.from(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_${action(0)}"/>`);
  const body = Buffer.from(`SAMLRequest=${encodeURIComponent(xml.toString('base64'))}&RelayState=${encodeURIComponent(`sp1:${RUN}:${action(0)}`)}`);
  assert.strictEqual(publicSamlRequestBody(body, 'application/x-www-form-urlencoded; charset=UTF-8', { runId: RUN }), body);
  for (const bad of [Buffer.from('SAMLRequest=a&RelayState=b&password=private-control'), Buffer.from('SAMLRequest=a&SAMLRequest=b&RelayState=c'),
    Buffer.from('SAMLRequest=a'), Buffer.from([0xff]), Buffer.alloc(2 * 1024 * 1024 + 1)])
    assert.throws(() => publicSamlRequestBody(bad, 'application/x-www-form-urlencoded'));
  assert.throws(() => publicSamlRequestBody(body, 'text/html'));
  assert.throws(() => publicSamlRequestBody(body, 'application/x-www-form-urlencoded', { runId: OTHER }), /Foreign/);
  assert.throws(() => publicSamlRequestBody(Buffer.from(body.toString().replace(action(0), action(1))), 'application/x-www-form-urlencoded'), /Foreign fixture request action/);
  assert.throws(() => publicSamlRequestBody(Buffer.from('SAMLRequest=not-base64!&RelayState=private-control'), 'application/x-www-form-urlencoded'));
});

test('same SessionIndex or response counts cannot replace real same-context cookie facts', () => {
  assert.equal(assertSessionProof(session(), stats()).ownedSessionPresentAndSame, true);
  for (const patch of [{ contextsCreated: 2 }, { normalContextOrdinal: 2 }, { formalContextOrdinals: [1, 2] },
    { normalCookiePresent: true }, { formalCookiePresent: [true, false] }, { formalCookieMatchesNormal: [true, false] },
    { credentialOrCookieValuesPersisted: 1 }]) assert.throws(() => assertSessionProof({ ...session(), ...patch }, stats()), /proof incomplete/);
  for (const patch of [{ normalReplies: 2 }, { formalReplies: 1 }, { newSessions: 2 }, { reusedSessions: 1 }, { missingSessionRejects: 1 }])
    assert.throws(() => assertSessionProof(session(), { ...stats(), ...patch }), /proof incomplete/);
});

test('six exported captures must be unique, current Recorder bindings with exact normal and selected-case scope', () => {
  assert.equal(assertCaptureProof(bindings(), RUN).exportedDecodedOriginals, 6);
  const faults = [rows => rows.pop(), rows => { rows[5].file = rows[0].file; }, rows => { rows[5].runId = OTHER; },
    rows => { rows[5].transcriptReferences = rows[0].transcriptReferences; }, rows => { rows[5].transcriptReferences = []; },
    rows => { rows[5].bindingState = 'original-captured-recorder-hash-unavailable'; }, rows => { rows[5].caseId = 'IIP-IDP12-b-idp-01'; },
    rows => { rows[5].operationKind = 'M0_NORMAL'; }, rows => { rows[0].caseId = SELECTED_CASE; },
    rows => { rows[5].actionId = 'action_' + 'f'.repeat(32); }];
  for (const fault of faults) { const rows = bindings(); fault(rows); assert.throws(() => assertCaptureProof(rows, RUN)); }
});

test('native physical original binding needs exact bytes/row/current nonce/action when API hashes are absent', () => {
  const runtime = native('honor'), rows = runtime.transcriptOriginals.map(row => ({ ...row, samlSummary: {
    ...(row.id === tx(0) ? { id: '_normal-unit' } : row.id === tx(1) ? { normalFlowAccepted: true, inResponseTo: '_normal-unit' }
      : row.direction === 'OUTBOUND' ? { scenario_case_id: SELECTED_CASE } : { activeProbeAccepted: true }) } }));
  const guard = { source: 'official-Suite-Recorder-normalFlowAccepted', runId: RUN, planId: PLAN, activeAuthnRequestId: '_normal-unit',
    normalAuthnRequestReferences: [tx(0)], acceptedNormalFlowReferences: [tx(1)] };
  const captures = bindings().map((row, index) => ({ file: row.file, record: { ...row, planId: PLAN }, bytes: decoded(index) }));
  const task = { runId: RUN, planId: PLAN };
  const joined = bindNativeProtocolOriginals(task, captures, rows, guard, runtime);
  assert.equal(joined.length, 6); assert.equal(joined[0].hashSource, 'read-only-native-physical-Recorder-original');
  for (const mutate of [p => { p.rows[0].decodedSamlRef = `transcripts/${OTHER}/${tx(0)}.saml.xml`; },
    p => { p.guard.activeAuthnRequestId = '_stale-valid-old-M0'; }, p => { p.rows[3].correlationId = '_foreign-action'; },
    p => { p.runtime.transcriptOriginals[0].computedDecodedSha256 = '0'.repeat(64); },
    p => { p.captures[2].bytes = Buffer.from('changed-public-capture'); }, p => { p.runtime.runId = OTHER; }]) {
    const p = structuredClone({ rows, guard, runtime }); p.captures = captures.map(c => ({ ...c, record: { ...c.record }, bytes: Buffer.from(c.bytes) }));
    mutate(p); assert.throws(() => bindNativeProtocolOriginals(task, p.captures, p.rows, p.guard, p.runtime));
  }
});

test('positive and always-default mutant proof never qualify the incomplete whole Run or adoption', () => {
  assert.equal(assertFormalProof(proof()).selectedCaseOutcome, 'SATISFIED');
  assert.equal(assertFormalProof(proof('ignore')).selectedCaseOutcome, 'VIOLATED');
  for (const patch of [{ qualificationOutcome: 'NOT_VERIFIED' }, { selectedCaseOutcome: 'VIOLATED' },
    { wholeRunConformance: 'QUALIFIED' }, { canonicalAdoption: true }])
    assert.throws(() => assertFormalProof({ ...proof(), runtime: { ...proof().runtime, ...patch } }), /native selected-case/);
  for (const patch of [{ initialNormalFlowSubmissions: 2 }, { normalLoginContexts: 2 }, { fullProfileStartCalls: 0 },
    { selectedTargetActions: 1 }, { authenticatedContextReuses: 1 }, { freshEmptyContexts: 1 }, { automatedCredentialPosts: 1 }]) {
    const p = proof(); p.collected.counts = { ...p.collected.counts, ...patch }; assert.throws(() => assertFormalProof(p), /collector scope/);
  }
});

test('native scope and exact all-six physical declarations reject foreign same-outcome data, missing B and changed bytes', () => {
  const scope = { runId: RUN, planId: PLAN, mode: 'honor' };
  assert.equal(checkedPortableOriginals(native('honor'), scope, bindings()).length, 6);
  const faults = [r => { r.runId = OTHER; }, r => { r.planId = 'plan_1123456789ABCDEFGHJKMNPQRS'; },
    r => { r.fixtureMode = 'ignore'; }, r => { r.approvedSelectedCase.id = 'IIP-IDP12-b-idp-01'; },
    r => { r.actualRequestSignaturesVerified = false; }, r => { r.selectedFixturePairs[1].fixture = 'default-control'; },
    r => { r.transcriptOriginals.pop(); }, r => { r.portableEvidenceReferences.pop(); },
    r => { r.selectedCaseEvidence[1] = r.selectedCaseEvidence[0]; },
    r => { r.transcriptOriginals[5].bodyBase64 = Buffer.from('changed-control').toString('base64'); },
    r => { r.transcriptOriginals[5].decodedSamlBytes++; }, r => { r.transcriptOriginals[5].decodedSamlRef = `transcripts/${OTHER}/${tx(5)}.saml.xml`; },
    r => { r.transcriptOriginals[5].bodyRef = 'private/owned-unit-control'; }, r => { r.transcriptOriginals[5].storedBodySha256 = 'f'.repeat(64); },
    r => { r.transcriptOriginals[0].rawQuery = null; }, r => { r.transcriptOriginals[5].correlationId = '_' + action(0); }];
  for (const fault of faults) { const r = native('honor'); fault(r); assert.throws(() => checkedPortableOriginals(r, scope, bindings())); }
});

test('all twelve native byte files plus signed query and six browser files match physical portable hashes', async () => {
  const output = await mkdtemp('/private/tmp/samlscope-formal-public-control-');
  try {
    await mkdir(resolve(output, 'browser-saml-originals'));
    for (const [index, row] of bindings().entries()) await writeFile(resolve(output, row.file), decoded(index));
    const result = await exportPortableOriginals(native('honor'), { runId: RUN, planId: PLAN, mode: 'honor' }, bindings(), output);
    assert.equal(result.requiredSelectedOriginalsExported, true); assert.equal(result.originals.length, 6);
    for (const row of result.originals) for (const physical of Object.values(row.physical)) {
      const bytes = await readFile(resolve(output, physical.file)); assert.equal(bytes.length, physical.bytes); assert.equal(sha(bytes), physical.sha256);
    }
  } finally { await rm(output, { recursive: true, force: true }); }
});

test('portable gate rejects a symbolic parent, a symbolic browser leaf and mismatched physical browser bytes', async () => {
  const parent = await mkdtemp('/private/tmp/samlscope-formal-path-control-');
  try {
    const real = resolve(parent, 'real'); await mkdir(real); await symlink(real, resolve(parent, 'alias'));
    await assert.rejects(exportPortableOriginals(native('honor'), { runId: RUN, planId: PLAN, mode: 'honor' }, bindings(), resolve(parent, 'alias')), /symlink/);
    for (const fault of ['symlink', 'bytes']) {
      const output = resolve(parent, fault); await mkdir(output); await mkdir(resolve(output, 'browser-saml-originals'));
      for (const [index, row] of bindings().entries()) {
        if (index === 0 && fault === 'symlink') { const fake = resolve(parent, 'owned-public-original.xml'); await writeFile(fake, decoded(index)); await symlink(fake, resolve(output, row.file)); }
        else await writeFile(resolve(output, row.file), index === 0 ? Buffer.from('changed-owned-control') : decoded(index));
      }
      await assert.rejects(exportPortableOriginals(native('honor'), { runId: RUN, planId: PLAN, mode: 'honor' }, bindings(), output), /symlink|size differs|bytes differ/);
    }
  } finally { await rm(parent, { recursive: true, force: true }); }
});

test('actual result completeness and centrally produced selected verdict remain independent of native qualification label', () => {
  const result = outcome => ({ run: { id: RUN, completeness: 'INCOMPLETE', conformance: outcome === 'SATISFIED' ? 'INDETERMINATE' : 'NON_CONFORMANT' },
    requirements: [{ cases: [{ id: SELECTED_CASE, outcome, verdict: outcome === 'SATISFIED' ? 'PASS' : 'FAIL' }] }] });
  assert.equal(assertResultProof(result('SATISFIED'), { runId: RUN }, 'SATISFIED').observedCentralSuiteVerdict, 'PASS');
  assert.equal(assertResultProof(result('VIOLATED'), { runId: RUN }, 'VIOLATED').observedCentralSuiteVerdict, 'FAIL');
  for (const fault of [r => { r.run.id = OTHER; }, r => { r.run.completeness = 'COMPLETE'; },
    r => { r.requirements[0].cases[0].outcome = 'VIOLATED'; }, r => { r.requirements[0].cases[0].verdict = 'FAIL'; }]) {
    const r = result('SATISFIED'); fault(r); assert.throws(() => assertResultProof(r, { runId: RUN }, 'SATISFIED'));
  }
});

test('actual Node Response status and public-body retention behavior remains correctly called', async () => {
  const events = [];
  const response = new Response('{"run":{"id":"public-control"},"managementUrl":null}', { status: 200, headers: { 'content-type': 'application/json' } });
  assert.deepEqual(fetchStatus(response), { status: 200, ok: true, contentType: 'application/json' });
  assert.equal((await readPublicResponse(response, facts => events.push(facts), bytes => events.push(bytes.length))).run.id, 'public-control');
  assert.equal(events.length, 2);
  const errors = [];
  await assert.rejects(readPublicResponse(new Response('{"error":"owned-control"}', { status: 409, headers: { 'content-type': 'application/json' } }),
    facts => errors.push(facts), bytes => errors.push(bytes.length)), /status 409/);
  assert.equal(errors.length, 2);
  const privateEvents = [];
  await assert.rejects(readPublicResponse(new Response('{"nested":{"managementUrl":"private-control"}}', { status: 200, headers: { 'content-type': 'application/json' } }),
    facts => privateEvents.push(facts), bytes => privateEvents.push(bytes.length)), /Non-public Suite/);
  assert.equal(privateEvents.length, 1, 'raw body must never reach retention callback');
});
