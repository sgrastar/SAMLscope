/** Pure controls only: no browser launch, listener, Docker, HTTP or Suite Run. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, mkdtemp, rm, readdir, realpath, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
import { CASE_ID, CASE_DIGEST, DEFINITION_VERSION, REALM_GIT_BLOB, IMAGE_REFERENCE, SUITE_ORIGIN,
  TARGET_ORIGIN, TARGET_ENTITY, LOGIN_PATH, validateOwnedSetup, checkedDemoSeed, ownedLoginScope, ownedLoginPageScope,
  checkedNativeColdScope, readOwnedTranscriptResponse, bindOwnedNativeOriginals,
  approvedScope, createLoginGate, createOwnedLoginHandler, ownedChromium, assertCredentialFree,
  observedSuiteResult, assertCaptureScope, validateOwnedApiScope, checkedOwnedPortableOriginals,
  exportOwnedPortableOriginals } from './owned_keycloak_nameid_browser.mjs';
import { validateTask } from './generic_browser_campaign.mjs';
import { publicDocument, readPublicResponse } from './synthetic_normal_browser_http.mjs';
import { createImmutableEvidenceRecorder } from './synthetic_formal_browser_runtime_smoke.mjs';

const RUN = 'run_0123456789ABCDEFGHJKMNPQRS';
const PLAN = 'plan_0123456789ABCDEFGHJKMNPQRS';
const seed = Object.freeze({ username: 'pure-fixture-user-value', password: 'pure-fixture-password-value' });
const setup = () => ({ schema: 'owned-keycloak-nameid-setup-v1', generation: 'pure-r1', suiteOrigin: SUITE_ORIGIN,
  targetOrigin: TARGET_ORIGIN, targetEntityId: TARGET_ENTITY, runId: RUN, planId: PLAN, caseId: CASE_ID, caseDigest: CASE_DIGEST,
  definitionIdentity: { profile: 'browser_sso_idp', version: DEFINITION_VERSION, digest: 'sha256:' + 'a'.repeat(64) },
  suitePublicMetadataFile: resolve('build/acceptance/pure-owned-fixture/suite-public-metadata.xml'),
  suitePublicMetadataSha256: 'b'.repeat(64), clientDbId: '12345678-1234-1234-1234-123456789abc',
  ownedContainerId: 'c'.repeat(64), ownedContainerName: 'samlscope-owned-kc-nameid-v2-pure-r1', imageReference: IMAGE_REFERENCE,
  ownedLabels: { 'com.samlscope.owned.acceptance': 'keycloak-public-ci-nameid-v2',
    'com.samlscope.owned.generation': 'pure-r1', 'com.samlscope.owned.realm-blob': REALM_GIT_BLOB } });
const task = () => validateTask({ suiteBaseUrl: SUITE_ORIGIN, targetOrigins: [TARGET_ORIGIN], runId: RUN, planId: PLAN,
  caseIds: [CASE_ID], outputDirectory: '/private/tmp/pure-owned-browser', maxActions: 100, completeNormalFlow: true, startTests: true });
const run = () => ({ id: RUN, planId: PLAN, status: 'CREATED', context: {} });
const plan = () => ({ id: PLAN, profile: 'browser_sso_idp', target: { kind: 'IDP', entityId: TARGET_ENTITY },
  definitionIdentity: setup().definitionIdentity });
const result = () => ({ run: { id: RUN, completeness: 'INCOMPLETE', conformance: 'NOT_QUALIFIED' },
  requirements: [{ cases: [{ id: CASE_ID, outcome: 'NOT_VERIFIED', verdict: 'NOT_VERIFIED' }] }] });
const zero = () => ({ runId: RUN, actualCaseExecutions: 0, pendingInteractions: 0, readyOrLiveCaseActions: 0,
  source: 'official-public-zero-execution-projections' });
const guard = () => ({ runId: RUN, planId: PLAN, source: 'official-Suite-Recorder-normalFlowAccepted',
  completedRunStatus: 'COMPLETED', activeAuthnRequestId: '_pure-normal',
  normalAuthnRequestReferences: ['tx_pure-normal-request'], acceptedNormalFlowReferences: ['tx_pure-normal-response'] });

function mockPage(url = TARGET_ORIGIN + LOGIN_PATH + '?opaque-pure-state=one', overrides = {}) {
  const events = new Map(), fills = [], clicks = [];
  let current = url, closed = false;
  const attributes = { '#password': { type: 'password' }, '#kc-login': { formaction: null },
    'form#kc-form-login': { action: url, method: 'post' }, ...overrides.attributes };
  const page = { on: (event, fn) => events.set(event, fn), isClosed: () => closed, url: () => current,
    locator: selector => ({ count: async () => overrides.counts?.[selector] ?? 1,
      getAttribute: async name => attributes[selector]?.[name] ?? null,
      fill: async value => { fills.push({ selector, value }); if (overrides.afterFill) overrides.afterFill(selector, () => { current += '&changed=one'; }); },
      click: async () => { clicks.push('clicked'); if (overrides.click) await overrides.click(); } }),
    content: () => { throw new Error('Forbidden DOM serialization'); }, screenshot: () => { throw new Error('Forbidden screenshot'); },
  };
  return { page, events, fills, clicks, navigate: value => { current = value; }, close: () => { closed = true; } };
}

test('strict setup binds only the owned v2 generation, public seed identity and pinned product image', () => {
  assert.equal(validateOwnedSetup(setup()).caseDigest, CASE_DIGEST);
  const mutations = [
    value => { value.targetOrigin = 'http://localhost:8180'; }, value => { value.suiteOrigin = 'http://localhost:8080'; },
    value => { value.targetEntityId += '/foreign'; }, value => { value.caseId = 'IIP-SSO01-f-idp-01'; },
    value => { value.caseDigest = 'sha256:' + 'd'.repeat(64); }, value => { value.definitionIdentity.version = 'functional-case-v1'; },
    value => { value.definitionIdentity.profile = 'browser_sso_sp'; }, value => { value.definitionIdentity.digest = 'unpinned'; },
    value => { value.imageReference = 'quay.io/keycloak/keycloak:latest'; }, value => { value.ownedContainerId = 'old'; },
    value => { value.ownedContainerName = 'samlscope-reference-keycloak'; }, value => { value.ownedLabels['com.samlscope.owned.generation'] = 'old'; },
    value => { value.ownedLabels['com.samlscope.owned.realm-blob'] = 'd'.repeat(40); }, value => { value.generation = '../foreign'; },
    value => { value.suitePublicMetadataFile = resolve('private/metadata.xml'); }, value => { value.clientDbId = 'not-a-native-UUID'; },
    value => { value.token = 'pure-private-sentinel'; }, value => { value.ownedLabels.extra = 'unreviewed'; },
  ];
  for (const mutate of mutations) { const value = setup(); mutate(value); assert.throws(() => validateOwnedSetup(value)); }
});

test('public realm credential extraction requires exact SHA and Git blob before parsing', async () => {
  const raw = await readFile(resolve('dev/keycloak/realm-samlscope.json'));
  const actualSeed = checkedDemoSeed(raw, raw);
  assert.equal(typeof actualSeed.username === 'string' && actualSeed.username.length > 0, true);
  assert.equal(typeof actualSeed.password === 'string' && actualSeed.password.length > 0, true);
  const altered = Buffer.from(raw); altered[0] ^= 1;
  assert.throws(() => checkedDemoSeed(altered, raw), /public-demo-seed-identity-invalid/);
  assert.throws(() => checkedDemoSeed(raw, altered), /public-demo-seed-identity-invalid/);
  assert.throws(() => checkedDemoSeed(Buffer.from('{invalid'), raw), /public-demo-seed-identity-invalid/);
});

test('login scope allows query in RAM only and excludes foreign endpoints and every alias', () => {
  assert.equal(ownedLoginScope(TARGET_ORIGIN + LOGIN_PATH + '?opaque=kept-in-ram'), true);
  for (const value of ['http://localhost:8180' + LOGIN_PATH, 'http://127.0.0.1:28080' + LOGIN_PATH,
    'https://localhost:28080' + LOGIN_PATH, SUITE_ORIGIN + LOGIN_PATH, TARGET_ORIGIN + '/realms/other/login-actions/authenticate',
    TARGET_ORIGIN + LOGIN_PATH + '/extra', TARGET_ORIGIN + LOGIN_PATH + '#private-state',
    'http://user:private-value@localhost:28080' + LOGIN_PATH, 'not-a-url']) assert.equal(ownedLoginScope(value), false);
});

test('actual membership and full approved definition identity must both match before login', () => {
  assert.equal(approvedScope(setup(), task(), run(), plan(), result()).actualMembershipVerified, true);
  const cases = [
    [run(), { ...plan(), definitionIdentity: { ...plan().definitionIdentity, digest: 'sha256:' + 'f'.repeat(64) } }, result()],
    [{ ...run(), planId: 'plan_FOREIGN' }, plan(), result()],
    [run(), { ...plan(), target: { kind: 'IDP', entityId: 'http://foreign.example/realms/samlscope' } }, result()],
    [run(), plan(), { ...result(), requirements: [{ cases: [] }] }],
    [run(), plan(), { ...result(), requirements: [{ cases: [{ id: CASE_ID }, { id: CASE_ID }] }] }],
  ];
  for (const values of cases) assert.throws(() => approvedScope(setup(), task(), ...values));
});

test('API scope permits only official existing owned Run operations and rejects foreign Run or creation endpoints', () => {
  assert.equal(validateOwnedApiScope(setup(), `/api/runs/${RUN}/transcript`), `/api/runs/${RUN}/transcript`);
  assert.equal(validateOwnedApiScope(setup(), `/api/runs/${RUN}/tests/start`, {}), `/api/runs/${RUN}/tests/start`);
  for (const [path, body] of [['/api/plans', {}], [`/api/plans/${PLAN}/runs`, {}],
    ['/api/runs/run_FOREIGN/transcript', undefined], [`/api/runs/${RUN}/transcript?opaque=one`, undefined],
    [`/api/runs/${RUN}/tests/start`, undefined], [`/api/runs/${RUN}/transcript`, {}],
    [TARGET_ORIGIN + LOGIN_PATH, {}]]) assert.throws(() => validateOwnedApiScope(setup(), path, body));
});

test('cold normal gate requires zero executions; formal gate requires actual M0 guard and same-context policy', () => {
  const gate = createLoginGate(setup(), task());
  assert.throws(() => gate.assertAllowed(), /login-not-authorized/);
  assert.throws(() => gate.startNormal());
  assert.throws(() => gate.authorizeCold({ ...run(), status: 'RUNNING' }, plan(), result(), [], zero()));
  assert.throws(() => gate.authorizeCold(run(), plan(), result(), [{}], zero()));
  assert.throws(() => gate.authorizeCold(run(), plan(), result(), [], { ...zero(), actualCaseExecutions: 1 }));
  gate.authorizeCold(run(), plan(), result(), [], zero()); gate.startNormal(); gate.assertAllowed();
  assert.throws(() => gate.recordNormal({ ...guard(), source: 'html-success' }));
  gate.recordNormal(guard());
  const status = { caseId: CASE_ID, requiresFreshSession: false };
  assert.throws(() => gate.startFormal(run(), plan(), result(), { ...status, requiresFreshSession: true }, 'fresh-empty-context'));
  gate.startFormal(run(), plan(), result(), status, 'authenticated-context'); gate.assertAllowed();
  gate.endFormal(); assert.throws(() => gate.assertAllowed());
});

test('owned handler fills only exact selectors, records observed posts and never exports login values or URL state', async () => {
  const mock = mockPage(), handler = createOwnedLoginHandler(seed, { assertAllowed() {} });
  handler.attach(mock.page); assert.equal(typeof mock.events.get('domcontentloaded'), 'function');
  await handler.handle(mock.page); handler.assertHealthy();
  assert.deepEqual(mock.fills.map(value => value.selector), ['#username', '#password']); assert.equal(mock.clicks.length, 1);
  handler.observeRequest({ method: () => 'POST', url: () => TARGET_ORIGIN + LOGIN_PATH + '?opaque=state',
    postData: () => { throw new Error('Forbidden login body'); }, headers: () => { throw new Error('Forbidden login headers'); } });
  const facts = handler.facts(); assert.equal(facts.observedLoginPostRequests, 1);
  assert.equal(facts.loginRequestBodiesReadByOwnedHandler, false);
  assert.equal(JSON.stringify(facts).includes('opaque'), false); assertCredentialFree(facts, seed);
});

test('foreign origin, missing selectors, foreign form action and unauthorized gate cannot submit credentials', async () => {
  for (const mock of [mockPage('http://foreign.example' + LOGIN_PATH), mockPage(TARGET_ORIGIN + '/different-path')]) {
    const handler = createOwnedLoginHandler(seed, { assertAllowed() {} }); await handler.handle(mock.page);
    assert.equal(mock.fills.length, 0); assert.equal(mock.clicks.length, 0);
  }
  const failures = [mockPage(undefined, { counts: { '#password': 0 } }),
    mockPage(undefined, { counts: { '#username': 2 } }),
    mockPage(undefined, { attributes: { 'form#kc-form-login': { action: 'http://foreign.example/login', method: 'post' } } }),
    mockPage(undefined, { attributes: { '#kc-login': { formaction: TARGET_ORIGIN + LOGIN_PATH } } })];
  for (const mock of failures) {
    const handler = createOwnedLoginHandler(seed, { assertAllowed() {} }); await handler.handle(mock.page);
    assert.throws(() => handler.assertHealthy()); assert.equal(mock.fills.length, 0); assert.equal(mock.clicks.length, 0);
  }
  const mock = mockPage(), handler = createOwnedLoginHandler(seed, { assertAllowed() { throw Object.assign(new Error('closed'), { code: 'closed' }); } });
  await handler.handle(mock.page); assert.throws(() => handler.assertHealthy()); assert.equal(mock.fills.length, 0);
});

test('duplicate page/state fails closed after one submission, including a second page with copied login state', async () => {
  const first = mockPage(), second = mockPage(), handler = createOwnedLoginHandler(seed, { assertAllowed() {} });
  await handler.handle(first.page); await handler.handle(second.page); await handler.handle(first.page);
  assert.equal(first.clicks.length, 1); assert.equal(second.clicks.length, 0);
  assert.equal(handler.facts().repeatedLoginStateRejected, 1); assert.throws(() => handler.assertHealthy(), /duplicate-login-state/);
});

test('overlapping DOM events cannot produce a second auto-submit and changed state cannot click', async () => {
  let release; const blocked = new Promise(done => { release = done; });
  const mock = mockPage(undefined, { click: () => blocked }), handler = createOwnedLoginHandler(seed, { assertAllowed() {} });
  const first = handler.handle(mock.page);
  while (!mock.clicks.length) await new Promise(done => setImmediate(done));
  await handler.handle(mock.page); release(); await first;
  assert.equal(mock.clicks.length, 1); assert.equal(handler.facts().duplicateEventsSkipped, 1);
  const changed = mockPage(undefined, { afterFill: (_, change) => change() }), guarded = createOwnedLoginHandler(seed, { assertAllowed() {} });
  await guarded.handle(changed.page); assert.equal(changed.clicks.length, 0); assert.throws(() => guarded.assertHealthy());
});

test('newPage installs login DOM hook before navigation and rejects a second or restored context', async () => {
  const mock = mockPage(), events = [], context = { on: (name, fn) => events.push([name, fn]), newPage: async () => mock.page };
  const underlying = { newContext: async () => context };
  const chromium = { launch: async options => { assert.equal(options.headless, false); return underlying; } };
  const facts = { primaryContextsCreated: 0 }, handler = createOwnedLoginHandler(seed, { assertAllowed() {} });
  const browser = await ownedChromium(chromium, handler, facts).launch({ channel: 'chrome', headless: false });
  const primary = await browser.newContext(), page = await primary.newPage();
  assert.equal(page, mock.page); assert.equal(mock.events.has('domcontentloaded'), true); assert.equal(events[0][0], 'request');
  await assert.rejects(browser.newContext(), /owned-single-empty-context-required/);
  await assert.rejects(ownedChromium(chromium, handler, { primaryContextsCreated: 0 }).launch({ channel: 'chromium', headless: true }));
  const restored = await ownedChromium(chromium, handler, { primaryContextsCreated: 0 }).launch({ channel: 'chrome', headless: false });
  await assert.rejects(restored.newContext({ storageState: '/pure/forbidden.json' }));
});

test('frozen public Response guard and RAM seed-value guard reject non-public originals before raw retention', async () => {
  for (const raw of [JSON.stringify({ message: seed.password }), JSON.stringify({ innocent: seed.username }),
    JSON.stringify({ message: TARGET_ORIGIN + LOGIN_PATH + '?opaque-private-state=one' }),
    '{"token":"pure-private-sentinel","token":null}', '{"nested":{"cookie":"pure-private-sentinel"}}',
    '{"managementUrl":"pure-private-sentinel","managementUrl":null}', '{malformed',
    '<html><input type="password"></html>']) {
    let retained = false;
    await assert.rejects(readPublicResponse(new Response(raw, { headers: { 'Content-Type': 'application/json' } }),
      async () => {}, async bytes => { assertCredentialFree(publicDocument(bytes), seed); retained = true; }));
    assert.equal(retained, false);
  }
  assert.throws(() => assertCredentialFree(Buffer.from('<NameID>' + seed.username + '</NameID>'), seed));
  assert.throws(() => assertCredentialFree({ nested: [{ message: seed.password }] }, seed));
});

test('immutable recorder preserves actual repeated membership, steps and count events in order', async () => {
  const output = await mkdtemp(resolve(await realpath(tmpdir()), 'pure-owned-evidence-'));
  try {
    const record = createImmutableEvidenceRecorder(output);
    await record('membership.json', { phase: 'cold' }); await record('membership.json', { phase: 'formal' });
    await record('steps.json', []); await record('steps.json', [{ action: 'prepared-and-skipped' }]);
    await record('operation-counts.json', { selectedTargetActions: 0 }); await record('operation-counts.json', { selectedTargetActions: 3 });
    const history = record.history(); assert.equal(history.length, 6);
    assert.deepEqual(history.map(row => row.occurrence), [1, 2, 1, 2, 1, 2]);
    assert.equal(JSON.parse(await readFile(resolve(output, 'membership.json'))).phase, 'cold');
    assert.equal(JSON.parse(await readFile(resolve(output, history[1].file))).phase, 'formal');
    assert.equal((await readdir(resolve(output, 'record-revisions'))).length, 3);
  } finally { await rm(output, { recursive: true, force: true }); }
});

test('actual central verdict and whole Run incompleteness are preserved without deriving a verdict', () => {
  const value = result(); value.requirements[0].cases[0].outcome = 'VIOLATED'; value.requirements[0].cases[0].verdict = 'FAIL';
  const observed = observedSuiteResult(setup(), value);
  assert.equal(observed.actualSuiteOutcome, 'VIOLATED'); assert.equal(observed.centralVerdict, 'FAIL');
  assert.equal(observed.wholeRunCompleteness, 'INCOMPLETE'); assert.equal(observed.canonicalAdoption, false);
  assert.throws(() => observedSuiteResult(setup(), { ...value, run: { ...value.run, completeness: 'COMPLETE' } }));
});

test('capture proof requires exactly normal two plus three distinct formal request/response pairs', () => {
  const base = { runId: RUN, planId: PLAN, bindingState: 'recorder-hash-and-action-bound', bytes: 10, sha256: 'a'.repeat(64) };
  const bindings = [];
  for (const [index, direction] of ['OUTBOUND', 'INBOUND'].entries()) bindings.push({ ...base, direction,
    file: 'normal-' + index, operationKind: 'M0_NORMAL', transcriptReferences: ['normal-' + index], bindingState: 'recorder-hash-and-normal-flow-bound' });
  for (let pair = 0; pair < 3; pair++) for (const direction of ['OUTBOUND', 'INBOUND']) bindings.push({ ...base,
    file: pair + '-' + direction, transcriptReferences: [pair + '-' + direction], direction, caseId: CASE_ID, actionId: 'action_' + String(pair).padStart(32, '0') });
  assert.equal(assertCaptureScope(setup(), Array(8), bindings).formalActionsObserved, 3);
  assert.throws(() => assertCaptureScope(setup(), Array(7), bindings.slice(0, 7)));
  const bad = structuredClone(bindings); bad[2].caseId = 'IIP-SSO01-f-idp-01'; assert.throws(() => assertCaptureScope(setup(), Array(8), bad));
  const duplicate = structuredClone(bindings); duplicate[7].transcriptReferences = duplicate[6].transcriptReferences;
  assert.throws(() => assertCaptureScope(setup(), Array(8), duplicate));
});

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function purePortableFixture() {
  const binding = [], originals = [], fixtureIds = ['format-transient', 'format-persistent', 'sp-name-qualifier'];
  const refs = Array.from({ length: 8 }, (_, index) => 'tx_' + String(index).padStart(26, '0'));
  const pairs = fixtureIds.map((fixtureId, index) => ({ fixtureId, actionId: 'action_' + String(index + 1).padStart(32, '0'),
    requestReference: refs[2 + index * 2], responseReference: refs[3 + index * 2] }));
  const outcome = result(); outcome.requirements[0].cases[0].outcome = 'VIOLATED'; outcome.requirements[0].cases[0].verdict = 'FAIL';
  outcome.requirements[0].cases[0].evidence = pairs.map(pair => ({kind:'transcript',reference:pair.responseReference}));
  for (let index = 0; index < 8; index++) {
    const direction = index % 2 ? 'INBOUND' : 'OUTBOUND', normal = index < 2;
    const pair = normal ? null : pairs[Math.floor((index - 2) / 2)];
    const nonce = normal ? '_pure-normal' : '_' + pair.actionId;
    const decoded = Buffer.from(direction === 'OUTBOUND' ? `<AuthnRequest ID="${nonce}"/>` : `<Response InResponseTo="${nonce}"/>`);
    const endpoint = direction === 'OUTBOUND' ? TARGET_ENTITY + '/protocol/saml' : `${SUITE_ORIGIN}/p/${PLAN}/sp/acs/0`;
    const method = normal && direction === 'OUTBOUND' ? 'GET' : 'POST';
    const field = direction === 'OUTBOUND' ? 'SAMLRequest' : 'SAMLResponse';
    const fields = new URLSearchParams({ [field]: (method === 'GET' ? deflateRawSync(decoded) : decoded).toString('base64'), RelayState: 'pure-public-relay' });
    if (method === 'GET') { fields.set('SigAlg', 'urn:pure-fixture-signature'); fields.set('Signature', Buffer.from('pure-fixture-signature').toString('base64')); }
    const body = method === 'POST' ? Buffer.from(fields.toString()) : Buffer.alloc(0);
    const rawQuery = method === 'GET' ? fields.toString() : null;
    const summary = normal ? direction === 'INBOUND' ? { type: 'Response', normalFlowAccepted: true }
      : { type: 'AuthnRequest', id: nonce } : direction === 'OUTBOUND' ? { type: 'AuthnRequest',
        scenario_case_id: CASE_ID, fixture_id: pair.fixtureId, action_id: pair.actionId } : { type: 'Response' };
    const prefix = `transcripts/${RUN}/${refs[index]}`;
    originals.push({ id: refs[index], runId: RUN, direction, timestamp: new Date(Date.UTC(2026, 9, 8, 0, 0, index)).toISOString(),
      correlationId: normal ? nonce : (direction === 'INBOUND' ? '_' : '') + pair.actionId, method,
      url: endpoint + (rawQuery === null ? '' : '?' + rawQuery), status: direction === 'INBOUND' ? 200 : null,
      contentType: method === 'POST' ? 'application/x-www-form-urlencoded' : null, rawQuery, summary,
      bodyRef: method === 'POST' ? prefix + '.body' : null, bodyBytes: body.length, bodyBase64: body.toString('base64'),
      computedBodySha256: sha(body), storedBodySha256: sha(body), decodedSamlRef: prefix + '.saml.xml',
      decodedSamlBytes: decoded.length, decodedSamlBase64: decoded.toString('base64'), computedDecodedSha256: sha(decoded) });
    binding.push({ runId: RUN, planId: PLAN, direction, endpoint, bytes: decoded.length, sha256: sha(decoded),
      file: `browser-saml-originals/${String(index + 1).padStart(4, '0')}-${sha(decoded)}.xml`, transcriptReferences: [refs[index]],
      ...(normal ? { operationKind: 'M0_NORMAL', bindingState: 'recorder-hash-and-normal-flow-bound' }
        : { caseId: CASE_ID, actionId: pair.actionId, bindingState: 'recorder-hash-and-action-bound' }) });
  }
  return { bindings: binding, outcome, runtime: { schema: 'owned-keycloak-nameid-native-v1', runId: RUN, planId: PLAN,
    caseId: CASE_ID, caseDigest: CASE_DIGEST, definitionIdentity: setup().definitionIdentity,
    qualificationOutcome: 'VERIFIED', selectedCaseOutcome: 'VIOLATED', selectedCaseEvidence: pairs.map(pair => pair.responseReference),
    normalRequestReference: refs[0], normalResponseReference: refs[1], selectedActionPairs: pairs,
    portableEvidenceReferences: refs, transcriptOriginals: originals, selectedRegisteredScenarioProven: true,
    nativeRequiredRequestShapesProven: true, approvedControlReplayRequiredForAdoption: true,
    wholeRunConformance: 'NOT_QUALIFIED', canonicalAdoption: false } };
}

test('pure portable geometry binds all eight source bytes and preserves independent control replay requirement', () => {
  const value = purePortableFixture();
  const checked = checkedOwnedPortableOriginals(setup(), value.runtime, value.bindings, value.outcome, seed);
  assert.equal(checked.length, 8); assert.equal(checked.filter(row => row.query !== null).length, 1);
  assert.equal(checked.every(row => row.decoded.length > 0), true);
  assert.equal(value.runtime.selectedCaseOutcome, 'VIOLATED'); // The byte checker assigns no outcome.
  const mutations = [
    value => { value.runtime.runId = 'run_FOREIGN'; }, value => { value.runtime.caseDigest = 'sha256:' + 'd'.repeat(64); },
    value => { value.runtime.definitionIdentity.version = 'functional-case-v1'; },
    value => { value.runtime.approvedControlReplayRequiredForAdoption = false; },
    value => { value.runtime.selectedRegisteredScenarioProven = false; }, value => { value.runtime.selectedCaseOutcome = 'SATISFIED'; },
    value => { value.runtime.selectedCaseEvidence[2] = value.runtime.selectedCaseEvidence[1]; },
    value => { value.runtime.portableEvidenceReferences.pop(); }, value => { value.runtime.transcriptOriginals.pop(); },
    value => { value.runtime.selectedActionPairs[1].fixtureId = 'format-transient'; },
    value => { value.runtime.transcriptOriginals[2].bodyBytes++; },
    value => { value.runtime.transcriptOriginals[2].decodedSamlRef = 'transcripts/foreign/copied.saml.xml'; },
    value => { value.runtime.transcriptOriginals[2].headers = {}; },
    value => { value.runtime.transcriptOriginals[2].summary.headers = {}; },
    value => { value.runtime.transcriptOriginals[2].url = 'http://foreign.example/protocol/saml'; },
    value => { value.runtime.transcriptOriginals[2].correlationId = value.runtime.selectedActionPairs[1].actionId; },
    value => { value.runtime.transcriptOriginals[3].timestamp = '2025-01-01T00:00:00Z'; },
    value => { value.bindings[7].sha256 = 'e'.repeat(64); },
    value => { value.runtime.transcriptOriginals[0].rawQuery += '&username=pure-value';
      value.runtime.transcriptOriginals[0].url += '&username=pure-value'; },
  ];
  for (const mutate of mutations) { const invalid = purePortableFixture(); mutate(invalid);
    assert.throws(() => checkedOwnedPortableOriginals(setup(), invalid.runtime, invalid.bindings, invalid.outcome, seed)); }
});

test('base64 wrapper cannot hide native private credentials from portable byte guard', () => {
  const value = purePortableFixture(), original = value.runtime.transcriptOriginals[3];
  const privateXml = Buffer.from('<Response><NameID>' + seed.username + '</NameID></Response>');
  original.decodedSamlBase64 = privateXml.toString('base64'); original.decodedSamlBytes = privateXml.length;
  original.computedDecodedSha256 = sha(privateXml); value.bindings[3].sha256 = sha(privateXml); value.bindings[3].bytes = privateXml.length;
  assert.throws(() => checkedOwnedPortableOriginals(setup(), value.runtime, value.bindings, value.outcome, seed), /private-value-omitted/);
});

test('portable export checks actual browser files before any native physical retention, then verifies written bytes', async () => {
  await mkdir(resolve('build/acceptance'), { recursive: true });
  const output = await mkdtemp(resolve('build/acceptance/pure-owned-portable-'));
  const value = purePortableFixture();
  try {
    await mkdir(resolve(output, 'browser-saml-originals'));
    for (let index = 0; index < value.bindings.length; index++) await writeFile(resolve(output, value.bindings[index].file),
      Buffer.from(value.runtime.transcriptOriginals[index].decodedSamlBase64, 'base64'));
    const changed = resolve(output, value.bindings[7].file), expected = await readFile(changed);
    await writeFile(changed, Buffer.from('corrupt-pure-original'));
    await assert.rejects(exportOwnedPortableOriginals(setup(), value.runtime, value.bindings, value.outcome, output, seed), /physical-original-mismatch/);
    await assert.rejects(access(resolve(output, 'native-originals')));
    await writeFile(changed, expected);
    const manifest = await exportOwnedPortableOriginals(setup(), value.runtime, value.bindings, value.outcome, output, seed);
    assert.equal(manifest.selectedOriginalCount, 8); assert.equal(manifest.approvedControlReplayRequiredForAdoption, true);
    assert.equal(manifest.actualSuiteOutcome, 'VIOLATED'); assert.equal(manifest.centralVerdict, 'FAIL');
    assert.equal(manifest.wholeRunCompleteness, 'INCOMPLETE'); assert.equal(manifest.canonicalAdoption, false);
    for (const original of manifest.originals) for (const physical of Object.values(original.physical)) {
      const bytes = await readFile(resolve(output, physical.file)); assert.equal(bytes.length, physical.bytes); assert.equal(sha(bytes), physical.sha256);
    }
    await assert.rejects(exportOwnedPortableOriginals(setup(), value.runtime, value.bindings, value.outcome, output, seed));
  } finally { await rm(output, { recursive: true, force: true }); }
});


test('native cold proof binds actual owning v2 identity and rejects touched or foreign Run before login', () => {
 const current=setup();const cold={schema:'owned-keycloak-nameid-native-v1',mode:'scope',qualificationOutcome:'SCOPE_VERIFIED',
 runId:RUN,planId:PLAN,generation:current.generation,caseId:CASE_ID,caseDigest:CASE_DIGEST,targetEntityId:TARGET_ENTITY,
 definitionIdentity:current.definitionIdentity,actualCaseExecutions:0,actualOutboxActions:0,transcriptEntries:0,
 protocolSubmissionsByReader:0,privateKeyReads:0,canonicalAdoption:false};
 assert.equal(checkedNativeColdScope(current,cold).runId,RUN);
 const publicPlan={...plan()};delete publicPlan.definitionIdentity;
 const gate=createLoginGate(current,task());gate.authorizeCold(run(),publicPlan,null,[],zero(),cold);gate.startNormal();gate.assertAllowed();
 assert.throws(()=>createLoginGate(current,task()).authorizeCold(run(),publicPlan,null,[],zero(),null));
 for(const field of ['runId','planId','generation','caseDigest'])assert.throws(()=>checkedNativeColdScope(current,{...cold,[field]:'foreign'}));
 for(const field of ['actualCaseExecutions','actualOutboxActions','transcriptEntries','privateKeyReads'])assert.throws(()=>checkedNativeColdScope(current,{...cold,[field]:1}));
 assert.throws(()=>checkedNativeColdScope(current,{...cold,definitionIdentity:{...cold.definitionIdentity,version:'functional-case-v1'}}));
});

test('native SAML landing login page still requires exact login form; auto-POST page submits no credential', async () => {
 const url=TARGET_ENTITY+'/protocol/saml';assert.equal(ownedLoginPageScope(url),true);
 assert.equal(ownedLoginPageScope(url.replace(':28080',':8180')),false);
 const mock=mockPage(url,{attributes:{'form#kc-form-login':{action:TARGET_ORIGIN+LOGIN_PATH+'?opaque=one',method:'post'}}});
 const handler=createOwnedLoginHandler(seed,{assertAllowed(){}});await handler.handle(mock.page);handler.assertHealthy();
 assert.equal(mock.clicks.length,1);
 const post=mockPage(url,{counts:{'#username':0,'#password':0}}),noLogin=createOwnedLoginHandler(seed,{assertAllowed(){}});
 await noLogin.handle(post.page);noLogin.assertHealthy();assert.equal(post.fills.length,0);
});

test('actual transcript Response projects only strict redacted Cookie and never retains raw or rejected bytes', async () => {
 const raw=JSON.stringify([{id:'tx_pure',runId:RUN,headers:{Cookie:['KC_SESSION=<redacted: 32 bytes>']},samlSummary:{type:'Response'}}]);
 let saved;const projected=await readOwnedTranscriptResponse(new Response(raw,{headers:{'Content-Type':'application/json'}}),RUN,async()=>{},async value=>{saved=value;});
 assert.equal('Cookie' in saved[0].headers,false);assert.equal(projected[0].id,'tx_pure');
 for(const invalid of [raw.replace('<redacted: 32 bytes>','raw-private'),raw.replace(RUN,'run_FOREIGN'),
 raw.replace('"Cookie":','"Cookie":null,"Cookie":'),raw.replace('Cookie','Authorization'),'<html>private</html>']){
 let retained=false;await assert.rejects(readOwnedTranscriptResponse(new Response(invalid,{headers:{'Content-Type':'application/json'}}),RUN,async()=>{},async()=>{retained=true;}));assert.equal(retained,false);
 }
});

test('missing API hashes remain supplemental until exact native physical8 join; foreign refs/actions/bytes reject', () => {
 const value=purePortableFixture();const pending=value.bindings.map(row=>({...row,transcriptReferences:[],bindingState:'original-captured-recorder-hash-unavailable'}));
 assert.equal(assertCaptureScope(setup(),Array(8),pending,true).recorderBindingsVerified,false);
 assert.throws(()=>assertCaptureScope(setup(),Array(8),pending));
 const joined=bindOwnedNativeOriginals(setup(),value.runtime,pending);
 assert.equal(checkedOwnedPortableOriginals(setup(),value.runtime,joined,value.outcome,seed).length,8);
 for(const mutate of [v=>{v.runtime.runId='run_FOREIGN';},v=>{v.runtime.transcriptOriginals[3].computedDecodedSha256='a'.repeat(64);},
 v=>{v.runtime.selectedActionPairs[1].actionId=v.runtime.selectedActionPairs[0].actionId;},v=>{v.runtime.transcriptOriginals[7].id=v.runtime.transcriptOriginals[6].id;},
 v=>{v.runtime.transcriptOriginals[3].decodedSamlBase64='invalid';}]){const v=purePortableFixture();mutate(v);assert.throws(()=>bindOwnedNativeOriginals(setup(),v.runtime,pending));}
 const duplicate=structuredClone(value.outcome);duplicate.requirements[0].cases[0].evidence[2]=duplicate.requirements[0].cases[0].evidence[1];
 assert.throws(()=>checkedOwnedPortableOriginals(setup(),value.runtime,joined,duplicate,seed),/central-evidence-mismatch/);
});
