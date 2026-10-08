import test from 'node:test';
import assert from 'node:assert/strict';
import { deflateRawSync } from 'node:zlib';
import { validateTask, probeUrl, sessionPolicy, validateMembership, validateM0Guard,
  samlMessage, bindProtocolOriginals, collectSelected } from './generic_browser_campaign.mjs';

const RUN = 'run_0123456789ABCDEFGHJKMNPQRS';
const PLAN = 'plan_0123456789ABCDEFGHJKMNPQRS';
const CASE = 'IIP-SSO01-f-idp-01';
const OTHER = 'IIP-IDP12-d-idp-01';
const action = number => `action_${number.toString(16).padStart(32, '0')}`;
const task = overrides => validateTask({ suiteBaseUrl: 'https://suite.example', runId: RUN, planId: PLAN,
  targetOrigins: ['https://idp.example'], caseIds: [CASE], outputDirectory: '/private/tmp/generic-browser-test', ...overrides });
const ready = (number, id = CASE, fresh = false) => ({ state: 'READY', caseId: id, actionId: action(number),
  startUrl: `https://suite.example/p/${PLAN}/probe/${action(number)}?run=${RUN}`, requiresFreshSession: fresh });
const run = { id: RUN, planId: PLAN, status: 'COMPLETED' };
const plan = { plan: { id: PLAN, profile: 'browser_sso_idp', target: { kind: 'IDP', entityId: 'https://idp.example/idp' } } };
const result = { run: { id: RUN }, requirements: [{ cases: [{ id: CASE }, { id: OTHER }] }] };
const m0 = [{ id: 'tx_m0_request', runId: RUN, direction: 'OUTBOUND', samlSummary: { type: 'AuthnRequest', id: '_m0' } },
  { id: 'tx_m0_response', runId: RUN, direction: 'INBOUND', correlationId: '_m0',
    url: `https://suite.example/p/${PLAN}/sp/acs/0`, samlSummary: { normalFlowAccepted: true, type: 'Response',
      statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success', issuer: 'https://idp.example/idp',
      destination: `https://suite.example/p/${PLAN}/sp/acs/0`, inResponseTo: '_m0' } }];

test('task accepts remote IdP origins and rejects credential fields, malformed identifiers and transport credentials', () => {
  assert.equal(task().targetOrigins[0], 'https://idp.example');
  for (const overrides of [{ password: 'never-store' }, { cookies: [] }, { runId: 'other' },
    { suiteBaseUrl: 'https://user:password@suite.example' }, { caseIds: [CASE, CASE] },
    { targetOrigins: ['https://suite.example'] }, { targetOrigins: ['https://idp.example/login'] },
    { startTests: 'true' }, { maxActions: 0 }]) assert.throws(() => task(overrides));
});

test('one-use probe URL requires the exact Run, Plan and action, and never accepts a target URL', () => {
  assert.equal(probeUrl(task(), ready(1)), ready(1).startUrl);
  for (const override of [{ startUrl: 'https://idp.example/login' }, { actionId: action(2) },
    { startUrl: ready(1).startUrl + '&run=run_OTHER' }, { startUrl: ready(1).startUrl + '#fragment' },
    { startUrl: ready(1).startUrl.replace(PLAN, 'plan_OTHER') }, { state: 'AWAITING_RESPONSE' }]) {
    assert.throws(() => probeUrl(task(), { ...ready(1), ...override }));
  }
});

test('session reuse requires explicit false; passive uses a new empty context', () => {
  assert.equal(sessionPolicy(ready(1)), 'authenticated-context');
  assert.equal(sessionPolicy(ready(1, CASE, true)), 'fresh-empty-context');
  for (const invalid of [null, 'false', 0, undefined]) assert.throws(() => sessionPolicy({ requiresFreshSession: invalid }));
});

test('actual Run membership is required before any Suite or target mutation; tests/start is explicitly full-profile', () => {
  const membership = validateMembership(task(), run, plan, result);
  assert.equal(membership.selectedTestsApiExists, false);
  assert.equal(membership.startTestsScope, 'full-approved-profile');
  assert.throws(() => validateMembership(task(), { ...run, planId: 'plan_other' }, plan, result));
  assert.throws(() => validateMembership(task(), run, plan, { ...result, run: { id: 'run_other' } }));
  assert.throws(() => validateMembership(task(), run, plan, { ...result, requirements: [{ cases: [] }] }));
  assert.throws(() => validateMembership(task(), run, { plan: { ...plan.plan, profile: 'metadata_idp' } }, result));
  assert.throws(() => validateMembership(task(), run, plan, { ...result, requirements: [{ cases: [{ id: CASE }, { id: CASE }] }] }));
});

test('tests/start requires an accepted correlated M0 response; RUNNING or an unrelated Success is insufficient', () => {
  assert.equal(validateM0Guard(task(), run, plan, m0).acceptedNormalFlowReferences.length, 1);
  assert.throws(() => validateM0Guard(task(), { ...run, status: 'RUNNING' }, plan, m0));
  assert.throws(() => validateM0Guard(task(), run, plan, []));
  assert.throws(() => validateM0Guard(task(), run, plan, [m0[1]]));
  assert.throws(() => validateM0Guard(task(), run, plan, [m0[0], { ...m0[1], runId: 'run_other' }]));
  assert.throws(() => validateM0Guard(task(), run, plan, [m0[0], { ...m0[1], correlationId: '_other' }]));
});

function fakeRequest(url, method = 'GET', body = null) {
  return { url: () => url, method: () => method, postData: () => body,
    headers: () => ({ 'content-type': 'application/x-www-form-urlencoded', cookie: 'never-export', authorization: 'never-export' }) };
}

test('capture retains original POST and Redirect SAML bytes without raw query, cookies or authorization', () => {
  const raw = Buffer.from('<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>');
  const post = samlMessage(task(), fakeRequest('https://idp.example/sso', 'POST',
    new URLSearchParams({ SAMLRequest: raw.toString('base64'), RelayState: 'opaque-state' }).toString()), ready(1));
  assert.deepEqual(post.bytes, raw);
  assert.equal(post.record.actionId, action(1));
  assert.equal(post.record.endpoint, 'https://idp.example/sso');
  assert.equal(JSON.stringify(post.record).includes('never-export'), false);
  const redirect = samlMessage(task(), fakeRequest('https://idp.example/sso?' + new URLSearchParams({
    SAMLRequest: deflateRawSync(raw).toString('base64'), Signature: 'public-signature', RelayState: 'opaque-state' })), ready(1));
  assert.deepEqual(redirect.bytes, raw);
  assert.equal(redirect.record.binding, 'HTTP-Redirect');
  assert.equal(JSON.stringify(redirect.record).includes('opaque-state'), false);
});

test('credential submissions, unrelated origins, another peer and duplicate SAML fields are never protocol evidence', () => {
  const raw = Buffer.from('<Response/>').toString('base64');
  for (const request of [
    fakeRequest('https://idp.example/login', 'POST', 'username=user&password=never-export'),
    fakeRequest('https://other.example/sso?SAMLRequest=' + raw),
    fakeRequest('https://suite.example/p/plan_OTHER/sp/acs/0', 'POST', 'SAMLResponse=' + encodeURIComponent(raw)),
    fakeRequest(`https://suite.example/p/${PLAN}/sp/acs/0`, 'POST', 'SAMLResponse=' + raw + '&SAMLResponse=' + raw),
  ]) assert.equal(samlMessage(task(), request, ready(1)), null);
  assert.equal(samlMessage(task(), fakeRequest('https://idp.example/sso?SAMLRequest=' + raw), null), null);
});

test('captured originals are not promoted without a unique Recorder hash, correct action and same Run', () => {
  const captured = { record: { runId: RUN, direction: 'OUTBOUND', caseId: CASE, actionId: action(1), bytes: 5, sha256: 'digest' }, file: '1.xml' };
  const entry = { id: 'tx_one', runId: RUN, direction: 'OUTBOUND', correlationId: action(1), decodedSamlBytes: 5,
    samlSummary: { scenario_case_id: CASE, decodedSha256: 'digest' } };
  assert.equal(bindProtocolOriginals(task(), [captured], [entry])[0].bindingState, 'recorder-hash-and-action-bound');
  for (const changed of [{ ...entry, samlSummary: {} }, { ...entry, correlationId: action(2) },
    { ...entry, samlSummary: { ...entry.samlSummary, scenario_case_id: OTHER } }]) {
    assert.equal(bindProtocolOriginals(task(), [captured], [changed])[0].bindingState, 'original-captured-recorder-hash-unavailable');
  }
  assert.throws(() => bindProtocolOriginals(task(), [captured], [{ ...entry, runId: 'run_other' }]));
  assert.throws(() => bindProtocolOriginals(task(), [captured], [entry, entry]));
});

function fakeCampaign(sequence, { badMembership = false, abortNeverAdvances = false, probeConclusive = true } = {}) {
  let index = 0;
  let current = { ...sequence[0] };
  const calls = [];
  const records = {};
  const operations = [];
  const advance = () => { index++; current = sequence[index] ? { ...sequence[index] } : { state: 'NONE' }; };
  const api = async (path, body) => {
    calls.push({ path, mutation: body !== undefined });
    if (path === `/api/runs/${RUN}`) return run;
    if (path === `/api/plans/${PLAN}`) return plan;
    if (path.endsWith('/result.json')) return badMembership ? { ...result, requirements: [{ cases: [] }] } : result;
    if (path.endsWith('/transcript')) return m0;
    if (path.endsWith('/active-probe')) return { ...current };
    if (path.endsWith('/abort')) { if (abortNeverAdvances) current.state = 'READY'; else advance(); return {}; }
    if (path.endsWith('/browser-response')) { advance(); return {}; }
    if (path.endsWith('/evaluate')) return { noVerdictAssignedByCollector: true };
    if (path.endsWith('/tests/start')) return { scope: 'full-profile' };
    throw new Error('Unknown fake API path');
  };
  const browser = {
    async prepareWithoutTarget(currentTask, status) { operations.push({ operation: 'prepare', action: status.actionId, targetSubmitted: false }); current.state = 'AWAITING_RESPONSE'; },
    async probe(currentTask, status, policy) {
      operations.push({ operation: 'probe', action: status.actionId, policy });
      if (probeConclusive) advance(); else current.state = 'AWAITING_RESPONSE';
      return { recorded: probeConclusive, manualAuthenticationCheckpoints: index === 1 ? 1 : 0,
        ...(probeConclusive ? {} : { reason: 'target-http-error-without-saml', httpStatus: 500,
          observedTerminalUrl: 'https://idp.example/error', responseBodyExported: false }) };
    },
    async normalFlow() { return { recorded: true, manualAuthenticationCheckpoints: 1 }; },
  };
  return { api, browser, calls, records, operations, record: async (name, value) => { records[name] = structuredClone(value); } };
}

test('complete SSO01.f chain preserves all four target operations and its final fresh boundary', async () => {
  const fake = fakeCampaign([ready(1), ready(2), ready(3), ready(4, CASE, true), ready(5, OTHER)]);
  const collected = await collectSelected(task({ startTests: true }), fake.api, fake.browser, fake.record);
  assert.equal(collected.counts.selectedTargetActions, 4);
  assert.equal(collected.counts.authenticatedContextReuses, 3);
  assert.equal(collected.counts.freshEmptyContexts, 1);
  assert.equal(collected.counts.fullProfileStartCalls, 1);
  assert.equal(fake.operations.length, 4);
  assert.equal(fake.records['operation-counts.json'].verdictAdopted, false);
  assert.equal(fake.records['operation-counts.json'].restorationRequired, false);
  assert.equal(fake.calls.some(call => call.path.endsWith('/browser-response')), false);
});

test('unselected actions are prepared at the Suite and aborted without target navigation', async () => {
  const fake = fakeCampaign([ready(1, OTHER), ready(2), ready(3)]);
  const collected = await collectSelected(task({ maxActions: 2 }), fake.api, fake.browser, fake.record);
  assert.equal(collected.counts.skippedBeforeTargetSubmission, 1);
  assert.equal(collected.counts.selectedTargetActions, 1);
  assert.equal(fake.operations[0].targetSubmitted, false);
  assert.equal(fake.operations.filter(operation => operation.operation === 'probe').length, 1);
});

test('a measured target HTTP error is recorded with body omitted and never sent as a fabricated SAML Status', async () => {
  const fake = fakeCampaign([ready(1)], { probeConclusive: false });
  const collected = await collectSelected(task(), fake.api, fake.browser, fake.record);
  assert.equal(collected.steps[0].observation.httpStatus, 500);
  assert.equal(fake.calls.filter(call => call.path.endsWith('/abort')).length, 0);
  assert.equal(fake.calls.filter(call => call.path.endsWith('/browser-response')).length, 1);
  assert.equal(collected.counts.terminalHttpObservationsWithBodyOmitted, 1);
  assert.equal(collected.counts.conclusionAssignments, 0);
});

test('generic network exceptions cannot manufacture HTTP500 or cut a live action off automatically', async () => {
  const fake = fakeCampaign([ready(1)]);
  fake.browser.probe = async () => { throw new Error('Network failure'); };
  await assert.rejects(collectSelected(task(), fake.api, fake.browser, fake.record), /Network failure/);
  assert.equal(fake.calls.some(call => call.path.endsWith('/abort') || call.path.endsWith('/browser-response')), false);
  assert.equal(fake.records['operation-counts.json'].selectedBrowserDispatchAttempts, 1);
  assert.equal(fake.records['operation-counts.json'].terminalHttpObservationsWithBodyOmitted, 0);
});

test('passive authentication HTML is omitted and its measured HTTP200 does not fabricate a SAML error', async () => {
  const fake = fakeCampaign([ready(1, CASE, true)]);
  fake.browser.probe = async () => ({ recorded: false, reason: 'passive-request-required-authentication',
    httpStatus: 200, observedTerminalUrl: 'https://idp.example/login', responseBodyExported: false,
    manualAuthenticationCheckpoints: 0 });
  const originalApi = fake.api;
  let firstStatus = true;
  fake.api = async (path, body) => {
    const result = await originalApi(path, body);
    if (path.endsWith('/active-probe')) {
      if (firstStatus) { firstStatus = false; return result; }
      if (result.actionId === action(1)) return { ...result, state: 'AWAITING_RESPONSE' };
    }
    return result;
  };
  const collected = await collectSelected(task(), fake.api, fake.browser, fake.record);
  assert.equal(collected.counts.passiveAuthenticationLandingsWithBodyOmitted, 1);
  assert.equal(collected.counts.terminalHttpObservationsWithBodyOmitted, 0);
  assert.equal(collected.counts.automatedCredentialPosts, 0);
  assert.equal(collected.counts.conclusionAssignments, 0);
});

test('missing Run membership rejects before tests/start, baseline login or target navigation', async () => {
  const fake = fakeCampaign([ready(1)], { badMembership: true });
  await assert.rejects(collectSelected(task({ startTests: true, initialNormalFlow: true }), fake.api, fake.browser, fake.record));
  assert.equal(fake.calls.some(call => call.mutation), false);
  assert.equal(fake.operations.length, 0);
});

test('a live AWAITING_RESPONSE action is left untouched rather than aborted or restarted', async () => {
  const fake = fakeCampaign([{ ...ready(1), state: 'AWAITING_RESPONSE' }]);
  const collected = await collectSelected(task(), fake.api, fake.browser, fake.record);
  assert.equal(collected.counts.selectedTargetActions, 0);
  assert.equal(fake.calls.some(call => call.path.endsWith('/abort') || call.path.endsWith('/retry')), false);
  assert.equal(fake.calls.some(call => call.path.endsWith('/evaluate')), false);
  assert.equal(collected.collectionState, 'AWAITING_RESPONSE');
  assert.equal(collected.pendingAction.actionId, action(1));
});

test('observation timeout preserves the same live handle and never advances to another target action', async () => {
  const fake = fakeCampaign([ready(1), ready(2)], { probeConclusive: false });
  const originalProbe = fake.browser.probe;
  fake.browser.probe = async (...args) => {
    await originalProbe(...args);
    return { recorded: false, reason: 'observation-timeout', manualAuthenticationCheckpoints: 1 };
  };
  const collected = await collectSelected(task(), fake.api, fake.browser, fake.record);
  assert.equal(collected.collectionState, 'AWAITING_RESPONSE');
  assert.deepEqual(collected.pendingAction, { state: 'AWAITING_RESPONSE', caseId: CASE, actionId: action(1) });
  assert.equal(fake.operations.length, 1);
  assert.equal(collected.counts.liveActionsRetained, 1);
  assert.equal(fake.records['evaluation.json'].performed, false);
  assert.equal(fake.calls.some(call => ['/abort', '/retry', '/evaluate', '/browser-response']
    .some(suffix => call.path.endsWith(suffix))), false);
});

test('repeated one-use action fails closed and preserves counts without replay', async () => {
  const fake = fakeCampaign([ready(1, OTHER)], { abortNeverAdvances: true });
  await assert.rejects(collectSelected(task(), fake.api, fake.browser, fake.record), /one-use action/);
  assert.equal(fake.operations.length, 1);
  assert.equal(fake.records['operation-counts.json'].skippedBeforeTargetSubmission, 1);
});
