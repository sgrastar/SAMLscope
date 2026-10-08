/** Browser-policy calibration only: real Chromium, owned synthetic Suite/IdP HTTP fixtures. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { validateTask, playwrightAdapter, collectSelected, bindProtocolOriginals } from './generic_browser_campaign.mjs';

const dependency = process.env.SAML_SCOPE_PLAYWRIGHT;
const RUN = 'run_0123456789ABCDEFGHJKMNPQRS', PLAN = 'plan_0123456789ABCDEFGHJKMNPQRS', CASE = 'IIP-SSO01-f-idp-01';
const action = index => `action_${index.toString(16).padStart(32, '0')}`;
const sha = raw => createHash('sha256').update(raw).digest('hex');
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`)));
const close = server => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); });
const body = async request => { const chunks = []; for await (const chunk of request) chunks.push(chunk); return Buffer.concat(chunks).toString(); };
const json = (response, value) => { response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value)); };
const html = (response, value, headers = {}) => { response.writeHead(200, { 'Content-Type': 'text/html', ...headers }); response.end(value); };
const form = (url, field, raw, submit = true) => `<form id="saml" method="post" action="${url}"><input name="${field}" value="${raw.toString('base64')}"></form>${submit ? '<script>document.querySelector("#saml").submit()</script>' : ''}`;

async function fixture({ delay = false, unrelated = false, passiveLogin = false } = {}) {
  let suiteOrigin, targetOrigin, adapter, fixtureFailure;
  let runStatus = 'CREATED', authnRequestId, resultReady = false, released = !delay, index = 0, cases = 0, outbox = 0, awaiting = false;
  const entries = [], wire = [], records = {}, originals = [], beforeM0 = [];
  const counts = { normalStartGets: 0, preflight: 0, emptyEvaluate: 0, testsStart: 0, cookieValuesExported: 0 };
  const current = () => cases === 0 ? { state: 'NOT_STARTED' } : index >= 4 ? { state: 'FINISHED' }
    : { state: awaiting ? 'AWAITING_RESPONSE' : 'READY', caseId: CASE, actionId: action(index), requiresFreshSession: index === 3,
      startUrl: `${suiteOrigin}/p/${PLAN}/probe/${action(index)}?run=${RUN}` };
  const add = (direction, raw, summary, correlationId) => entries.push({ id: `tx_fixture_${entries.length}`, runId: RUN, direction,
    url: `${suiteOrigin}/p/${PLAN}/sp/acs/0`, correlationId, decodedSamlBytes: raw.length,
    samlSummary: { ...summary, decodedSha256: sha(raw) } });
  const suite = createServer(async (request, response) => {
    try {
      const url = new URL(request.url, suiteOrigin);
      if (url.pathname === `/api/runs/${RUN}`) return json(response, { id: RUN, planId: PLAN, status: runStatus, context: authnRequestId ? { authnRequestId } : {} });
      if (url.pathname === `/api/plans/${PLAN}`) return json(response, { plan: { id: PLAN, profile: 'browser_sso_idp', target: { kind: 'IDP', entityId: targetOrigin + '/idp' } } });
      if (url.pathname.endsWith('/transcript')) return json(response, entries);
      if (url.pathname.endsWith('/campaigns')) return json(response, { runId: RUN, cases, classifications: [], campaigns: [] });
      if (url.pathname.endsWith('/protocol-evidence')) return json(response, { eligibleCases: 0, readyCases: 0, cases: [] });
      if (url.pathname.endsWith('/interactions')) return json(response, []);
      if (url.pathname.endsWith('/preflight')) {
        assert.equal(runStatus, 'CREATED'); counts.preflight++; runStatus = 'RUNNING';
        beforeM0.push({ cases, outbox, targetSamlSends: wire.length, transcriptEntries: entries.length });
        return json(response, { checks: [{ status: 'PASS' }] });
      }
      if (url.pathname.endsWith('/protocol-evidence/evaluate')) {
        if (cases === 0) {
          counts.emptyEvaluate++; resultReady = true;
          beforeM0.push({ cases, outbox, targetSamlSends: wire.length, transcriptEntries: entries.length });
        }
        return json(response, { completed: [], remaining: { eligibleCases: 0, readyCases: 0, cases: [] } });
      }
      if (url.pathname.endsWith('/result.json')) {
        assert.equal(resultReady, true);
        return json(response, { run: { id: RUN }, requirements: [{ cases: [{ id: CASE, outcome: 'NOT_VERIFIED' }] }] });
      }
      if (url.pathname.endsWith('/tests/start')) {
        assert.equal(runStatus, 'COMPLETED'); assert.equal(entries.some(entry => entry.samlSummary.normalFlowAccepted), true);
        counts.testsStart++; cases = 1; return json(response, { fullProfile: true });
      }
      if (url.pathname.endsWith('/active-probe')) return json(response, current());
      if (url.pathname.endsWith('/active-probe/browser-response')) {
        const fact = JSON.parse(await body(request)); assert.equal(fact.body, ''); assert.equal(fact.status, 200);
        index++; awaiting = false; return json(response, {});
      }
      if (url.pathname === `/p/${PLAN}/start/m0-roundtrip`) {
        assert.equal(url.searchParams.get('run'), RUN); assert.equal(runStatus, 'RUNNING');
        counts.normalStartGets++; beforeM0.push({ cases, outbox, targetSamlSends: wire.length, transcriptEntries: entries.length });
        assert.equal(authnRequestId, undefined); authnRequestId = '_m0'; runStatus = 'WAITING_BROWSER';
        const raw = Buffer.from('<AuthnRequest ID="_m0"/>');
        add('OUTBOUND', raw, { type: 'AuthnRequest', id: '_m0' }, '_m0');
        return html(response, form(targetOrigin + '/sso', 'SAMLRequest', raw));
      }
      if (url.pathname === `/p/${PLAN}/sp/acs/0`) {
        const values = new URLSearchParams(await body(request)); const raw = Buffer.from(values.get('SAMLResponse'), 'base64');
        if (raw.toString().includes('InResponseTo="_m0"')) {
          runStatus = 'COMPLETED';
          add('INBOUND', raw, { type: 'Response', normalFlowAccepted: true,
            statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success', issuer: targetOrigin + '/idp',
            destination: `${suiteOrigin}/p/${PLAN}/sp/acs/0`, inResponseTo: unrelated ? '_foreign' : '_m0' }, '_m0');
        } else { add('INBOUND', raw, { scenario_case_id: CASE }, '_' + action(index)); index++; awaiting = false; }
        return html(response, '<h1>SAML Response recorded</h1>');
      }
      if (url.pathname === `/p/${PLAN}/probe/${action(index)}`) {
        if (request.method === 'GET') return html(response, `<form method="post">${index === 3 ? '<input type="checkbox" name="freshSessionConfirmed" value="true">' : ''}<button>Continue with this request</button></form>`);
        if (index === 3) assert.equal(new URLSearchParams(await body(request)).get('freshSessionConfirmed'), 'true');
        outbox++; awaiting = true; const raw = Buffer.from(`<AuthnRequest ID="_${action(index)}"/>`);
        add('OUTBOUND', raw, { scenario_case_id: CASE }, action(index));
        return html(response, form(targetOrigin + '/sso', 'SAMLRequest', raw));
      }
      response.writeHead(404); response.end();
    } catch (error) { fixtureFailure = error; response.writeHead(500); response.end(); }
  });
  const target = createServer(async (request, response) => {
    try {
      if (request.url === '/wait') return json(response, { released });
      const values = new URLSearchParams(await body(request)); const raw = Buffer.from(values.get('SAMLRequest'), 'base64');
      const normal = raw.toString().includes('ID="_m0"');
      wire.push({ normal, cookiePresent: (request.headers.cookie ?? '').includes('owned-context=yes'), fresh: !normal && index === 3 });
      if (!normal && index === 3 && passiveLogin) return html(response, '<input type="password"><p>private login sentinel</p>');
      const reply = Buffer.from(`<Response InResponseTo="${normal ? '_m0' : '_' + action(index)}"/>`);
      const deferred = normal && delay;
      return html(response, form(`${suiteOrigin}/p/${PLAN}/sp/acs/0`, 'SAMLResponse', reply, !deferred)
        + (deferred ? '<p>M0 SSO round trip completed</p><script>const t=setInterval(async()=>{if((await (await fetch("/wait")).json()).released){clearInterval(t);document.querySelector("#saml").submit()}},100)</script>' : ''),
      normal ? { 'Set-Cookie': 'owned-context=yes; HttpOnly; Path=/' } : {});
    } catch (error) { fixtureFailure = error; response.writeHead(500); response.end(); }
  });
  suiteOrigin = await listen(suite); targetOrigin = await listen(target);
  const { chromium } = createRequire(import.meta.url)(dependency);
  const task = validateTask({ suiteBaseUrl: suiteOrigin, targetOrigins: [targetOrigin], runId: RUN, planId: PLAN,
    caseIds: [CASE], outputDirectory: '/private/tmp/synthetic-normal-browser-policy', startTests: true,
    completeNormalFlow: true, actionTimeoutSeconds: delay ? 1 : 5 });
  try {
    adapter = await playwrightAdapter(task, { launch: options => chromium.launch({ ...options, headless: true }) }, async () => {}, originals);
  } catch (error) { await close(suite); await close(target); throw error; }
  return { task, adapter, counts, originals, records, entries, wire, beforeM0,
    record: async (name, value) => { records[name] = structuredClone(value); },
    release: () => { released = true; }, check: () => { if (fixtureFailure) throw fixtureFailure; },
    close: async () => { const closed = await adapter.close('explicit-synthetic-test-stop'); await close(suite); await close(target); return closed; } };
}

test('cold real-browser M0 establishes the primary session, then three same-context actions and empty passive isolation',
  { skip: !dependency, timeout: 60000 }, async () => {
    const f = await fixture({ passiveLogin: true });
    try {
      const result = await collectSelected(f.task, f.adapter.api, f.adapter, f.record); f.check();
      assert.deepEqual(f.beforeM0, Array(3).fill({ cases: 0, outbox: 0, targetSamlSends: 0, transcriptEntries: 0 }));
      assert.deepEqual(f.wire.map(row => row.cookiePresent), [false, true, true, true, false]);
      assert.equal(result.counts.normalLoginContexts, 1); assert.equal(result.counts.initialNormalFlowSubmissions, 1);
      assert.equal(result.counts.authenticatedContextReuses, 3); assert.equal(result.counts.freshEmptyContexts, 1);
      assert.equal(result.counts.passiveAuthenticationLandingsWithBodyOmitted, 1);
      assert.equal(f.counts.normalStartGets, 1); assert.equal(f.counts.testsStart, 1);
      assert.equal(f.originals.filter(row => row.record.operationKind === 'M0_NORMAL').length, 2);
      assert.equal(f.originals.filter(row => row.record.operationKind === 'M0_NORMAL').every(row => !('caseId' in row.record) && !('actionId' in row.record)), true);
      const manifest = bindProtocolOriginals(f.task, f.originals, f.entries, f.records['m0-guard.json']);
      assert.equal(manifest.filter(row => row.operationKind === 'M0_NORMAL').every(row => row.bindingState === 'recorder-hash-and-normal-flow-bound'), true);
      assert.equal(JSON.stringify({ records: f.records, manifest }).includes('owned-context=yes'), false);
      assert.equal(JSON.stringify(f.records).includes('private login sentinel'), false);
    } finally { assert.equal((await f.close()).browserContextsClosed, true); }
  });

test('timeout ignores a success-looking HTML marker, retains the actual page, and poll-only resume reuses its cookie',
  { skip: !dependency, timeout: 60000 }, async () => {
    const f = await fixture({ delay: true });
    try {
      const pending = await collectSelected(f.task, f.adapter.api, f.adapter, f.record);
      assert.equal(pending.collectionState, 'WAITING_M0'); assert.equal(pending.pendingNormalFlow.authnRequestId, '_m0');
      assert.equal(pending.pendingNormalFlow.browserPageRetained, true); assert.equal(f.counts.testsStart, 0);
      assert.equal(f.wire.length, 1); assert.equal(f.counts.normalStartGets, 1);
      const timer = setTimeout(f.release, 200);
      const resumed = await collectSelected(f.task, f.adapter.api, f.adapter, f.record); clearTimeout(timer); f.check();
      assert.equal(resumed.collectionState, 'COLLECTED'); assert.equal(resumed.counts.normalPollOnlyResumes, 1);
      assert.equal(resumed.counts.initialNormalFlowSubmissions, 0); assert.equal(f.counts.normalStartGets, 1);
      assert.equal(f.counts.preflight, 1); assert.equal(f.counts.emptyEvaluate, 1);
      assert.deepEqual(f.wire.map(row => row.cookiePresent), [false, true, true, true, false]);
    } finally { await f.close(); }
  });

test('actual Completed status with unrelated Recorder Response fails the retained strong M0 gate before cases',
  { skip: !dependency, timeout: 60000 }, async () => {
    const f = await fixture({ unrelated: true });
    try {
      await assert.rejects(collectSelected(f.task, f.adapter.api, f.adapter, f.record), /normal SSO control is missing/);
      f.check(); assert.equal(f.counts.testsStart, 0); assert.equal(f.wire.length, 1);
    } finally { await f.close(); }
  });

for (const command of ['resume', 'stop']) test(`CLI timeout retains its live process and ${command} preserves the M0 request identity`,
  { skip: !dependency, timeout: 60000 }, async () => {
    const f = await fixture({ delay: true });
    const directory = await mkdtemp(resolve(tmpdir(), 'samlscope-normal-cli-'));
    let child;
    try {
      await f.adapter.close('unused-empty-fixture-adapter');
      const taskFile = resolve(directory, 'task.json'), outputDirectory = resolve(directory, 'evidence');
      await writeFile(taskFile, JSON.stringify({ ...f.task, outputDirectory }));
      child = spawn(process.execPath, [resolve('dev/reference-acceptance/generic_browser_campaign.mjs'), taskFile],
        { env: { ...process.env, SAML_SCOPE_PLAYWRIGHT: dependency }, stdio: ['pipe', 'pipe', 'pipe'] });
      let stderr = '';
      child.stderr.on('data', chunk => { stderr += chunk.toString(); });
      const exited = new Promise(resolve => child.once('exit', (code, signal) => resolve({ code, signal })));
      const deadline = Date.now() + 15000;
      while (!stderr.includes('M0 retained:') && Date.now() < deadline && child.exitCode === null) await new Promise(done => setTimeout(done, 50));
      assert.equal(stderr.includes(`M0 retained: ${RUN} _m0`), true);
      assert.equal(child.exitCode, null); assert.equal(f.counts.normalStartGets, 1); assert.equal(f.counts.testsStart, 0);
      const handle = JSON.parse(await readFile(resolve(outputDirectory, 'live-normal-flow.json')));
      assert.equal(handle.processRetained, true); assert.equal(handle.browserPageRetained, true);
      if (command === 'resume') setTimeout(f.release, 200);
      child.stdin.write(command + '\n');
      const ended = await Promise.race([exited, new Promise((_, reject) => setTimeout(() => reject(new Error('Owned CLI did not exit')), 15000).unref())]);
      assert.equal(ended.code, 0); assert.equal(ended.signal, null); f.check();
      const completion = JSON.parse(await readFile(resolve(outputDirectory, 'collector-completion.json')));
      assert.equal(completion.browserContextsClosed, true); assert.equal(completion.existingSuiteM0AbortedOrRestarted, false);
      assert.equal(completion.explicitlyStopped, command === 'stop');
      assert.equal(f.counts.normalStartGets, 1); assert.equal(f.counts.preflight, 1); assert.equal(f.counts.emptyEvaluate, 1);
      if (command === 'stop') { assert.equal(f.counts.testsStart, 0); assert.equal(f.wire.length, 1); }
      else {
        assert.deepEqual(f.wire.map(row => row.cookiePresent), [false, true, true, true, false]);
        const counts = JSON.parse(await readFile(resolve(outputDirectory, 'campaign-operation-counts.json')));
        assert.equal(counts.normalLoginContexts, 1); assert.equal(counts.normalPollOnlyResumes, 1);
        assert.equal(counts.actualHumanLoginCountMeasured, false);
      }
      assert.equal(stderr.includes('owned-context=yes'), false);
    } finally {
      if (child && child.exitCode === null) child.kill('SIGTERM');
      await f.close(); await rm(directory, { recursive: true, force: true });
    }
  });
