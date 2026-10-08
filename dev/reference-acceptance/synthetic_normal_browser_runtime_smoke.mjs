#!/usr/bin/env node
/** Owned actual-Suite cold-M0 smoke only; no M1 case start or product adoption. */
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { mkdir, writeFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { validateTask, playwrightAdapter, collectSelected, bindProtocolOriginals, publicJson } from './generic_browser_campaign.mjs';
import { fetchStatus, readPublicResponse } from './synthetic_normal_browser_http.mjs';

if (![4, 6].includes(process.argv.length) || process.argv[2] !== '--execute'
    || (process.argv.length === 6 && process.argv[4] !== '--existing-created')) throw new Error('Explicit --execute, fresh output directory and optional public --existing-created required');
const output = resolve(process.argv[3]); await mkdir(output, { recursive: false });
const suite = 'http://localhost:18080', upstream = 'http://127.0.0.1:18936', target = 'http://127.0.0.1:18939';
const publicMetadata = 'http://host.docker.internal:18939/metadata/match';
const hashes = Object.fromEntries(await Promise.all(['generic_browser_campaign.mjs', 'synthetic_normal_browser_runtime_smoke.mjs', 'synthetic_normal_browser_http.mjs', 'SyntheticAdditionalMetadataFixture.java', 'ReadSyntheticNormalBrowserScope.java', 'ReadSyntheticArtifactRuntime.java'].map(async name => [name, createHash('sha256').update(await readFile(resolve('dev/reference-acceptance', name))).digest('hex')])));
const record = async (name, value) => writeFile(resolve(output, name), JSON.stringify(publicJson(value), null, 2) + '\n', { flag: 'wx' });
const fixture = spawn('/opt/homebrew/opt/openjdk@21/bin/java', ['-cp', 'build/synthetic-additional-fixture:api/build/install/samlscope/lib/*',
  'com.samlscope.api.SyntheticAdditionalMetadataFixture', '--serve', '18936', suite, 'host.docker.internal'], { stdio: ['ignore', 'pipe', 'pipe'] });
const fixtureExited = new Promise(resolve => fixture.once('exit', (code, signal) => resolve({ code, signal })));
let ready = false, adapter, server, failure, publicRun = null, helperInstalled = false;
const helper = '/tmp/samlscope-synthetic-normal-browser-r1', container = 'samlscope-reference-suite';
fixture.stdout.on('data', bytes => { if (bytes.toString().includes('Synthetic fixture listening')) ready = true; });
fixture.stderr.resume(); // no raw diagnostic or HTML persistence
const counts = { suiteApiRequests: 0, productCredentialPosts: 0, productSettingWrites: 0, caseStartCalls: 0,
  fixtureMetadataGets: 0, fixtureNormalTargetGets: 0, fixtureCookiePresenceCount: 0, credentialValuesPersisted: 0 };
Object.assign(counts, { suiteDockerExecAttempts: 0, suiteDockerExecSuccesses: 0, helperCopyAttempts: 0, helperCopySuccesses: 0,
  helperRemovalAttempts: 0, helperRemovalSuccesses: 0 });
const docker = async args => {
  const kind = args[0] === 'exec' ? 'suiteDockerExec' : 'helperCopy'; counts[kind + 'Attempts']++;
  try { const result = await promisify(execFile)('docker', args, { maxBuffer: 8 * 1024 * 1024 }); counts[kind + 'Successes']++; return result.stdout; }
  catch { throw new Error('Owned helper operation failed'); }
};
const native = async mode => publicJson(JSON.parse(await docker(['exec', container, 'java', '-cp', helper + '/classes:/opt/samlscope/lib/*',
  'com.samlscope.api.ReadSyntheticNormalBrowserScope', '/data', publicRun.runId, mode, helper + '/suite-public-metadata.xml'])));
try {
  const until = Date.now() + 10000;
  while (!ready && fixture.exitCode === null && Date.now() < until) await new Promise(done => setTimeout(done, 50));
  if (!ready) throw new Error('Owned signing fixture did not start');
  server = createServer(async (request, response) => {
    try {
      const path = new URL(request.url, target).pathname;
      if (request.method !== 'GET' || !['/metadata/match', '/sso'].includes(path)) { response.writeHead(404); response.end(); return; }
      // The exact Redirect query is forwarded without decoding/reconstruction.
      const received = await fetch(upstream + request.url, { redirect: 'manual', signal: AbortSignal.timeout(30000) });
      const raw = await received.text();
      const status = fetchStatus(received).status;
      if (status !== 200) { response.writeHead(status); response.end(); return; }
      if (path === '/metadata/match') {
        counts.fixtureMetadataGets++;
        response.writeHead(200, { 'Content-Type': 'application/samlmetadata+xml' });
        response.end(raw.replace("Location='http://host.docker.internal:18936/sso'", `Location='${target}/sso'`));
      } else {
        counts.fixtureNormalTargetGets++;
        if (request.headers.cookie) counts.fixtureCookiePresenceCount++; // values are never exported or forwarded
        if (!raw.includes("name='SAMLResponse'") || !raw.includes("name='RelayState'") || /name=['"](?:password|token|username)/i.test(raw)) throw new Error('Non-public fixture form rejected');
        response.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': 'owned-normal-fixture=yes; HttpOnly; Path=/' });
        response.end(raw + '<script>document.querySelector("form").submit()</script>');
      }
    } catch { response.writeHead(500); response.end(); }
  });
  await new Promise((done, reject) => { server.once('error', reject); server.listen(18939, '0.0.0.0', done); });
  const api = async (path, body) => {
    counts.suiteApiRequests++;
    const response = await fetch(suite + path, { method: body === undefined ? 'GET' : 'POST',
      ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }), redirect: 'manual', signal: AbortSignal.timeout(30000) });
    const prefix = `api-${String(counts.suiteApiRequests).padStart(4, '0')}`;
    return readPublicResponse(response,
      facts => record(prefix + '-status.json', { path, method: body === undefined ? 'GET' : 'POST', ...facts }),
      raw => writeFile(resolve(output, prefix + '-response.body'), raw, { flag: 'wx' }));
  };
  const input = { name: 'Synthetic normal browser cold M0; no adoption', profile: 'browser_sso_idp', targetKind: 'IDP',
    targetEntityId: 'http://host.docker.internal:18936/entity', metadataSourceKind: 'URL', metadataSourceLocation: publicMetadata,
    suiteMetadataDelivery: 'MANUAL', declaredFeatures: {}, parameters: { clockSkewToleranceSeconds: 180, metadataRefreshWaitSeconds: 300,
      testUserHint: 'synthetic-public-principal', requestSigningMode: 'REQUIRED' },
    interaction: { allowBrowserSteps: true, allowAttestation: false, preset: 'assisted' }, authorizedTarget: true };
  await record('plan-input.json', input);
  let prior;
  if (process.argv[5]) {
    const bytes = await readFile(resolve(process.argv[5])); if (bytes.length > 1024 * 1024) throw new Error('Oversized public creation record');
    prior = publicJson(JSON.parse(bytes.toString()));
    if (JSON.stringify(prior.input) !== JSON.stringify(input)) throw new Error('Existing synthetic creation scope differs');
  }
  const created = prior?.created ?? await api('/api/plans', input);
  await record('plan-created.json', created);
  const planId = created.plan.plan.id;
  const runCreated = prior?.runCreated ?? await api(`/api/plans/${planId}/runs`, {}), runId = runCreated.run.id;
  publicRun = { runId, planId };
  await record('created.json', { input, created, runCreated });
  const task = validateTask({ suiteBaseUrl: suite, targetOrigins: [target], runId, planId, caseIds: ['IIP-SSO01-f-idp-01'],
    completeNormalFlow: true, startTests: false, maxActions: 1, actionTimeoutSeconds: 15, outputDirectory: output });
  await record('task.json', task);
  if (prior) {
    const live = await api(`/api/runs/${runId}`), current = live.run ?? live;
    if (current.id !== runId || current.planId !== planId || current.status !== 'CREATED' || current.context?.authnRequestId != null) throw new Error('Existing Run is not untouched cold scope');
    await record('existing-cold-run.json', { runId, planId, status: current.status, newPlanCreations: 0, newRunCreations: 0 });
  }
  const metadata = await fetch(`${suite}/p/${planId}/metadata`, { signal: AbortSignal.timeout(30000) }); if (!fetchStatus(metadata).ok) throw new Error('Public Suite metadata unavailable');
  await writeFile(resolve(output, 'suite-public-metadata.xml'), Buffer.from(await metadata.arrayBuffer()), { flag: 'wx' });
  await docker(['exec', container, 'test', '!', '-e', helper]);
  await docker(['exec', container, 'mkdir', helper]); helperInstalled = true;
  await docker(['cp', resolve('build/synthetic-normal-browser-scope'), container + ':' + helper + '/classes']);
  await docker(['cp', resolve(output, 'suite-public-metadata.xml'), container + ':' + helper + '/suite-public-metadata.xml']);
  await record('native-before-preflight.json', await native('scope'));
  const dependency = process.env.SAML_SCOPE_PLAYWRIGHT;
  if (!dependency?.startsWith('/')) throw new Error('Installed absolute Playwright path required');
  const { chromium } = createRequire(import.meta.url)(dependency), originals = [];
  adapter = await playwrightAdapter(task, chromium, record, originals);
  const operations = new Map();
  const recorded = async (name, value) => {
    operations.set(name, value);
    if (name === 'normal-scope-after-empty-evaluation.json') await record('native-after-empty-evaluation.json', await native('scope'));
  };
  const countedApi = async (path, body) => { counts.suiteApiRequests++; return adapter.api(path, body); };
  const collected = await collectSelected(task, countedApi, adapter, recorded);
  for (const [name, value] of operations) await record(name, value);
  const transcript = await countedApi(`/api/runs/${runId}/transcript`);
  await record('transcript.json', transcript);
  await record('result.json', await countedApi(`/api/runs/${runId}/result.json`));
  await mkdir(resolve(output, 'browser-saml-originals'));
  for (const original of originals) await writeFile(resolve(output, original.file), original.bytes, { flag: 'wx' });
  await record('browser-saml-manifest.json', bindProtocolOriginals(task, originals, transcript, operations.get('m0-guard.json')));
  const runtime = await native('runtime'); await record('native-after-m0.json', runtime);
  if (collected.collectionState !== 'COLLECTED' || collected.counts.initialNormalFlowSubmissions !== 1
      || collected.counts.selectedTargetActions !== 0 || collected.counts.fullProfileStartCalls !== 0
      || counts.fixtureNormalTargetGets !== 1 || originals.length !== 2) throw new Error('Actual cold-M0 scope did not qualify');
  await record('actual-cold-m0-qualification.json', { ...publicRun, collectionState: collected.collectionState,
    sourceSha256: hashes, actualM0AcceptedBySuiteRecorder: true, normalLoginContexts: collected.counts.normalLoginContexts,
    actualHumanLoginCountMeasured: false, caseStartCalls: 0, selectedCaseMembershipVerified: true,
    qualificationScope: 'actual-public-cold-preparation-and-signed-M0-only', fullCaseQualification: false,
    sameContextSubsequentActionsQualifiedHere: false, nativeOutboxCountMeasured: true,
    actualCaseExecutions: runtime.actualCaseExecutions, actualOutboxActions: runtime.actualOutboxActions,
    authnRequestId: runtime.authnRequestId, normalRequestReference: runtime.normalRequestReference, normalResponseReference: runtime.normalResponseReference,
    requestRedirectSignatureVerified: runtime.requestRedirectSignatureVerified, responseSignatureVerified: runtime.responseSignatureVerified,
    assertionSignatureVerified: runtime.assertionSignatureVerified, canonicalAdoption: false });
} catch (error) { failure = error; await record('first-error.json', { ...publicRun, name: error.name, message: 'Owned cold-M0 qualification incomplete; raw private diagnostics omitted' }); }
finally {
  let browserClosed = !adapter;
  try { if (adapter) browserClosed = (await adapter.close()).browserContextsClosed; }
  catch { failure ??= new Error('Owned browser cleanup failed'); }
  if (server?.listening) await new Promise(done => { server.closeAllConnections(); server.close(done); });
  if (fixture.exitCode === null) fixture.kill('SIGTERM');
  let exit = await Promise.race([fixtureExited, new Promise(done => setTimeout(() => done(null), 5000).unref())]);
  if (!exit) { fixture.kill('SIGKILL'); exit = await fixtureExited; }
  if (helperInstalled) {
    counts.helperRemovalAttempts++;
    try { await docker(['exec', '-u', '0', container, 'rm', '-r', '--', helper]); counts.helperRemovalSuccesses++; }
    catch { failure ??= new Error('Owned helper cleanup failed'); }
  }
  await record('resource-closure.json', { browserClosed, ownedProxyClosed: !server?.listening, signingFixtureExit: exit,
    fixtureKeysPersisted: false, ownedHelperRemoved: helperInstalled && counts.helperRemovalSuccesses === 1,
    productionContainersRestarted: 0, actualRunDeletedOrRelabeled: false });
  await record('host-operation-counts.json', counts);
}
if (failure) process.exitCode = 1;
