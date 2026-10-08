#!/usr/bin/env node
/** Browser-only driver for a newly owned public CI Keycloak fixture. */
import { createRequire } from 'node:module';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, writeFile, mkdir, lstat } from 'node:fs/promises';
import { resolve, relative, dirname, isAbsolute } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { validateTask, validateMembership, assertEmptyNormalScope,
  playwrightAdapter, collectSelected, bindProtocolOriginals, publicJson, publicTranscriptProjection } from './generic_browser_campaign.mjs';
import { publicDocument, readPublicResponse, fetchStatus } from './synthetic_normal_browser_http.mjs';
import { createImmutableEvidenceRecorder } from './synthetic_formal_browser_runtime_smoke.mjs';

export const CASE_ID = 'IIP-IDP10-d-idp-01';
export const CASE_DIGEST = 'sha256:a02075559dff2bf93b50bcc17a601f9037093d5405a9ee93ff5f7f0e80fa346a';
export const DEFINITION_VERSION = 'functional-case-v2-nameid';
export const REALM_SHA256 = 'fb68fa3129b14ee3c57c41d1f0473984ec4c2acf4cecaaaab683661192d45113';
export const REALM_GIT_BLOB = '1b28bdece9b1af90eeadf9422c5195a4cc5ffcbb';
export const IMAGE_REFERENCE = 'quay.io/keycloak/keycloak:26.7.2@sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067';
export const SUITE_ORIGIN = 'http://localhost:18080';
export const TARGET_ORIGIN = 'http://localhost:28080';
export const TARGET_ENTITY = TARGET_ORIGIN + '/realms/samlscope';
export const LOGIN_PATH = '/realms/samlscope/login-actions/authenticate';
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw Object.assign(new Error(code), { code }); };
const object = value => value && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) => object(value) && Object.keys(value).length === keys.length
  && Object.keys(value).every(key => keys.includes(key));
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const actualRun = value => value.run ?? value;
const actualPlan = value => value.plan?.plan ?? value.plan ?? value;

export function assertCredentialFree(value, seed) {
  const visit = item => {
    if (typeof item === 'string' && /\/login-actions\//i.test(item)) fail('login-url-omitted');
    if (typeof item === 'string' && [seed.username, seed.password].some(secret =>
      typeof secret === 'string' && secret.length && item.includes(secret))) fail('private-value-omitted');
    if (item && typeof item === 'object') for (const [key, child] of Object.entries(item)) { visit(key); visit(child); }
  };
  visit(Buffer.isBuffer(value) ? value.toString('utf8') : value);
  return value;
}

export function validateOwnedSetup(value) {
  const keys = ['schema', 'generation', 'suiteOrigin', 'targetOrigin', 'targetEntityId', 'runId', 'planId',
    'caseId', 'caseDigest', 'definitionIdentity', 'suitePublicMetadataFile', 'suitePublicMetadataSha256',
    'clientDbId', 'ownedContainerId', 'ownedContainerName', 'imageReference', 'ownedLabels'];
  if (!exactKeys(value, keys) || value.schema !== 'owned-keycloak-nameid-setup-v1'
      || !/^[a-z0-9][a-z0-9-]{0,35}$/.test(value.generation ?? '')
      || value.suiteOrigin !== SUITE_ORIGIN || value.targetOrigin !== TARGET_ORIGIN || value.targetEntityId !== TARGET_ENTITY
      || value.caseId !== CASE_ID || value.caseDigest !== CASE_DIGEST
      || !/^run_[0-9A-HJKMNP-TV-Z]{26}$/.test(value.runId ?? '')
      || !/^plan_[0-9A-HJKMNP-TV-Z]{26}$/.test(value.planId ?? '')
      || !exactKeys(value.definitionIdentity, ['profile', 'version', 'digest'])
      || value.definitionIdentity.profile !== 'browser_sso_idp' || value.definitionIdentity.version !== DEFINITION_VERSION
      || !/^sha256:[a-f0-9]{64}$/.test(value.definitionIdentity.digest ?? '')
      || !digest(value.suitePublicMetadataSha256) || !isAbsolute(value.suitePublicMetadataFile ?? '')
      || !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value.clientDbId ?? '')
      || !digest(value.ownedContainerId) || value.ownedContainerName !== 'samlscope-owned-kc-nameid-v2-' + value.generation
      || value.imageReference !== IMAGE_REFERENCE
      || !exactKeys(value.ownedLabels, ['com.samlscope.owned.acceptance', 'com.samlscope.owned.generation', 'com.samlscope.owned.realm-blob'])
      || value.ownedLabels['com.samlscope.owned.acceptance'] !== 'keycloak-public-ci-nameid-v2'
      || value.ownedLabels['com.samlscope.owned.generation'] !== value.generation
      || value.ownedLabels['com.samlscope.owned.realm-blob'] !== REALM_GIT_BLOB) fail('owned-setup-scope-invalid');
  publicJson(value);
  ownedArtifactPath(value.suitePublicMetadataFile);
  return Object.freeze({ ...value, definitionIdentity: Object.freeze({ ...value.definitionIdentity }),
    ownedLabels: Object.freeze({ ...value.ownedLabels }) });
}

function ownedArtifactPath(path) {
  const local = relative(resolve(ROOT, 'build/acceptance'), resolve(path));
  if (!local || local.startsWith('..') || isAbsolute(local)) fail('owned-artifact-path-invalid');
  return resolve(path);
}

async function noSymlinks(path) {
  for (let current = resolve(path); ; current = dirname(current)) {
    try { if ((await lstat(current)).isSymbolicLink()) fail('owned-artifact-symlink'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (dirname(current) === current) break;
  }
}

/** Compare both immutable identities before parsing or extracting any login value. */
export function checkedDemoSeed(raw, trackedRaw) {
  const blob = bytes => createHash('sha1').update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex');
  if (!Buffer.isBuffer(raw) || !Buffer.isBuffer(trackedRaw) || sha(raw) !== REALM_SHA256
      || sha(trackedRaw) !== REALM_SHA256 || blob(raw) !== REALM_GIT_BLOB
      || blob(trackedRaw) !== REALM_GIT_BLOB || !raw.equals(trackedRaw)) fail('public-demo-seed-identity-invalid');
  const realm = JSON.parse(raw.toString('utf8'));
  if (realm.realm !== 'samlscope' || realm.enabled !== true || realm.users?.length !== 1) fail('public-demo-seed-shape-invalid');
  const account = realm.users[0], credentials = account.credentials;
  if (account.enabled !== true || typeof account.username !== 'string' || !account.username
      || !Array.isArray(credentials) || credentials.length !== 1 || credentials[0].type !== 'password'
      || credentials[0].temporary !== false || typeof credentials[0].value !== 'string' || !credentials[0].value)
    fail('public-demo-seed-shape-invalid');
  return Object.freeze({ username: account.username, password: credentials[0].value });
}

async function loadDemoSeed() {
  const name = 'dev/keycloak/realm-samlscope.json', git = promisify(execFile);
  try {
    await noSymlinks(resolve(ROOT, name));
    await git('git', ['ls-files', '--error-unmatch', '--', name], { cwd: ROOT, encoding: 'buffer' });
    const [raw, tracked] = await Promise.all([readFile(resolve(ROOT, name)),
      git('git', ['cat-file', 'blob', REALM_GIT_BLOB], { cwd: ROOT, encoding: 'buffer', maxBuffer: 64 * 1024 })]);
    return checkedDemoSeed(raw, tracked.stdout);
  } catch { fail('public-demo-seed-unavailable'); }
}

export function ownedLoginScope(raw) {
  try {
    const url = new URL(raw);
    return url.origin === TARGET_ORIGIN && url.pathname === LOGIN_PATH && !url.username && !url.password && !url.hash;
  } catch { return false; }
}

export function ownedLoginPageScope(raw) {
  if (ownedLoginScope(raw)) return true;
  try { const url=new URL(raw);return url.origin===TARGET_ORIGIN&&url.pathname===TARGET_ENTITY.slice(TARGET_ORIGIN.length)+'/protocol/saml'&&!url.username&&!url.password&&!url.hash; }
  catch { return false; }
}

export function validateOwnedApiScope(setup, path, body) {
  const run = `/api/runs/${setup.runId}`, plan = `/api/plans/${setup.planId}`;
  const allowedGet = new Set([run, plan, ...['result.json', 'transcript', 'campaigns',
    'protocol-evidence', 'interactions', 'active-probe'].map(suffix => run + '/' + suffix)]);
  const allowedPost = new Set(['preflight', 'protocol-evidence/evaluate', 'tests/start',
    'active-probe/abort', 'active-probe/browser-response'].map(suffix => run + '/' + suffix));
  if (!(body === undefined ? allowedGet : allowedPost).has(path)) fail('owned-api-path-invalid');
  return path;
}

export function approvedScope(setup, task, run, plan, result) {
  const current = actualRun(run), peer = actualPlan(plan);
  validateMembership(task, run, plan, result);
  // Public PlanView is a summary; exact identity comes from the native cold reader.
  if (current.id !== setup.runId || current.planId !== setup.planId || peer.target?.entityId !== TARGET_ENTITY
      || peer.definitionIdentity !== undefined && (!exactKeys(peer.definitionIdentity, ['profile', 'version', 'digest'])
        || Object.keys(setup.definitionIdentity).some(key => peer.definitionIdentity[key] !== setup.definitionIdentity[key])))
    fail('approved-native-scope-invalid');
  return { runId: current.id, planId: peer.id, caseId: CASE_ID, caseDigest: CASE_DIGEST,
    definitionIdentity: setup.definitionIdentity, actualMembershipVerified: true };
}

/** Actual read-only v238 identity proof, before any public-demo login. */
export function checkedNativeColdScope(setup, value) {
  publicJson(value);
  if (value.schema !== 'owned-keycloak-nameid-native-v1' || value.mode !== 'scope'
      || value.qualificationOutcome !== 'SCOPE_VERIFIED' || value.runId !== setup.runId
      || value.planId !== setup.planId || value.generation !== setup.generation
      || value.caseId !== CASE_ID || value.caseDigest !== CASE_DIGEST || value.targetEntityId !== TARGET_ENTITY
      || !exactKeys(value.definitionIdentity, ['profile', 'version', 'digest'])
      || Object.keys(setup.definitionIdentity).some(key => value.definitionIdentity[key] !== setup.definitionIdentity[key])
      || value.actualCaseExecutions !== 0 || value.actualOutboxActions !== 0 || value.transcriptEntries !== 0
      || value.protocolSubmissionsByReader !== 0 || value.privateKeyReads !== 0 || value.canonicalAdoption !== false)
    fail('owned-native-cold-scope-invalid');
  return value;
}

/** Omit only already-redacted Cookie metadata; raw API bytes are never retained. */
export async function readOwnedTranscriptResponse(response, runId, retainStatus, retainProjected) {
  const facts = fetchStatus(response);
  await retainStatus({ status: facts.status, rawBodyOmitted: true, scopedTranscriptProjection: true });
  if (!facts.ok || !/^application\/json(?:;|$)/i.test(facts.contentType)) fail('owned-transcript-api-status');
  const reader = response.body?.getReader(), chunks = []; let length = 0;
  if (reader) while (true) {
    const next = await reader.read(); if (next.done) break;
    length += next.value.length;
    if (length > 6 * 1024 * 1024) { await reader.cancel(); fail('owned-transcript-oversized'); }
    chunks.push(next.value);
  }
  const projected = publicTranscriptProjection(Buffer.concat(chunks), runId);
  await retainProjected(projected);
  return projected;
}

export function createLoginGate(setup, task) {
  let cold = false, guard = null, phase = 'closed';
  return {
    authorizeCold(run, plan, result, transcript, zeroScope, nativeCold = null) {
      if (result) approvedScope(setup, task, run, plan, result);
      else {
        checkedNativeColdScope(setup, nativeCold);
        if (actualRun(run).id !== setup.runId || actualRun(run).planId !== setup.planId
            || actualPlan(plan).id !== setup.planId || actualPlan(plan).profile !== 'browser_sso_idp'
            || actualPlan(plan).target?.entityId !== TARGET_ENTITY) fail('approved-native-scope-invalid');
      }
      if (actualRun(run).status !== 'CREATED' || actualRun(run).context?.authnRequestId != null
          || !Array.isArray(transcript) || transcript.length || zeroScope?.runId !== setup.runId
          || zeroScope.actualCaseExecutions !== 0 || zeroScope.pendingInteractions !== 0
          || zeroScope.readyOrLiveCaseActions !== 0
          || zeroScope.source !== 'official-public-zero-execution-projections') fail('cold-m0-login-scope-invalid');
      cold = true;
    },
    startNormal() { if (!cold || phase !== 'closed') fail('normal-login-gate-invalid'); phase = 'normal'; },
    recordNormal(value) {
      if (!cold || phase !== 'normal' || value?.runId !== setup.runId || value.planId !== setup.planId
          || value.source !== 'official-Suite-Recorder-normalFlowAccepted'
          || value.completedRunStatus !== 'COMPLETED'
          || !/^_[A-Za-z0-9_-]+$/.test(value.activeAuthnRequestId ?? '')
          || value.normalAuthnRequestReferences?.length !== 1 || value.acceptedNormalFlowReferences?.length !== 1
          || typeof value.normalAuthnRequestReferences[0] !== 'string' || !value.normalAuthnRequestReferences[0]
          || typeof value.acceptedNormalFlowReferences[0] !== 'string' || !value.acceptedNormalFlowReferences[0]
          || value.normalAuthnRequestReferences[0] === value.acceptedNormalFlowReferences[0])
        fail('official-m0-login-guard-invalid');
      guard = structuredClone(value); phase = 'closed';
    },
    startFormal(run, plan, result, status, policy) {
      approvedScope(setup, task, run, plan, result);
      if (!guard || phase !== 'closed' || status.caseId !== CASE_ID || status.requiresFreshSession !== false
          || policy !== 'authenticated-context') fail('formal-login-gate-invalid');
      phase = 'formal';
    },
    endFormal() { phase = 'closed'; },
    assertAllowed() { if (!(phase === 'normal' && cold || phase === 'formal' && guard)) fail('login-not-authorized'); },
    normalGuard() { return guard && structuredClone(guard); },
  };
}

/** Events hold only RAM state. No DOM serialization, screenshot or session export. */
export function createOwnedLoginHandler(seed, gate) {
  const pages = new WeakSet(), inFlight = new WeakSet(), attemptedStates = new Set();
  let failureCode = null;
  const counts = { domEvents: 0, ownedLoginPagesObserved: 0, loginFillAttempts: 0, loginClickAttempts: 0,
    observedLoginPostRequests: 0, duplicateEventsSkipped: 0, repeatedLoginStateRejected: 0, loginFailures: 0 };
  const reject = code => { failureCode ??= code; counts.loginFailures++; };
  async function handle(page) {
    counts.domEvents++;
    if (failureCode || page.isClosed()) return;
    const url = page.url(); // Opaque query state remains in RAM and is never a record field.
    if (!ownedLoginPageScope(url)) return;
    if (inFlight.has(page)) { counts.duplicateEventsSkipped++; return; }
    inFlight.add(page);
    try {
      gate.assertAllowed();
      const identity = sha(Buffer.from(url));
      if (attemptedStates.has(identity)) { counts.repeatedLoginStateRejected++; fail('duplicate-login-state'); }
      counts.ownedLoginPagesObserved++;
      const user = page.locator('#username'), password = page.locator('#password'), button = page.locator('#kc-login');
      // Keycloak can render its challenge directly at the native SAML endpoint.
      // A successful auto-POST response page at that endpoint is not a login.
      if (await user.count()===0&&await password.count()===0) return;
      if (await user.count() !== 1 || await password.count() !== 1 || await button.count() !== 1
          || await password.getAttribute('type') !== 'password') fail('owned-login-selectors-invalid');
      const form = page.locator('form#kc-form-login');
      if (await form.count() !== 1 || !ownedLoginScope(new URL(await form.getAttribute('action'), url).href)
          || (await form.getAttribute('method') ?? '').toLowerCase() !== 'post'
          || await button.getAttribute('formaction') !== null) fail('owned-login-form-scope-invalid');
      if (page.url() !== url || page.isClosed()) fail('owned-login-state-changed');
      attemptedStates.add(identity); // Claim before the first fill or click; failures cannot retry.
      counts.loginFillAttempts++;
      await user.fill(seed.username); await password.fill(seed.password);
      if (page.url() !== url || page.isClosed()) fail('owned-login-state-changed');
      counts.loginClickAttempts++; await button.click();
    } catch (error) { reject(/^[a-z0-9-]+$/.test(error.code ?? '') ? error.code : 'owned-login-dom-failed'); }
    finally { inFlight.delete(page); }
  }
  return {
    attach(page) {
      if (pages.has(page)) return;
      pages.add(page); page.on('domcontentloaded', () => { void handle(page); });
    },
    handle,
    observeRequest(request) { if (request.method() === 'POST' && ownedLoginScope(request.url())) counts.observedLoginPostRequests++; },
    assertHealthy() { if (failureCode) fail(failureCode); },
    facts() { return { ...counts, failureCode, credentialValuesPersisted: 0,
      loginRequestBodiesReadByOwnedHandler: false, loginUrlsExported: false, cookiesOrStorageStateExported: false }; },
  };
}

export function ownedChromium(chromium, login, contextFacts) {
  const bind = (target, key) => typeof target[key] === 'function' ? target[key].bind(target) : target[key];
  return { async launch(options) {
    if (options.channel !== 'chrome' || options.headless !== false) fail('owned-real-chrome-required');
    const browser = await chromium.launch(options);
    return new Proxy(browser, { get(target, key) {
      if (key !== 'newContext') return bind(target, key);
      return async (...args) => {
        if (contextFacts.primaryContextsCreated !== 0 || args.length && Object.keys(args[0] ?? {}).length)
          fail('owned-single-empty-context-required');
        const context = await target.newContext(...args); contextFacts.primaryContextsCreated++;
        context.on('request', request => login.observeRequest(request));
        return new Proxy(context, { get(current, field) {
          if (field !== 'newPage') return bind(current, field);
          return async (...pageArgs) => { const page = await current.newPage(...pageArgs); login.attach(page); return page; };
        } });
      };
    } });
  } };
}

export function observedSuiteResult(setup, result) {
  const selected = result.requirements?.flatMap(requirement => requirement.cases ?? []).filter(row => row.id === CASE_ID);
  if (result.run?.id !== setup.runId || result.run.completeness !== 'INCOMPLETE' || selected?.length !== 1
      || typeof selected[0].outcome !== 'string' || typeof selected[0].verdict !== 'string') fail('actual-suite-result-invalid');
  return { actualSuiteOutcome: selected[0].outcome, centralVerdict: selected[0].verdict,
    wholeRunCompleteness: result.run.completeness, wholeRunConformance: result.run.conformance,
    conformanceConclusionAssigned: false, canonicalAdoption: false };
}

export function assertCaptureScope(setup, captures, bindings, allowNativePending = false) {
  if (captures.length !== 8 || bindings.length !== 8 || new Set(bindings.map(row => row.file)).size !== 8
      || bindings.some(row => row.runId !== setup.runId || row.planId !== setup.planId
        || !(row.transcriptReferences?.length === 1 && /^recorder-hash-and-(?:normal-flow|action)-bound$/.test(row.bindingState ?? '')
          || allowNativePending && row.transcriptReferences?.length === 0 && row.bindingState === 'original-captured-recorder-hash-unavailable'))
      || !allowNativePending && new Set(bindings.flatMap(row => row.transcriptReferences)).size !== 8) fail('owned-eight-original-bindings-incomplete');
  const normal = bindings.filter(row => row.operationKind === 'M0_NORMAL');
  const formal = bindings.filter(row => row.operationKind !== 'M0_NORMAL');
  if (normal.length !== 2 || new Set(normal.map(row => row.direction)).size !== 2 || formal.length !== 6
      || formal.some(row => row.caseId !== CASE_ID) || new Set(formal.map(row => row.actionId)).size !== 3)
    fail('owned-normal-formal-scope-invalid');
  for (const action of new Set(formal.map(row => row.actionId))) {
    const pair = formal.filter(row => row.actionId === action);
    if (pair.length !== 2 || new Set(pair.map(row => row.direction)).size !== 2) fail('owned-formal-pair-invalid');
  }
  return { normalOriginals: 2, formalOriginals: 6, formalActionsObserved: 3, recorderBindingsVerified: bindings.every(row => row.transcriptReferences.length === 1), nativeReaderRequired: allowNativePending };
}

async function retainBrowserOriginals(setup, output, captures, bindings, seed) {
  await mkdir(resolve(output, 'browser-saml-originals'), { recursive: true });
  for (const capture of captures) {
    if (!/^browser-saml-originals\/[0-9]{4}-[a-f0-9]{64}\.xml$/.test(capture.file)
        || !Buffer.isBuffer(capture.bytes) || sha(capture.bytes) !== capture.record.sha256
        || capture.record.bytes !== capture.bytes.length
        || capture.record.runId !== setup.runId || capture.record.planId !== setup.planId
        || capture.record.direction === 'OUTBOUND' && capture.record.endpoint !== TARGET_ENTITY + '/protocol/saml'
        || capture.record.direction === 'INBOUND' && capture.record.endpoint !== `${SUITE_ORIGIN}/p/${capture.record.planId}/sp/acs/0`
        || !['OUTBOUND', 'INBOUND'].includes(capture.record.direction)
        || capture.record.operationKind !== 'M0_NORMAL' && capture.record.caseId !== CASE_ID)
      fail('owned-original-file-invalid');
    assertCredentialFree(capture.bytes, seed); assertCredentialFree(capture.record, seed);
  }
  for (const capture of captures) await writeFile(resolve(output, capture.file), capture.bytes, { flag: 'wx' });
  return bindings;
}

export async function runOwnedBrowser(setupFile, outputDirectory) {
  const setupPath = ownedArtifactPath(setupFile); await noSymlinks(setupPath);
  const seed = await loadDemoSeed();
  const setupRaw = await readFile(setupPath);
  if (setupRaw.length > 64 * 1024) fail('owned-setup-oversized');
  const setup = validateOwnedSetup(assertCredentialFree(publicDocument(setupRaw), seed));
  const output = ownedArtifactPath(outputDirectory);
  await noSymlinks(setup.suitePublicMetadataFile); await noSymlinks(output);
  const metadata = await readFile(setup.suitePublicMetadataFile);
  if (metadata.length > 1024 * 1024 || sha(metadata) !== setup.suitePublicMetadataSha256) fail('owned-suite-metadata-identity-invalid');
  assertCredentialFree(metadata, seed);
  await mkdir(output, { recursive: false });
  const immutable = createImmutableEvidenceRecorder(output);
  const task = validateTask({ suiteBaseUrl: SUITE_ORIGIN, targetOrigins: [TARGET_ORIGIN], runId: setup.runId,
    planId: setup.planId, caseIds: [CASE_ID], outputDirectory: output, maxActions: 100,
    actionTimeoutSeconds: 60, completeNormalFlow: true, startTests: true });
  const gate = createLoginGate(setup, task), login = createOwnedLoginHandler(seed, gate);
  const contextFacts = { primaryContextsCreated: 0, formalContextReuses: 0 };
  const counts = { apiAttempts: 0, apiSuccesses: 0 };
  const record = async (name, value) => {
    assertCredentialFree(value, seed); await immutable(name, value);
    if (name === 'm0-guard.json') gate.recordNormal(value);
  };
  const api = async (path, body) => {
    login.assertHealthy();
    validateOwnedApiScope(setup, path, body);
    if (body !== undefined) assertCredentialFree(publicJson(body), seed);
    counts.apiAttempts++; const index = counts.apiAttempts;
    const response = await fetch(SUITE_ORIGIN + path, { method: body === undefined ? 'GET' : 'POST', redirect: 'manual',
      ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(30000) });
    const statusRecord = facts => record(`api-${String(index).padStart(4, '0')}-status.json`, { path, ...facts });
    const result = path === `/api/runs/${setup.runId}/transcript`
      ? await readOwnedTranscriptResponse(response, setup.runId, statusRecord, async value => {
        assertCredentialFree(value, seed);
        await writeFile(resolve(output, `api-${String(index).padStart(4, '0')}-projected.json`), JSON.stringify(value), { flag: 'wx' });
      })
      : await readPublicResponse(response, statusRecord,
        async raw => { assertCredentialFree(publicDocument(raw), seed);
          await writeFile(resolve(output, `api-${String(index).padStart(4, '0')}-response.body`), raw, { flag: 'wx' }); });
    counts.apiSuccesses++; login.assertHealthy(); return result;
  };
  let adapter = null, collected = null, failure = null, browserClosed = false, originalsExported = false;
  const captures = [];
  try {
    await record('owned-setup.json', setup); await record('task.json', task);
    const sourcePins = {};
    for (const name of ['owned_keycloak_nameid_browser.mjs', 'generic_browser_campaign.mjs',
      'synthetic_normal_browser_http.mjs', 'synthetic_formal_browser_runtime_smoke.mjs'])
      sourcePins[name] = sha(await readFile(resolve(ROOT, 'dev/reference-acceptance', name)));
    await record('source-sha256.json', sourcePins);
    const run = await api(`/api/runs/${setup.runId}`), plan = await api(`/api/plans/${setup.planId}`);
    const transcript = await api(`/api/runs/${setup.runId}/transcript`);
    const zero = await assertEmptyNormalScope(task, api, run, { cold: true });
    const coldPath = resolve(dirname(setup.suitePublicMetadataFile), 'native-cold-scope.json');
    await noSymlinks(coldPath);
    const coldRaw = await readFile(coldPath);
    if (coldRaw.length > 64 * 1024) fail('owned-native-cold-scope-oversized');
    const nativeCold = checkedNativeColdScope(setup, assertCredentialFree(publicDocument(coldRaw), seed));
    await record('native-cold-scope.json', nativeCold);
    gate.authorizeCold(run, plan, null, transcript, zero, nativeCold);
    await record('owned-pre-login-scope.json', { runId: setup.runId, planId: setup.planId, caseId: CASE_ID,
      caseDigest: CASE_DIGEST, definitionIdentity: setup.definitionIdentity, source: 'native-owning-cold-case-membership',
      publicResultAvailableBeforeM0: false });
    const dependency = process.env.SAML_SCOPE_PLAYWRIGHT;
    if (!dependency?.startsWith('/')) fail('owned-playwright-path-required');
    const { chromium } = createRequire(import.meta.url)(dependency);
    adapter = await playwrightAdapter(task, ownedChromium(chromium, login, contextFacts), record, captures);
    const browser = {
      ...adapter,
      normalFlow: (...args) => { gate.startNormal(); return adapter.normalFlow(...args); },
      probe: async (currentTask, status, policy, currentApi) => {
        const run = await api(`/api/runs/${setup.runId}`), plan = await api(`/api/plans/${setup.planId}`);
        const result = await api(`/api/runs/${setup.runId}/result.json`);
        gate.startFormal(run, plan, result, status, policy); contextFacts.formalContextReuses++;
        try { return await adapter.probe(currentTask, status, policy, currentApi); }
        finally { gate.endFormal(); }
      },
    };
    collected = await collectSelected(task, api, browser, record);
    login.assertHealthy();
    const finalTranscript = await api(`/api/runs/${setup.runId}/transcript`);
    const finalResult = await api(`/api/runs/${setup.runId}/result.json`);
    await record('transcript.json', finalTranscript); await record('result.json', finalResult);
    const guard = gate.normalGuard();
    if (!guard) fail('owned-normal-control-unproven');
    // The frozen collector already validated this guard against actual COMPLETED
    // M0 state before /tests/start. Never relabel a later Run to repeat that check.
    const bindings = bindProtocolOriginals(task, captures, finalTranscript, guard);
    const scope = assertCaptureScope(setup, captures, bindings, true);
    if (collected.collectionState !== 'COLLECTED' || collected.counts.initialNormalFlowSubmissions !== 1
        || collected.counts.fullProfileStartCalls !== 1 || collected.counts.selectedTargetActions !== 3
        || collected.counts.freshEmptyContexts !== 0 || contextFacts.primaryContextsCreated !== 1
        || contextFacts.formalContextReuses !== 3) fail('owned-browser-operation-scope-incomplete');
    await retainBrowserOriginals(setup, output, captures, bindings, seed);
    originalsExported = true;
    await record('browser-saml-manifest.json', bindings);
    await record('owned-browser-observation.json', { ...scope, ...observedSuiteResult(setup, finalResult),
      collectionState: collected.collectionState, actualProductLoginPostsObserved: login.facts().observedLoginPostRequests,
      actualHumanLoginCountMeasured: false, genericCountsAreCredentialNeutralCoreOnly: true,
      nativeReaderStillRequired: 'ReadOwnedKeycloakNameIdRuntime' });
  } catch (error) {
    failure = error;
    await record('first-error.json', { failureCode: /^[a-z0-9-]+$/.test(error.code ?? '') ? error.code : 'owned-browser-collection-failed',
      runId: setup.runId, planId: setup.planId, conformanceConclusionAssigned: false });
  } finally {
    try { if (adapter) browserClosed = (await adapter.close('owned-nameid-browser-finished')).browserContextsClosed === true; }
    catch { failure ??= Object.assign(new Error('owned-browser-close-failed'), { code: 'owned-browser-close-failed' }); }
    if (!originalsExported && captures.length) {
      try {
        const supplemental = captures.map(capture => ({ ...capture.record, file: capture.file, transcriptReferences: [],
          bindingState: 'original-captured-recorder-unqualified', conformanceConclusionAssigned: false }));
        await retainBrowserOriginals(setup, output, captures, supplemental, seed);
        await record('supplemental-browser-saml-manifest.json', supplemental);
      } catch { failure ??= Object.assign(new Error('owned-supplemental-capture-failed'), { code: 'owned-supplemental-capture-failed' }); }
    }
    await record('owned-login-counts.json', { ...login.facts(), ...contextFacts, ...counts, actualHumanLoginCountMeasured: false });
    await record('owned-browser-closure.json', { browserClosed, collectionState: collected?.collectionState ?? 'FAILED',
      protocolOriginalsCapturedInRam: captures.length, productConfigurationWrites: 0, productRestarts: 0,
      existingRunDeletedOrRelabeled: false, credentialsOrSessionExported: false, conformanceConclusionAssigned: false });
    await record('evidence-record-history.json', immutable.history());
  }
  if (failure) fail('owned-browser-campaign-incomplete');
}

const FORMAL_FIXTURES = ['format-transient', 'format-persistent', 'sp-name-qualifier'];
const sameRefs = (actual, expected) => Array.isArray(actual) && actual.length === expected.length
  && new Set(actual).size === actual.length && actual.every(value => expected.includes(value));

function decodeNativeOriginal(encoded, size, hash) {
  if (typeof encoded !== 'string' || !Number.isInteger(size) || size < 0 || size > 4 * 1024 * 1024 || !digest(hash)
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))
    fail('owned-native-original-encoding-invalid');
  const bytes = Buffer.from(encoded, 'base64');
  if (bytes.length !== size || bytes.toString('base64') !== encoded || sha(bytes) !== hash)
    fail('owned-native-original-hash-invalid');
  return bytes;
}

function headerFree(value) {
  if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
    if (key.replace(/[_-]/g, '').toLowerCase() === 'headers') fail('owned-native-headers-omitted');
    headerFree(child);
  }
  return value;
}

function checkNativeWire(original, body, decoded, seed) {
  let fields, query = null;
  if (original.method === 'GET') {
    if (body.length !== 0 || typeof original.rawQuery !== 'string' || !original.rawQuery
        || Buffer.byteLength(original.rawQuery) > 2 * 1024 * 1024
        || new URL(original.url).search.slice(1) !== original.rawQuery) fail('owned-native-redirect-query-invalid');
    query = Buffer.from(original.rawQuery, 'utf8'); fields = new URLSearchParams(original.rawQuery);
    if (['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'].some(key => fields.getAll(key).length !== 1))
      fail('owned-native-redirect-fields-invalid');
  } else if (original.method === 'POST') {
    if (original.rawQuery !== null || new URL(original.url).search
        || !/^application\/x-www-form-urlencoded(?:;|$)/i.test(original.contentType ?? ''))
      fail('owned-native-post-shape-invalid');
    let text;
    try { text = new TextDecoder('utf8', { fatal: true }).decode(body); }
    catch { fail('owned-native-post-encoding-invalid'); }
    fields = new URLSearchParams(text);
  } else fail('owned-native-method-invalid');
  const field = original.direction === 'OUTBOUND' ? 'SAMLRequest' : 'SAMLResponse';
  const allowed = original.method === 'GET' ? ['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'] : [field, 'RelayState'];
  if ([...fields.keys()].some(key => !allowed.includes(key)) || fields.getAll(field).length !== 1
      || fields.getAll('RelayState').length !== 1 || [...new Set(fields.keys())].some(key => fields.getAll(key).length !== 1))
    fail('owned-native-wire-fields-invalid');
  assertCredentialFree([...fields.values()], seed);
  const encoded = fields.get(field);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded ?? ''))
    fail('owned-native-wire-base64-invalid');
  let wire = Buffer.from(encoded, 'base64');
  try { if (original.method === 'GET') wire = inflateRawSync(wire, { maxOutputLength: 4 * 1024 * 1024 }); }
  catch { fail('owned-native-redirect-deflate-invalid'); }
  if (!wire.equals(decoded)) fail('owned-native-wire-decoded-mismatch');
  return query;
}

/** Pure binding/byte checks. Native protocol proof and G2 controls remain separate. */
export function checkedOwnedPortableOriginals(setup, runtime, bindings, result, seed) {
  publicJson(runtime); assertCredentialFree(runtime, seed); headerFree(runtime);
  const actual = observedSuiteResult(setup, result);
  const selected = result.requirements.flatMap(requirement => requirement.cases ?? []).find(row => row.id === CASE_ID);
  if (!Array.isArray(selected.evidence) || selected.evidence.some(ref => ref.kind !== 'transcript')
      || !sameRefs(selected.evidence.map(ref => ref.reference), runtime.selectedCaseEvidence)) fail('owned-native-central-evidence-mismatch');
  if (runtime.schema !== 'owned-keycloak-nameid-native-v1' || runtime.runId !== setup.runId || runtime.planId !== setup.planId
      || runtime.caseId !== CASE_ID || runtime.caseDigest !== CASE_DIGEST
      || !exactKeys(runtime.definitionIdentity, ['profile', 'version', 'digest'])
      || Object.keys(setup.definitionIdentity).some(key => runtime.definitionIdentity[key] !== setup.definitionIdentity[key])
      || runtime.qualificationOutcome !== 'VERIFIED' || runtime.selectedCaseOutcome !== actual.actualSuiteOutcome
      || runtime.selectedRegisteredScenarioProven !== true || runtime.nativeRequiredRequestShapesProven !== true
      || runtime.approvedControlReplayRequiredForAdoption !== true || runtime.wholeRunConformance !== 'NOT_QUALIFIED'
      || runtime.canonicalAdoption !== false) fail('owned-native-runtime-scope-invalid');
  assertCaptureScope(setup, Array(8), bindings);
  const pairs = runtime.selectedActionPairs;
  if (!Array.isArray(pairs) || pairs.length !== 3 || !sameRefs(pairs.map(pair => pair.fixtureId), FORMAL_FIXTURES)
      || pairs.some(pair => !exactKeys(pair, ['fixtureId', 'actionId', 'requestReference', 'responseReference'])
        || !/^action_[a-f0-9]{32}$/.test(pair.actionId ?? '')) || new Set(pairs.map(pair => pair.actionId)).size !== 3)
    fail('owned-native-formal-pairs-invalid');
  const formalRefs = pairs.flatMap(pair => [pair.requestReference, pair.responseReference]);
  const required = [runtime.normalRequestReference, runtime.normalResponseReference, ...formalRefs];
  if (new Set(required).size !== 8 || required.some(reference => !/^tx_[0-9A-HJKMNP-TV-Z]{26}$/.test(reference ?? ''))
      || !sameRefs(runtime.portableEvidenceReferences, required)
      || !sameRefs(runtime.selectedCaseEvidence, pairs.map(pair => pair.responseReference))
      || !sameRefs(bindings.flatMap(binding => binding.transcriptReferences), required)
      || !Array.isArray(runtime.transcriptOriginals) || !sameRefs(runtime.transcriptOriginals.map(value => value.id), required))
    fail('owned-native-evidence-reference-set-invalid');
  const originalKeys = ['id', 'runId', 'direction', 'timestamp', 'correlationId', 'method', 'url', 'status', 'contentType',
    'rawQuery', 'summary', 'bodyRef', 'bodyBytes', 'bodyBase64', 'computedBodySha256', 'storedBodySha256',
    'decodedSamlRef', 'decodedSamlBytes', 'decodedSamlBase64', 'computedDecodedSha256'];
  let total = 0;
  const originals = runtime.transcriptOriginals.map(original => {
    if (!exactKeys(original, originalKeys) || original.runId !== setup.runId || !['INBOUND', 'OUTBOUND'].includes(original.direction)
        || typeof original.timestamp !== 'string' || !Number.isFinite(Date.parse(original.timestamp)) || !object(original.summary))
      fail('owned-native-original-scope-invalid');
    const prefix = `transcripts/${setup.runId}/${original.id}`;
    if (original.decodedSamlRef !== prefix + '.saml.xml'
        || !(original.bodyRef === prefix + '.body' || original.bodyRef === null && original.bodyBytes === 0))
      fail('owned-native-original-reference-invalid');
    const body = decodeNativeOriginal(original.bodyBase64, original.bodyBytes, original.computedBodySha256);
    const decoded = decodeNativeOriginal(original.decodedSamlBase64, original.decodedSamlBytes, original.computedDecodedSha256);
    total += body.length + decoded.length;
    if (!decoded.length || total > 16 * 1024 * 1024 || original.storedBodySha256 !== null && original.storedBodySha256 !== sha(body))
      fail('owned-native-original-size-invalid');
    assertCredentialFree(body, seed); assertCredentialFree(decoded, seed);
    const binding = bindings.find(row => row.transcriptReferences[0] === original.id);
    const endpoint = new URL(original.url);
    if (endpoint.username || endpoint.password || endpoint.hash || binding.direction !== original.direction
        || binding.endpoint !== endpoint.origin + endpoint.pathname || binding.bytes !== decoded.length || binding.sha256 !== sha(decoded))
      fail('owned-native-browser-original-mismatch');
    if (original.direction === 'OUTBOUND' ? endpoint.origin + endpoint.pathname !== TARGET_ENTITY + '/protocol/saml'
      : endpoint.href !== `${SUITE_ORIGIN}/p/${setup.planId}/sp/acs/0`) fail('owned-native-original-endpoint-invalid');
    const pair = pairs.find(value => value.requestReference === original.id || value.responseReference === original.id);
    if (pair) {
      if (binding.caseId !== CASE_ID || binding.actionId !== pair.actionId || original.method !== 'POST'
          || original.id !== (original.direction === 'OUTBOUND' ? pair.requestReference : pair.responseReference)
          || original.correlationId !== (original.direction === 'INBOUND' ? '_' : '') + pair.actionId
          || original.direction === 'OUTBOUND' && (original.summary.scenario_case_id !== CASE_ID
            || original.summary.fixture_id !== pair.fixtureId || original.summary.action_id !== pair.actionId))
        fail('owned-native-original-action-pair-invalid');
    } else if (binding.operationKind !== 'M0_NORMAL'
        || original.id !== (original.direction === 'OUTBOUND' ? runtime.normalRequestReference : runtime.normalResponseReference)
        || original.method !== (original.direction === 'OUTBOUND' ? 'GET' : 'POST')) fail('owned-native-normal-pair-invalid');
    const query = checkNativeWire(original, body, decoded, seed);
    return { original, binding, body, decoded, query };
  });
  const find = reference => originals.find(value => value.original.id === reference).original;
  const normalRequest = find(runtime.normalRequestReference), normalResponse = find(runtime.normalResponseReference);
  if (normalRequest.correlationId !== normalResponse.correlationId || normalResponse.summary.normalFlowAccepted !== true
      || Date.parse(normalResponse.timestamp) < Date.parse(normalRequest.timestamp)) fail('owned-native-normal-order-invalid');
  let preceding = Date.parse(normalResponse.timestamp);
  for (const fixture of FORMAL_FIXTURES) {
    const pair = pairs.find(value => value.fixtureId === fixture), request = find(pair.requestReference), response = find(pair.responseReference);
    if (Date.parse(request.timestamp) < preceding || Date.parse(response.timestamp) < Date.parse(request.timestamp))
      fail('owned-native-formal-order-invalid');
    preceding = Date.parse(response.timestamp);
  }
  return originals;
}

/** Join supplemental browser hashes to exact native stored physical originals. */
export function bindOwnedNativeOriginals(setup, runtime, bindings) {
  assertCaptureScope(setup, Array(8), bindings, true);
  if (runtime.runId !== setup.runId || runtime.planId !== setup.planId || runtime.transcriptOriginals?.length !== 8
      || new Set(runtime.transcriptOriginals.map(row => row.id)).size !== 8) fail('owned-native-join-scope-invalid');
  const joined = bindings.map(binding => {
    const pair = runtime.selectedActionPairs?.find(value => value.actionId === binding.actionId);
    const reference = binding.operationKind === 'M0_NORMAL'
      ? binding.direction === 'OUTBOUND' ? runtime.normalRequestReference : runtime.normalResponseReference
      : pair && (binding.direction === 'OUTBOUND' ? pair.requestReference : pair.responseReference);
    const matches = runtime.transcriptOriginals.filter(original => original.id === reference && original.runId === setup.runId
      && original.direction === binding.direction && original.decodedSamlBytes === binding.bytes
      && original.computedDecodedSha256 === binding.sha256);
    if (matches.length !== 1 || binding.transcriptReferences.length && !sameRefs(binding.transcriptReferences, [reference]))
      fail('owned-native-join-byte-reference-mismatch');
    const original = matches[0], endpoint = new URL(original.url);
    if (binding.endpoint !== endpoint.origin + endpoint.pathname
        || binding.operationKind !== 'M0_NORMAL' && (binding.caseId !== CASE_ID || !pair
          || original.correlationId !== (binding.direction === 'INBOUND' ? '_' : '') + pair.actionId))
      fail('owned-native-join-action-mismatch');
    // Decode and verify the claimed bytes; the physical browser copy is checked before export.
    decodeNativeOriginal(original.decodedSamlBase64, original.decodedSamlBytes, original.computedDecodedSha256);
    return { ...binding, transcriptReferences: [reference],
      bindingState: binding.operationKind === 'M0_NORMAL' ? 'recorder-hash-and-normal-flow-bound' : 'recorder-hash-and-action-bound',
      hashSource: 'read-only-native-physical-Recorder-original', apiDecodedHashRequiredOrFabricated: false };
  });
  assertCaptureScope(setup, Array(8), joined);
  return joined;
}

export async function exportOwnedPortableOriginals(setup, runtime, bindings, result, output, seed) {
  const originals = checkedOwnedPortableOriginals(setup, runtime, bindings, result, seed);
  ownedArtifactPath(output); await noSymlinks(output);
  // Verify all existing browser files before retaining any native body or query.
  for (const value of originals) {
    if (!/^browser-saml-originals\/[0-9]{4}-[a-f0-9]{64}\.xml$/.test(value.binding.file)) fail('owned-browser-file-invalid');
    const path = resolve(output, value.binding.file); await noSymlinks(path);
    const stat = await lstat(path), bytes = await readFile(path);
    if (!stat.isFile() || stat.size !== value.decoded.length || !bytes.equals(value.decoded)) fail('owned-browser-physical-original-mismatch');
  }
  const folder = resolve(output, 'native-originals'); await noSymlinks(folder); await mkdir(folder, { recursive: false });
  const manifest = [];
  for (const value of originals) {
    const physical = {};
    for (const [kind, suffix, bytes] of [['body', '.body', value.body], ['decoded', '.saml.xml', value.decoded], ['query', '.query.txt', value.query]]) {
      if (bytes === null) continue;
      const file = `native-originals/${value.original.id}${suffix}`, path = resolve(output, file);
      await writeFile(path, bytes, { flag: 'wx' });
      const stat = await lstat(path), actual = await readFile(path);
      if (!stat.isFile() || stat.size !== bytes.length || !actual.equals(bytes)) fail('owned-native-physical-original-mismatch');
      physical[kind] = { file, bytes: actual.length, sha256: sha(actual) };
    }
    manifest.push({ id: value.original.id, runId: setup.runId, nativeBodyReference: value.original.bodyRef,
      nativeDecodedReference: value.original.decodedSamlRef, browserFile: value.binding.file, physical });
  }
  return { scope: 'exact-normal2-and-selected-case6', selectedOriginalCount: 8,
    requiredSelectedOriginalsExported: true, allDeclaredAndPhysicalBytesAndHashesMatched: true,
    approvedControlReplayRequiredForAdoption: true, ...observedSuiteResult(setup, result), originals: manifest };
}

async function portableCommand(setupFile, outputDirectory, runtimeFile) {
  const setupPath = ownedArtifactPath(setupFile), output = ownedArtifactPath(outputDirectory), nativePath = ownedArtifactPath(runtimeFile);
  await noSymlinks(setupPath); await noSymlinks(output); await noSymlinks(nativePath);
  const seed = await loadDemoSeed();
  const readPublicFile = async (path, max) => {
    await noSymlinks(path); const bytes = await readFile(path);
    if (bytes.length > max) fail('owned-public-file-oversized');
    return assertCredentialFree(publicDocument(bytes), seed);
  };
  const setup = validateOwnedSetup(await readPublicFile(setupPath, 64 * 1024));
  await noSymlinks(setup.suitePublicMetadataFile);
  const metadata = await readFile(setup.suitePublicMetadataFile);
  if (metadata.length > 1024 * 1024 || sha(metadata) !== setup.suitePublicMetadataSha256) fail('owned-suite-metadata-identity-invalid');
  assertCredentialFree(metadata, seed);
  const runtime = await readPublicFile(nativePath, 32 * 1024 * 1024);
  const originalBindings = await readPublicFile(resolve(output, 'browser-saml-manifest.json'), 1024 * 1024);
  const bindings = bindOwnedNativeOriginals(setup, runtime, originalBindings);
  const result = await readPublicFile(resolve(output, 'result.json'), 6 * 1024 * 1024);
  const manifest = await exportOwnedPortableOriginals(setup, runtime, bindings, result, output, seed);
  await writeFile(resolve(output, 'browser-saml-manifest-native-bound.json'), JSON.stringify(publicJson(bindings), null, 2) + '\n', { flag: 'wx' });
  await writeFile(resolve(output, 'selected-portable-originals.json'), JSON.stringify(publicJson(manifest), null, 2) + '\n', { flag: 'wx' });
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const command = process.argv.length === 5 && process.argv[2] === '--execute'
    ? runOwnedBrowser(process.argv[3], process.argv[4])
    : process.argv.length === 6 && process.argv[2] === '--export-portable'
      ? portableCommand(process.argv[3], process.argv[4], process.argv[5]) : null;
  if (!command) {
    process.stderr.write('Use --execute setup.json fresh-output or --export-portable setup.json browser-output native-public.json.\n'); process.exitCode = 1;
  } else command.catch(() => {
    process.stderr.write('Owned Keycloak browser campaign incomplete; private diagnostics omitted.\n'); process.exitCode = 1;
  });
}
