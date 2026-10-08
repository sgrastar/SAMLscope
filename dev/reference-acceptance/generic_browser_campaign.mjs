#!/usr/bin/env node
/**
 * Product-neutral browser collector for an already registered Suite peer.
 *
 * The Suite owns fixtures, case membership, outbox dispatch and conclusions. This
 * collector never enters a password, creates a product setting, or assigns a
 * verdict. A visible browser lets the test user complete a normal sign-in once;
 * its in-memory context is reused only when the Suite explicitly permits it.
 *
 * Usage: SAML_SCOPE_PLAYWRIGHT=/absolute/path/to/playwright node this.mjs task.json
 * No storageState, cookies, authentication headers, page dumps or screenshots
 * are exported. Only original SAML messages and public Suite artifacts are saved.
 */
import { createRequire } from 'node:module';
import { readFile, writeFile, mkdir, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const RUN = /^run_[0-9A-HJKMNP-TV-Z]{26}$/;
const PLAN = /^plan_[0-9A-HJKMNP-TV-Z]{26}$/;
const CASE = /^IIP-[A-Za-z0-9]+-[A-Za-z0-9]+-idp-01$/;
const ACTION = /^action_[a-f0-9]{32}$/;
const sleep = milliseconds => new Promise(done => setTimeout(done, milliseconds));

export function checkedOrigin(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password
      || url.pathname !== '/' || url.search || url.hash) throw new Error('Invalid browser origin');
  return url.origin;
}

export function validateTask(input) {
  const allowedFields = new Set(['suiteBaseUrl', 'runId', 'planId', 'caseIds', 'targetOrigins',
    'outputDirectory', 'maxActions', 'actionTimeoutSeconds', 'startTests', 'initialNormalFlow']);
  if (input && Object.keys(input).some(key => !allowedFields.has(key))) throw new Error('Unexpected task field; credentials are not accepted');
  if (!input || !RUN.test(input.runId) || !PLAN.test(input.planId)
      || !Array.isArray(input.caseIds) || !input.caseIds.length
      || input.caseIds.some(id => !CASE.test(id))
      || new Set(input.caseIds).size !== input.caseIds.length) throw new Error('Invalid Run, Plan or selected cases');
  const suite = checkedOrigin(input.suiteBaseUrl);
  if (!Array.isArray(input.targetOrigins) || !input.targetOrigins.length) throw new Error('Target navigation origins are required');
  const targets = input.targetOrigins.map(checkedOrigin);
  if (targets.includes(suite) || new Set(targets).size !== targets.length) throw new Error('Invalid target origin list');
  if (input.startTests !== undefined && typeof input.startTests !== 'boolean') throw new Error('Invalid startTests policy');
  if (input.initialNormalFlow !== undefined && typeof input.initialNormalFlow !== 'boolean') throw new Error('Invalid initial flow policy');
  const maxActions = input.maxActions ?? 400;
  const actionTimeoutSeconds = input.actionTimeoutSeconds ?? 300;
  if (!Number.isInteger(maxActions) || maxActions < 1 || maxActions > 2000
      || !Number.isInteger(actionTimeoutSeconds) || actionTimeoutSeconds < 1
      || actionTimeoutSeconds > 3600) throw new Error('Invalid campaign limits');
  if (typeof input.outputDirectory !== 'string' || !input.outputDirectory) throw new Error('Output directory is required');
  return Object.freeze({ ...input, suiteBaseUrl: suite, targetOrigins: targets,
    outputDirectory: resolve(input.outputDirectory), maxActions, actionTimeoutSeconds,
    startTests: input.startTests === true, initialNormalFlow: input.initialNormalFlow === true });
}

export function probeUrl(task, status) {
  const url = new URL(status.startUrl);
  if (status.state !== 'READY' || !CASE.test(status.caseId) || !ACTION.test(status.actionId)
      || url.origin !== task.suiteBaseUrl || url.username || url.password || url.hash
      || url.pathname !== `/p/${task.planId}/probe/${status.actionId}`
      || url.searchParams.getAll('run').length !== 1
      || url.searchParams.get('run') !== task.runId || [...url.searchParams.keys()].some(key => key !== 'run')) {
    throw new Error('Probe URL is not bound to this Suite, Run, Plan and action');
  }
  return url.href;
}

export function sessionPolicy(status) {
  if (typeof status.requiresFreshSession !== 'boolean') throw new Error('Fresh-session policy is missing');
  return status.requiresFreshSession ? 'fresh-empty-context' : 'authenticated-context';
}

export function validateMembership(task, run, plan, result) {
  const effectiveRun = run.run ?? run;
  const effectivePlan = plan.plan?.plan ?? plan.plan ?? plan;
  if (effectiveRun.id !== task.runId || effectiveRun.planId !== task.planId
      || effectivePlan.id !== task.planId || effectivePlan.profile !== 'browser_sso_idp'
      || effectivePlan.target?.kind !== 'IDP' || result.run?.id !== task.runId) {
    throw new Error('Run/Plan/result identity or profile mismatch');
  }
  const cases = result.requirements.flatMap(requirement => requirement.cases);
  const ids = cases.map(test => test.id);
  if (new Set(ids).size !== ids.length || task.caseIds.some(id => !ids.includes(id))) {
    throw new Error('Selected case is absent from the actual Run');
  }
  // API /tests/start starts the complete approved profile; it is not a selector.
  // The collector skips other prepared actions before any target submission.
  return { profile: effectivePlan.profile, selectedCases: [...task.caseIds],
    actualRunCaseCount: ids.length, actualRunCaseIds: ids, selectedTestsApiExists: false,
    startTestsScope: 'full-approved-profile', selectionMethod: 'prepare-and-abort-unselected-before-target-submission' };
}

export function validateM0Guard(task, run, plan, transcript) {
  const effectiveRun = run.run ?? run;
  const effectivePlan = plan.plan?.plan ?? plan.plan ?? plan;
  if (effectiveRun.status !== 'COMPLETED' || !Array.isArray(transcript)
      || new Set(transcript.map(entry => entry.id)).size !== transcript.length
      || transcript.some(entry => entry.runId !== task.runId)) throw new Error('Normal-flow Run completion is unproven');
  const controls = transcript.filter(entry => entry.direction === 'INBOUND'
    && entry.samlSummary?.normalFlowAccepted === true && entry.samlSummary?.type === 'Response'
    && entry.samlSummary?.statusCode === 'urn:oasis:names:tc:SAML:2.0:status:Success'
    && entry.samlSummary?.issuer === effectivePlan.target.entityId
    && entry.samlSummary?.destination === `${task.suiteBaseUrl}/p/${task.planId}/sp/acs/0`
    && entry.url === entry.samlSummary.destination && entry.correlationId === entry.samlSummary.inResponseTo
    && transcript.some(request => request.direction === 'OUTBOUND'
      && request.samlSummary?.type === 'AuthnRequest' && request.samlSummary?.id === entry.samlSummary.inResponseTo));
  if (!controls.length) throw new Error('Accepted, correlated normal SSO control is missing');
  return { completedRunStatus: effectiveRun.status,
    acceptedNormalFlowReferences: controls.map(entry => entry.id),
    source: 'official-Suite-Recorder-normalFlowAccepted', additionalTargetInteraction: false };
}

/** Capture public protocol originals only; never rewrite requests before sending. */
export function samlMessage(task, request, action) {
  if (!action) return null;
  const url = new URL(request.url());
  const isSuite = url.origin === task.suiteBaseUrl;
  if (isSuite ? !url.pathname.startsWith(`/p/${task.planId}/sp/acs/`) : !task.targetOrigins.includes(url.origin)) return null;
  let fields;
  let binding;
  if (request.method() === 'POST') {
    if (!/^application\/x-www-form-urlencoded(?:;|$)/i.test(request.headers()['content-type'] ?? '')) return null;
    fields = new URLSearchParams(request.postData() ?? '');
    binding = 'HTTP-POST';
  } else if (request.method() === 'GET') {
    fields = url.searchParams;
    binding = 'HTTP-Redirect';
  } else return null;
  const field = isSuite ? 'SAMLResponse' : 'SAMLRequest';
  if (fields.getAll(field).length !== 1 || fields.has(isSuite ? 'SAMLRequest' : 'SAMLResponse')) return null;
  const encoded = fields.get(field);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded) || !encoded) throw new Error('Malformed SAML base64');
  let bytes = Buffer.from(encoded, 'base64');
  if (binding === 'HTTP-Redirect') bytes = inflateRawSync(bytes, { maxOutputLength: 4 * 1024 * 1024 });
  if (bytes.length > 4 * 1024 * 1024) throw new Error('Oversized SAML message');
  return { bytes, record: { runId: task.runId, planId: task.planId,
    caseId: action.caseId, actionId: action.actionId, fixtureContext: action.fixtureContext ?? null,
    direction: isSuite ? 'INBOUND' : 'OUTBOUND', binding,
    // URLs can contain opaque login state. Keep the public endpoint without its query.
    endpoint: url.origin + url.pathname, sha256: sha(bytes), bytes: bytes.length,
    observedAtUtc: new Date().toISOString() } };
}

export function bindProtocolOriginals(task, captures, transcript) {
  if (!Array.isArray(transcript) || new Set(transcript.map(entry => entry.id)).size !== transcript.length
      || transcript.some(entry => entry.runId !== task.runId)) throw new Error('Transcript is not uniquely bound to this Run');
  const bindings = [];
  for (const capture of captures) {
    // Recorder summary includes the actual decoded message hash. Exported browser
    // messages are supplemental originals until this equality is established.
    const matches = transcript.filter(entry => entry.direction === capture.record.direction
      && entry.decodedSamlBytes === capture.record.bytes
      && (entry.samlSummary?.decodedSha256 === capture.record.sha256
        || entry.samlSummary?.decoded_sha256 === capture.record.sha256));
    const owned = matches.filter(entry => capture.record.direction === 'INBOUND'
      ? entry.correlationId === '_' + capture.record.actionId
      : entry.correlationId === capture.record.actionId
        && entry.samlSummary?.scenario_case_id === capture.record.caseId);
    bindings.push({ ...capture.record, file: capture.file,
      transcriptReferences: owned.map(entry => entry.id),
      bindingState: owned.length === 1 ? 'recorder-hash-and-action-bound' : 'original-captured-recorder-hash-unavailable',
      conformanceConclusionAssigned: false });
  }
  return bindings;
}

/** Coordinate only official Suite actions. The adapter never manufactures evidence. */
export async function collectSelected(task, api, browser, record) {
  const selected = new Set(task.caseIds);
  const counts = { preparedActions: 0, selectedTargetActions: 0, skippedBeforeTargetSubmission: 0,
    selectedBrowserDispatchAttempts: 0, terminalHttpObservationsWithBodyOmitted: 0,
    passiveAuthenticationLandingsWithBodyOmitted: 0,
    authenticatedContextReuses: 0, freshEmptyContexts: 0, manualAuthenticationCheckpoints: 0,
      credentialValuesPersisted: 0, automatedCredentialPosts: 0,
    productSettingWriteAttempts: 0, productSettingWrites: 0, restorationWrites: 0,
    productRestarts: 0, fullProfileStartCalls: 0, initialNormalFlowSubmissions: 0,
    conclusionAssignments: 0, liveActionsRetained: 0 };
  const run = await api(`/api/runs/${task.runId}`);
  const plan = await api(`/api/plans/${task.planId}`);
  const result = await api(`/api/runs/${task.runId}/result.json`);
  const membership = validateMembership(task, run, plan, result);
  await record('membership.json', membership);
  const beforeTranscript = await api(`/api/runs/${task.runId}/transcript`);
  await record('transcript-before.json', beforeTranscript);
  await record('m0-guard.json', validateM0Guard(task, run, plan, beforeTranscript));
  if (task.initialNormalFlow) {
    counts.initialNormalFlowSubmissions++;
    const observed = await browser.normalFlow(`${task.suiteBaseUrl}/p/${task.planId}/start/m0-roundtrip?run=${task.runId}`, task.actionTimeoutSeconds);
    counts.manualAuthenticationCheckpoints += observed.manualAuthenticationCheckpoints;
    await record('initial-normal-flow.json', observed);
    if (!observed.recorded) throw new Error('The actual normal flow did not complete');
  }
  if (task.startTests) {
    counts.fullProfileStartCalls++;
    await record('tests-start.json', await api(`/api/runs/${task.runId}/tests/start`, {}));
  }
  const steps = [];
  const seen = new Set();
  let pendingAction = null;
  try {
    for (let index = 0; index < task.maxActions; index++) {
      const status = await api(`/api/runs/${task.runId}/active-probe`);
      if (status.state !== 'READY') {
        steps.push({ state: status.state, caseId: status.caseId ?? null, action: 'stop-without-retry' });
        if (status.state === 'AWAITING_RESPONSE') {
          pendingAction = { state: status.state, caseId: status.caseId, actionId: status.actionId };
          counts.liveActionsRetained++;
        }
        break;
      }
      probeUrl(task, status);
      if (!membership.actualRunCaseIds.includes(status.caseId)) throw new Error('Ready action is outside the actual Run membership');
      if (seen.has(status.actionId)) throw new Error('The same one-use action became READY twice');
      seen.add(status.actionId);
      if (!selected.has(status.caseId)) {
        await browser.prepareWithoutTarget(task, status);
        const prepared = await api(`/api/runs/${task.runId}/active-probe`);
        if (prepared.state !== 'AWAITING_RESPONSE' || prepared.caseId !== status.caseId
            || prepared.actionId !== status.actionId) throw new Error('Skipped action preparation did not remain current');
        counts.preparedActions++;
        await api(`/api/runs/${task.runId}/active-probe/abort`, {});
        counts.skippedBeforeTargetSubmission++;
        steps.push({ caseId: status.caseId, actionId: status.actionId, action: 'prepared-and-skipped', targetSubmitted: false });
      } else {
        const policy = sessionPolicy(status);
        if (policy === 'fresh-empty-context') counts.freshEmptyContexts++;
        else counts.authenticatedContextReuses++;
        counts.selectedBrowserDispatchAttempts++;
        const observed = await browser.probe(task, status, policy, api);
        counts.preparedActions++;
        counts.selectedTargetActions++;
        counts.manualAuthenticationCheckpoints += observed.manualAuthenticationCheckpoints;
        let after = await api(`/api/runs/${task.runId}/active-probe`);
        if (after.actionId === status.actionId && after.caseId === status.caseId
            && after.state === 'AWAITING_RESPONSE'
            && ['target-http-error-without-saml', 'passive-request-required-authentication'].includes(observed.reason)) {
          const landing = new URL(observed.observedTerminalUrl);
          if (!task.targetOrigins.includes(landing.origin) || landing.search || landing.hash
              || !Number.isInteger(observed.httpStatus) || observed.httpStatus < 100 || observed.httpStatus > 599
              || observed.reason === 'target-http-error-without-saml' && observed.httpStatus < 400) {
            throw new Error('Terminal browser fact is outside the configured target');
          }
          // This is an observed HTTP landing, never a SAML Status or native
          // rejection proof. An empty body explicitly omits potentially private
          // authentication HTML. The f/ep/d oracles remain NOT_VERIFIED for it,
          // while their ordinary scenario engine can continue its next fixture.
          await api(`/api/runs/${task.runId}/active-probe/browser-response`, {
            actionId: status.actionId, status: observed.httpStatus, url: landing.href, body: '' });
          if (observed.reason === 'target-http-error-without-saml') counts.terminalHttpObservationsWithBodyOmitted++;
          else counts.passiveAuthenticationLandingsWithBodyOmitted++;
          after = await api(`/api/runs/${task.runId}/active-probe`);
        }
        steps.push({ caseId: status.caseId, actionId: status.actionId, sessionPolicy: policy,
          targetSubmitted: true, observation: observed, nextState: after.state });
        if (after.actionId === status.actionId && after.caseId === status.caseId
            && ['READY', 'AWAITING_RESPONSE'].includes(after.state)) {
          // Polling expiry is an observation limit, not a terminal Runner event.
          // Keep the existing action; neither abort nor re-evaluate its live state.
          pendingAction = { state: after.state, caseId: after.caseId, actionId: after.actionId };
          counts.liveActionsRetained++;
          steps.at(-1).action = 'live-action-retained';
          await record('steps.json', steps);
          break;
        }
      }
      await record('steps.json', steps);
      if (selected.size && [...selected].every(id => steps.some(step => step.caseId === id))) {
        const next = await api(`/api/runs/${task.runId}/active-probe`);
        if (!selected.has(next.caseId)) break; // do not cut off remaining fixtures of the final case
      }
    }
    await record('evaluation.json', pendingAction
      ? { performed: false, reason: 'live-action-retained', pendingAction }
      : await api(`/api/runs/${task.runId}/protocol-evidence/evaluate`, {}));
    return { counts, membership, steps,
      collectionState: pendingAction ? 'AWAITING_RESPONSE' : 'COLLECTED', pendingAction };
  } finally {
    await record('steps.json', steps);
    await record('operation-counts.json', { ...counts, settingsWereNotModifiedByCollector: true,
      restorationRequired: false, sessionStorageExported: false,
      credentialFieldsFilledByCollector: false,
      fullProfileMayStartUnselectedCases: task.startTests,
      fullProfileCaseMembershipCount: membership.actualRunCaseCount,
      fullProfileQueueChangeCount: null,
      fullProfileQueueChangesMeasured: false,
      manualAuthenticationCheckpointsAreNotCredentialSubmissionCounts: true,
      verdictAdopted: false });
  }
}

export async function playwrightAdapter(task, chromium, record, originals) {
  const browser = await chromium.launch({ channel: process.env.SAML_SCOPE_BROWSER_CHANNEL || 'chrome', headless: false });
  const authenticated = await browser.newContext();
  const suiteOrigin = task.suiteBaseUrl;
  const allowed = new Set([suiteOrigin, ...task.targetOrigins]);
  let active = null;
  let captureFailure = null;
  let sequence = 0;
  const monitored = new Set();
  async function monitor(context) {
    if (monitored.has(context)) return;
    monitored.add(context);
    await context.route('**/*', async route => {
      const request = route.request();
      if (request.isNavigationRequest() && !allowed.has(new URL(request.url()).origin)) return route.abort('blockedbyclient');
      await route.continue();
    });
    context.on('request', request => {
      try {
        const captured = samlMessage(task, request, active);
        if (!captured) return;
        captured.file = `browser-saml-originals/${String(++sequence).padStart(4, '0')}-${captured.record.sha256}.xml`;
        originals.push(captured);
      } catch (error) { captureFailure = error; }
    });
  }
  await monitor(authenticated);
  const api = async (path, body) => {
    if (!path.startsWith('/api/')) throw new Error('Not a Suite API path');
    const response = await authenticated.request.fetch(suiteOrigin + path, { method: body === undefined ? 'GET' : 'POST',
      ...(body === undefined ? {} : { data: body }), timeout: 30000, maxRedirects: 0 });
    if (!response.ok()) throw new Error(`Suite API status ${response.status()}`);
    return response.json();
  };
  async function navigate(url, context, timeoutSeconds, status, poll) {
    const page = await context.newPage();
    let checkpoint = false;
    let terminalStatus = null;
    let lastNavigationStatus = null;
    page.on('response', response => {
      if (response.request().isNavigationRequest() && response.frame() === page.mainFrame()) {
        lastNavigationStatus = response.status();
        if (task.targetOrigins.includes(new URL(response.url()).origin) && response.status() >= 400) terminalStatus = response.status();
      }
    });
    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      if (status) {
        if (page.url() !== url) throw new Error('The Suite probe redirected before deliberate submission');
        const confirmation = page.locator('input[name="freshSessionConfirmed"]');
        if (status.requiresFreshSession) {
          if (context === authenticated || await confirmation.count() !== 1) throw new Error('Fresh context confirmation is unproven');
          await confirmation.check();
        } else if (await confirmation.count()) throw new Error('Fresh session policy differs from the actual page');
        await page.getByRole('button', { name: 'Continue with this request', exact: true }).click();
      }
      const until = Date.now() + timeoutSeconds * 1000;
      while (Date.now() < until) {
        if (captureFailure) throw captureFailure;
        if (poll && await poll()) return { recorded: true, manualAuthenticationCheckpoints: checkpoint ? 1 : 0 };
        if (page.isClosed()) {
          // Suite receipt pages close after recording. Require server-side progression.
          if (poll) { await sleep(100); continue; }
          return { recorded: false, manualAuthenticationCheckpoints: checkpoint ? 1 : 0 };
        }
        if (await page.locator('input[type="password"]').count()) {
          if (status?.requiresFreshSession) {
            const landing = new URL(page.url());
            return { recorded: false, reason: 'passive-request-required-authentication',
              httpStatus: lastNavigationStatus, observedTerminalUrl: landing.origin + landing.pathname,
              responseBodyExported: false, manualAuthenticationCheckpoints: 0 };
          }
          if (!checkpoint) {
            checkpoint = true;
            process.stderr.write('Complete the sign-in in the visible browser. Credentials stay in that browser context.\n');
          }
        }
        if (terminalStatus !== null && await page.locator('input[name="SAMLResponse"]').count() === 0) {
          const landing = new URL(page.url());
          return { recorded: false, reason: 'target-http-error-without-saml',
            httpStatus: terminalStatus, observedTerminalUrl: landing.origin + landing.pathname,
            responseBodyExported: false, manualAuthenticationCheckpoints: checkpoint ? 1 : 0 };
        }
        if (!poll && new URL(page.url()).origin === suiteOrigin
            && await page.getByText('M0 SSO round trip completed', { exact: false }).count()) {
          return { recorded: true, manualAuthenticationCheckpoints: checkpoint ? 1 : 0 };
        }
        await sleep(300);
      }
      return { recorded: false, reason: 'observation-timeout', lastNavigationStatus,
        manualAuthenticationCheckpoints: checkpoint ? 1 : 0 };
    } finally { if (!page.isClosed()) await page.close(); }
  }
  return {
    api,
    async normalFlow(url, timeout) { return navigate(url, authenticated, timeout, null, null); },
    async prepareWithoutTarget(currentTask, status) {
      const response = await authenticated.request.post(probeUrl(currentTask, status), {
        form: { freshSessionConfirmed: 'true' }, maxRedirects: 0, timeout: 30000 });
      if (response.status() < 200 || response.status() >= 400) throw new Error('Suite-only preparation failed');
      // APIRequestContext does not execute HTML or follow this disabled redirect.
    },
    async probe(currentTask, status, policy, currentApi) {
      const context = policy === 'fresh-empty-context' ? await browser.newContext() : authenticated;
      await monitor(context);
      active = status;
      try {
        return await navigate(probeUrl(currentTask, status), context, currentTask.actionTimeoutSeconds, status,
          async () => { const after = await currentApi(`/api/runs/${currentTask.runId}/active-probe`);
            return after.actionId !== status.actionId || !['READY', 'AWAITING_RESPONSE'].includes(after.state); });
      } finally { active = null; if (context !== authenticated) await context.close(); }
    },
    async close() {
      await browser.close();
      if (browser.isConnected()) throw new Error('Browser closure is unproven');
      return { browserContextsClosed: true };
    },
  };
}

async function main() {
  if (process.argv.length !== 3) throw new Error('Provide one public task JSON path');
  const task = validateTask(JSON.parse(await readFile(process.argv[2], 'utf8')));
  await mkdir(task.outputDirectory, { recursive: true });
  if ((await readdir(task.outputDirectory)).length) throw new Error('Output directory must be empty');
  const require = createRequire(import.meta.url);
  const dependency = process.env.SAML_SCOPE_PLAYWRIGHT;
  if (!dependency || !dependency.startsWith('/')) throw new Error('Set SAML_SCOPE_PLAYWRIGHT to the installed absolute package path');
  const { chromium } = require(dependency);
  const record = async (name, value) => writeFile(resolve(task.outputDirectory, name), JSON.stringify(value, null, 2) + '\n');
  await record('task.json', task);
  const originals = [];
  const adapter = await playwrightAdapter(task, chromium, record, originals);
  let succeeded = false;
  let collected = null;
  let transcript = null;
  try {
    collected = await collectSelected(task, adapter.api, adapter, record);
    await record('collection-state.json', { state: collected.collectionState, pendingAction: collected.pendingAction });
    transcript = await adapter.api(`/api/runs/${task.runId}/transcript`);
    await record('transcript.json', transcript);
    await record('result.json', await adapter.api(`/api/runs/${task.runId}/result.json`));
    succeeded = true;
  } finally {
    let browserContextsClosed = false;
    try {
      // Keep public protocol originals from failed attempts as well. Without a
      // server transcript they remain explicitly unqualified supplemental bytes.
      await mkdir(resolve(task.outputDirectory, 'browser-saml-originals'));
      for (const capture of originals) await writeFile(resolve(task.outputDirectory, capture.file), capture.bytes, { flag: 'wx' });
      await record('browser-saml-manifest.json', transcript
        ? bindProtocolOriginals(task, originals, transcript)
        : originals.map(capture => ({ ...capture.record, file: capture.file,
            transcriptReferences: [], bindingState: 'original-captured-recorder-unavailable',
            conformanceConclusionAssigned: false })));
    } finally {
      try { browserContextsClosed = (await adapter.close()).browserContextsClosed === true; }
      finally {
        await record('collector-completion.json', { succeeded, verdictAdopted: false,
          collectionState: collected?.collectionState ?? 'FAILED', pendingAction: collected?.pendingAction ?? null,
          browserContextsClosed, credentialsOrCookiesExported: false,
          collectorChangedProductSettings: false, restorationRequired: false,
          protocolOriginalsCaptured: originals.length });
      }
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  // Browser errors can contain a login URL with opaque state. Do not print them.
  main().catch(error => { process.stderr.write(`Browser collector failed (${error.name}); no conclusion adopted.\n`); process.exitCode = 1; });
}
