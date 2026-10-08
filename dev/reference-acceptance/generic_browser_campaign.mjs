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
import { createInterface } from 'node:readline';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const RUN = /^run_[0-9A-HJKMNP-TV-Z]{26}$/;
const PLAN = /^plan_[0-9A-HJKMNP-TV-Z]{26}$/;
const TX = /^tx_[0-9A-HJKMNP-TV-Z]{26}$/;
const CASE = /^IIP-[A-Za-z0-9]+-[A-Za-z0-9]+-idp-01$/;
const ACTION = /^action_[a-f0-9]{32}$/;
const sleep = milliseconds => new Promise(done => setTimeout(done, milliseconds));
const SENSITIVE = new Set(['managementurl', 'token', 'accesstoken', 'refreshtoken', 'idtoken', 'clientsecret',
  'privatekey', 'password', 'passwd', 'authorization', 'proxyauthorization', 'cookie', 'setcookie',
  'credential', 'credentials', 'bearertoken', 'apikey', 'apisecret']);
export function publicJson(value) {
  if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
    if (SENSITIVE.has(key.replace(/[_-]/g, '').toLowerCase()) && child !== null) throw new Error('Non-public Suite JSON omitted');
    publicJson(child);
  }
  return value;
}

/** Public Recorder projection: omit only irreversible Cookie metadata, never raw values. */
export function publicTranscriptProjection(raw, runId) {
  const fail = () => { throw new Error('Malformed or non-public Transcript omitted'); };
  if (!(raw instanceof Uint8Array) || raw.length > 6 * 1024 * 1024 || !RUN.test(runId)) fail();
  let text; try { text = new TextDecoder('utf-8', { fatal: true }).decode(raw); } catch { fail(); }
  let offset = 0;
  const space = () => { while (/\s/.test(text[offset] ?? '') && offset < text.length) offset++; };
  const string = () => {
    if (text[offset] !== '"') fail(); const start = offset++;
    while (offset < text.length) {
      const character = text[offset++]; if (character === '\\') { offset++; continue; }
      if (character === '"') { try { return JSON.parse(text.slice(start, offset)); } catch { fail(); } }
    }
    fail();
  };
  const value = () => {
    space(); const first = text[offset];
    if (first === '{') {
      offset++; space(); const keys = new Set(); if (text[offset] === '}') { offset++; return; }
      while (true) {
        space(); const key = string(); if (keys.has(key)) fail(); keys.add(key); space(); if (text[offset++] !== ':') fail(); value(); space();
        const next = text[offset++]; if (next === '}') return; if (next !== ',') fail();
      }
    }
    if (first === '[') {
      offset++; space(); if (text[offset] === ']') { offset++; return; }
      while (true) { value(); space(); const next = text[offset++]; if (next === ']') return; if (next !== ',') fail(); }
    }
    if (first === '"') { string(); return; }
    const primitive = /^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(offset));
    if (!primitive || !['null', 'true', 'false'].includes(primitive[0]) && !Number.isFinite(Number(primitive[0]))) fail();
    offset += primitive[0].length;
  };
  value(); space(); if (offset !== text.length) fail();
  let rows; try { rows = JSON.parse(text); } catch { fail(); }
  if (!Array.isArray(rows) || rows.some(row => !row || row.runId !== runId || typeof row.id !== 'string')
      || new Set(rows.map(row => row.id)).size !== rows.length) fail();
  for (const row of rows) {
    if (row.headers === undefined || row.headers === null) continue;
    if (typeof row.headers !== 'object' || Array.isArray(row.headers)) fail();
    const cookieKeys = Object.keys(row.headers).filter(key => key.toLowerCase() === 'cookie');
    if (cookieKeys.length > 1) fail();
    for (const key of cookieKeys) {
      const headers = row.headers[key]; const names = new Set();
      if (headers !== null) {
        if (!Array.isArray(headers) || headers.length === 0) fail();
        for (const header of headers) {
          if (typeof header !== 'string') fail();
          for (const part of header.split('; ')) {
            const matched = /^([!#$%&'*+\-.^_`|~0-9A-Za-z]+)=<redacted: (0|[1-9][0-9]*) bytes>$/.exec(part);
            if (!matched || !Number.isSafeInteger(Number(matched[2])) || names.has(matched[1])) fail();
            names.add(matched[1]);
          }
        }
      }
      delete row.headers[key];
    }
  }
  return publicJson(rows); // Global rejection of all other credential fields stays unchanged.
}

export function checkedOrigin(value) {
  const url = new URL(value);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password
      || url.pathname !== '/' || url.search || url.hash) throw new Error('Invalid browser origin');
  return url.origin;
}

export function validateTask(input) {
  const allowedFields = new Set(['suiteBaseUrl', 'runId', 'planId', 'caseIds', 'targetOrigins',
    'outputDirectory', 'maxActions', 'actionTimeoutSeconds', 'startTests', 'initialNormalFlow', 'completeNormalFlow']);
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
  if (input.completeNormalFlow !== undefined && typeof input.completeNormalFlow !== 'boolean') throw new Error('Invalid normal completion policy');
  if (input.completeNormalFlow && input.initialNormalFlow) throw new Error('Two normal-flow submissions are forbidden');
  const maxActions = input.maxActions ?? 400;
  const actionTimeoutSeconds = input.actionTimeoutSeconds ?? 300;
  if (!Number.isInteger(maxActions) || maxActions < 1 || maxActions > 2000
      || !Number.isInteger(actionTimeoutSeconds) || actionTimeoutSeconds < 1
      || actionTimeoutSeconds > 3600) throw new Error('Invalid campaign limits');
  if (typeof input.outputDirectory !== 'string' || !input.outputDirectory) throw new Error('Output directory is required');
  return Object.freeze({ ...input, suiteBaseUrl: suite, targetOrigins: targets,
    outputDirectory: resolve(input.outputDirectory), maxActions, actionTimeoutSeconds,
    startTests: input.startTests === true, initialNormalFlow: input.initialNormalFlow === true,
    completeNormalFlow: input.completeNormalFlow === true });
}

const actualRun = run => run.run ?? run;
const actualPlan = plan => plan.plan?.plan ?? plan.plan ?? plan;
function normalIdentity(task, run, plan) {
  if (actualRun(run).id !== task.runId || actualRun(run).planId !== task.planId
      || actualPlan(plan).id !== task.planId || actualPlan(plan).profile !== 'browser_sso_idp'
      || actualPlan(plan).target?.kind !== 'IDP') throw new Error('Normal flow identity/profile mismatch');
}

/** Public zero-execution projections. There is no public outbox-count endpoint. */
export async function assertEmptyNormalScope(task, api, run, { cold = false } = {}) {
  const current = actualRun(run);
  if (cold && (current.status !== 'CREATED' || current.context?.authnRequestId != null)) {
    throw new Error('Cold normal flow requires CREATED without an AuthnRequest');
  }
  const campaigns = await api(`/api/runs/${task.runId}/campaigns`);
  const protocol = await api(`/api/runs/${task.runId}/protocol-evidence`);
  const interactions = await api(`/api/runs/${task.runId}/interactions`);
  const probe = await api(`/api/runs/${task.runId}/active-probe`);
  if (campaigns.runId !== task.runId || campaigns.cases !== 0
      || !Array.isArray(campaigns.classifications) || campaigns.classifications.length
      || !Array.isArray(campaigns.campaigns) || campaigns.campaigns.length
      || protocol.eligibleCases !== 0 || protocol.readyCases !== 0
      || !Array.isArray(protocol.cases) || protocol.cases.length
      || !Array.isArray(interactions) || interactions.length
      || probe.state !== 'NOT_STARTED') throw new Error('Normal flow requires zero actual case executions');
  return { runId: task.runId, runStatus: current.status, actualCaseExecutions: 0,
    pendingInteractions: 0, readyOrLiveCaseActions: 0, outboxCountMeasured: false,
    targetSamlSendCountMeasured: false, source: 'official-public-zero-execution-projections' };
}

/** An existing M0 handle is observed, never reissued by GET/start or preflight. */
export async function completeNormalControl(task, api, browser, record, counts, initialRun, plan) {
  let run = initialRun;
  normalIdentity(task, run, plan);
  let transcript = await api(`/api/runs/${task.runId}/transcript`);
  if (actualRun(run).status === 'COMPLETED') {
    const membership = validateMembership(task, run, plan, await api(`/api/runs/${task.runId}/result.json`));
    await record('m0-guard.json', validateM0Guard(task, run, plan, transcript));
    return { run, transcript, membership, pendingNormalFlow: null };
  }
  const cold = actualRun(run).status === 'CREATED' && actualRun(run).context?.authnRequestId == null;
  if (cold) {
    if (!Array.isArray(transcript) || transcript.length) throw new Error('Cold normal flow has existing Recorder operations');
    await record('normal-scope-before-preflight.json', await assertEmptyNormalScope(task, api, run, { cold: true }));
    counts.normalPreflightCalls++;
    const preflight = await api(`/api/runs/${task.runId}/preflight`, {});
    await record('normal-preflight.json', preflight);
    if (!Array.isArray(preflight.checks) || preflight.checks.some(check => check.status === 'FAIL')) throw new Error('Normal preflight failed');
    run = await api(`/api/runs/${task.runId}`);
    if (actualRun(run).status !== 'RUNNING' || actualRun(run).context?.authnRequestId != null) throw new Error('Preflight changed normal flow unexpectedly');
    await assertEmptyNormalScope(task, api, run);
    counts.normalEmptyEvaluations++;
    const evaluated = await api(`/api/runs/${task.runId}/protocol-evidence/evaluate`, {});
    if (!Array.isArray(evaluated.completed) || evaluated.completed.length
        || evaluated.remaining?.eligibleCases !== 0 || evaluated.remaining?.readyCases !== 0
        || !Array.isArray(evaluated.remaining?.cases) || evaluated.remaining.cases.length) throw new Error('Cold evaluation executed a case');
    await record('normal-empty-evaluation.json', evaluated);
    run = await api(`/api/runs/${task.runId}`);
    if (actualRun(run).status !== 'RUNNING' || actualRun(run).context?.authnRequestId != null) throw new Error('Cold evaluation started M0');
    transcript = await api(`/api/runs/${task.runId}/transcript`);
    if (transcript.length) throw new Error('Cold evaluation recorded an outbound operation');
    await record('normal-scope-after-empty-evaluation.json', await assertEmptyNormalScope(task, api, run));
  } else if (actualRun(run).status !== 'WAITING_BROWSER'
      || typeof actualRun(run).context?.authnRequestId !== 'string'
      || !/^_[A-Za-z0-9_-]+$/.test(actualRun(run).context.authnRequestId)) {
    throw new Error('Normal flow is neither safe cold scope nor an existing live M0');
  } else {
    await assertEmptyNormalScope(task, api, run);
    if (!transcript.some(entry => entry.runId === task.runId && entry.direction === 'OUTBOUND'
        && entry.samlSummary?.type === 'AuthnRequest' && entry.samlSummary.id === actualRun(run).context.authnRequestId)) {
      throw new Error('Existing live M0 has no matching Recorder request');
    }
  }
  const membership = validateMembership(task, run, plan, await api(`/api/runs/${task.runId}/result.json`));
  await record('membership.json', membership);
  let guard;
  const poll = async () => {
    run = await api(`/api/runs/${task.runId}`);
    if (actualRun(run).status !== 'COMPLETED') return false;
    transcript = await api(`/api/runs/${task.runId}/transcript`);
    guard = validateM0Guard(task, run, plan, transcript); // Success HTML cannot satisfy this.
    return true;
  };
  let observed;
  if (cold) {
    counts.initialNormalFlowSubmissions++;
    counts.normalLoginContexts++;
    observed = await browser.normalFlow(`${task.suiteBaseUrl}/p/${task.planId}/start/m0-roundtrip?run=${task.runId}`,
      task.actionTimeoutSeconds, poll);
  } else {
    const handle = { runId: task.runId, planId: task.planId, authnRequestId: actualRun(run).context.authnRequestId };
    counts.normalPollOnlyResumes++;
    observed = await browser.resumeNormalFlow(handle, task.actionTimeoutSeconds, poll);
  }
  counts.manualAuthenticationCheckpoints += observed.manualAuthenticationCheckpoints ?? 0;
  await record('normal-flow-observation.json', observed);
  if (await poll()) {
    await record('m0-guard.json', guard);
    return { run, transcript, membership, pendingNormalFlow: null };
  }
  const authnRequestId = actualRun(run).context?.authnRequestId;
  if (actualRun(run).status !== 'WAITING_BROWSER' || typeof authnRequestId !== 'string'
      || !/^_[A-Za-z0-9_-]+$/.test(authnRequestId)) throw new Error('Pending M0 handle is unproven');
  counts.liveNormalFlowsRetained++;
  return { run, transcript, membership, pendingNormalFlow: { runId: task.runId, planId: task.planId,
    authnRequestId, state: 'WAITING_BROWSER', browserPageRetained: observed.browserPageRetained === true,
    resumePolicy: 'poll-only-no-start-resend' } };
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
  normalIdentity(task, run, plan);
  const effectiveRun = run.run ?? run;
  const effectivePlan = plan.plan?.plan ?? plan.plan ?? plan;
  const nonce = effectiveRun.context?.authnRequestId;
  if (effectiveRun.status !== 'COMPLETED' || typeof nonce !== 'string' || !/^_[A-Za-z0-9_-]+$/.test(nonce) || !Array.isArray(transcript)
      || new Set(transcript.map(entry => entry.id)).size !== transcript.length
      || transcript.some(entry => entry.runId !== task.runId)) throw new Error('Normal-flow Run completion is unproven');
  const controls = transcript.filter(entry => entry.direction === 'INBOUND'
    && entry.samlSummary?.normalFlowAccepted === true && entry.samlSummary?.type === 'Response'
    && entry.samlSummary?.statusCode === 'urn:oasis:names:tc:SAML:2.0:status:Success'
    && entry.samlSummary?.issuer === effectivePlan.target.entityId
    && entry.samlSummary?.destination === `${task.suiteBaseUrl}/p/${task.planId}/sp/acs/0`
    && entry.url === entry.samlSummary.destination && entry.correlationId === entry.samlSummary.inResponseTo
    && entry.samlSummary.inResponseTo === nonce
    && transcript.filter(request => request.direction === 'OUTBOUND'
      && request.samlSummary?.type === 'AuthnRequest' && request.samlSummary?.id === nonce).length === 1);
  if (controls.length !== 1) throw new Error('Accepted, correlated normal SSO control is missing or ambiguous');
  const requests = transcript.filter(request => request.direction === 'OUTBOUND'
    && request.samlSummary?.type === 'AuthnRequest' && request.samlSummary?.id === nonce);
  return { runId: task.runId, planId: task.planId, completedRunStatus: effectiveRun.status, activeAuthnRequestId: nonce,
    normalAuthnRequestReferences: requests.map(entry => entry.id),
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
  if ([...fields.keys()].some(key => !['SAMLRequest', 'SAMLResponse', 'RelayState', 'SigAlg', 'Signature'].includes(key))) return null;
  if (fields.getAll(field).length !== 1 || fields.has(isSuite ? 'SAMLRequest' : 'SAMLResponse')) return null;
  const encoded = fields.get(field);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded) || !encoded) throw new Error('Malformed SAML base64');
  let bytes = Buffer.from(encoded, 'base64');
  if (binding === 'HTTP-Redirect') bytes = inflateRawSync(bytes, { maxOutputLength: 4 * 1024 * 1024 });
  if (bytes.length > 4 * 1024 * 1024) throw new Error('Oversized SAML message');
  return { bytes, record: { runId: task.runId, planId: task.planId,
    ...(action.operationKind === 'M0_NORMAL' ? { operationKind: 'M0_NORMAL' }
      : { caseId: action.caseId, actionId: action.actionId, fixtureContext: action.fixtureContext ?? null }),
    direction: isSuite ? 'INBOUND' : 'OUTBOUND', binding,
    // URLs can contain opaque login state. Keep the public endpoint without its query.
    endpoint: url.origin + url.pathname, sha256: sha(bytes), bytes: bytes.length,
    observedAtUtc: new Date().toISOString() } };
}

function protocolOriginalCandidates(task, capture, transcript, normalGuard) {
  if (capture.record.runId !== task.runId || capture.record.planId !== task.planId) throw new Error('Capture belongs to another Run or Plan');
  const normalRefs = direction => direction === 'INBOUND' ? normalGuard?.acceptedNormalFlowReferences : normalGuard?.normalAuthnRequestReferences;
  const normalGuardBound = normalGuard?.source === 'official-Suite-Recorder-normalFlowAccepted'
    && normalGuard?.runId === task.runId && normalGuard?.planId === task.planId
    && /^_[A-Za-z0-9_-]+$/.test(normalGuard.activeAuthnRequestId ?? '')
    && ['INBOUND', 'OUTBOUND'].every(direction => Array.isArray(normalRefs(direction)) && normalRefs(direction).length === 1
      && transcript.some(entry => entry.id === normalRefs(direction)[0] && entry.direction === direction
        && (direction === 'INBOUND' ? entry.samlSummary?.normalFlowAccepted === true
          && entry.samlSummary?.inResponseTo === normalGuard.activeAuthnRequestId && entry.correlationId === normalGuard.activeAuthnRequestId
          : entry.samlSummary?.id === normalGuard.activeAuthnRequestId)));
  return transcript.filter(entry => TX.test(entry.id) && entry.direction === capture.record.direction
    && entry.decodedSamlBytes === capture.record.bytes
    && entry.decodedSamlRef === `transcripts/${task.runId}/${entry.id}.saml.xml`
    && entry.samlSummary?.type === (capture.record.direction === 'INBOUND' ? 'Response' : 'AuthnRequest')
    && (capture.record.operationKind === 'M0_NORMAL'
      ? normalGuardBound && normalRefs(capture.record.direction).includes(entry.id)
      : task.caseIds.includes(capture.record.caseId) && ACTION.test(capture.record.actionId ?? '')
        && (capture.record.direction === 'INBOUND'
          ? entry.correlationId === '_' + capture.record.actionId
          : entry.correlationId === capture.record.actionId && entry.samlSummary?.scenario_case_id === capture.record.caseId)));
}

function checkedTranscript(task, transcript) {
  if (!Array.isArray(transcript) || new Set(transcript.map(entry => entry.id)).size !== transcript.length
      || transcript.some(entry => entry.runId !== task.runId)) throw new Error('Transcript is not uniquely bound to this Run');
}

export function validateNativeOriginalDigest(task, txId, value) {
  publicJson(value);
  if (!TX.test(txId) || !value || Object.keys(value).sort().join(',') !== 'decodedSamlBytes,decodedSamlSha256,runId,schema,txId'
      || value.schema !== 'samlscope-transcript-original-digest-v1' || value.runId !== task.runId || value.txId !== txId
      || !/^[a-f0-9]{64}$/.test(value.decodedSamlSha256 ?? '') || !Number.isSafeInteger(value.decodedSamlBytes)
      || value.decodedSamlBytes <= 0 || value.decodedSamlBytes > 4 * 1024 * 1024) throw new Error('Invalid native original digest omitted');
  return value;
}

/** Fetch each selected, correlated native original once per collector generation. */
export async function collectNativeOriginalDigests(task, captures, transcript, readDigest, normalGuard = null, proofs = new Map()) {
  checkedTranscript(task, transcript);
  if (!(proofs instanceof Map)) throw new Error('Invalid native proof map');
  for (const capture of captures) for (const entry of protocolOriginalCandidates(task, capture, transcript, normalGuard)) {
    if (proofs.has(entry.id)) continue;
    try { proofs.set(entry.id, validateNativeOriginalDigest(task, entry.id, await readDigest(entry.id))); }
    catch { proofs.set(entry.id, { runId: task.runId, txId: entry.id, state: 'unavailable',
      reason: 'native-original-unavailable-or-invalid', originalContentExported: false }); }
  }
  return proofs;
}

export function bindProtocolOriginals(task, captures, transcript, normalGuard = null, nativeProofs = new Map()) {
  checkedTranscript(task, transcript);
  if (!(nativeProofs instanceof Map)) throw new Error('Invalid native proof map');
  const bindings = [];
  for (const capture of captures) {
    const owned = protocolOriginalCandidates(task, capture, transcript, normalGuard).filter(entry => {
      try {
        const proof = validateNativeOriginalDigest(task, entry.id, nativeProofs.get(entry.id));
        return proof.decodedSamlBytes === capture.record.bytes && proof.decodedSamlSha256 === capture.record.sha256;
      } catch { return false; }
    });
    bindings.push({ ...capture.record, file: capture.file,
      transcriptReferences: owned.length === 1 ? [owned[0].id] : [],
      ...(owned.length === 1 ? { nativeDigestReference: `/api/runs/${task.runId}/transcript/${owned[0].id}/original-digest`,
        bindingProofSource: 'native-original-digest-api' } : {}),
      bindingState: owned.length === 1 ? (capture.record.operationKind === 'M0_NORMAL'
        ? 'recorder-hash-and-normal-flow-bound' : 'recorder-hash-and-action-bound') : 'original-captured-recorder-hash-unavailable',
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
    normalPreflightCalls: 0, normalEmptyEvaluations: 0, normalLoginContexts: 0,
    normalPollOnlyResumes: 0, liveNormalFlowsRetained: 0,
    conclusionAssignments: 0, liveActionsRetained: 0 };
  let run = await api(`/api/runs/${task.runId}`);
  const plan = await api(`/api/plans/${task.planId}`);
  let membership;
  let beforeTranscript;
  const recordCounts = async () => record('operation-counts.json', { ...counts, settingsWereNotModifiedByCollector: true,
    restorationRequired: false, sessionStorageExported: false, credentialFieldsFilledByCollector: false,
    normalLoginContextIsBrowserReuseNotMeasuredHumanLoginCount: true,
    actualHumanLoginCount: null, actualHumanLoginCountMeasured: false,
    fullProfileMayStartUnselectedCases: task.startTests,
    fullProfileCaseMembershipCount: membership?.actualRunCaseCount ?? null,
    fullProfileQueueChangeCount: null, fullProfileQueueChangesMeasured: false,
    manualAuthenticationCheckpointsAreNotCredentialSubmissionCounts: true, verdictAdopted: false });
  try {
    if (task.completeNormalFlow) {
      const normal = await completeNormalControl(task, api, browser, record, counts, run, plan);
      ({ run, membership, transcript: beforeTranscript } = normal);
      if (normal.pendingNormalFlow) {
        await recordCounts();
        await record('evaluation.json', { performed: false, reason: 'live-normal-flow-retained' });
        return { counts, membership, steps: [], collectionState: 'WAITING_M0', pendingAction: null,
          pendingNormalFlow: normal.pendingNormalFlow };
      }
    } else {
      membership = validateMembership(task, run, plan, await api(`/api/runs/${task.runId}/result.json`));
      beforeTranscript = await api(`/api/runs/${task.runId}/transcript`);
      await record('m0-guard.json', validateM0Guard(task, run, plan, beforeTranscript));
    }
  } catch (error) { await recordCounts(); throw error; }
  await record('membership.json', membership);
  await record('transcript-before.json', beforeTranscript);
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
    await recordCounts();
  }
}

export async function playwrightAdapter(task, chromium, record, originals) {
  const browser = await chromium.launch({ channel: process.env.SAML_SCOPE_BROWSER_CHANNEL || 'chrome', headless: false });
  let authenticated;
  try { authenticated = await browser.newContext(); } catch (error) { await browser.close(); throw error; }
  const suiteOrigin = task.suiteBaseUrl;
  const allowed = new Set([suiteOrigin, ...task.targetOrigins]);
  let active = null;
  let captureFailure = null;
  let sequence = 0;
  let normalPage = null;
  let normalCheckpoint = false;
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
    if (!/^application\/json(?:;|$)/i.test(response.headers()['content-type'] ?? '')) throw new Error('Non-JSON Suite body omitted');
    if (path === `/api/runs/${task.runId}/transcript`) return publicTranscriptProjection(await response.body(), task.runId);
    return publicJson(await response.json());
  };
  const readOriginalDigest = txId => {
    if (!TX.test(txId)) throw new Error('Invalid Transcript identifier');
    return api(`/api/runs/${task.runId}/transcript/${txId}/original-digest`);
  };
  async function navigate(url, context, timeoutSeconds, status, poll, normal = false) {
    // A resume supplies no URL and cannot invoke page.goto or another M0 GET.
    if (normal && !url && (!normalPage || normalPage.isClosed())) {
      return { recorded: false, reason: 'no-live-browser-page', browserPageRetained: false, manualAuthenticationCheckpoints: 0 };
    }
    const page = normal && normalPage ? normalPage : await context.newPage();
    if (normal) normalPage = page;
    let checkpoint = normal && normalCheckpoint;
    let retain = false;
    let terminalStatus = null;
    let lastNavigationStatus = null;
    const observeResponse = response => {
      if (response.request().isNavigationRequest() && response.frame() === page.mainFrame()) {
        lastNavigationStatus = response.status();
        if (task.targetOrigins.includes(new URL(response.url()).origin) && response.status() >= 400) terminalStatus = response.status();
      }
    };
    page.on('response', observeResponse);
    try {
      if (url) {
        try { await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 }); }
        catch (error) {
          if (!normal) throw error;
          retain = !page.isClosed();
          return { recorded: false, reason: 'normal-navigation-observation-error', browserPageRetained: retain,
            manualAuthenticationCheckpoints: checkpoint ? 1 : 0 };
        }
      }
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
        if (poll && await poll()) return { recorded: true, browserPageRetained: false,
          manualAuthenticationCheckpoints: checkpoint && (!normal || !normalCheckpoint) ? 1 : 0 };
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
          if (normal) retain = true;
          return { recorded: false, reason: 'target-http-error-without-saml',
            httpStatus: terminalStatus, observedTerminalUrl: landing.origin + landing.pathname,
            responseBodyExported: false, browserPageRetained: retain,
            manualAuthenticationCheckpoints: checkpoint && (!normal || !normalCheckpoint) ? 1 : 0 };
        }
        if (!poll && new URL(page.url()).origin === suiteOrigin
            && await page.getByText('M0 SSO round trip completed', { exact: false }).count()) {
          return { recorded: true, manualAuthenticationCheckpoints: checkpoint ? 1 : 0 };
        }
        await sleep(300);
      }
      if (normal) retain = !page.isClosed();
      return { recorded: false, reason: 'observation-timeout', lastNavigationStatus,
        browserPageRetained: retain, manualAuthenticationCheckpoints: checkpoint && (!normal || !normalCheckpoint) ? 1 : 0 };
    } finally {
      page.off('response', observeResponse);
      if (normal) normalCheckpoint = checkpoint;
      if (!retain && !page.isClosed()) await page.close();
      if (normal && !retain) normalPage = null;
    }
  }
  return {
    api,
    readOriginalDigest,
    async normalFlow(url, timeout, poll) {
      if (normalPage) throw new Error('Existing normal page cannot be reissued');
      if (!poll) return navigate(url, authenticated, timeout, null, null); // legacy explicit extra flow
      active = { operationKind: 'M0_NORMAL' };
      const observed = await navigate(url, authenticated, timeout, null, poll, true);
      if (!observed.browserPageRetained) active = null;
      return observed;
    },
    async resumeNormalFlow(handle, timeout, poll) {
      if (handle.runId !== task.runId || handle.planId !== task.planId) throw new Error('Normal handle mismatch');
      active = { operationKind: 'M0_NORMAL' };
      const observed = await navigate(null, authenticated, timeout, null, poll, true);
      if (!observed.browserPageRetained) active = null;
      return observed;
    },
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
    async close(reason = 'collector-finished') {
      await browser.close();
      if (browser.isConnected()) throw new Error('Browser closure is unproven');
      normalPage = null;
      return { browserContextsClosed: true, reason };
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
  let approvedNormalGuard = null;
  const record = async (name, value) => {
    publicJson(value);
    if (name === 'm0-guard.json') approvedNormalGuard = value;
    await writeFile(resolve(task.outputDirectory, name), JSON.stringify(value, null, 2) + '\n');
  };
  await record('task.json', task);
  const originals = [];
  const adapter = await playwrightAdapter(task, chromium, record, originals);
  let succeeded = false;
  let collected = null;
  let transcript = null;
  let explicitlyStopped = false;
  let commands;
  let commandIterator;
  const totalCounts = {};
  const exported = new Set();
  const nativeOriginalProofs = new Map();
  const flushOriginals = async () => {
    await mkdir(resolve(task.outputDirectory, 'browser-saml-originals'), { recursive: true });
    for (const capture of originals) {
      if (exported.has(capture.file)) continue;
      await writeFile(resolve(task.outputDirectory, capture.file), capture.bytes, { flag: 'wx' });
      exported.add(capture.file);
    }
    if (transcript) await collectNativeOriginalDigests(task, originals, transcript,
      adapter.readOriginalDigest, approvedNormalGuard, nativeOriginalProofs);
    await record('native-original-digest-proofs.json', [...nativeOriginalProofs.values()]);
    await record('browser-saml-manifest.json', transcript
      ? bindProtocolOriginals(task, originals, transcript, approvedNormalGuard, nativeOriginalProofs)
      : originals.map(capture => ({ ...capture.record, file: capture.file,
          transcriptReferences: [], bindingState: 'original-captured-recorder-unavailable', conformanceConclusionAssigned: false })));
  };
  try {
    if (task.completeNormalFlow) {
      commands = createInterface({ input: process.stdin, terminal: false });
      commandIterator = commands[Symbol.asyncIterator]();
    }
    for (let attempt = 1; ; attempt++) {
      const attemptPath = `attempt-${String(attempt).padStart(4, '0')}`;
      if (task.completeNormalFlow) await mkdir(resolve(task.outputDirectory, attemptPath));
      const attemptRecord = task.completeNormalFlow ? async (name, value) => {
        await record(`${attemptPath}/${name}`, value); await record(name, value);
      } : record;
      collected = await collectSelected(task, adapter.api, adapter, attemptRecord);
      for (const [key, value] of Object.entries(collected.counts)) totalCounts[key] = (totalCounts[key] ?? 0) + value;
      await record('collection-state.json', { state: collected.collectionState, pendingAction: collected.pendingAction,
        pendingNormalFlow: collected.pendingNormalFlow ?? null });
      transcript = await adapter.api(`/api/runs/${task.runId}/transcript`);
      await record('transcript.json', transcript);
      await record('result.json', await adapter.api(`/api/runs/${task.runId}/result.json`));
      await flushOriginals();
      if (!collected.pendingNormalFlow?.browserPageRetained) { succeeded = collected.collectionState !== 'WAITING_M0'; break; }
      const handle = collected.pendingNormalFlow;
      await record('live-normal-flow.json', { ...handle, processRetained: true, pageOrSessionExported: false });
      process.stderr.write(`M0 retained: ${handle.runId} ${handle.authnRequestId}. Type resume to poll the same page, or stop to close it.\n`);
      let command;
      while (true) {
        const next = await commandIterator.next();
        command = next.done ? 'stop' : next.value.trim();
        if (command === 'resume' || command === 'stop') break;
        process.stderr.write('Use resume or stop; no target request is resent.\n');
      }
      if (command === 'stop') { explicitlyStopped = true; break; }
    }
    await record('campaign-operation-counts.json', { ...totalCounts, actualHumanLoginCount: null,
      nativeOriginalDigestReadAttempts: nativeOriginalProofs.size,
      nativeOriginalDigestsAvailable: [...nativeOriginalProofs.values()].filter(value => value.schema === 'samlscope-transcript-original-digest-v1').length,
      actualHumanLoginCountMeasured: false, normalLoginContextIsBrowserReuseNotMeasuredHumanLoginCount: true,
      credentialsOrCookiesExported: false, verdictAdopted: false });
  } finally {
    let browserContextsClosed = false;
    try {
      // Keep public protocol originals from failed attempts as well. Without a
      // server transcript they remain explicitly unqualified supplemental bytes.
      await flushOriginals();
    } finally {
      commands?.close();
      try { browserContextsClosed = (await adapter.close(explicitlyStopped ? 'explicit-stop-or-input-closed' : 'collector-finished')).browserContextsClosed === true; }
      finally {
        await record('collector-completion.json', { succeeded, verdictAdopted: false,
          collectionState: collected?.collectionState ?? 'FAILED', pendingAction: collected?.pendingAction ?? null,
          pendingNormalFlow: collected?.pendingNormalFlow ?? null, explicitlyStopped,
          existingSuiteM0AbortedOrRestarted: false,
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
