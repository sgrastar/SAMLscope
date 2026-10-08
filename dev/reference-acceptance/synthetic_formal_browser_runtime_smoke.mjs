#!/usr/bin/env node
/** Owned actual-Suite M0 -> approved ACS-index case; no product or adoption operations. */
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { mkdir, writeFile, readFile, lstat } from 'node:fs/promises';
import { resolve, relative, dirname, basename } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { validateTask, playwrightAdapter, collectSelected, bindProtocolOriginals, publicJson } from './generic_browser_campaign.mjs';
import { fetchStatus, publicDocument, readPublicResponse } from './synthetic_normal_browser_http.mjs';

export const SELECTED_CASE = 'IIP-IDP12-a-idp-01';
const COOKIE_NAME = 'samlscope_owned_formal_session';
const cookiePattern = new RegExp(`^${COOKIE_NAME}=[0-9a-f]{32}$`);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const sleep = ms => new Promise(done => setTimeout(done, ms));
const fail = message => { throw new Error(message); };

/** Only the fixture's own RAM session may be forwarded. Other values are discarded. */
export function ownedCookieHeader(raw) {
  if (raw === undefined || raw === null || raw === '') return null;
  if (typeof raw !== 'string' || raw.length > 8192 || /[\r\n]/.test(raw)) fail('Malformed owned session header');
  const owned = raw.split(';').map(part => part.trim()).filter(part => part.split('=', 1)[0] === COOKIE_NAME);
  if (owned.length > 1 || owned.length === 1 && !cookiePattern.test(owned[0])) fail('Malformed owned session header');
  return owned[0] ?? null;
}

export function ownedSetCookie(raw) {
  if (typeof raw !== 'string' || raw.length > 512 || /[\r\n,]/.test(raw)) fail('Non-public fixture session header omitted');
  const parts = raw.split(';').map(part => part.trim());
  if (!cookiePattern.test(parts[0]) || new Set(parts.slice(1)).size !== parts.length - 1
      || parts.length !== 4 || !['Path=/', 'HttpOnly', 'SameSite=Lax'].every(part => parts.includes(part)))
    fail('Non-public fixture session header omitted');
  return raw;
}

/** Recorder's fixed owned-cookie redaction is omitted before public persistence. */
export function publicTranscriptDocument(raw, runId) {
  let text; try { text = new TextDecoder('utf-8', { fatal: true }).decode(raw); } catch { fail('Non-public Transcript omitted'); }
  let replaced = 0;
  const scrubbed = text.replace(/("cookie"\s*:\s*)\[\s*"samlscope_owned_formal_session=<redacted: 32 bytes>"\s*\]/gi,
    (_, key) => { replaced++; return key + 'null'; });
  // The unchanged public parser checks grammar, duplicate keys and every other
  // credential field before either the original or sanitized document is kept.
  const checked = publicDocument(Buffer.from(scrubbed));
  if (!Array.isArray(checked) || checked.some(row => row?.runId !== runId)) fail('Foreign Transcript omitted');
  const original = JSON.parse(text); let omitted = 0;
  for (const row of original) {
    if (!row.headers || typeof row.headers !== 'object' || Array.isArray(row.headers)) fail('Malformed Transcript headers omitted');
    for (const key of Object.keys(row.headers)) if (key.toLowerCase() === 'cookie' && row.headers[key] !== null) {
      const values = row.headers[key];
      if (!Array.isArray(values) || values.length !== 1 || values[0] !== `${COOKIE_NAME}=<redacted: 32 bytes>`)
        fail('Non-public Transcript omitted');
      delete row.headers[key]; omitted++;
    }
  }
  if (omitted !== replaced) fail('Unexpected Transcript credential location omitted');
  return { document: publicJson(original), irreversiblyRedactedOwnedCookieHeadersOmitted: omitted };
}

export async function readFormalPublicResponse(response, path, runId, retainStatus, retainBody) {
  if (path !== `/api/runs/${runId}/transcript`) return readPublicResponse(response, retainStatus, retainBody);
  const facts = fetchStatus(response);
  await retainStatus({ status: facts.status, bodyOmittedUntilPublicValidation: true, rawTranscriptBodyRetained: false });
  if (!/^application\/json(?:;|$)/i.test(facts.contentType)) fail(`Owned Suite API status ${facts.status}; body omitted`);
  const reader = response.body?.getReader(), chunks = []; let length = 0;
  if (reader) while (true) {
    const next = await reader.read(); if (next.done) break;
    length += next.value.length; if (length > 6 * 1024 * 1024) { await reader.cancel(); fail('Oversized Transcript omitted'); }
    chunks.push(next.value);
  }
  const publicResult = publicTranscriptDocument(Buffer.concat(chunks), runId);
  await retainBody(Buffer.from(JSON.stringify(publicResult.document)), {
    rawTranscriptBodyRetained: false,
    irreversiblyRedactedOwnedCookieHeadersOmitted: publicResult.irreversiblyRedactedOwnedCookieHeadersOmitted });
  if (!facts.ok) fail(`Owned Suite API status ${facts.status}`);
  return publicResult.document;
}

/** Validate public fixture forms in memory; their HTML is never an evidence export. */
export function publicSamlFixtureHtml(raw, suiteOrigin, scope = null) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > 2 * 1024 * 1024
      || /type\s*=\s*['"]?password|\b(?:username|password|access_token|managementUrl)\b/i.test(raw))
    fail('Non-public fixture form omitted');
  const forms = [...raw.matchAll(/<form\b([^>]*)>/gi)];
  if (forms.length !== 1 || !/\bmethod\s*=\s*(['"])post\1/i.test(forms[0][1])) fail('Unexpected fixture form');
  const action = /\baction\s*=\s*(['"])(.*?)\1/i.exec(forms[0][1]);
  let target; try { target = new URL(action?.[2]); } catch { fail('Unexpected fixture ACS'); }
  if (target.origin !== suiteOrigin || !/^\/p\/plan_[0-9A-HJKMNP-TV-Z]{26}\/sp\/acs\/[01]$/.test(target.pathname)
      || target.search || target.hash || target.username || target.password) fail('Unexpected fixture ACS');
  const inputs = [...raw.matchAll(/<input\b([^>]*)>/gi)];
  const closedAttributes = (source, allowed) => {
    const attrs = [...source.matchAll(/([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(['"])(.*?)\2/g)];
    if (new Set(attrs.map(attr => attr[1].toLowerCase())).size !== attrs.length
        || attrs.some(attr => !allowed.includes(attr[1].toLowerCase()))
        || source.replace(/([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(['"])(.*?)\2/g, '').replace(/\/\s*$/, '').trim())
      fail('Unexpected fixture attributes');
  };
  closedAttributes(forms[0][1], ['method', 'action']);
  inputs.forEach(input => closedAttributes(input[1], ['type', 'name', 'value']));
  if ((raw.match(/<\/form\s*>/gi) ?? []).length !== 1
      || raw.replace(/<!doctype\s+html\s*>/gi, '').replace(/<form\b[^>]*>|<\/form\s*>|<input\b[^>]*>/gi, '').trim())
    fail('Unexpected fixture content');
  const names = inputs.map(match => /\bname\s*=\s*(['"])(.*?)\1/i.exec(match[1])?.[2]);
  if (inputs.length !== 2 || new Set(names).size !== 2 || !names.includes('SAMLResponse') || !names.includes('RelayState')
      || inputs.some(match => !/\btype\s*=\s*(['"])hidden\1/i.test(match[1]))) fail('Unexpected fixture fields');
  const values = Object.fromEntries(inputs.map((match, index) => [names[index], /\bvalue\s*=\s*(['"])(.*?)\1/i.exec(match[1])?.[2]]));
  if (typeof values.SAMLResponse !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(values.SAMLResponse)
      || values.SAMLResponse.length % 4 !== 0 || typeof values.RelayState !== 'string'
      || !/^(?:run_[0-9A-HJKMNP-TV-Z]{26}|sp1:run_[0-9A-HJKMNP-TV-Z]{26}:action_[a-f0-9]{32})$/.test(values.RelayState))
    fail('Unexpected fixture protocol values');
  if (scope && (target.pathname.split('/')[2] !== scope.planId
      || !(values.RelayState === scope.runId || values.RelayState.startsWith(`sp1:${scope.runId}:`)))) fail('Foreign fixture Run or Plan');
  if (/<(?:iframe|object|embed|textarea|select|script)\b|\bon[a-z]+\s*=/i.test(raw)) fail('Unexpected fixture content');
  // Execute a closed known form rather than arbitrary upstream HTML. SAML bytes are unchanged.
  return `<!doctype html><form method="post" action="${target.href}"><input type="hidden" name="SAMLResponse" value="${values.SAMLResponse}"><input type="hidden" name="RelayState" value="${values.RelayState}"></form>`;
}

export function publicSamlRequestBody(bytes, contentType, scope = null) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 2 * 1024 * 1024
      || typeof contentType !== 'string' || !/^application\/x-www-form-urlencoded(?:;\s*charset=utf-8)?$/i.test(contentType))
    fail('Unexpected fixture request type');
  let fields; try { fields = new URLSearchParams(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { fail('Unexpected fixture request encoding'); }
  if ([...fields.keys()].length !== 2 || fields.getAll('SAMLRequest').length !== 1 || fields.getAll('RelayState').length !== 1)
    fail('Non-public fixture request fields');
  const encoded = fields.get('SAMLRequest'), relay = fields.get('RelayState');
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded ?? '') || !encoded
      || !/^sp1:run_[0-9A-HJKMNP-TV-Z]{26}:action_[a-f0-9]{32}$/.test(relay ?? '')) fail('Non-public fixture request values');
  let xml; try { xml = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.from(encoded, 'base64')); } catch { fail('Non-public fixture request encoding'); }
  if (!/^(?:<\?xml[^>]{0,200}\?>\s*)?<([A-Za-z_][A-Za-z0-9_.-]*:)?AuthnRequest(?:\s|>)/.test(xml.trimStart())
      || !xml.includes('urn:oasis:names:tc:SAML:2.0:protocol') || /<!DOCTYPE|<!ENTITY|PRIVATE KEY|Authorization|Cookie/i.test(xml))
    fail('Non-public fixture request XML');
  const root = /<([A-Za-z_][A-Za-z0-9_.-]*:)?AuthnRequest\b([^>]*)>/.exec(xml);
  const id = /\bID\s*=\s*(['"])(.*?)\1/.exec(root?.[2] ?? '')?.[2];
  if (id !== '_' + relay.split(':')[2]) fail('Foreign fixture request action');
  if (scope && !relay.startsWith(`sp1:${scope.runId}:`)) fail('Foreign fixture request Run');
  return bytes; // Validate a copy without reconstructing signature-covered protocol bytes.
}

export function buildPlanInput(mode) {
  if (!['honor', 'ignore'].includes(mode)) fail('Only owned honor/ignore fixture modes are permitted');
  return { name: `Synthetic formal browser runtime ${mode}; no adoption`, profile: 'browser_sso_idp', targetKind: 'IDP',
    targetEntityId: `http://host.docker.internal:18946/entity/${mode}`, metadataSourceKind: 'URL',
    metadataSourceLocation: `http://host.docker.internal:18949/metadata/${mode}`, suiteMetadataDelivery: 'MANUAL',
    declaredFeatures: {}, parameters: { clockSkewToleranceSeconds: 180, metadataRefreshWaitSeconds: 300,
      testUserHint: 'synthetic-public-principal', requestSigningMode: 'REQUIRED' },
    interaction: { allowBrowserSteps: true, allowAttestation: false, preset: 'assisted' }, authorizedTarget: true };
}

export function existingColdCreation(prior, input) {
  publicJson(prior);
  const plan = prior?.created?.plan?.plan, run = prior?.runCreated?.run;
  if (JSON.stringify(prior?.input) !== JSON.stringify(input) || !/^plan_[0-9A-HJKMNP-TV-Z]{26}$/.test(plan?.id ?? '')
      || !/^run_[0-9A-HJKMNP-TV-Z]{26}$/.test(run?.id ?? '') || run.planId !== plan.id
      || run.status !== 'CREATED' || run.context?.authnRequestId != null) fail('Existing creation is outside cold owned scope');
  return { created: prior.created, runCreated: prior.runCreated, planId: plan.id, runId: run.id };
}

export function publicFailureDetails(error, stage) {
  const message = String(error.message ?? '');
  return { stage, errorName: error.name, reason: 'Owned formal qualification incomplete; private diagnostics omitted',
    safeProjectStack: [...String(error.stack ?? '').matchAll(/\/Users\/yuta\/Documents\/SAMLscope\/dev\/reference-acceptance\/([A-Za-z0-9_.-]+\.mjs):(\d+):(\d+)/g)]
      .map(match => ({ file: 'dev/reference-acceptance/' + match[1], line: Number(match[2]), column: Number(match[3]) })),
    publicCategories: { missingExecutable: /Executable.*(?:doesn.t exist|not found)/i.test(message),
      permissionDenied: /Permission denied|Operation not permitted|EACCES|EPERM|sandbox|bootstrap_check_in/i.test(message),
      browserClosed: /Target page, context or browser has been closed|Browser closed/.test(message) } };
}

export async function retainSupplementalCaptures(originals, output) {
  await noSymlinkAncestors(output); await mkdir(resolve(output, 'browser-saml-originals'), { recursive: true });
  const manifest = [];
  for (const capture of originals) {
    const file = capture.file, bytes = capture.bytes, declared = capture.record;
    if (!/^browser-saml-originals\/\d{4}-[a-f0-9]{64}\.xml$/.test(file ?? '') || !Buffer.isBuffer(bytes)
        || bytes.length !== declared?.bytes || sha(bytes) !== declared.sha256 || !file.endsWith(`-${declared.sha256}.xml`))
      fail('Supplemental public original declaration differs');
    const target = resolve(output, file); await noSymlinkAncestors(target);
    await writeFile(target, bytes, { flag: 'wx' });
    manifest.push({ ...declared, file, transcriptReferences: [],
      bindingState: 'original-captured-recorder-unqualified', conformanceConclusionAssigned: false });
  }
  return publicJson(manifest);
}

export function createImmutableEvidenceRecorder(output) {
  const versions = new Map(), history = [];
  const record = async (name, value) => {
    if (!/^[A-Za-z0-9_./-]+\.json$/.test(name) || name.startsWith('/') || name.split('/').some(part => !part || part === '.' || part === '..'))
      fail('Invalid public evidence name');
    const bytes = Buffer.from(JSON.stringify(publicJson(value), null, 2) + '\n');
    const version = (versions.get(name) ?? 0) + 1;
    const file = version === 1 ? name : `${dirname(name) === '.' ? '' : dirname(name) + '/'}record-revisions/${String(version).padStart(4, '0')}-${basename(name)}`;
    const target = resolve(output, file); await noSymlinkAncestors(target); await mkdir(dirname(target), { recursive: true });
    await writeFile(target, bytes, { flag: 'wx' }); versions.set(name, version);
    history.push({ logicalName: name, occurrence: version, file, bytes: bytes.length, sha256: sha(bytes) });
  };
  record.history = () => structuredClone(history);
  return record;
}

export function assertSessionProof(session, stats) {
  if (session.contextsCreated !== 1 || session.normalContextOrdinal !== 1 || session.formalContextOrdinals.length !== 2
      || session.formalContextOrdinals.some(value => value !== 1)
      || session.normalCookiePresent !== false || session.formalCookiePresent.length !== 2
      || session.formalCookiePresent.some(value => value !== true)
      || session.formalCookieMatchesNormal.length !== 2 || session.formalCookieMatchesNormal.some(value => value !== true)
      || session.credentialOrCookieValuesPersisted !== 0) fail('Same-context owned session proof incomplete');
  if (stats.normalReplies !== 1 || stats.formalReplies !== 2 || stats.newSessions !== 1 || stats.reusedSessions !== 2
      || stats.missingSessionRejects !== 0) fail('Fixture RAM session proof incomplete');
  return { primaryContexts: 1, normalRequests: 1, selectedFormalRequests: 2, ownedSessionPresentAndSame: true,
    fixtureEnforcedRunPlanModeSession: true, humanLoginCountMeasured: false, cookieValuesExported: false };
}

export function assertCaptureProof(bindings, runId) {
  if (!Array.isArray(bindings) || bindings.length !== 6 || new Set(bindings.map(row => row.file)).size !== 6
      || bindings.some(row => row.runId !== runId || row.transcriptReferences?.length !== 1
        || !/^recorder-hash-and-(?:normal-flow|action)-bound$/.test(row.bindingState ?? ''))
      || new Set(bindings.flatMap(row => row.transcriptReferences)).size !== 6) fail('Six original Recorder bindings incomplete');
  const normal = bindings.filter(row => row.operationKind === 'M0_NORMAL');
  const formal = bindings.filter(row => row.operationKind !== 'M0_NORMAL');
  if (normal.length !== 2 || formal.length !== 4 || formal.some(row => row.caseId !== SELECTED_CASE)
      || normal.some(row => 'caseId' in row || 'actionId' in row)
      || ['INBOUND', 'OUTBOUND'].some(direction => normal.filter(row => row.direction === direction).length !== 1
        || formal.filter(row => row.direction === direction).length !== 2)) fail('Original operation scope differs');
  const actions = new Set(formal.map(row => row.actionId));
  if (actions.size !== 2 || [...actions].some(action => !/^action_[a-f0-9]{32}$/.test(action ?? '')
      || ['INBOUND', 'OUTBOUND'].some(direction => formal.filter(row => row.actionId === action && row.direction === direction).length !== 1)))
    fail('Original request/response action pairs differ');
  return { exportedDecodedOriginals: 6, normalOriginals: 2, selectedCaseOriginals: 4, recorderBindingVerified: true };
}

/** Join against the actual Recorder files when its API has no decoded hash field. */
export function bindNativeProtocolOriginals(task, captures, transcript, guard, runtime) {
  if (runtime.runId !== task.runId || runtime.planId !== task.planId || runtime.transcriptOriginals?.length !== 6
      || new Set(runtime.transcriptOriginals.map(row => row.id)).size !== 6 || captures.length !== 6
      || guard?.source !== 'official-Suite-Recorder-normalFlowAccepted' || guard.runId !== task.runId || guard.planId !== task.planId
      || !/^_[A-Za-z0-9_-]+$/.test(guard.activeAuthnRequestId ?? '')
      || !Array.isArray(transcript) || transcript.some(row => row.runId !== task.runId)
      || new Set(transcript.map(row => row.id)).size !== transcript.length) fail('Native physical binding scope differs');
  const originals = runtime.transcriptOriginals.map(original => {
    const row = transcript.find(entry => entry.id === original.id);
    if (original.runId !== task.runId || !row || ['direction', 'correlationId', 'method', 'url', 'decodedSamlRef', 'decodedSamlBytes', 'bodyRef', 'bodyBytes']
      .some(key => row[key] !== original[key])) fail('Native physical row differs from public Recorder identity');
    const decoded = decodeOriginal(original.decodedSamlBase64, original.decodedSamlBytes, original.computedDecodedSha256);
    return { original, row, decoded };
  });
  const bindings = captures.map(capture => {
    if (capture.record.runId !== task.runId || capture.record.planId !== task.planId || !Buffer.isBuffer(capture.bytes)
        || capture.bytes.length !== capture.record.bytes || sha(capture.bytes) !== capture.record.sha256) fail('Browser capture scope/hash differs');
    const matches = originals.filter(({ original, decoded }) => original.direction === capture.record.direction
      && decoded.equals(capture.bytes));
    const owned = matches.filter(({ original, row }) => {
      if (capture.record.operationKind === 'M0_NORMAL') {
        const refs = capture.record.direction === 'INBOUND' ? guard.acceptedNormalFlowReferences : guard.normalAuthnRequestReferences;
        return refs?.length === 1 && refs[0] === original.id && (capture.record.direction === 'INBOUND'
          ? row.samlSummary?.normalFlowAccepted === true && row.correlationId === guard.activeAuthnRequestId
            && row.samlSummary?.inResponseTo === guard.activeAuthnRequestId
          : row.samlSummary?.id === guard.activeAuthnRequestId);
      }
      return capture.record.caseId === SELECTED_CASE && (capture.record.direction === 'INBOUND'
        ? row.correlationId === '_' + capture.record.actionId && row.samlSummary?.activeProbeAccepted === true
        : row.correlationId === capture.record.actionId && row.samlSummary?.scenario_case_id === capture.record.caseId);
    });
    if (owned.length !== 1) fail('Browser original has no unique native physical binding');
    return { ...capture.record, file: capture.file, transcriptReferences: [owned[0].original.id],
      bindingState: capture.record.operationKind === 'M0_NORMAL' ? 'recorder-hash-and-normal-flow-bound' : 'recorder-hash-and-action-bound',
      hashSource: 'read-only-native-physical-Recorder-original', apiDecodedHashRequiredOrFabricated: false,
      conformanceConclusionAssigned: false };
  });
  assertCaptureProof(bindings, task.runId); return bindings;
}

const exactRefs = (actual, expected) => Array.isArray(actual) && actual.length === expected.length
  && new Set(actual).size === actual.length && expected.every(ref => actual.includes(ref));
const decodeOriginal = (value, size, digest) => {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
      || !Number.isInteger(size) || size < 0 || size > 8 * 1024 * 1024 || !/^[a-f0-9]{64}$/.test(digest ?? ''))
    fail('Invalid portable original declaration');
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== size || sha(bytes) !== digest) fail('Portable original bytes/hash differ');
  return bytes;
};

/** Join native exact references to the six independently observed browser captures. */
export function checkedPortableOriginals(runtime, scope, bindings) {
  assertCaptureProof(bindings, scope.runId);
  if (runtime.runId !== scope.runId || runtime.planId !== scope.planId || runtime.fixtureMode !== scope.mode
      || runtime.approvedSelectedCase?.id !== SELECTED_CASE || runtime.selectedOutboxActions !== 2
      || runtime.actualCaseAndRequiredControlsProven !== true || runtime.actualRequestSignaturesVerified !== true
      || runtime.actualResponseAndAssertionSignaturesVerified !== true || runtime.protocolSessionReused !== true)
    fail('Foreign or incomplete native formal scope');
  const pairs = runtime.selectedFixturePairs;
  if (!Array.isArray(pairs) || pairs.length !== 2 || new Set(pairs.map(pair => pair.fixture)).size !== 2
      || !['default-control', 'non-default-index'].every(fixture => pairs.some(pair => pair.fixture === fixture))
      || new Set(pairs.map(pair => pair.actionId)).size !== 2 || pairs.some(pair => !/^action_[a-f0-9]{32}$/.test(pair.actionId ?? '')))
    fail('Native approved fixture pairs differ');
  const required = [runtime.normalRequestReference, runtime.normalResponseReference,
    ...pairs.flatMap(pair => [pair.requestReference, pair.responseReference])];
  if (!exactRefs(required, bindings.flatMap(row => row.transcriptReferences))
      || !exactRefs(runtime.portableEvidenceReferences, required)
      || !Array.isArray(runtime.selectedCaseEvidence) || runtime.selectedCaseEvidence.length !== 2
      || runtime.selectedCaseEvidence.some(row => row.kind !== 'transcript')
      || !exactRefs(runtime.selectedCaseEvidence.map(row => row.reference), pairs.map(pair => pair.responseReference)))
    fail('Native selected evidence references incomplete');
  const originals = runtime.transcriptOriginals;
  if (!Array.isArray(originals) || !exactRefs(originals.map(row => row.id), required)) fail('Native original map incomplete');
  return originals.map(original => {
    if (!/^tx_[0-9A-HJKMNP-TV-Z]{26}$/.test(original.id ?? '') || original.runId !== scope.runId)
      fail('Foreign original Run or entry');
    const prefix = `transcripts/${scope.runId}/${original.id}`;
    if (original.decodedSamlRef !== prefix + '.saml.xml'
        || !(original.bodyRef === prefix + '.body' || original.bodyRef === null && original.bodyBytes === 0))
      fail('Original references are not exact selected entries');
    const body = decodeOriginal(original.bodyBase64, original.bodyBytes, original.computedBodySha256);
    const decoded = decodeOriginal(original.decodedSamlBase64, original.decodedSamlBytes, original.computedDecodedSha256);
    if (!decoded.length || original.storedBodySha256 != null && original.storedBodySha256 !== sha(body)) fail('Stored original hash differs');
    const binding = bindings.find(row => row.transcriptReferences[0] === original.id);
    if (binding.direction !== original.direction || binding.bytes !== decoded.length || binding.sha256 !== sha(decoded))
      fail('Browser and native decoded originals differ');
    const pair = pairs.find(pair => pair.requestReference === original.id || pair.responseReference === original.id);
    if (pair && (binding.actionId !== pair.actionId || original.correlationId !== (original.direction === 'INBOUND' ? '_' : '') + pair.actionId))
      fail('Native original action pair differs');
    if (!pair && (binding.operationKind !== 'M0_NORMAL' || original.id !== (original.direction === 'OUTBOUND'
        ? runtime.normalRequestReference : runtime.normalResponseReference))) fail('Native normal references differ');
    let query = null;
    if (original.method === 'GET' && original.rawQuery === null) fail('Original signed Redirect query missing');
    if (original.rawQuery !== null) {
      if (typeof original.rawQuery !== 'string' || original.method !== 'GET' || Buffer.byteLength(original.rawQuery) > 2 * 1024 * 1024
          || new URL(original.url).search.slice(1) !== original.rawQuery) fail('Original Redirect query differs');
      const fields = new URLSearchParams(original.rawQuery);
      if ([...fields.keys()].some(key => !['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'].includes(key))
          || ['SAMLRequest', 'RelayState', 'SigAlg', 'Signature'].some(key => fields.getAll(key).length !== 1)) fail('Non-public original Redirect fields');
      query = Buffer.from(original.rawQuery, 'utf8');
    }
    return { original, binding, body, decoded, query };
  });
}

async function noSymlinkAncestors(path) {
  for (let current = resolve(path); ; current = dirname(current)) {
    try { if ((await lstat(current)).isSymbolicLink()) fail('Portable evidence path contains symlink'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (dirname(current) === current) break;
  }
}

export async function exportPortableOriginals(runtime, scope, bindings, output) {
  const originals = checkedPortableOriginals(runtime, scope, bindings), folder = resolve(output, 'native-originals');
  await noSymlinkAncestors(folder); await mkdir(folder, { recursive: false });
  const manifest = [];
  for (const value of originals) {
    const physical = {};
    for (const [kind, suffix, bytes] of [['body', '.body', value.body], ['decoded', '.saml.xml', value.decoded], ['query', '.query.txt', value.query]]) {
      if (bytes === null) continue;
      const file = `native-originals/${value.original.id}${suffix}`, path = resolve(output, file);
      await noSymlinkAncestors(path); await writeFile(path, bytes, { flag: 'wx' });
      const stat = await lstat(path); const actual = await readFile(path);
      if (!stat.isFile() || stat.size !== bytes.length || sha(actual) !== sha(bytes)) fail('Physical portable original differs');
      physical[kind] = { file, bytes: actual.length, sha256: sha(actual) };
    }
    if (!/^browser-saml-originals\/\d{4}-[a-f0-9]{64}\.xml$/.test(value.binding.file)) fail('Unsafe browser original filename');
    const browserPath = resolve(output, value.binding.file); await noSymlinkAncestors(browserPath);
    const stat = await lstat(browserPath); if (!stat.isFile() || stat.size !== value.decoded.length) fail('Browser physical original size differs');
    if (sha(await readFile(browserPath)) !== sha(value.decoded)) fail('Browser physical original bytes differ');
    manifest.push({ id: value.original.id, runId: scope.runId, nativeBodyReference: value.original.bodyRef,
      nativeDecodedReference: value.original.decodedSamlRef, browserFile: value.binding.file, physical });
  }
  return { scope: 'exact-normal2-and-selected-case4', selectedOriginalCount: 6,
    requiredSelectedOriginalsExported: true, allDeclaredAndPhysicalBytesAndHashesMatched: true, originals: manifest };
}

export function assertResultProof(result, scope, outcome) {
  const cases = result.requirements?.flatMap(requirement => requirement.cases ?? []), selected = cases?.filter(row => row.id === SELECTED_CASE);
  if (result.run?.id !== scope.runId || result.run.completeness !== 'INCOMPLETE' || selected?.length !== 1
      || selected[0].outcome !== outcome || selected[0].verdict !== (outcome === 'SATISFIED' ? 'PASS' : 'FAIL'))
    fail('Actual central Suite result scope differs');
  return { wholeRunCompleteness: result.run.completeness, observedCentralSuiteVerdict: selected[0].verdict,
    suiteRunConformance: result.run.conformance, conformanceAdopted: false };
}

export function assertFormalProof({ mode, collected, bindings, runtime, session, stats, runId, planId }) {
  const expected = mode === 'honor' ? 'SATISFIED' : mode === 'ignore' ? 'VIOLATED' : null;
  if (!expected || collected.collectionState !== 'COLLECTED' || collected.counts.initialNormalFlowSubmissions !== 1
      || collected.counts.normalLoginContexts !== 1 || collected.counts.fullProfileStartCalls !== 1
      || collected.counts.selectedTargetActions !== 2 || collected.counts.authenticatedContextReuses !== 2
      || collected.counts.freshEmptyContexts !== 0 || collected.counts.automatedCredentialPosts !== 0)
    fail('Actual collector scope incomplete');
  const capture = assertCaptureProof(bindings, runId), context = assertSessionProof(session, stats);
  checkedPortableOriginals(runtime, { mode, runId, planId }, bindings);
  if (runtime.qualificationOutcome !== 'VERIFIED' || runtime.selectedCaseOutcome !== expected
      || runtime.wholeRunConformance !== 'NOT_QUALIFIED' || runtime.canonicalAdoption !== false)
    fail('Actual native selected-case proof incomplete');
  return { qualificationScope: 'owned-actual-Suite-M0-and-selected-approved-ACS-index-case', mode, runId,
    selectedCaseId: SELECTED_CASE, selectedCaseOutcome: expected, wholeRunConformance: 'NOT_QUALIFIED',
    canonicalAdoption: false, selectedProof: capture, sessionProof: context };
}

export async function runFormalSmoke(outputDirectory, mode, existingCreatedFile = null) {
  const output = resolve(outputDirectory), ownedRoot = resolve('build/acceptance');
  if (relative(ownedRoot, output).startsWith('..') || output === ownedRoot) fail('Fresh owned evidence directory required');
  const input = buildPlanInput(mode); await mkdir(output, { recursive: false });
  // Same site across ports lets an explicit Lax owned cookie accompany the real POST fixtures.
  const suite = 'http://localhost:18080', target = 'http://localhost:18949', upstream = 'http://127.0.0.1:18946';
  const classes = resolve('build/synthetic-formal-browser-fixture'), container = 'samlscope-reference-suite';
  const helper = `/tmp/samlscope-synthetic-formal-browser-${mode}-${process.pid}`;
  const record = createImmutableEvidenceRecorder(output);
  const counts = { apiAttempts: 0, apiSuccesses: 0, helperExecAttempts: 0, helperExecSuccesses: 0,
    helperCopyAttempts: 0, helperCopySuccesses: 0, helperRemovalAttempts: 0, helperRemovalSuccesses: 0,
    deploymentIdentityReadAttempts: 0, deploymentIdentityReadSuccesses: 0, fixtureMetricsAttempts: 0, fixtureMetricsSuccesses: 0,
    metadataGets: 0, normalTargetGets: 0, formalTargetSubmissions: 0, formalTargetMethods: { GET: 0, POST: 0 }, fixtureKeysPersisted: false,
    realProductOperations: 0, actualRunRetries: 0, credentialValuesPersisted: 0 };
  const session = { contextsCreated: 0, normalContextOrdinal: null, formalContextOrdinals: [], normalCookiePresent: null,
    formalCookiePresent: [], formalCookieMatchesNormal: [], credentialOrCookieValuesPersisted: 0 };
  let fixture, server, adapter, publicRun, helperInstalled = false, ready = false, fixtureExit, failure, stopped = false, stage = 'source-pins';
  const originals = []; let originalsExported = false;
  let operation = 'M0_NORMAL', sessionValue = null, targetSeen = 0;
  const sourceNames = ['generic_browser_campaign.mjs', 'synthetic_normal_browser_http.mjs',
    'synthetic_formal_browser_runtime_smoke.mjs', 'SyntheticFormalBrowserFixture.java', 'ReadSyntheticFormalBrowserRuntime.java',
    'ReadSyntheticArtifactRuntime.java', 'SyntheticAdditionalMetadataFixture.java', 'ReadSyntheticNormalBrowserScope.java',
    'SyntheticFormalBrowserFixtureControls.java'];
  let sourcePins;
  const docker = async args => {
    const kind = args[0] === 'cp' ? 'helperCopy' : args[0] === 'inspect' ? 'deploymentIdentityRead' : 'helperExec'; counts[kind + 'Attempts']++;
    try { const result = await promisify(execFile)('docker', args, { maxBuffer: 16 * 1024 * 1024 }); counts[kind + 'Successes']++; return result.stdout; }
    catch { fail('Owned public helper operation failed; private diagnostics omitted'); }
  };
  const native = async scope => publicDocument(Buffer.from(await docker(['exec', container, 'java', '-cp',
    `${helper}/classes:/opt/samlscope/lib/*`, 'com.samlscope.api.ReadSyntheticFormalBrowserRuntime',
    '/data', publicRun.runId, scope, `${helper}/suite-public-metadata.xml`])));
  const api = async (path, body) => {
    counts.apiAttempts++; const index = counts.apiAttempts;
    const response = await fetch(suite + path, { method: body === undefined ? 'GET' : 'POST', redirect: 'manual',
      ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }), signal: AbortSignal.timeout(30000) });
    const result = await readFormalPublicResponse(response, path, publicRun?.runId,
      facts => record(`api-${String(index).padStart(4, '0')}-status.json`, { path, ...facts }),
      async (bytes, sanitized) => {
        await writeFile(resolve(output, `api-${String(index).padStart(4, '0')}-response.${sanitized ? 'public.json' : 'body'}`), bytes, { flag: 'wx' });
        if (sanitized) await record(`api-${String(index).padStart(4, '0')}-retention.json`, sanitized);
      });
    counts.apiSuccesses++; return result;
  };
  try {
    sourcePins = Object.fromEntries(await Promise.all(sourceNames.map(async name => [name, sha(await readFile(resolve('dev/reference-acceptance', name)))])));
    await record('source-pins.json', sourcePins); await record('plan-input.json', input);
    stage = 'deployment-identity';
    const deploymentFile = resolve('build/acceptance/reference-20261008/deployment-v237-r2/runtime-live-verification.json');
    const deploymentBytes = await readFile(deploymentFile), deployment = publicDocument(deploymentBytes);
    const identity = (await docker(['inspect', '--format', '{{json .Id}}\n{{json .Image}}', container])).trim().split('\n').map(line => JSON.parse(line));
    if (deployment.approvedCommit !== '8b913dfd6ca8172b99fe047164089c5ae5515d7f'
        || deployment.approvalCommit !== '5d6de8bb1c6f1a1b3a98b7a6dacc86ff670c5e43'
        || deployment.all108JarsVerified !== true || deployment.healthStatus !== 200
        || identity.length !== 2 || identity[0] !== deployment.suiteContainerId || identity[1] !== deployment.imageId)
      fail('Actual Suite is outside qualified v237 deployment');
    await record('deployment-source-binding.json', { file: deploymentFile, sha256: sha(deploymentBytes),
      approvedCommit: deployment.approvedCommit, approvalCommit: deployment.approvalCommit,
      suiteContainerId: identity[0], imageId: identity[1], publicIdentityVerified: true, environmentRead: false });
    stage = 'fixture-start';
    fixture = spawn('/opt/homebrew/opt/openjdk@21/bin/java', ['-cp', `${classes}:api/build/install/samlscope/lib/*`,
      'com.samlscope.api.SyntheticFormalBrowserFixture', '--serve', '18946', suite, 'host.docker.internal'], { stdio: ['ignore', 'pipe', 'pipe'] });
    fixtureExit = new Promise(done => {
      fixture.once('exit', (code, signal) => done({ code, signal }));
      fixture.once('error', () => done({ code: null, signal: null, spawnFailure: true }));
    });
    fixture.stdout.on('data', bytes => { if (bytes.toString().includes('Synthetic formal fixture listening')) ready = true; });
    fixture.stderr.resume();
    const deadline = Date.now() + 10000;
    while (!ready && fixture.exitCode === null && Date.now() < deadline) await sleep(50);
    if (!ready) fail('Owned formal signing fixture did not start');
    stage = 'proxy-start';
    server = createServer(async (request, response) => {
      try {
        const path = new URL(request.url, target).pathname;
        if (!['GET', 'POST'].includes(request.method) || ![`/metadata/${mode}`, `/sso/${mode}`].includes(path)
            || path.startsWith('/metadata/') && request.method !== 'GET') { response.writeHead(404); response.end(); return; }
        const owned = ownedCookieHeader(request.headers.cookie);
        const headers = owned ? { Cookie: owned } : {};
        let body;
        if (request.method === 'POST') {
          const chunks = []; let bytes = 0;
          for await (const chunk of request) { bytes += chunk.length; if (bytes > 2 * 1024 * 1024) fail('Oversized fixture request'); chunks.push(chunk); }
          body = Buffer.concat(chunks);
          publicSamlRequestBody(body, request.headers['content-type'], publicRun);
          headers['Content-Type'] = request.headers['content-type'];
        }
        const received = await fetch(upstream + request.url, { method: request.method, ...(body ? { body } : {}), headers,
          redirect: 'manual', signal: AbortSignal.timeout(30000) });
        const status = fetchStatus(received).status;
        if (status !== 200) { response.writeHead(status); response.end(); return; }
        const raw = await received.text();
        if (path.startsWith('/metadata/')) {
          counts.metadataGets++;
          response.writeHead(200, { 'Content-Type': 'application/samlmetadata+xml' });
          response.end(raw.replaceAll(`http://host.docker.internal:18946/sso/${mode}`, `${target}/sso/${mode}`)); return;
        }
        const formHtml = publicSamlFixtureHtml(raw, suite, publicRun);
        if (targetSeen++ === 0) { counts.normalTargetGets++; session.normalCookiePresent = owned !== null; }
        else { counts.formalTargetSubmissions++; counts.formalTargetMethods[request.method]++;
          session.formalCookiePresent.push(owned !== null); session.formalCookieMatchesNormal.push(owned === sessionValue && owned !== null); }
        const setHeaders = received.headers.getSetCookie();
        if (setHeaders.length > 1) fail('Unexpected fixture session headers');
        const responseHeaders = { 'Content-Type': 'text/html' };
        if (setHeaders.length) { responseHeaders['Set-Cookie'] = ownedSetCookie(setHeaders[0]); sessionValue = setHeaders[0].split(';', 1)[0]; }
        response.writeHead(200, responseHeaders); response.end(formHtml + '<script>document.querySelector("form").submit()</script>');
      } catch { response.writeHead(500); response.end(); }
    });
    await new Promise((done, reject) => { server.once('error', reject); server.listen(18949, '0.0.0.0', done); });
    let reused;
    if (existingCreatedFile) {
      const source = resolve(existingCreatedFile);
      if (relative(ownedRoot, source).startsWith('..')) fail('Existing creation record must be owned public evidence');
      await noSymlinkAncestors(source); const stat = await lstat(source);
      if (!stat.isFile() || stat.size > 1024 * 1024) fail('Existing public creation record invalid');
      reused = existingColdCreation(publicDocument(await readFile(source)), input);
    }
    stage = reused ? 'existing-cold-run-check' : 'plan-create';
    const created = reused?.created ?? await api('/api/plans', input); const planId = created.plan.plan.id;
    await record('plan-created.json', created);
    stage = reused ? 'existing-cold-run-check' : 'run-create';
    const runCreated = reused?.runCreated ?? await api(`/api/plans/${planId}/runs`, {}); const runId = runCreated.run.id;
    publicRun = { runId, planId }; await record('created.json', { input, created, runCreated });
    if (reused) {
      const doc = await api(`/api/runs/${runId}`), live = doc.run ?? doc;
      if (live.id !== runId || live.planId !== planId || live.status !== 'CREATED' || live.context?.authnRequestId != null)
        fail('Existing Run is no longer cold; no M0 reissue permitted');
      await record('existing-cold-continuation.json', { ...publicRun, creationRecordSha256: sha(await readFile(resolve(existingCreatedFile))),
        newPlanCreations: 0, newRunCreations: 0, actualM0NonceAbsent: true });
    }
    const task = validateTask({ suiteBaseUrl: suite, targetOrigins: [target], runId, planId, caseIds: [SELECTED_CASE],
      completeNormalFlow: true, startTests: true, maxActions: 100, actionTimeoutSeconds: 30, outputDirectory: output });
    await record('task.json', task);
    stage = 'public-metadata';
    const md = await fetch(`${suite}/p/${planId}/metadata`, { signal: AbortSignal.timeout(30000) });
    if (!fetchStatus(md).ok) fail('Owned public Suite metadata unavailable');
    await writeFile(resolve(output, 'suite-public-metadata.xml'), Buffer.from(await md.arrayBuffer()), { flag: 'wx' });
    await docker(['exec', container, 'test', '!', '-e', helper]); await docker(['exec', container, 'mkdir', helper]); helperInstalled = true;
    await docker(['cp', classes, container + ':' + helper + '/classes']);
    await docker(['cp', resolve(output, 'suite-public-metadata.xml'), container + ':' + helper + '/suite-public-metadata.xml']);
    stage = 'native-cold-scope'; await record('native-cold-scope.json', await native('scope'));
    const dependency = process.env.SAML_SCOPE_PLAYWRIGHT;
    if (!dependency?.startsWith('/')) fail('Installed absolute Playwright path required');
    const { chromium } = createRequire(import.meta.url)(dependency);
    const instrumented = { launch: async options => {
      const browser = await chromium.launch(options), makeContext = browser.newContext.bind(browser);
      browser.newContext = async (...args) => {
        const context = await makeContext(...args), ordinal = ++session.contextsCreated, makePage = context.newPage.bind(context);
        context.newPage = async (...pageArgs) => {
          if (operation === 'M0_NORMAL') session.normalContextOrdinal = ordinal;
          else session.formalContextOrdinals.push(ordinal);
          return makePage(...pageArgs);
        }; return context;
      }; return browser;
    } };
    stage = 'browser-launch'; adapter = await playwrightAdapter(task, instrumented, record, originals);
    const observedAdapter = { ...adapter,
      normalFlow: async (...args) => { operation = 'M0_NORMAL'; return adapter.normalFlow(...args); },
      resumeNormalFlow: async (...args) => { operation = 'M0_NORMAL'; return adapter.resumeNormalFlow(...args); },
      probe: async (...args) => { operation = 'SELECTED_CASE'; return adapter.probe(...args); } };
    const operations = new Map(); let attempt = 0;
    const collect = async () => {
      const prefix = `collection-${String(++attempt).padStart(2, '0')}`; await mkdir(resolve(output, prefix));
      return collectSelected(task, api, observedAdapter, async (name, value) => {
        operations.set(name, value); await record(`${prefix}/${name}`, value);
        if (name === 'normal-scope-after-empty-evaluation.json') await record(`${prefix}/native-empty-scope.json`, await native('scope'));
      });
    };
    stage = 'collection'; let collected = await collect();
    if (collected.collectionState === 'WAITING_M0') {
      await record('live-normal-flow.json', { ...collected.pendingNormalFlow, processId: process.pid, processRetained: true });
      process.stderr.write(`Owned M0 retained: ${runId} ${collected.pendingNormalFlow.authnRequestId}. Type resume or stop.\n`);
      const inputLines = createInterface({ input: process.stdin, crlfDelay: Infinity });
      for await (const line of inputLines) {
        if (line.trim() === 'stop') { stopped = true; break; }
        if (line.trim() !== 'resume') continue;
        collected = await collect(); if (collected.collectionState !== 'WAITING_M0') break;
      }
      inputLines.close(); if (collected.collectionState === 'WAITING_M0') stopped = true;
    }
    if (!stopped) {
      stage = 'native-runtime'; const runtime = await native('runtime'); await record('native-before-result.json', runtime);
      const transcript = await api(`/api/runs/${runId}/transcript`); await record('transcript.json', transcript);
      await mkdir(resolve(output, 'browser-saml-originals'));
      for (const original of originals) await writeFile(resolve(output, original.file), original.bytes, { flag: 'wx' });
      const bindings = bindNativeProtocolOriginals(task, originals, transcript, operations.get('m0-guard.json'), runtime);
      await record('browser-saml-manifest.json', bindings);
      originalsExported = true;
      stage = 'portable-export'; const portable = await exportPortableOriginals(runtime, { mode, runId, planId }, bindings, output);
      await record('selected-portable-originals.json', portable);
      stage = 'fixture-metrics'; counts.fixtureMetricsAttempts++;
      const statsResponse = await fetch(upstream + '/stats', { signal: AbortSignal.timeout(10000) });
      if (!fetchStatus(statsResponse).ok) fail('Owned public fixture metrics unavailable');
      const statsDoc = publicDocument(Buffer.from(await statsResponse.arrayBuffer()));
      counts.fixtureMetricsSuccesses++;
      await record('fixture-public-stats.json', statsDoc); await record('browser-session-facts.json', session);
      const stats = statsDoc[mode] ?? statsDoc.modes?.[mode];
      const qualification = assertFormalProof({ mode, collected, bindings, runtime, session, stats, runId, planId });
      stage = 'central-result'; const result = await api(`/api/runs/${runId}/result.json`); await record('result.json', result);
      const resultProof = assertResultProof(result, { runId, planId }, runtime.selectedCaseOutcome);
      await record('actual-formal-qualification.json', { ...qualification, planId, sourcePins,
        ...resultProof, physicalSelectedOriginalsExported: portable.requiredSelectedOriginalsExported,
        fullProfileStarts: collected.counts.fullProfileStartCalls, unselectedPreparedAndAborted: collected.counts.skippedBeforeTargetSubmission,
        fullProfileQueueChangesMeasured: false, actualHumanLoginCountMeasured: false });
    }
  } catch (error) {
    failure = error; await record('first-error.json', { ...publicRun, mode, ...publicFailureDetails(error, stage) });
  } finally {
    if (failure || stopped) {
      await record('supplemental-browser-session-facts.json', { ...session, conformanceConclusionAssigned: false });
      if (ready && fixture?.exitCode === null) {
        try {
          counts.fixtureMetricsAttempts++;
          const metrics = await fetch(upstream + '/stats', { signal: AbortSignal.timeout(5000) });
          if (fetchStatus(metrics).ok) { const facts = publicDocument(Buffer.from(await metrics.arrayBuffer()));
            counts.fixtureMetricsSuccesses++; await record('supplemental-fixture-public-stats.json', facts); }
        } catch { /* The failure remains incomplete if public metrics are unavailable. */ }
      }
    }
    if (!originalsExported && originals.length) {
      try { await record('browser-saml-supplemental-manifest.json', await retainSupplementalCaptures(originals, output)); }
      catch { failure ??= new Error('Supplemental public protocol originals export incomplete'); }
    }
    let browserClosed = !adapter;
    try { if (adapter) browserClosed = (await adapter.close(stopped ? 'explicit-stop-or-input-closed' : 'owned-formal-complete')).browserContextsClosed; }
    catch { failure ??= new Error('Owned browser closure incomplete'); }
    if (server?.listening) await new Promise(done => { server.closeAllConnections(); server.close(done); });
    if (fixture && fixture.exitCode === null) fixture.kill('SIGTERM');
    let exit = fixtureExit ? await Promise.race([fixtureExit, sleep(5000).then(() => null)]) : null;
    if (fixture && !exit) { fixture.kill('SIGKILL'); exit = await fixtureExit; }
    if (helperInstalled) {
      counts.helperRemovalAttempts++;
      try { await docker(['exec', '-u', '0', container, 'rm', '-r', '--', helper]); counts.helperRemovalSuccesses++; }
      catch { failure ??= new Error('Owned helper cleanup incomplete'); }
    }
    await record('host-operation-counts.json', counts);
    await record('resource-closure.json', { ...publicRun, mode, browserClosed, ownedProxyClosed: !server?.listening,
      fixtureExit: exit, fixtureKeysPersisted: false, helperRemoved: helperInstalled && counts.helperRemovalSuccesses === 1,
      existingSuiteM0AbortedOrRestarted: false, explicitlyStopped: stopped, realProductOperations: 0, canonicalAdoption: false });
    await record('evidence-record-history.json', record.history());
    sessionValue = null;
  }
  if (failure) throw new Error('Owned formal campaign incomplete; see public first-error and operation counts');
}

async function main(args) {
  if (![4, 6].includes(args.length) || args[0] !== '--execute' || args[2] !== '--mode'
      || args.length === 6 && args[4] !== '--existing-created') fail('Explicit --execute fresh-output --mode honor|ignore and optional public cold creation required');
  await runFormalSmoke(args[1], args[3], args[5] ?? null);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  main(process.argv.slice(2)).catch(() => { process.stderr.write('Owned formal campaign incomplete; public evidence retained, private diagnostics omitted.\n'); process.exitCode = 1; });
