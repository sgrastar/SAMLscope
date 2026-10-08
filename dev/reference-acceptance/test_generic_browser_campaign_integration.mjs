/** Real headless Chromium against synthetic local Suite/IdP HTTP fixtures only. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { validateTask, playwrightAdapter, collectSelected, bindProtocolOriginals, collectNativeOriginalDigests } from './generic_browser_campaign.mjs';

const dependency = process.env.SAML_SCOPE_PLAYWRIGHT;
const RUN = 'run_0123456789ABCDEFGHJKMNPQRS';
const PLAN = 'plan_0123456789ABCDEFGHJKMNPQRS';
const CASE = 'IIP-SSO01-f-idp-01';
const action = index => `action_${index.toString(16).padStart(32, '0')}`;
const listen = server => new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(`http://127.0.0.1:${server.address().port}`)));
const close = server => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); });
const bytes = async request => { const chunks = []; for await (const chunk of request) chunks.push(chunk); return Buffer.concat(chunks); };
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const json = (response, value) => { response.writeHead(200, { 'Content-Type': 'application/json' }); response.end(JSON.stringify(value)); };
const html = (response, body, status = 200, headers = {}) => { response.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...headers }); response.end(body); };
const post = (endpoint, name, value) => `<form id="saml" method="post" action="${endpoint}"><input name="${name}" value="${value}"></form><script>document.querySelector('#saml').submit()</script>`;

test('real browser preserves three authenticated operations and isolates passive, exporting only bound SAML originals',
  { skip: !dependency, timeout: 60000 }, async () => {
    const require = createRequire(import.meta.url);
    const { chromium } = require(dependency);
    let suiteOrigin;
    let targetOrigin;
    let index = 0;
    const entries = [];
    const nativeBytes = new Map(), digestReads = [];
    const wire = [];
    const record = {};
    let fixtureFailure;
    const current = () => index < 4 ? { state: 'READY', caseId: CASE, actionId: action(index), requiresFreshSession: index === 3,
      startUrl: `${suiteOrigin}/p/${PLAN}/probe/${action(index)}?run=${RUN}` } : { state: 'FINISHED' };
    const add = (direction, actionId, raw) => {
      const id = `tx_${String(entries.length).padStart(26, '0')}`; nativeBytes.set(id, raw);
      entries.push({ id, runId: RUN, direction, correlationId: direction === 'OUTBOUND' ? actionId : '_' + actionId,
        decodedSamlRef: `transcripts/${RUN}/${id}.saml.xml`, decodedSamlBytes: raw.length,
        samlSummary: { type: direction === 'OUTBOUND' ? 'AuthnRequest' : 'Response', scenario_case_id: CASE } });
    };
    const suite = createServer(async (request, response) => {
      try {
        const url = new URL(request.url, suiteOrigin);
        if (url.pathname === `/api/runs/${RUN}`) return json(response, { id: RUN, planId: PLAN, status: 'COMPLETED', context: { authnRequestId: '_m0' } });
        if (url.pathname === `/api/plans/${PLAN}`) return json(response, { plan: { id: PLAN, profile: 'browser_sso_idp', target: { kind: 'IDP', entityId: targetOrigin + '/idp' } } });
        if (url.pathname.endsWith('/transcript')) return json(response, [
          { id: 'tx_m0_request', runId: RUN, direction: 'OUTBOUND', samlSummary: { type: 'AuthnRequest', id: '_m0' } },
          { id: 'tx_m0_response', runId: RUN, direction: 'INBOUND', correlationId: '_m0', url: `${suiteOrigin}/p/${PLAN}/sp/acs/0`,
            samlSummary: { type: 'Response', normalFlowAccepted: true, statusCode: 'urn:oasis:names:tc:SAML:2.0:status:Success',
              issuer: targetOrigin + '/idp', destination: `${suiteOrigin}/p/${PLAN}/sp/acs/0`, inResponseTo: '_m0' } }, ...entries]);
        const original = new RegExp(`^/api/runs/${RUN}/transcript/(tx_[0-9A-HJKMNP-TV-Z]{26})/original-digest$`).exec(url.pathname);
        if (original && nativeBytes.has(original[1])) {
          const raw = nativeBytes.get(original[1]); digestReads.push(original[1]);
          return json(response, { schema: 'samlscope-transcript-original-digest-v1', runId: RUN, txId: original[1],
            decodedSamlSha256: digest(raw), decodedSamlBytes: raw.length });
        }
        if (url.pathname.endsWith('/result.json')) return json(response, { run: { id: RUN }, requirements: [{ cases: [{ id: CASE, outcome: 'NOT_VERIFIED' }] }] });
        if (url.pathname.endsWith('/active-probe')) return json(response, current());
        if (url.pathname.endsWith('/protocol-evidence/evaluate')) return json(response, { syntheticOnly: true, readyCases: 0 });
        if (url.pathname === `/p/${PLAN}/sp/acs/0`) {
          const form = new URLSearchParams((await bytes(request)).toString());
          const raw = Buffer.from(form.get('SAMLResponse'), 'base64');
          const currentAction = action(index);
          add('INBOUND', currentAction, raw);
          index++;
          return html(response, '<h1>SAML Response recorded</h1><script>setTimeout(()=>window.close(),100)</script>');
        }
        if (url.pathname === `/p/${PLAN}/probe/${action(index)}`) {
          if (request.method === 'GET') return html(response, `<form method="post">${index === 3
            ? '<input type="checkbox" name="freshSessionConfirmed" value="true">' : ''}<button type="submit">Continue with this request</button></form>`);
          const form = new URLSearchParams((await bytes(request)).toString());
          if (index === 3) assert.equal(form.get('freshSessionConfirmed'), 'true');
          const raw = Buffer.from(`<AuthnRequest ID="_${action(index)}" IsPassive="${index === 3}"/>`);
          add('OUTBOUND', action(index), raw);
          return html(response, post(targetOrigin + '/sso', 'SAMLRequest', raw.toString('base64')));
        }
        response.writeHead(404); response.end();
      } catch (error) { fixtureFailure = error; response.writeHead(500); response.end(); }
    });
    const target = createServer(async (request, response) => {
      try {
        const form = new URLSearchParams((await bytes(request)).toString());
        assert.equal(new URL(request.url, targetOrigin).pathname, '/sso');
        assert.ok(form.get('SAMLRequest'));
        wire.push({ index, cookiePresent: (request.headers.cookie ?? '').includes('fixture-authenticated=yes') });
        if (index === 0 || index === 3) assert.equal(wire.at(-1).cookiePresent, false);
        else assert.equal(wire.at(-1).cookiePresent, true);
        const raw = Buffer.from(`<Response InResponseTo="_${action(index)}"/>`);
        return html(response, post(suiteOrigin + `/p/${PLAN}/sp/acs/0`, 'SAMLResponse', raw.toString('base64')), 200,
          index === 0 ? { 'Set-Cookie': 'fixture-authenticated=yes; HttpOnly; Path=/' } : {});
      } catch (error) { fixtureFailure = error; response.writeHead(500); response.end(); }
    });
    let adapter;
    try {
      suiteOrigin = await listen(suite); targetOrigin = await listen(target);
      const task = validateTask({ suiteBaseUrl: suiteOrigin, targetOrigins: [targetOrigin], runId: RUN, planId: PLAN,
        caseIds: [CASE], outputDirectory: '/private/tmp/synthetic-browser-fixture', actionTimeoutSeconds: 5 });
      const originals = [];
      // The production collector stays visible. This synthetic regression test
      // alone uses headless Chromium; no real IdP or credential is involved.
      const headlessChromium = { launch: options => chromium.launch({ ...options, headless: true }) };
      adapter = await playwrightAdapter(task, headlessChromium, async () => {}, originals);
      const collected = await collectSelected(task, adapter.api, adapter, async (name, value) => { record[name] = structuredClone(value); });
      if (fixtureFailure) throw fixtureFailure;
      assert.equal(collected.counts.selectedTargetActions, 4);
      assert.equal(collected.counts.authenticatedContextReuses, 3);
      assert.equal(collected.counts.freshEmptyContexts, 1);
      assert.equal(collected.counts.automatedCredentialPosts, 0);
      assert.equal(collected.counts.conclusionAssignments, 0);
      assert.deepEqual(wire.map(row => row.cookiePresent), [false, true, true, false]);
      assert.equal(originals.length, 8);
      const proofs = await collectNativeOriginalDigests(task, originals, entries, adapter.readOriginalDigest);
      await collectNativeOriginalDigests(task, originals, entries, adapter.readOriginalDigest, null, proofs);
      const manifest = bindProtocolOriginals(task, originals, entries, null, proofs);
      assert.equal(manifest.every(row => row.bindingState === 'recorder-hash-and-action-bound'), true);
      assert.equal(digestReads.length, 8); assert.equal(new Set(digestReads).size, 8);
      assert.equal(entries.every(entry => entry.samlSummary.decodedSha256 === undefined), true);
      assert.equal(JSON.stringify(record).includes('fixture-authenticated=yes'), false);
      assert.equal(JSON.stringify(manifest).includes('fixture-authenticated=yes'), false);
      assert.equal(record['evaluation.json'].syntheticOnly, true);
    } finally { await adapter?.close(); await close(suite); await close(target); }
  });
