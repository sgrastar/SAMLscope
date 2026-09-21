#!/usr/bin/env node
/**
 * Drives the Suite's active-probe chain in a real browser so the IdP's own Webflow
 * (including the propagation view scripts) completes. The browser performs the user
 * actions; the Suite records the protocol evidence. Exit code 0 only when the chain
 * finished and the evaluation was written.
 */
import { chromium } from 'playwright';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const repoRoot = process.env.SAML_SCOPE_ROOT || process.cwd();

const base = 'http://localhost:18080';
const plan = process.argv[2] ?? 'plan_3C0PZPNZD8P9C1MXK9V9QJ43DD';
const outDir = process.argv[3] ?? path.join(repoRoot, 'build/acceptance/reference-20260915/peer-intent/shibboleth/slo_webflow');
const username = 'samlscope-m0-user';
const password = 'samlscope-m0-password';
fs.mkdirSync(outDir, { recursive: true });

const record = { status: 'running', plan, steps: [], probes: [] };
const api = async (path, post = false, body) => {
  const response = await fetch(base + path, {
    method: post ? 'POST' : 'GET',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : post ? '' : undefined,
  });
  if (!response.ok) throw new Error(`${path} -> ${response.status}`);
  return await response.text();
};
const json = async (path) => JSON.parse(await api(path));
const fail = (detail) => { record.status = 'failure'; record.failure_reason = detail; };

async function fillLogin(page) {
  const user = page.locator('#username, input[name="j_username"], input[name="username"]').first();
  if (await user.count()) {
    await user.fill(username);
    const pass = page.locator('#password, input[name="j_password"], input[name="password"]').first();
    await pass.fill(password);
    await page.locator('button[type=submit], #kc-login, button:has-text("Sign In"), button:has-text("Login")').first().click();
    await page.waitForLoadState('networkidle');
    return true;
  }
  return false;
}

let browser;
try {
  const created = JSON.parse(await api(`/api/plans/${plan}/runs`, true));
  const run = created.run.id;
  record.run = run;
  await api(`/api/runs/${run}/preflight`, true);
  const { execFileSync } = await import('node:child_process');
  execFileSync('python3', [path.join(repoRoot, 'build/acceptance/reference-20260915/slo-oracle/setup_rs_participants.py'), run], { cwd: repoRoot, stdio: 'pipe' });

  browser = await chromium.launch({ channel: 'chrome', headless: true });
  const context = await browser.newContext();
  let page = await context.newPage();
  const ensurePage = async () => {
    if (page.isClosed()) page = await context.newPage();
    return page;
  };

  await page.goto(`${base}/p/${plan}/start/m0-roundtrip?run=${run}`, { waitUntil: 'networkidle' });
  await fillLogin(page);
  await page.waitForLoadState('networkidle');
  record.steps.push('primary-login');
  for (const suffix of ['fail', 'remain']) {
    // Establish the participant's IdP session through the target's unsolicited SSO profile. The
    // Suite records such an unsolicited Response only against a prepared single-use intent, so
    // prepare one per participant; otherwise the Suite drops the assertion before recording it
    // and the participant session cannot be correlated with a later LogoutRequest.
    await api(`/api/runs/${run}/target-initiated`, true, { kind: 'UNSOLICITED_SSO' });
    const provider = `http://localhost:18080/p/${plan}/sp-${suffix}`;
    await page.goto(`http://localhost:18280/idp/profile/SAML2/Unsolicited/SSO?providerId=${encodeURIComponent(provider)}`, { waitUntil: 'networkidle' });
    await page.waitForLoadState('networkidle');
    record.steps.push(`participant-${suffix}`);
  }
  await api(`/api/runs/${run}/tests/start`, true);
  await api(`/api/runs/${run}/target-initiated`, true, { kind: 'TARGET_LOGOUT' });

  for (let index = 0; index < 400; index++) {
    const pageRef = await ensurePage();
    const status = await json(`/api/runs/${run}/active-probe`);
    if (status.state === 'AWAITING_RESPONSE') {
      record.probes.push({ caseId: status.caseId, action: 'abort' });
      await api(`/api/runs/${run}/active-probe/abort`, true);
      continue;
    }
    if (status.state !== 'READY') { record.steps.push(`chain-${status.state}`); break; }
    await pageRef.goto(status.startUrl, { waitUntil: 'networkidle', timeout: 120000 }).catch((error) => {
      record.probes.push({ caseId: status.caseId, navigation: String(error).slice(0, 120) });
    });
    const checkbox = pageRef.locator('input[name="freshSessionConfirmed"]');
    if (await checkbox.count()) await checkbox.check().catch(() => {});
    const confirm = pageRef.getByRole('button', { name: /Continue with this request/i });
    if (await confirm.count()) {
      await confirm.click().catch(() => {});
      await pageRef.waitForLoadState('networkidle').catch(() => {});
    }
    await fillLogin(pageRef).catch(() => false);
    await pageRef.waitForLoadState('networkidle').catch(() => {});
    if (!pageRef.isClosed()) await pageRef.waitForTimeout(1500);
    // The IdP Webflow progresses through its propagation scripts; the target logout stage
    // must not be aborted before the propagation reaches the remaining participants.
    const targetLogout = status.caseId === 'IIP-IDP17-a-idp-01' && !status.requiresFreshSession;
    const maxWait = targetLogout ? 90 : 20;
    let current = await json(`/api/runs/${run}/active-probe`);
    for (let wait = 0; wait < maxWait; wait++) {
      if (current.actionId !== status.actionId || current.state !== 'AWAITING_RESPONSE') break;
      if (targetLogout && !pageRef.isClosed()) {
        // Advance the propagation view exactly as a user would, without faking completion.
        const propagate = pageRef.getByRole('button', { name: /propagate|continue|proceed|logout/i });
        if (await propagate.count()) await propagate.first().click({ timeout: 2000 }).catch(() => {});
        const link = pageRef.getByRole('link', { name: /continue|proceed|logout/i });
        if (await link.count()) await link.first().click({ timeout: 2000 }).catch(() => {});
      }
      if (!pageRef.isClosed()) await pageRef.waitForTimeout(1000);
      current = await json(`/api/runs/${run}/active-probe`);
    }
    record.probes.push({ caseId: status.caseId, advanced: current.actionId !== status.actionId || current.state !== 'AWAITING_RESPONSE' });
    if (current.state === 'AWAITING_RESPONSE' && current.actionId === status.actionId) {
      await api(`/api/runs/${run}/active-probe/abort`, true);
    }
  }
  const finalPage = await ensurePage();
  const text = await finalPage.locator('body').innerText().catch(() => '');
  fs.writeFileSync(`${outDir}/final-page.txt`, text);
  if (text.includes('Response recorded')) record.steps.push('browser-response-delivered');
  try { await api(`/api/runs/${run}/target-initiated/conclude`, true); } catch {}
  await api(`/api/runs/${run}/protocol-evidence/evaluate`, true);
  for (const suffix of ['', '/result.json', '/report.html', '/campaigns']) {
    const body = await api(`/api/runs/${run}${suffix}`);
    fs.writeFileSync(`${outDir}/${suffix.replace(/^\//, '') || 'run.json'}`, body);
  }
  const result = JSON.parse(fs.readFileSync(`${outDir}/result.json`, 'utf8'));
  const outcomes = {};
  for (const requirement of result.requirements) {
    for (const testCase of requirement.cases) {
      if (['IIP-IDP17-r-idp-01', 'IIP-IDP17-s-idp-01', 'IIP-IDP18-c-idp-01', 'IIP-IDP18-d-idp-01', 'IIP-IDP17-c-idp-01'].includes(testCase.id)) {
        outcomes[testCase.id] = `${testCase.outcome} ${testCase.verdict} ${testCase.reason_code}`;
      }
    }
  }
  record.outcomes = outcomes;
  fs.writeFileSync(`${outDir}/webflow-record.json`, JSON.stringify(record, null, 2));
  record.status = 'success';
  console.log('WEBFLOW CHAIN DONE', JSON.stringify(outcomes));
} catch (error) {
  fail(String(error).slice(0, 500));
  record.outcomes = record.outcomes ?? {};
} finally {
  await browser?.close();
}
fs.writeFileSync(`${outDir}/webflow-record.json`, JSON.stringify(record, null, 2));
if (record.status !== 'success') {
  console.error(`WEBFLOW CHAIN FAILED: ${record.failure_reason}`);
  process.exit(1);
}
process.exit(0);
