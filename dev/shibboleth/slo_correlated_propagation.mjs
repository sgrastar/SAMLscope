#!/usr/bin/env node
/** One Suite-initiated logout, with participant sessions established before delivery. */
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const repo = process.env.SAML_SCOPE_ROOT || process.cwd();
const base = 'http://localhost:18080';
const idp = 'http://localhost:18280';
const plan = process.argv[2];
const out = process.argv[3];
const record = { plan, steps: [], status: 'running' };
const api = async (route, body) => {
  const res = await fetch(base + route, { method: body === undefined ? 'GET' : 'POST',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body) });
  if (!res.ok) throw new Error(`${route}: HTTP ${res.status}`);
  return res.json();
};
let browser;
async function login(page) {
  const user = page.locator('#username, input[name="j_username"]').first();
  if (!await user.count()) return;
  await user.fill('samlscope-m0-user');
  await page.locator('#password, input[name="j_password"]').first().fill('samlscope-m0-password');
  await page.locator('button[type=submit]').first().click();
  await page.waitForLoadState('networkidle');
}
try {
  const created = await api(`/api/plans/${plan}/runs`, {});
  const run = record.run = created.run.id;
  fs.writeFileSync(path.join(out, 'created.json'), JSON.stringify(created, null, 2));
  await api(`/api/runs/${run}/preflight`, {});
  execFileSync('python3', [path.join(repo, 'dev/shibboleth/setup_slo_participants.py'), run]);
  browser = await chromium.launch({ headless: true, channel: 'chrome' });
  const bootstrap = await browser.newContext();
  const bootstrapPage = await bootstrap.newPage();
  await bootstrapPage.goto(`${base}/p/${plan}/start/m0-roundtrip?run=${run}`, { waitUntil: 'networkidle' });
  await login(bootstrapPage);
  await bootstrap.close();
  record.steps.push('baseline-session');
  let context = await browser.newContext();
  let page = await context.newPage();
  await api(`/api/runs/${run}/tests/start`, {});
  let status = await api(`/api/runs/${run}/active-probe`);
  record.preparatoryActions = [];
  for (let index = 0; index < 150 && status.caseId !== 'IIP-IDP17-a-idp-01'; index++) {
    if (status.state !== 'READY') throw new Error(`Cannot reach logout: ${JSON.stringify(status)}`);
    if (status.requiresFreshSession) {
      await context.close();
      context = await browser.newContext();
      page = await context.newPage();
    }
    await page.goto(status.startUrl, { waitUntil: 'networkidle', timeout: 30000 }).catch(() => {});
    const checkbox = page.locator('input[name="freshSessionConfirmed"]');
    if (await checkbox.count()) await checkbox.check();
    const proceed = page.getByRole('button', { name: /Continue with this request/i });
    if (await proceed.count()) await proceed.click();
    await page.waitForLoadState('networkidle').catch(() => {});
    await login(page);
    const next = await api(`/api/runs/${run}/active-probe`);
    const pending = next.state === 'AWAITING_RESPONSE' && next.actionId === status.actionId;
    record.preparatoryActions.push({ caseId: status.caseId, actionId: status.actionId, aborted: pending });
    // These preparatory cases are outside this campaign's adoption scope.
    status = pending ? await api(`/api/runs/${run}/active-probe/abort`, {}) : next;
  }
  if (status.caseId !== 'IIP-IDP17-a-idp-01' || status.state !== 'READY' || !status.requiresFreshSession)
    throw new Error(`Unexpected first scenario: ${JSON.stringify(status)}`);
  await context.close();
  context = await browser.newContext();
  page = await context.newPage();
  await page.goto(status.startUrl, { waitUntil: 'networkidle' });
  const fresh = page.locator('input[name="freshSessionConfirmed"]');
  if (await fresh.count()) await fresh.check();
  const confirm = page.getByRole('button', { name: /Continue with this request/i });
  if (await confirm.count()) await confirm.click();
  await page.waitForLoadState('networkidle');
  await login(page);
  record.steps.push('fresh-primary-login');
  status = await api(`/api/runs/${run}/active-probe`);
  if (status.caseId !== 'IIP-IDP17-a-idp-01' || status.state !== 'READY' || status.requiresFreshSession)
    throw new Error(`Logout was not queued: ${JSON.stringify(status)}`);
  record.initiatorAction = status.actionId;
  for (const suffix of ['fail', 'remain']) {
    await api(`/api/runs/${run}/target-initiated`, { kind: 'UNSOLICITED_SSO' });
    const entity = `${base}/p/${plan}/sp-${suffix}`;
    await page.goto(`${idp}/idp/profile/SAML2/Unsolicited/SSO?providerId=${encodeURIComponent(entity)}`,
      { waitUntil: 'networkidle' });
    record.steps.push(`participant-${suffix}`);
  }
  await api(`/api/runs/${run}/target-initiated`, { kind: 'TARGET_LOGOUT' });
  await page.goto(status.startUrl, { waitUntil: 'networkidle', timeout: 120000 });
  const sendLogout = page.getByRole('button', { name: /Continue with this request/i });
  if (await sendLogout.count()) {
    await sendLogout.click();
    await page.waitForLoadState('networkidle').catch(() => {});
  }
  record.steps.push('suite-logout');
  for (let attempt = 0; attempt < 90; attempt++) {
    const next = await api(`/api/runs/${run}/active-probe`);
    if (next.actionId !== status.actionId || next.state !== 'AWAITING_RESPONSE') {
      record.completedInitiator = next.actionId !== status.actionId;
      break;
    }
    const button = page.getByRole('button', { name: /\u30b0\u30ed\u30fc\u30d0\u30eb|global|propagate|continue|proceed|confirm/i });
    const link = page.getByRole('link', { name: /\u30b0\u30ed\u30fc\u30d0\u30eb|global|propagate|continue|proceed/i });
    if (await button.count()) await button.first().click({ timeout: 2000 }).catch(() => {});
    else if (await link.count()) await link.first().click({ timeout: 2000 }).catch(() => {});
    await page.waitForTimeout(1000);
  }
  // Do not navigate the next queued action: the Run must contain exactly one logout operation.
  await api(`/api/runs/${run}/target-initiated/conclude`, {});
  await api(`/api/runs/${run}/protocol-evidence/evaluate`, {});
  for (const suffix of ['transcript', 'result.json', 'protocol-evidence']) {
    const value = await api(`/api/runs/${run}/${suffix}`);
    fs.writeFileSync(path.join(out, suffix.includes('.') ? suffix : suffix + '.json'),
      JSON.stringify(value, null, 2));
  }
  record.status = 'success';
} catch (error) {
  record.status = 'failure';
  record.failureReason = String(error).slice(0, 800);
  process.exitCode = 1;
} finally {
  await browser?.close();
  fs.writeFileSync(path.join(out, 'webflow-record.json'), JSON.stringify(record, null, 2));
  console.log(JSON.stringify(record));
}
