#!/usr/bin/env node
/**
 * Drive a SimpleSAMLphp single-logout run in a real browser: complete the initial login through
 * the Suite SP round trip, start the profile tests, then trigger a Suite-initiated logout.
 * The Suite records the target's propagated LogoutRequests. Exit code 0 only on success.
 */
import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const repoRoot = process.env.SAML_SCOPE_ROOT || process.cwd();
const base = 'http://localhost:18080';
const plan = process.argv[2];
const outDir = process.argv[3] ?? path.join(repoRoot, 'build/acceptance/reference-20260918/ssp-slo');
const username = 'samlscope-m0-user';
const password = 'samlscope-m0-password';
fs.mkdirSync(outDir, { recursive: true });
if (!plan) { console.error('plan argument required'); process.exit(2); }

const record = { status: 'running', plan, steps: [] };
const api = async (p, post = false, body) => {
  const response = await fetch(base + p, {
    method: post ? 'POST' : 'GET',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : post ? '' : undefined,
  });
  if (!response.ok) throw new Error(`${p} -> ${response.status}`);
  return await response.text();
};
const json = async (p) => JSON.parse(await api(p));

async function fillLogin(page) {
  // SimpleSAMLphp's loginuserpass form, plus the common Suite probe fields.
  const user = page.locator('input[name="username"], #username, input[name="j_username"]').first();
  if (await user.count()) {
    await user.fill(username);
    await page.locator('input[name="password"], #password, input[name="j_password"]').first().fill(password);
    const submit = page.locator('#submit_button, button[type=submit], input[type=submit], #kc-login, button:has-text("Login")').first();
    if (await submit.count()) await submit.click();
    else await page.locator('form#f').first().evaluate((form) => form.submit());
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

  browser = await chromium.launch({ channel: 'chrome', headless: true });
  const context = await browser.newContext();
  let page = await context.newPage();
  const ensurePage = async () => { if (page.isClosed()) page = await context.newPage(); return page; };

  // Initial login through the Suite SP round trip.
  await page.goto(`${base}/p/${plan}/start/m0-roundtrip?run=${run}`, { waitUntil: 'networkidle' });
  for (let i = 0; i < 6; i++) {
    const checkbox = page.locator('input[name="freshSessionConfirmed"]');
    if (await checkbox.count()) { await checkbox.check().catch(() => {}); }
    const confirm = page.getByRole('button', { name: /Continue with this request/i });
    if (await confirm.count()) { await confirm.click().catch(() => {}); await page.waitForLoadState('networkidle').catch(() => {}); }
    await fillLogin(page).catch(() => false);
    await page.waitForLoadState('networkidle').catch(() => {});
    const text = await page.locator('body').innerText().catch(() => '');
    if (/round trip completed|Response recorded|SAML Response recorded/i.test(text)) break;
    await page.waitForTimeout(1000);
  }
  record.steps.push('initial-login');
  record.loginPage = await page.locator('body').innerText().catch(() => '');
  record.loginUrl = page.url();
  await page.screenshot({ path: path.join(outDir, 'after-login.png'), fullPage: true }).catch(() => {});

  await api(`/api/runs/${run}/tests/start`, true);
  record.steps.push('tests-start');

  // Drive the active-probe chain, completing logins and advancing propagation views.
  for (let index = 0; index < 400; index++) {
    const pageRef = await ensurePage();
    const status = await json(`/api/runs/${run}/active-probe`);
    if (status.state === 'AWAITING_RESPONSE') {
      record.probes = record.probes ?? [];
      record.probes.push({ caseId: status.caseId, action: 'abort' });
      await api(`/api/runs/${run}/active-probe/abort`, true);
      continue;
    }
    if (status.state !== 'READY') { record.steps.push(`chain-${status.state}`); break; }
    await pageRef.goto(status.startUrl, { waitUntil: 'networkidle', timeout: 120000 }).catch((error) => {
      record.probes = record.probes ?? [];
      record.probes.push({ caseId: status.caseId, navigation: String(error).slice(0, 120) });
    });
    const checkbox = pageRef.locator('input[name="freshSessionConfirmed"]');
    if (await checkbox.count()) await checkbox.check().catch(() => {});
    const confirm = pageRef.getByRole('button', { name: /Continue with this request/i });
    if (await confirm.count()) { await confirm.click().catch(() => {}); await pageRef.waitForLoadState('networkidle').catch(() => {}); }
    await fillLogin(pageRef).catch(() => false);
    await pageRef.waitForLoadState('networkidle').catch(() => {});
    if (!pageRef.isClosed()) await pageRef.waitForTimeout(1500);
    const maxWait = status.caseId === 'IIP-IDP17-a-idp-01' ? 60 : 20;
    let current = await json(`/api/runs/${run}/active-probe`);
    for (let wait = 0; wait < maxWait; wait++) {
      if (current.actionId !== status.actionId || current.state !== 'AWAITING_RESPONSE') break;
      if (!pageRef.isClosed()) {
        const propagate = pageRef.getByRole('button', { name: /continue|proceed|logout|yes|OK/i });
        if (await propagate.count()) await propagate.first().click({ timeout: 2000 }).catch(() => {});
        const link = pageRef.getByRole('link', { name: /continue|proceed|logout/i });
        if (await link.count()) await link.first().click({ timeout: 2000 }).catch(() => {});
      }
      if (!pageRef.isClosed()) await pageRef.waitForTimeout(1000);
      current = await json(`/api/runs/${run}/active-probe`);
    }
    if (current.state === 'AWAITING_RESPONSE' && current.actionId === status.actionId) {
      await api(`/api/runs/${run}/active-probe/abort`, true);
    }
  }

  await api(`/api/runs/${run}/protocol-evidence/evaluate`, true);
  for (const suffix of ['', '/result.json', '/transcript']) {
    fs.writeFileSync(path.join(outDir, suffix.replace(/^\//, '') || 'run.json'), await api(`/api/runs/${run}${suffix}`));
  }
  const result = JSON.parse(fs.readFileSync(path.join(outDir, 'result.json'), 'utf8'));
  const outcomes = {};
  for (const requirement of result.requirements) {
    for (const testCase of requirement.cases) {
      if (testCase.id.startsWith('IIP-IDP17') || testCase.id.startsWith('IIP-IDP18') || testCase.id.startsWith('IIP-IDP19')) {
        outcomes[testCase.id] = `${testCase.outcome} ${testCase.verdict} ${testCase.reason_code}`;
      }
    }
  }
  record.outcomes = outcomes;
  record.status = 'success';
  console.log('SSP SLO CHAIN DONE', JSON.stringify(outcomes));
} catch (error) {
  record.status = 'failure';
  record.failure_reason = String(error).slice(0, 500);
  console.error('SSP SLO CHAIN FAILED', record.failure_reason);
  process.exitCode = 1;
} finally {
  await browser?.close();
  fs.writeFileSync(path.join(outDir, 'chain-record.json'), JSON.stringify(record, null, 2));
}
