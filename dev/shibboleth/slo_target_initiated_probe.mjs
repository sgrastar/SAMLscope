#!/usr/bin/env node
/**
 * IdP-initiated-only logout probe: establish the Suite participant sessions, prepare the
 * target-initiated logout intent, then trigger the target's own logout profile WITHOUT a
 * Suite-initiated LogoutRequest. IIP-IDP17.r/s need a run whose transcript has no OUTBOUND
 * LogoutRequest, so the propagation rules take the target-initiated branch.
 */
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const repoRoot = process.env.SAML_SCOPE_ROOT || process.cwd();
const base = 'http://localhost:18080';
const idp = 'http://localhost:18280';
const plan = process.argv[2] ?? 'plan_3C0PZPNZD8P9C1MXK9V9QJ43DD';
const outDir = process.argv[3] ?? path.join(repoRoot, 'build/acceptance/reference-20260918/shibboleth-slo-target-initiated');
const username = 'samlscope-m0-user';
const password = 'samlscope-m0-password';
fs.mkdirSync(outDir, { recursive: true });

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
  const user = page.locator('#username, input[name="j_username"], input[name="username"]').first();
  if (await user.count()) {
    await user.fill(username);
    await page.locator('#password, input[name="j_password"], input[name="password"]').first().fill(password);
    await page.locator('button[type=submit], #kc-login, button:has-text("Sign In"), button:has-text("Login")').first().click();
    await page.waitForLoadState('networkidle');
    return true;
  }
  return false;
}

let browser;
const record = { plan, steps: [] };
try {
  const created = JSON.parse(await api(`/api/plans/${plan}/runs`, true));
  const run = created.run.id;
  record.run = run;
  await api(`/api/runs/${run}/preflight`, true);
  execFileSync('python3', [path.join(repoRoot, 'build/acceptance/reference-20260915/slo-oracle/setup_rs_participants.py'), run], { cwd: repoRoot, stdio: 'pipe' });

  browser = await chromium.launch({ channel: 'chrome', headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(`${base}/p/${plan}/start/m0-roundtrip?run=${run}`, { waitUntil: 'networkidle' });
  await fillLogin(page);
  await page.waitForLoadState('networkidle');
  record.steps.push('primary-login');
  for (const suffix of ['fail', 'remain']) {
    await api(`/api/runs/${run}/target-initiated`, true, { kind: 'UNSOLICITED_SSO' });
    const provider = `${base}/p/${plan}/sp-${suffix}`;
    await page.goto(`${idp}/idp/profile/SAML2/Unsolicited/SSO?providerId=${encodeURIComponent(provider)}`, { waitUntil: 'networkidle' });
    await page.waitForLoadState('networkidle');
    record.steps.push(`participant-${suffix}`);
  }
  await api(`/api/runs/${run}/tests/start`, true);
  await api(`/api/runs/${run}/target-initiated`, true, { kind: 'TARGET_LOGOUT' });
  // Trigger the target's own logout profile; the IdP should propagate LogoutRequests to the
  // participants without any Suite-initiated LogoutRequest in the transcript.
  await page.goto(`${idp}/idp/profile/Logout`, { waitUntil: 'networkidle' }).catch((error) => String(error));
  record.logoutUrl = page.url();
  record.steps.push('idp-logout');
  // Advance the target's own logout/propagation view exactly as a user would.
  for (let step = 0; step < 20; step++) {
    const before = page.url();
    // The IdP logout view offers a local logout and a global (propagating) logout. Only the
    // global option makes the target send LogoutRequests to the other participants.
    const global = page.getByRole('button', { name: /グローバル|global/i });
    const globalLink = page.getByRole('link', { name: /グローバル|global/i });
    if (await global.count()) await global.first().click({ timeout: 2000 }).catch(() => {});
    else if (await globalLink.count()) await globalLink.first().click({ timeout: 2000 }).catch(() => {});
    const propagate = page.getByRole('button', { name: /propagate|continue|proceed|confirm/i });
    if (await propagate.count()) await propagate.first().click({ timeout: 2000 }).catch(() => {});
    await page.waitForLoadState('networkidle').catch(() => {});
    await page.waitForTimeout(1500);
    if (page.url() === before && step > 3) break;
  }
  record.finalPage = await page.locator('body').innerText().catch(() => '');
  for (let wait = 0; wait < 15; wait++) {
    await page.waitForTimeout(1000);
  }
  try { await api(`/api/runs/${run}/target-initiated/conclude`, true); } catch {}
  const entries = await json(`/api/runs/${run}/transcript`);
  fs.writeFileSync(`${outDir}/transcript.json`, JSON.stringify(entries));
  record.outboundLogoutRequests = entries.filter((e) => e.direction === 'OUTBOUND' && (e.samlSummary || {}).type === 'LogoutRequest').length;
  record.inboundLogoutRequests = entries.filter((e) => e.direction === 'INBOUND' && (e.rawQuery || '').includes('SAMLRequest=')).length;
  record.inboundLogoutResponses = entries.filter((e) => e.direction === 'INBOUND' && (e.samlSummary || {}).type === 'LogoutResponse').length;
  await api(`/api/runs/${run}/protocol-evidence/evaluate`, true);
  for (const suffix of ['', '/result.json']) {
    fs.writeFileSync(`${outDir}/${suffix.replace(/^\//, '') || 'run.json'}`, await api(`/api/runs/${run}${suffix}`));
  }
  const result = JSON.parse(fs.readFileSync(`${outDir}/result.json`, 'utf8'));
  const outcomes = {};
  for (const requirement of result.requirements) {
    for (const testCase of requirement.cases) {
      if (['IIP-IDP17-r-idp-01', 'IIP-IDP17-s-idp-01'].includes(testCase.id)) {
        outcomes[testCase.id] = `${testCase.outcome} ${testCase.verdict} ${testCase.reason_code}`;
      }
    }
  }
  record.outcomes = outcomes;
  fs.writeFileSync(`${outDir}/probe-record.json`, JSON.stringify(record, null, 2));
  console.log('TARGET INITIATED PROBE', JSON.stringify(record));
} catch (error) {
  record.failure_reason = String(error).slice(0, 500);
  fs.writeFileSync(`${outDir}/probe-record.json`, JSON.stringify(record, null, 2));
  console.error('PROBE FAILED', record.failure_reason);
  process.exitCode = 1;
} finally {
  await browser?.close();
}
