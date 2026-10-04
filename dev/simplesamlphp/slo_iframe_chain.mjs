#!/usr/bin/env node
/**
 * Drive a SimpleSAMLphp single-logout run in a real browser with the IdP's iframe logout handler.
 * The Python wrapper pre-registers the Suite SP and two propagation participants and sets
 * logouttype=iframe. This driver logs every top-level navigation so the iframe-logout page can be
 * advanced deterministically; it never assigns a verdict.
 */
import { chromium } from 'playwright';
import fs from 'fs';
import path from 'path';

const base = 'http://localhost:18080';
const ssp = 'http://localhost:18380';
const plan = process.argv[2];
const run = process.argv[3];
const outDir = process.argv[4];
const username = 'samlscope-m0-user';
const password = 'samlscope-m0-password';
fs.mkdirSync(outDir, { recursive: true });
if (!plan || !run) { console.error('plan and run arguments are required'); process.exit(2); }

const record = { status: 'running', plan, run, navigations: [], steps: [] };
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
  const user = page.locator('input[name="username"], #username, input[name="j_username"]').first();
  if (await user.count()) {
    await user.fill(username);
    await page.locator('input[name="password"], #password, input[name="j_password"]').first().fill(password);
    const submit = page.locator('#submit_button, button[type=submit], input[type=submit], #kc-login, button:has-text("Login")').first();
    if (await submit.count()) await submit.click().catch(() => {});
    else await page.locator('form#f').first().evaluate((form) => form.submit()).catch(() => {});
    await page.waitForLoadState('networkidle').catch(() => {});
    return true;
  }
  return false;
}

let browser;
try {
  browser = await chromium.launch({
    headless: true,
    ...(process.env.SAML_SCOPE_CHROMIUM_EXECUTABLE
      ? { executablePath: process.env.SAML_SCOPE_CHROMIUM_EXECUTABLE }
      : { channel: 'chrome' }),
  });
  const context = await browser.newContext();
  const pages = [];
  record.failed = [];
  record.console = [];
  record.securityHeaders = [];
  const track = (p) => {
    if (pages.includes(p)) return;
    pages.push(p);
    p.on('framenavigated', (frame) => {
      if (frame === p.mainFrame() && record.navigations.length < 400) {
        record.navigations.push({ page: pages.indexOf(p), url: p.url() });
      }
    });
    p.on('requestfailed', (req) => {
      if (record.failed.length < 100) record.failed.push({ url: req.url().slice(0, 140), err: (req.failure() || {}).errorText });
    });
    p.on('response', (response) => {
      const pathname = new URL(response.url()).pathname;
      if (!/logout-iframe|singleLogout|\/sp\/slo/.test(pathname) || record.securityHeaders.length >= 100) return;
      const headers = response.headers();
      record.securityHeaders.push({ pathname, status: response.status(),
        csp: headers['content-security-policy'] || null,
        xFrameOptions: headers['x-frame-options'] || null });
    });
    p.on('console', (msg) => {
      if (msg.type() === 'error' && record.console.length < 100) record.console.push(msg.text().slice(0, 220));
    });
  };
  context.on('page', track);
  let page = await context.newPage();
  track(page);
  const currentPage = () => (pages.filter((p) => !p.isClosed()).slice(-1)[0]) || page;

  await page.goto(`${base}/p/${plan}/start/m0-roundtrip?run=${run}`, { waitUntil: 'networkidle' });
  for (let i = 0; i < 6; i++) {
    const checkbox = page.locator('input[name="freshSessionConfirmed"]');
    if (await checkbox.count()) await checkbox.check().catch(() => {});
    const confirm = page.getByRole('button', { name: /Continue with this request/i });
    if (await confirm.count()) { await confirm.click().catch(() => {}); await page.waitForLoadState('networkidle').catch(() => {}); }
    await fillLogin(page).catch(() => false);
    await page.waitForLoadState('networkidle').catch(() => {});
    const text = await page.locator('body').innerText().catch(() => '');
    if (/round trip completed|Response recorded|SAML Response recorded/i.test(text)) break;
    await page.waitForTimeout(1000);
  }
  record.steps.push('initial-login');

  for (const suffix of ['remain', 'fail']) {
    await api(`/api/runs/${run}/target-initiated`, true, { kind: 'UNSOLICITED_SSO' });
    const provider = `${base}/p/${plan}/sp-${suffix}`;
    await page.goto(`${ssp}/simplesaml/module.php/saml/idp/singleSignOnService?spentityid=${encodeURIComponent(provider)}`, { waitUntil: 'networkidle' });
    record.steps.push(`participant-${suffix}`);
  }

  await api(`/api/runs/${run}/tests/start`, true);

  for (let index = 0; index < 400; index++) {
    let pageRef = currentPage();
    const status = await json(`/api/runs/${run}/active-probe`);
    if (status.state === 'AWAITING_RESPONSE') { await api(`/api/runs/${run}/active-probe/abort`, true); continue; }
    if (status.state !== 'READY') { record.steps.push(`chain-${status.state}`); break; }
    await pageRef.goto(status.startUrl, { waitUntil: 'networkidle', timeout: 120000 }).catch(() => {});
    const checkbox = pageRef.locator('input[name="freshSessionConfirmed"]');
    if (await checkbox.count()) await checkbox.check().catch(() => {});
    const confirm = pageRef.getByRole('button', { name: /Continue with this request/i });
    if (await confirm.count()) { await confirm.click().catch(() => {}); await pageRef.waitForLoadState('networkidle').catch(() => {}); }
    await fillLogin(pageRef).catch(() => false);
    await pageRef.waitForLoadState('networkidle').catch(() => {});
    if (!pageRef.isClosed()) await pageRef.waitForTimeout(1500);

    const maxWait = status.caseId === 'IIP-IDP17-a-idp-01' ? 60 : 12;
    let current = await json(`/api/runs/${run}/active-probe`);
    let clickedAllForAction = false;
    for (let wait = 0; wait < maxWait; wait++) {
      if (current.actionId !== status.actionId || current.state !== 'AWAITING_RESPONSE') break;
      for (const p of pages.filter((q) => !q.isClosed())) {
        const url = p.url();
        if (url.includes('logout-iframe') && !record.iframePage) {
          record.iframePage = url;
          fs.writeFileSync(path.join(outDir, 'logout-iframe.html'), await p.content().catch(() => '<unavailable>'));
          record.iframeBefore = await p.evaluate(() => Array.from(document.querySelectorAll('iframe[id^="iframe-"]'))
            .map((f) => ({ id: f.id, data: (f.getAttribute('data-url') || '').slice(0, 60), src: (f.getAttribute('src') || '').slice(0, 60) })))
            .catch(() => 'error');
          const btn = p.locator('#btn-all');
          if (await btn.count()) {
            try {
              await btn.first().click({ force: true });
              clickedAllForAction = true;
              record.iframeClicked = (record.iframeClicked || 0) + 1;
            } catch { /* Leave the protocol outcome unresolved. */ }
          }
          await p.waitForTimeout(4000);
          record.iframeAfter = await p.evaluate(() => Array.from(document.querySelectorAll('iframe[id^="iframe-"]'))
            .map((f) => ({ id: f.id, src: (f.getAttribute('src') || '').slice(0, 80) })))
            .catch(() => 'error');
        }
        const all = p.locator('#btn-all');
        if (!clickedAllForAction && await all.count()) {
          try {
            await all.first().click({ timeout: 2000, force: true });
            clickedAllForAction = true;
            record.iframeClicked = (record.iframeClicked || 0) + 1;
          } catch { /* Leave the protocol outcome unresolved. */ }
        }
        const cont = p.locator('#btn-continue');
        const iframeCount = await p.locator('iframe[id^="iframe-"]').count().catch(() => 0);
        if (iframeCount > 0 && record.framesSeen !== true) { record.framesSeen = true; record.framePage = url; }
        // The product auto-continues only when every participant succeeds. After an induced
        // failure it intentionally reveals a Continue button for the user to acknowledge the
        // partial logout. Click it only once it is visible and enabled; this records the
        // genuine product transition without inventing a SAML response.
        if (await cont.count() && await cont.isVisible().catch(() => false)
            && await cont.isEnabled().catch(() => false)) {
          try {
            await cont.click({ timeout: 3000 });
            record.partialLogoutContinues = (record.partialLogoutContinues || 0) + 1;
          } catch { /* Keep the underlying protocol outcome unresolved. */ }
        }
      }
      await pageRef.waitForTimeout(1000);
      current = await json(`/api/runs/${run}/active-probe`);
    }
    if (current.state === 'AWAITING_RESPONSE' && current.actionId === status.actionId) {
      await api(`/api/runs/${run}/active-probe/abort`, true);
    }
    // A case may first use one or more login actions before its logout action. Stop only
    // after the product's logout iframe has actually been observed in this browser run.
    if (process.env.SAML_SCOPE_SLO_STOP_AFTER_FIRST_COMPLETED === '1'
        && (record.partialLogoutContinues || 0) > 0
        && (current.actionId !== status.actionId || current.state !== 'AWAITING_RESPONSE')) {
      record.steps.push('stopped-after-first-completed-partial-logout');
      break;
    }
    if (process.env.SAML_SCOPE_SLO_STOP_AFTER_CASE === status.caseId && record.iframePage) {
      record.steps.push(`stopped-after-${status.caseId}`);
      break;
    }
  }

  try { await api(`/api/runs/${run}/target-initiated/conclude`, true); } catch {}
  await api(`/api/runs/${run}/protocol-evidence/evaluate`, true);
  const result = JSON.parse(await api(`/api/runs/${run}/result.json`));
  const outcomes = {};
  for (const requirement of result.requirements) {
    for (const testCase of requirement.cases) {
      if (testCase.id.startsWith('IIP-IDP17') || testCase.id.startsWith('IIP-IDP18')) {
        outcomes[testCase.id] = `${testCase.outcome} ${testCase.verdict} ${testCase.reason_code}`;
      }
    }
  }
  record.outcomes = outcomes;
  record.status = 'success';
  console.log('SSP IFRAME CHAIN DONE', JSON.stringify(outcomes));
} catch (error) {
  record.status = 'failure';
  record.failure_reason = String(error).slice(0, 500);
  console.error('SSP IFRAME CHAIN FAILED', record.failure_reason);
  process.exitCode = 1;
} finally {
  await browser?.close();
  fs.writeFileSync(path.join(outDir, 'iframe-chain-record.json'), JSON.stringify(record, null, 2));
}
