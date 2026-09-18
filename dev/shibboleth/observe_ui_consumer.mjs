#!/usr/bin/env node
/** Stop at the native login screen; no credentials or form submission are needed. */
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { observeUiConsumer, saveUiConsumerObservation } from '../reference-acceptance/ui_consumer_observation.mjs';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.SAMLSCOPE_PLAYWRIGHT_MODULE || 'playwright');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const target = new URL(input.startUrl);
if (target.origin !== 'http://localhost:18080' || !target.pathname.startsWith('/p/')) {
  throw new Error('Unexpected Suite start URL');
}
let browser;
try {
  browser = await chromium.launch({ channel: 'chrome', headless: true });
  const context = await browser.newContext({ locale: 'en-US' });
  const page = await context.newPage();
  await page.goto(input.startUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForURL(url => url.origin === 'http://localhost:18280', { timeout: 30000 });
  await page.locator('#username').waitFor({ state: 'visible', timeout: 30000 });
  // Both paths are advertised by this pinned reference IdP. Never accept an arbitrary current path.
  const loginPath = new URL(page.url()).pathname;
  if (!['/idp/profile/SAML2/Redirect/SSO', '/idp/profile/SAML2/POST/SSO'].includes(loginPath)) {
    throw new Error('Unexpected native SSO endpoint');
  }
  const record = await observeUiConsumer(page, {
    ...input.observation, expectedOrigin: 'http://localhost:18280',
    expectedPath: loginPath, preferredLanguage: 'en-US',
    elementSelector: input.observation.kind === 'logo' ? 'img.service-logo' : 'header h1',
  });
  saveUiConsumerObservation(input.output, record);
  console.log(record.status, record.reason ?? record.selected_candidate);
} catch {
  // Browser exception strings can contain SAML query strings. Persist a fixed diagnostic only.
  saveUiConsumerObservation(input.output, {
    schema: 'samlscope-ui-consumer-navigation-failure-v1',
    run_id: input.observation.runId, condition: input.observation.condition,
    status: 'not-observed', reason: 'native-login-page-unavailable', verdict_adopted: false,
  });
  process.exitCode = 1;
} finally {
  await browser?.close();
}
