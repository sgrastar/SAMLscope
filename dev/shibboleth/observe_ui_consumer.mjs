#!/usr/bin/env node
/** Stop at the native login screen; no credentials or form submission are needed. */
import fs from 'node:fs';
import crypto from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { createRequire } from 'node:module';
import { observeUiConsumer, observeUiUrlConsumer, saveUiConsumerObservation } from '../reference-acceptance/ui_consumer_observation.mjs';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.SAMLSCOPE_PLAYWRIGHT_MODULE || 'playwright');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const target = new URL(input.startUrl);
if (target.origin !== 'http://localhost:18080' || !target.pathname.startsWith('/p/')) {
  throw new Error('Unexpected Suite start URL');
}
let browser;
try {
  const assetSpki = process.env.SAMLSCOPE_UI_ASSET_SPKI;
  if (assetSpki && !/^[A-Za-z0-9+/]{43}=$/.test(assetSpki)) throw new Error('Invalid fixture certificate pin');
  browser = await chromium.launch({ channel: 'chrome', headless: true,
    args: assetSpki ? [`--ignore-certificate-errors-spki-list=${assetSpki}`] : [] });
  const context = await browser.newContext({ locale: 'en-US' });
  const page = await context.newPage();
  const requestSamples = [];
  page.on('request', request => {
    const url = new URL(request.url());
    if (!request.isNavigationRequest() || request.frame() !== page.mainFrame()
        || url.origin !== 'http://localhost:18280'
        || !['/idp/profile/SAML2/Redirect/SSO', '/idp/profile/SAML2/POST/SSO'].includes(url.pathname)) return;
    const fields = request.method() === 'POST' ? new URLSearchParams(request.postData() ?? '') : url.searchParams;
    if (!fields.has('SAMLRequest')) return; // Never record login values or Webflow form submissions.
    requestSamples.push((async () => {
      try {
        const values = fields.getAll('SAMLRequest');
        if (values.length !== 1 || values[0].length > 262144 || !/^[A-Za-z0-9+/]*={0,2}$/.test(values[0])) {
          return { status: 'invalid-request-encoding' };
        }
        const encoded = Buffer.from(values[0], 'base64');
        const xml = request.method() === 'GET' ? inflateRawSync(encoded, { maxOutputLength: 262144 }) : encoded;
        const language = await request.headerValue('accept-language');
        return { status: 'captured', decoded_sha256: crypto.createHash('sha256').update(xml).digest('hex'),
          decoded_bytes: xml.length, method: request.method(), endpoint_path: url.pathname,
          // Explicit allowlist: no Cookie, Authorization, full URL, request body, or response text.
          accept_language: language && /^[A-Za-z0-9,;=*.\- ]{1,128}$/.test(language) ? language : null };
      } catch { return { status: 'request-capture-unavailable' }; }
    })());
  });
  await page.goto(input.startUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForURL(url => url.origin === 'http://localhost:18280', { timeout: 30000 });
  await page.locator('#username').waitFor({ state: 'visible', timeout: 30000 });
  // Both paths are advertised by this pinned reference IdP. Never accept an arbitrary current path.
  const loginPath = new URL(page.url()).pathname;
  if (!['/idp/profile/SAML2/Redirect/SSO', '/idp/profile/SAML2/POST/SSO'].includes(loginPath)) {
    throw new Error('Unexpected native SSO endpoint');
  }
  if (input.observation.kind === 'logo') {
    // Operational wait only. Timeout remains unobserved, never a product violation.
    await page.waitForFunction(() => {
      const image = document.querySelector('img.service-logo');
      return !image || image.complete;
    }, null, { timeout: 15000 }).catch(() => {});
  }
  const observer = input.observation.condition.startsWith('ui-url-') ? observeUiUrlConsumer : observeUiConsumer;
  const record = await observer(page, {
    ...input.observation, expectedOrigin: 'http://localhost:18280',
    expectedPath: loginPath, preferredLanguage: 'en-US',
    elementSelector: input.observation.kind === 'logo' ? 'img.service-logo'
      : input.observation.kind === 'link' ? `a[href=${JSON.stringify(input.observation.candidates.probe)}]` : 'header h1',
  });
  if (input.observation.condition.startsWith('ui-url-')) {
    // An absent URL element is only a diagnostic. First establish that the correct SP login UI rendered.
    const anchor = await observeUiConsumer(page, {
      ...input.observation, expectedOrigin: 'http://localhost:18280', expectedPath: loginPath,
      preferredLanguage: 'en-US', elementSelector: 'header h1', kind: 'display-name',
      candidates: { control: 'Login to SAMLscope URL policy control' },
    });
    record.page_anchor = { status: anchor.status, reason: anchor.reason ?? null, selected_candidate: anchor.selected_candidate ?? null };
    record.url_absence_is_nonuse_proof = false;
    record.url_selector_scope = input.observation.kind === 'logo' ? 'native-logo-slot' : 'candidate-matching-anchor';
  }
  const samples = await Promise.all(requestSamples);
  record.browser_request = samples.length === 1 ? samples[0] : { status: 'ambiguous-or-missing-request', count: samples.length };
  record.fixture_certificate_pin = assetSpki ?? null;
  record.document_language = await page.evaluate(() => {
    const language = document.documentElement.lang;
    return /^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$/.test(language) ? language : null;
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
