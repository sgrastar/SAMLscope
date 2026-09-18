/** Browser boundary tests; run with the reference harness's installed Playwright environment. */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';
import { observeUiConsumer, saveUiConsumerObservation } from './ui_consumer_observation.mjs';

test('only a visible candidate on the bound product page is recorded', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'samlscope-ui-observation-'));
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  try {
    const fixturePath = path.join(dir, 'fixture.xml');
    const importReceiptPath = path.join(dir, 'import.json');
    fs.writeFileSync(fixturePath, '<fixture/>');
    fs.writeFileSync(importReceiptPath, '{}');
    const context = await browser.newContext({ locale: 'en-US' });
    await context.route('http://product.test/**', route => route.fulfill({ contentType: 'text/html', body: '<main></main>' }));
    const page = await context.newPage();
    await page.goto('http://product.test/login');
    const options = {
      runId: 'run_C97YCPR7F5KNWRMCMHWNPQ11N9', condition: 'display-all', fixturePath, importReceiptPath,
      expectedOrigin: 'http://product.test', expectedPath: '/login', preferredLanguage: 'en-US',
      elementSelector: '#name', kind: 'display-name', candidates: { display: 'Display candidate', service: 'Service candidate' },
    };
    const sample = async html => {
      await page.setContent(html);
      return observeUiConsumer(page, options);
    };
    const good = await sample('<h1 id="name">Display candidate</h1>');
    assert.equal(good.status, 'observed');
    assert.equal(good.selected_candidate, 'display');
    assert.equal(good.import_binding_verified, false);
    assert.equal(good.verdict_adopted, false);
    for (const html of [
      '<h1 id="name" hidden>Display candidate</h1>',
      '<h1 id="name" style="opacity:0">Display candidate</h1>',
      '<h1 id="name">Display candidate</h1><h1 id="name">Display candidate</h1>',
      '<h1 id="name" style="position:absolute;top:10000px">Display candidate</h1>',
      '<input id="name" value="credential-sentinel"/>',
      '<div id="name"><input value="credential-sentinel"/>Display candidate</div>',
      '<h1 id="name">credential-sentinel</h1>',
      '<h1 id="name">Display candidate</h1><div style="position:fixed;inset:0;z-index:999;background:white"></div>',
    ]) {
      const rejected = await sample(html);
      assert.equal(rejected.status, 'not-observed');
      assert.equal(JSON.stringify(rejected).includes('credential-sentinel'), false);
      assert.equal('selected_candidate' in rejected, false);
    }
    await page.goto('http://product.test/admin');
    assert.equal((await observeUiConsumer(page, options)).reason, 'unexpected-product-page');
    await page.goto('http://product.test/login');
    assert.equal((await observeUiConsumer(page, { ...options, preferredLanguage: 'fr' })).reason, 'browser-language-mismatch');
    const image = 'data:image/svg+xml;base64,' + Buffer.from(
      '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20"><rect width="20" height="20"/></svg>'
    ).toString('base64');
    const logoOptions = { ...options, kind: 'logo', elementSelector: '#logo', candidates: { default: image } };
    await page.setContent(`<img id="logo" src="${image}"/>`);
    await page.locator('#logo').evaluate(element => element.decode());
    assert.equal((await observeUiConsumer(page, logoOptions)).selected_candidate, 'default');
    await page.setContent('<img id="logo" src="data:image/png;base64,broken" alt="Display candidate"/>');
    const brokenImage = await observeUiConsumer(page, logoOptions);
    assert.equal(brokenImage.status, 'not-observed');
    assert.equal('selected_candidate' in brokenImage, false);
    const recordPath = path.join(dir, 'observation.json');
    saveUiConsumerObservation(recordPath, good);
    assert.throws(() => saveUiConsumerObservation(recordPath, good), { code: 'EEXIST' });
  } finally {
    await browser.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
