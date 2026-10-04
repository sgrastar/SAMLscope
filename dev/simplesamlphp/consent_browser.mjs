import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.SAML_SCOPE_PLAYWRIGHT || '/private/tmp/samlscope-md05-audit.Yf6Pqm/build/acceptance/reference-20260915/slo-oracle/console-import/node_modules/playwright');
let input = ''; for await (const part of process.stdin) input += part;
const task = JSON.parse(input);
if (new URL(task.url).origin !== 'http://localhost:18380') throw new Error('Native UI origin differs');
let browser; let stage = 'launch';
try {
  browser = await chromium.launch({ headless: true, channel: 'chrome' });
  stage = 'cookies';
  const context = await browser.newContext({ locale: 'en-US' });
  await context.addCookies(task.cookies.map(c => ({ name: c.name, value: c.value, url: 'http://localhost:18380' })));
  const page = await context.newPage();
  stage = 'navigate';
  const response = await page.goto(task.url, { waitUntil: 'domcontentloaded', timeout: 20000 });
  stage = 'native-form';
  if (response.status() !== 200 || await page.locator('#consent-yes').count() !== 1) throw new Error('Native consent UI unavailable');
  stage = 'public-observation';
  const observation = { browser: 'chromium', origin: new URL(page.url()).origin, status: response.status(),
    firstParagraph: await page.locator('article p, main p, #content p').first().innerText().catch(async () => await page.locator('p').first().innerText()),
    attributeHeader: await page.locator('#attributeheader').innerText(),
    images: await page.locator('img').evaluateAll(elements => elements.map(e => ({ src: e.getAttribute('src'), alt: e.getAttribute('alt') }))),
    recordedAt: new Date().toISOString(), preferredLanguage: 'en-US' };
  const encoded = JSON.stringify(observation);
  if (task.tokens.some(token => token && encoded.includes(token))) throw new Error('Public projection contains authentication state');
  process.stdout.write(encoded);
} catch (error) { process.stderr.write(JSON.stringify({ stage, errorClass: error.name })); process.exitCode = 1; }
finally { await browser?.close(); }
