import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.SAML_SCOPE_PLAYWRIGHT || '/private/tmp/samlscope-md05-audit.Yf6Pqm/build/acceptance/reference-20260915/slo-oracle/console-import/node_modules/playwright');
const origin = 'http://localhost:18380';
const sha = body => createHash('sha256').update(body).digest('hex');
let browser, context, count = 0;
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
async function view(page) {
  return { firstParagraph: await page.locator('article p, main p, #content p').first().innerText().catch(async () => await page.locator('p').first().innerText()),
    images: await page.locator('img').evaluateAll(elements => elements.map(e => ({ src: e.getAttribute('src'), alt: e.getAttribute('alt'), naturalWidth: e.naturalWidth, naturalHeight: e.naturalHeight }))) };
}
try {
  for await (const line of lines) {
    if (!line.trim()) continue;
    let stage = 'input';
    try {
      const task = JSON.parse(line);
      if (task.stop) break;
      if (new URL(task.url).origin !== origin || !Array.isArray(task.tokens)) throw new Error('Native UI origin differs');
      if (!browser) {
        stage = 'launch'; browser = await chromium.launch({ headless: true, channel: 'chrome' });
        context = await browser.newContext({ locale: 'en-US' });
      }
      stage = 'cookies';
      await context.addCookies(task.cookies.map(c => ({ name: c.name, value: c.value, url: origin })));
      const page = await context.newPage(), resources = [], pending = [], securityResponses=[], nativeSecurityBlocks=[];
      const policyProjection=value=>(value||'').replace(/nonce-[A-Za-z0-9+/_=-]+/g,'nonce-[REDACTED]');
      const securityConsole=(message,source)=>{const value=message.text();if(/content.security.policy|violates.*policy/i.test(value)&&/javascript|script-src|inline/i.test(value))nativeSecurityBlocks.push({type:message.type(),message:policyProjection(value),source,recordedAt:new Date().toISOString()});};
      page.on('console',message=>securityConsole(message,'native-consent-window'));
      const nativeDialogs=[];
      const onDialog=(dialog,source)=>{nativeDialogs.push({type:dialog.type(),probeToken:dialog.message()==='SAMLscope-UI-safety-v1',source,recordedAt:new Date().toISOString()});return dialog.dismiss();};
      page.on('dialog',dialog=>onDialog(dialog,'native-consent-window'));
      const newPages=[];
      const onPage=other=>{if(other!==page){newPages.push(other);other.on('dialog',dialog=>onDialog(dialog,'native-link-popup'));other.on('console',message=>securityConsole(message,'native-link-popup'));}};
      context.on('page',onPage);
      page.on('response', response => {
        const url = new URL(response.url());
        if(url.origin===origin&&['/simplesaml/module.php/consent/getconsent','/simplesaml/module.php/consent/noconsent'].includes(url.pathname))securityResponses.push({path:url.pathname,status:response.status(),contentSecurityPolicy:policyProjection(response.headers()['content-security-policy']),recordedAt:new Date().toISOString()});
        if (url.origin !== origin || (!url.pathname.includes('/assets/') && !url.pathname.startsWith('/simplesaml/assets/'))) return;
        pending.push(response.body().then(bytes => resources.push({ path: url.pathname, status: response.status(), bytes: bytes.length, sha256: sha(bytes) })).catch(() => {}));
      });
      stage = 'navigate';
      const response = await page.goto(task.url, { waitUntil: 'networkidle', timeout: 25000 });
      stage = 'native-form';
      if (response.status() !== 200 || await page.locator('#consent-yes').count() !== 1) throw new Error('Native consent UI unavailable');
      stage = 'public-observation';
      const consent = await view(page);
      const observation = { browser: 'chromium', origin, status: response.status(), ...consent,
        attributeHeader: await page.locator('#attributeheader').innerText(),
        preferredLanguage: 'en-US', browserInstance: 'campaign-shared-browser', observationIndex: ++count };
      if(task.variant?.startsWith('ui-safety-'))observation.nativeImageSlot=await page.locator('img').evaluate(element=>element.outerHTML);
      if(task.variant==='ui-safety-privacy-javascript') {
        const link=page.locator('a').filter({hasText:'Privacy policy for the service'});
        if(await link.count()!==1)throw new Error('Native privacy link unavailable');
        observation.nativeLinkUse={element:'PrivacyStatementURL',href:await link.getAttribute('href'),target:await link.getAttribute('target'),anchorOuterHtml:await link.evaluate(element=>element.outerHTML),pagePath:new URL(page.url()).pathname,clickedAt:new Date().toISOString()};
        await link.click({timeout:10000});
        await page.waitForTimeout(250);
        observation.nativeLinkUse.completedAt=new Date().toISOString();
      }
      // This is the real native No button and the same StateId, not a separate login.
      stage = 'native-noconsent';
      await page.locator('#nobutton').click();
      await page.waitForURL(url => url.pathname.endsWith('/consent/noconsent'), { timeout: 10000 });
      await page.waitForLoadState('networkidle');
      observation.noConsent = { ...await view(page), path: new URL(page.url()).pathname,
        informationLinks: await page.locator('a').evaluateAll(elements => elements.filter(e => e.textContent.includes('Go to information page for the service')).map(e => ({ href: e.getAttribute('href'), text: e.textContent.trim() }))), recordedAt: new Date().toISOString() };
      if(task.variant==='ui-safety-information-javascript') {
        const link=page.locator('a').filter({hasText:'Go to information page for the service'});
        if(await link.count()!==1)throw new Error('Native information link unavailable');
        observation.nativeLinkUse={element:'InformationURL',href:await link.getAttribute('href'),target:await link.getAttribute('target'),anchorOuterHtml:await link.evaluate(element=>element.outerHTML),pagePath:new URL(page.url()).pathname,clickedAt:new Date().toISOString()};
        await link.click({timeout:10000});await page.waitForTimeout(250);
        observation.nativeLinkUse.completedAt=new Date().toISOString();
      }
      stage = 'return-consent';
      await page.locator('a').filter({ hasText: 'Return to consent page' }).click();
      await page.waitForURL(url => url.pathname.endsWith('/consent/getconsent'), { timeout: 10000 });
      if (await page.locator('#consent-yes').count() !== 1) throw new Error('Native same-state consent did not return');
      await Promise.all(pending);
      observation.resources = resources;
      observation.securityResponses=securityResponses;
      if(task.variant?.startsWith('ui-safety-')) {
        const controlContext=await browser.newContext({locale:'en-US'}),controlPage=await controlContext.newPage(),controlDialogs=[];
        const detectorDialog=async dialog=>{controlDialogs.push({type:dialog.type(),probeToken:dialog.message()==='SAMLscope-UI-safety-v1'});await dialog.dismiss();};
        controlPage.on('dialog',detectorDialog);
        controlContext.on('page',other=>{if(other!==controlPage)other.on('dialog',detectorDialog);});
        await controlPage.route('**/*',route=>route.abort());
        const svg="<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"180\" height=\"48\"><rect width=\"180\" height=\"48\" fill=\"#1d4ed8\"/><script>alert('SAMLscope-UI-safety-v1')</script></svg>";
        await controlPage.setContent(svg,{waitUntil:'load'});observation.activeDetectorControl={scope:'isolated-top-level-svg',bodySha256:sha(Buffer.from(svg)),dialogs:[...controlDialogs]};
        controlDialogs.length=0;
        const probe="javascript:alert('SAMLscope-UI-safety-v1')";
        if(observation.nativeLinkUse) {
          const anchor=observation.nativeLinkUse.anchorOuterHtml;
          if(task.tokens.some(token=>token&&anchor.includes(token)))throw new Error('Native public URL slot contains state');
          await controlPage.setContent(anchor,{waitUntil:'load'});
          await controlPage.locator('a').evaluate((element,value)=>element.setAttribute('href',value),probe);
          await controlPage.locator('a').click();await controlPage.waitForTimeout(50);
          observation.javascriptDetectorControl={scope:'isolated-native-link-slot',sourceAnchorSha256:sha(Buffer.from(anchor)),href:probe,onlyHrefChanged:true,dialogs:[...controlDialogs]};
          controlDialogs.length=0;
          await controlPage.locator('a').evaluate(element=>element.setAttribute('href','#safe'));
          await controlPage.locator('a').click();await controlPage.waitForTimeout(50);
          observation.safeLinkDetectorControl={scope:'isolated-native-link-slot',sourceAnchorSha256:sha(Buffer.from(anchor)),href:'#safe',onlyHrefChanged:true,dialogs:[...controlDialogs]};
        } else {
          await controlPage.setContent(observation.nativeImageSlot,{waitUntil:'load'});
          const mutated=svg;await controlPage.setContent(mutated,{waitUntil:'load'});
          await controlPage.waitForTimeout(50);
          observation.nativeImageSlotControl={scope:'isolated-native-image-slot',sourceImageSha256:sha(Buffer.from(observation.nativeImageSlot)),replacementSha256:sha(Buffer.from(mutated)),onlyImageSlotChanged:true,dialogs:[...controlDialogs]};
        }
        await controlContext.close();
        observation.nativeDialogs=nativeDialogs;observation.nativeSecurityBlocks=nativeSecurityBlocks;
      }
      observation.recordedAt = new Date().toISOString();
      const encoded = JSON.stringify(observation);
      if (task.tokens.some(token => token && encoded.includes(token))) throw new Error('Public projection contains authentication state');
      process.stdout.write(JSON.stringify({ ok: true, observation }) + '\n');
      context.removeListener('page',onPage);for(const other of newPages)await other.close().catch(()=>{});
      await page.close();
    } catch (error) { process.stdout.write(JSON.stringify({ ok: false, stage, errorClass: error.name }) + '\n'); }
  }
} finally { await browser?.close(); }
