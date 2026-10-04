/** Original native UI observations; one native session, isolated executable controls, no credentials persisted. */
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
const require=createRequire(import.meta.url),{chromium}=require(process.env.SAMLSCOPE_PLAYWRIGHT_MODULE);
const sha=b=>createHash('sha256').update(b).digest('hex'),now=()=>new Date().toISOString();
const TOKEN='SAMLscope-UI-safety-v1',SVG=`<svg xmlns="http://www.w3.org/2000/svg" width="180" height="48"><rect width="180" height="48" fill="#1d4ed8"/><script>alert('${TOKEN}')</script></svg>`,PROBE=`javascript:alert('${TOKEN}')`;
let browser,nativeContext,detector,credentials=0,index=0;
async function controls(){
 const startedAt=now(),context=await browser.newContext(),rows={};
 try{
  for(const kind of ['activeSvg','javascriptAnchor','safeImg','safeAnchor']){
   const page=await context.newPage(),dialogs=[];
   page.on('dialog',async d=>{dialogs.push({type:d.type(),probeToken:d.message()===TOKEN,recordedAt:now()});await d.dismiss();});
   await page.route('**/*',r=>{
    const u=new URL(r.request().url());
    if(u.origin!=='http://127.0.0.1:18482')return r.abort();
    const body=kind==='activeSvg'?SVG:kind==='safeImg'?`<!doctype html><img src="data:image/svg+xml;base64,${Buffer.from(SVG).toString('base64')}">`:`<!doctype html><a id="probe" href="${kind==='javascriptAnchor'?PROBE:'#safe'}">control</a>`;
    return r.fulfill({status:200,contentType:kind==='activeSvg'?'image/svg+xml':'text/html',body});
   });
   await page.goto('http://127.0.0.1:18482/'+kind,{waitUntil:'load',timeout:15000});
   if(kind.includes('Anchor'))await page.locator('#probe').click();
   if(kind==='safeImg')await page.locator('img').evaluate(async e=>{await e.decode();});
   await page.waitForTimeout(150);rows[kind]={dialogs};await page.close();
  }
 }finally{await context.close();}
 if(rows.activeSvg.dialogs.length!==1||!rows.activeSvg.dialogs[0].probeToken||rows.javascriptAnchor.dialogs.length!==1||!rows.javascriptAnchor.dialogs[0].probeToken||rows.safeImg.dialogs.length||rows.safeAnchor.dialogs.length)throw new Error('Detector not calibrated');
 return {scope:'isolated-sandbox-unsafe-sinks',stockProductObservation:false,svgSha256:sha(Buffer.from(SVG)),javascriptHref:PROBE,startedAt,completedAt:now(),...rows};
}
const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
try{
 for await(const line of lines){
  if(!line.trim())continue;const input=JSON.parse(line);if(input.stop)break;
  let page,stage='input',attemptedCredential=0;const pending=[];
  try{
   if(!browser){stage='launch';browser=await chromium.launch({channel:'chrome',headless:true});detector=await controls();nativeContext=await browser.newContext({locale:'en-US'});if((await nativeContext.cookies()).length)throw new Error('Native context was not fresh');}
   if(input.detectorOnly){process.stdout.write(JSON.stringify({ok:true,detector,nativeCredentialSubmissions:credentials,nativeBrowserContexts:1,isolatedDetectorContexts:1})+'\n');continue;}
   const start=new URL(input.startUrl);if(start.origin!=='http://localhost:18080'||!/^run_[0-9A-HJKMNP-TV-Z]{26}$/.test(input.runId)||!Array.isArray(input.candidates))throw new Error('Local Suite operation required');
   page=await nativeContext.newPage();const requests=[],resources=[],nativePages=[],nativeDialogs=[],nativeSecurityBlocks=[];
   page.on('dialog',async d=>{nativeDialogs.push({type:d.type(),probeToken:d.message()===TOKEN,source:'native-consent-page',recordedAt:now()});await d.dismiss();});
   page.on('console',m=>{if(m.type()==='error'&&m.text().includes('Content Security Policy')&&m.text().includes('javascript:'))nativeSecurityBlocks.push({type:'error',knownJavascriptPolicyBlock:true,recordedAt:now()});});
   await page.route('**/*',route=>{
    const u=new URL(route.request().url());
    if(['data:','about:'].includes(u.protocol)||(['http:','https:'].includes(u.protocol)&&u.hostname==='localhost'&&[18080,18180].includes(Number(u.port))))return route.continue();
    return route.abort();
   });
   page.on('request',request=>{
    const u=new URL(request.url());if(input.candidates.includes(request.url()))resources.push({urlSha256:sha(Buffer.from(request.url())),method:request.method(),resourceType:request.resourceType(),recordedAt:now()});
    if(u.origin!=='http://localhost:18180'||u.pathname!=='/realms/samlscope/protocol/saml'||!request.isNavigationRequest())return;
    const fields=request.method()==='GET'?u.searchParams:new URLSearchParams(request.postData()??'');if(!fields.has('SAMLRequest'))return;
    pending.push((async()=>{const b=Buffer.from(fields.get('SAMLRequest'),'base64'),raw=request.method()==='GET'?inflateRawSync(b,{maxOutputLength:1048576}):b,id=raw.toString().match(/\bID="([^"]+)"/);
     requests.push({requestId:id?.[1],method:request.method(),targetUrl:u.origin+u.pathname,rawQuery:request.method()==='GET'?u.search.slice(1):null,sha256:sha(raw),bytes:raw.length,acceptLanguage:await request.headerValue('accept-language'),recordedAt:now()});})());
   });
   page.on('response',response=>{const u=new URL(response.url());if(u.origin==='http://localhost:18180'&&response.request().isNavigationRequest())pending.push((async()=>{const body=await response.body().catch(()=>null);if(body)nativePages.push({path:u.pathname,status:response.status(),bodySha256:sha(body),bytes:body.length,recordedAt:now()});})());});
   stage='navigate';await page.goto(input.startUrl,{waitUntil:'domcontentloaded',timeout:45000});let consent=null;
   for(let step=0;step<100;step++){
    const url=new URL(page.url());
    if(url.origin==='http://localhost:18180'&&await page.locator('input[name="password"]').count()){
     stage='login';if(credentials!==0)throw new Error('Second credential challenge refused');credentials++;attemptedCredential++;
     await page.locator('input[name="username"]').fill(process.env.REFERENCE_USERNAME??'samlscope-m0-user');await page.locator('input[name="password"]').fill(process.env.REFERENCE_PASSWORD??'samlscope-m0-password');await page.locator('#kc-login').click();continue;
    }
    if(url.origin==='http://localhost:18180'&&await page.locator('#kc-oauth').count()){
     stage='consent';if(consent)throw new Error('Repeated consent operation');
     await page.locator('img').evaluateAll(async images=>{await Promise.all(images.map(e=>e.decode().catch(()=>{})));});
     consent=await page.evaluate(candidates=>{
      const images=[...document.querySelectorAll('img')].map(e=>({tag:e.tagName.toLowerCase(),src:e.getAttribute('src'),visible:!!(e.offsetWidth&&e.offsetHeight),complete:e.complete,naturalWidth:e.naturalWidth,naturalHeight:e.naturalHeight}));
      const policyLinks=[...document.querySelectorAll('#kc-oauth a')].map(e=>({href:e.getAttribute('href'),text:e.textContent.trim(),visible:!!(e.offsetWidth&&e.offsetHeight)}));
      const securityNodes=[...document.querySelectorAll('script,object,embed,iframe,[onload],[onerror]')].filter(e=>e.outerHTML.includes('SAMLscope-UI-safety-v1')).map(e=>({tag:e.tagName.toLowerCase(),outerHtml:e.outerHTML}));
      const copy=document.documentElement.cloneNode(true),strippedScripts=[];
      for(const e of copy.querySelectorAll('script')){if(!e.outerHTML.includes('SAMLscope-UI-safety-v1')){strippedScripts.push({src:e.getAttribute('src'),inline:!e.getAttribute('src')});e.remove();}}
      for(const e of copy.querySelectorAll('[nonce]'))e.removeAttribute('nonce');
      for(const e of copy.querySelectorAll('input')){e.removeAttribute('value');if(e.type==='password'||/username|password|token|csrf/i.test(e.name))e.setAttribute('data-redacted','true');}
      for(const e of copy.querySelectorAll('[action]'))e.setAttribute('action',new URL(e.getAttribute('action'),location.href).pathname);
      for(const e of copy.querySelectorAll('[href]')){try{const u=new URL(e.getAttribute('href'),location.href);if(u.origin===location.origin&&u.search&&!candidates.includes(u.href))e.setAttribute('href',u.pathname);}catch{}}
      return {images,policyLinks,securityNodes,strippedScripts,html:copy.outerHTML};
     },input.candidates);consent.path=url.pathname;consent.recordedAt=now();const html=consent.html;delete consent.html;consent.publicHtmlSha256=sha(Buffer.from(html));consent.publicHtmlBytes=Buffer.byteLength(html);fs.writeFileSync(input.publicHtmlFile,html,{flag:'wx',mode:0o600});
     await page.locator('#kc-oauth [name="accept"]').click();continue;
    }
    if(url.origin==='http://localhost:18080'&&consent&&requests.length)break;
    await page.waitForTimeout(100);
   }
   await Promise.all(pending);if(requests.length!==1||!consent)throw new Error('Native request or UI correlation incomplete');
   const observation={schema:'samlscope-keycloak-ui-safety-browser-v1',runId:input.runId,variant:input.variant,startedAt:input.startedAt,completedAt:now(),browserInstance:'single-campaign-Chrome',contextIndex:1,operationIndex:++index,initialCookieCount:0,preferredLanguage:'en-US',credentialSubmissions:attemptedCredential,cumulativeCredentialSubmissions:credentials,sessionReused:index>1,requests,nativePages,consent,resources,nativeDialogs,nativeSecurityBlocks,detector,finalOrigin:new URL(page.url()).origin,finalPath:new URL(page.url()).pathname,credentialsPersisted:false,externalRequestsPermitted:false};
   process.stdout.write(JSON.stringify({ok:true,observation})+'\n');
  }catch(error){process.stdout.write(JSON.stringify({ok:false,stage,errorClass:error.name,credentialSubmissions:attemptedCredential,cumulativeCredentialSubmissions:credentials})+'\n');}
  finally{await page?.close();}
 }
}finally{await nativeContext?.close();await browser?.close();}
