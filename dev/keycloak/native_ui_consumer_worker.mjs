/** One shared Chrome process, fresh empty context per native UI operation; no cookies/credentials persisted. */
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
const require=createRequire(import.meta.url);
const { chromium }=require(process.env.SAMLSCOPE_PLAYWRIGHT_MODULE);
const sha=b=>createHash('sha256').update(b).digest('hex');
const lines=createInterface({input:process.stdin,crlfDelay:Infinity});
let browser,count=0;
try{
 for await(const line of lines){
  if(!line.trim())continue;const input=JSON.parse(line);if(input.stop)break;
  let context,stage='input';const pending=[];
  try{
   const start=new URL(input.startUrl);
   if(start.origin!=='http://localhost:18080'||!/^run_[0-9A-HJKMNP-TV-Z]{26}$/.test(input.runId)||!Array.isArray(input.candidates))throw new Error('Local Suite operation required');
   if(!browser){stage='launch';browser=await chromium.launch({channel:'chrome',headless:true});}
   context=await browser.newContext({locale:'en-US'});
   if((await context.cookies()).length)throw new Error('Context was not fresh');
   const page=await context.newPage(),requests=[],resources=[],nativePages=[];
   await context.route('**/*',route=>{
    const u=new URL(route.request().url());
    if(['data:','about:'].includes(u.protocol)||(['http:','https:'].includes(u.protocol)&&u.hostname==='localhost'&&[18080,18180].includes(Number(u.port))))return route.continue();
    return route.abort();
   });
   page.on('request',request=>{
    const u=new URL(request.url());
    if(input.candidates.includes(request.url()))resources.push({urlSha256:sha(Buffer.from(request.url())),method:request.method(),resourceType:request.resourceType(),recordedAt:new Date().toISOString()});
    if(u.origin!=='http://localhost:18180'||u.pathname!=='/realms/samlscope/protocol/saml'||!request.isNavigationRequest())return;
    const fields=request.method()==='GET'?u.searchParams:new URLSearchParams(request.postData()??'');
    if(!fields.has('SAMLRequest'))return;
    pending.push((async()=>{const b=Buffer.from(fields.get('SAMLRequest'),'base64');const raw=request.method()==='GET'?inflateRawSync(b,{maxOutputLength:1048576}):b;
     const id=raw.toString().match(/\bID="([^"]+)"/);requests.push({requestId:id?.[1],method:request.method(),targetUrl:u.origin+u.pathname,rawQuery:request.method()==='GET'?u.search.slice(1):null,sha256:sha(raw),bytes:raw.length,acceptLanguage:await request.headerValue('accept-language'),recordedAt:new Date().toISOString()});})());
   });
   page.on('response',response=>{
    const u=new URL(response.url());
    if(u.origin==='http://localhost:18180'&&response.request().isNavigationRequest())pending.push((async()=>{
     const body=await response.body().catch(()=>null);if(!body)return;
     nativePages.push({path:u.pathname,status:response.status(),bodySha256:sha(body),bytes:body.length,recordedAt:new Date().toISOString()});
    })());
   });
   stage='navigate';await page.goto(input.startUrl,{waitUntil:'domcontentloaded',timeout:45000});
   let consent=null,login=null;
   for(let step=0;step<25;step++){
    await page.waitForLoadState('domcontentloaded').catch(()=>{});
    const url=new URL(page.url());
    if(url.origin==='http://localhost:18180'&&await page.locator('input[name="password"]').count()){
     stage='login';
     if(!login)login={path:url.pathname,recordedAt:new Date().toISOString()};
     await page.locator('input[name="username"]').fill(process.env.REFERENCE_USERNAME??'samlscope-m0-user');
     await page.locator('input[name="password"]').fill(process.env.REFERENCE_PASSWORD??'samlscope-m0-password');
     await page.locator('#kc-login').click();continue;
    }
    if(url.origin==='http://localhost:18180'&&await page.locator('#kc-oauth').count()){
     stage='consent';if(consent)throw new Error('Repeated consent operation');
     consent=await page.evaluate(candidates=>{
      const all=[...document.querySelectorAll('img')].map(e=>({src:e.getAttribute('src'),visible:!!(e.offsetWidth&&e.offsetHeight),naturalWidth:e.naturalWidth,naturalHeight:e.naturalHeight}));
      const links=[...document.querySelectorAll('#kc-oauth a')].map(e=>({href:e.getAttribute('href'),text:e.textContent.trim(),visible:!!(e.offsetWidth&&e.offsetHeight)}));
      const copy=document.documentElement.cloneNode(true);
      for(const e of copy.querySelectorAll('script'))e.remove();
      for(const e of copy.querySelectorAll('[nonce]'))e.removeAttribute('nonce');
      for(const e of copy.querySelectorAll('input')){e.removeAttribute('value');if(e.type==='password'||/username|password|token|csrf/i.test(e.name))e.setAttribute('data-redacted','true');}
      for(const e of copy.querySelectorAll('[action]'))e.setAttribute('action',new URL(e.getAttribute('action'),location.href).pathname);
      for(const e of copy.querySelectorAll('[href]')){try{const u=new URL(e.getAttribute('href'),location.href);if(u.origin===location.origin&&u.search&&!candidates.includes(u.href))e.setAttribute('href',u.pathname);}catch{}}
      return {images:all,policyLinks:links,html:copy.outerHTML};
     },input.candidates);
     consent.path=url.pathname;consent.recordedAt=new Date().toISOString();
     // Only the projected public UI leaves browser memory. Never the original CSRF/action state.
     const html=consent.html;delete consent.html;consent.publicHtmlSha256=sha(Buffer.from(html));consent.publicHtmlBytes=Buffer.byteLength(html);
     fs.writeFileSync(input.publicHtmlFile,html,{flag:'wx',mode:0o600});
     await page.locator('#kc-oauth [name="accept"]').click();continue;
    }
    if(url.origin==='http://localhost:18080'&&url.pathname.endsWith('/sp/acs'))break;
    if(url.origin==='http://localhost:18080'&&requests.length&&url.pathname.includes('/metadata'))break;
    // Navigation can be queued by the native auto-submit form. Do not submit an unrelated form.
    await page.waitForTimeout(100);
   }
   await Promise.all(pending);if(requests.length!==1)throw new Error('Native SAML request correlation ambiguous');
   const observation={schema:'samlscope-keycloak-native-ui-browser-v1',runId:input.runId,variant:input.variant,startedAt:input.startedAt,completedAt:new Date().toISOString(),browserInstance:'single-campaign-Chrome',contextIndex:++count,initialCookieCount:0,preferredLanguage:'en-US',requests,nativePages,login,consent,resources,finalOrigin:new URL(page.url()).origin,finalPath:new URL(page.url()).pathname,credentialsPersisted:false,externalRequestsPermitted:false};
   process.stdout.write(JSON.stringify({ok:true,observation})+'\n');
  }catch(error){process.stdout.write(JSON.stringify({ok:false,stage,errorClass:error.name})+'\n');}
  finally{await context?.close();}
 }
}finally{await browser?.close();}
