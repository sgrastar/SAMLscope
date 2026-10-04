#!/usr/bin/env node
/** One fresh native challenge. Secrets are removed before writing response originals. */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { inflateRawSync } from 'node:zlib';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { chromium } = require(process.env.SAMLSCOPE_PLAYWRIGHT_MODULE || 'playwright');
const input = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const folder = path.dirname(process.argv[2]);
const sha = raw => crypto.createHash('sha256').update(raw).digest('hex');
const save = (file, value) => fs.writeFileSync(path.join(folder, file), JSON.stringify(value, null, 2)+'\n', {flag:'wx',mode:0o600});
const start = new URL(input.startUrl);
if (start.origin !== 'http://localhost:18080' || !start.pathname.startsWith('/p/')
    || !/^run_[0-9A-HJKMNP-TV-Z]{26}$/.test(input.runId)) throw new Error('Unexpected local Suite identity');
const TOKEN='SAMLscope-UI-safety-v1';
let browser;
let stage='launch';
const record={schema:'samlscope-shibboleth-native-ui-browser-v1',runId:input.runId,variant:input.variant,
    startedAt:new Date().toISOString(),initialCookieCount:0,requests:[],resources:[],dialogs:[],status:'incomplete'};
const pending=[];
try {
    browser=await chromium.launch({channel:'chrome',headless:true});
    const context=await browser.newContext({locale:'en-US'});
    if ((await context.cookies()).length) throw new Error('Fresh browser unexpectedly has a cookie');
    const page=await context.newPage();
    const resources=new Map();
    page.on('request',request=>{
        if(request.resourceType()!=='image'||request.url()!==input.candidates.probe) return;
        const row={candidate:'probe',urlSha256:sha(Buffer.from(request.url())),method:request.method(),
            resourceType:request.resourceType(),requestedAt:new Date().toISOString()};
        resources.set(request,row);record.resources.push(row);
    });
    page.on('requestfailed',request=>{
        const row=resources.get(request);if(!row)return;
        row.failedAt=new Date().toISOString();
        const code=request.failure()?.errorText;
        row.failureCode=/^net::ERR_[A-Z_]+$/.test(code??'')?code:'network-failure';
    });
    page.on('response',response=>{
        const row=resources.get(response.request());if(!row)return;
        pending.push((async()=>{
            row.respondedAt=new Date().toISOString();row.status=response.status();
            const bytes=await response.body();row.bodySha256=sha(bytes);row.bytes=bytes.length;
        })());
    });
    let nativeChallenge;
    page.on('response',response=>{
        const url=new URL(response.url());
        if(url.origin==='http://localhost:18280'&&url.pathname.endsWith('/SSO')
            &&/^\?execution=e[0-9]+s[0-9]+$/.test(url.search)&&response.status()===200){
            nativeChallenge=(async()=>({url:url.href,status:response.status(),body:await response.body()}))();
        }
    });
    page.on('dialog', async dialog => {record.dialogs.push({type:dialog.type(),probeToken:dialog.message()===TOKEN});await dialog.dismiss();});
    page.on('request',request=>{
        const url=new URL(request.url());
        if (url.origin!=='http://localhost:18280' || !request.isNavigationRequest()
            || request.frame()!==page.mainFrame() || !url.pathname.endsWith('/SSO')) return;
        const fields=request.method()==='GET'?url.searchParams:new URLSearchParams(request.postData()??'');
        if (!fields.has('SAMLRequest')) return; // Never capture a credential/CSRF form submission.
        pending.push((async()=>{
            const encoded=Buffer.from(fields.get('SAMLRequest'),'base64');
            const raw=request.method()==='GET'?inflateRawSync(encoded,{maxOutputLength:1048576}):encoded;
            const ids=raw.toString().match(/\bID="([^"]+)"/g)??[];
            const requestId=ids.length?ids[0].slice(4,-1):null;
            const language=await request.headerValue('accept-language');
            record.requests.push({requestId,method:request.method(),targetUrl:url.origin+url.pathname,
                rawQuery:request.method()==='GET'?url.search.slice(1):null,sha256:sha(raw),bytes:raw.length,
                acceptLanguage:language,observedAt:new Date().toISOString()});
        })());
    });
    stage='navigate';
    await page.goto(input.startUrl,{waitUntil:'domcontentloaded',timeout:45000});
    stage='challenge';
    await page.locator('input[name="j_password"]').waitFor({state:'visible',timeout:45000});
    await Promise.all(pending);
    if (record.requests.length!==1) throw new Error('Ambiguous native SAML dispatch');
    const current=new URL(page.url());
    if (current.origin!=='http://localhost:18280' || !current.pathname.endsWith('/SSO')
        || !/^\?execution=e[0-9]+s[0-9]+$/.test(current.search)) throw new Error('Unexpected native challenge URL');
    if (await page.locator('input[name="j_username"]').inputValue()
        || await page.locator('input[name="j_password"]').inputValue()) throw new Error('Precredential fields were not empty');
    // The native response contains an anti-CSRF token. Only the sanitized original leaves memory.
    // Serialize no values from hidden/token fields, and no cookies, headers, or credentials.
    stage='native-body';
    if(!nativeChallenge)throw new Error('Missing native challenge response');
    const response=await nativeChallenge;
    const rawBody=response.body.toString('utf8');
    const body=rawBody.replace(/<input\b[^>]*>/giu,tag=>
        /\btype\s*=\s*(?:["']hidden["']|hidden(?=\s|>))|\bname\s*=\s*["'][^"']*(?:csrf|token)[^"']*["']/iu.test(tag)
            ?tag.replace(/\bvalue\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/giu,'value="[REDACTED]"'):tag);
    if (/\b(?:j_username|j_password)\b[^>]*value=["'][^"']+/iu.test(body)) throw new Error('Populated login field');
    fs.writeFileSync(path.join(folder,'native-challenge.html'),body,{flag:'wx',mode:0o600});
    record.challenge={url:current.href,status:response.status,recordedAt:new Date().toISOString(),
        bodyFile:'native-challenge.html',bodySha256:sha(Buffer.from(body)),redaction:'hidden-token-values-before-persistence'};
    await page.waitForTimeout(250);
    await Promise.all(pending);
    record.dom=await page.evaluate(candidates=>{
        const matches=(selector,attribute)=>Array.from(document.querySelectorAll(selector)).map(node=>{
            const value=attribute?node.getAttribute(attribute):node.textContent.trim().replace(/\s+/gu,' ');
            return {candidate:Object.entries(candidates).find(([,expected])=>value===expected)?.[0]??null,
                tag:node.tagName.toLowerCase(),visible:!!(node.getBoundingClientRect().width&&node.getBoundingClientRect().height),
                ...(node instanceof HTMLImageElement?{complete:node.complete,width:node.naturalWidth,height:node.naturalHeight}:{})};
        });
        return {headings:matches('header h1',null),logos:matches('img.service-logo','src'),
            candidateLinks:matches('a','href').filter(row=>row.candidate),
            passwordInputs:document.querySelectorAll('input[name="j_password"]').length,
            usernameInputs:document.querySelectorAll('input[name="j_username"]').length,
            preferredLanguage:navigator.language,observedAt:new Date().toISOString(),
            executableProbeNodes:Array.from(document.querySelectorAll('script,iframe,object,embed'))
                .filter(node=>(node.textContent+' '+Array.from(node.attributes).map(a=>a.value).join(' ')).includes('SAMLscope-UI-safety-v1')).length};
    },input.candidates);
    if(input.authenticate){
        const submitted=new Date().toISOString();
        await page.locator('input[name="j_username"]').fill(process.env.REFERENCE_USERNAME||'samlscope-m0-user');
        await page.locator('input[name="j_password"]').fill(process.env.REFERENCE_PASSWORD||'samlscope-m0-password');
        await page.locator('button[type="submit"]').first().click();
        await page.waitForURL(url=>url.origin==='http://localhost:18080',{timeout:45000});
        record.authentication={submittedAt:submitted,returnedToSuiteAt:new Date().toISOString()};
    }
    record.finishedAt=new Date().toISOString();record.status='captured';
    // An isolated active sink must trigger the same dialog detector. It never contacts the IdP.
    if(input.activeSinkControl){
        const control=await browser.newContext();const controlPage=await control.newPage();const dialogs=[];
        controlPage.on('dialog',async d=>{dialogs.push({type:d.type(),probeToken:d.message()===TOKEN});await d.dismiss();});
        const uri=input.candidates.probe;
        if(!uri?.startsWith('data:image/svg+xml;base64,'))throw new Error('Control requires fixed public SVG');
        const controlHtml=Buffer.from(uri.slice('data:image/svg+xml;base64,'.length),'base64').toString('utf8');
        fs.writeFileSync(path.join(folder,'active-sink-control.html'),controlHtml,{flag:'wx',mode:0o600});
        await controlPage.goto(uri,{waitUntil:'load'});await controlPage.waitForTimeout(250);
        record.activeSinkControl={htmlFile:'active-sink-control.html',htmlSha256:sha(Buffer.from(controlHtml)),
            scope:'isolated-top-level-svg',dialogs,observedAt:new Date().toISOString()};await control.close();
    }
}catch(error){record.status='failed';record.failureStage=stage;record.failureCode=error instanceof Error?error.constructor.name:'failure';process.exitCode=1;}
finally{await browser?.close();save('browser-original.json',record);console.log(input.variant,record.status);}
