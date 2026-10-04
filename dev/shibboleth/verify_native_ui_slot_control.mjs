#!/usr/bin/env node
/** Read-only detection-power control. No product requests, settings, credentials or cookies. */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';
const {chromium}=createRequire(import.meta.url)(process.env.SAMLSCOPE_PLAYWRIGHT_MODULE||'playwright');
const folder=path.resolve(process.argv[2]);
const input=JSON.parse(fs.readFileSync(path.join(folder,'browser-input.json'),'utf8'));
const original=JSON.parse(fs.readFileSync(path.join(folder,'browser-original.json'),'utf8'));
const html=fs.readFileSync(path.join(folder,'native-challenge.html'),'utf8');
const sha=raw=>crypto.createHash('sha256').update(raw).digest('hex');
const uri=input.candidates.probe;
if(input.variant!=='ui-safety-logo-data'||original.variant!==input.variant||original.runId!==input.runId
    ||sha(html)!==original.challenge.bodySha256||!uri.startsWith('data:image/svg+xml;base64,'))throw new Error('Original mismatch');
const svg=Buffer.from(uri.slice('data:image/svg+xml;base64,'.length),'base64').toString('utf8');
const slots=html.match(/<img\b(?=[^>]*\bclass="service-logo")[^>]*>/giu)??[];
if(slots.length!==1||svg!=="<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"180\" height=\"48\"><rect width=\"180\" height=\"48\" fill=\"#1d4ed8\"/><script>alert('SAMLscope-UI-safety-v1')</script></svg>")throw new Error('Unexpected fixture/sink');
const controlHtml=html.replace(slots[0],svg);
fs.writeFileSync(path.join(folder,'native-slot-control.html'),controlHtml,{flag:'wx',mode:0o600});
let browser;
const result={schema:'samlscope-shibboleth-native-ui-slot-control-v1',runId:input.runId,variant:input.variant,
    scope:'isolated-native-logo-slot',originalBodySha256:sha(html),svgSha256:sha(svg),htmlFile:'native-slot-control.html',
    htmlSha256:sha(controlHtml),dialogs:[],networkRequests:0,startedAt:new Date().toISOString(),status:'incomplete'};
try{
    browser=await chromium.launch({channel:'chrome',headless:true});
    const context=await browser.newContext();
    await context.route('**/*',route=>{result.networkRequests++;return route.abort();});
    const page=await context.newPage();
    page.on('dialog',async dialog=>{result.dialogs.push({type:dialog.type(),probeToken:dialog.message()==='SAMLscope-UI-safety-v1'});await dialog.dismiss();});
    await page.setContent(controlHtml,{waitUntil:'load'});await page.waitForTimeout(250);
    result.dom=await page.evaluate(()=>({probeScripts:Array.from(document.querySelectorAll('svg script'))
        .filter(node=>node.textContent==="alert('SAMLscope-UI-safety-v1')").length,
        passwordInputs:document.querySelectorAll('input[name="j_password"]').length,
        usernameInputs:document.querySelectorAll('input[name="j_username"]').length}));
    if(result.dialogs.length!==1||!result.dialogs[0].probeToken||result.dom.probeScripts!==1)throw new Error('Detector did not observe native-slot mutation');
    result.status='captured';result.finishedAt=new Date().toISOString();
}finally{
    await browser?.close();
    fs.writeFileSync(path.join(folder,'native-slot-control.json'),JSON.stringify(result,null,2)+'\n',{flag:'wx',mode:0o600});
}
console.log('same native Logo slot detection control',result.status);
