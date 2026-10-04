#!/usr/bin/env node
/** Native JS Webflow, no synthetic completion and no persisted browser secrets. */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {inflateRawSync} from 'node:zlib';
import {createRequire} from 'node:module';
import {propagationObservation, settlePending} from './slo_propagation_observation.mjs';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.SAMLSCOPE_PLAYWRIGHT_MODULE||'playwright');
const input=JSON.parse(fs.readFileSync(process.argv[2],'utf8')),folder=path.dirname(process.argv[2]);
const BASE='http://localhost:18080',IDP='http://localhost:18280',run=input.runId,plan=input.planId;
const record={schema:'samlscope-shibboleth-slo-browser-v1',runId:run,planId:plan,trial:input.trial,
    startedAt:new Date().toISOString(),initialCookieCount:0,steps:[],nativeResources:[],status:'incomplete'};
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const pending=[];let browser,stage='launch';
const scopes=new Set(),sessionKeys=new Set(),frameKeys=new Map();
const flowScope=url=>{const execution=url.searchParams.get('execution');return /^e\d+s\d+$/.test(execution??'')?sha(Buffer.from(run+'|'+url.origin+url.pathname+'|'+execution.replace(/s\d+$/,''))):null;};
const xmlSummary=raw=>({sha256:sha(raw),bytes:raw.length,id:raw.toString().match(/\bID="([^"]+)"/)?.[1]??null,
    inResponseTo:raw.toString().match(/\bInResponseTo="([^"]+)"/)?.[1]??null});
const sanitize=body=>{
    // Native SessionKey can be a one-digit ordinal. Replace only its syntactic positions;
    // global replacement would corrupt unrelated RP identifiers, scripts and even digests.
    for(const key of sessionKeys){const digest='sha256:'+sha(Buffer.from(key));
        body=body.split('SessionKey='+encodeURIComponent(key)).join('SessionKey='+digest)
            .split('sender_'+Buffer.from(key).toString('hex')).join('sender_'+digest)
            .split("'"+key+"')").join("'"+digest+"')")
            .split('_'+key+"']").join('_'+digest+"']");}
    body=body.replace(/\bexecution=e\d+s\d+/g,token=>'execution=sha256:'+sha(Buffer.from(token.slice('execution='.length))));
    return body.replace(/(<input\b[^>]*\bvalue=)(["'])[^"']*\2/gi,'$1"[REDACTED]"');
};
const api=async(route,body)=>{const r=await fetch(BASE+route,{method:body===undefined?'GET':'POST',
    headers:body===undefined?{}:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
    if(!r.ok)throw new Error('Suite API '+r.status);return r.json();};
async function observeNativeDom(page){
    record.nativeDom=await page.evaluate(()=>({participants:Array.from(document.querySelectorAll('li.logout')).map(node=>({
        entityHex:node.id.match(/^result_([0-9a-f]+)$/)?.[1]??null,
        classes:Array.from(node.classList),title:node.getAttribute('title')})),
        completed:document.querySelector('.logout-status.completed')!==null,observedAt:new Date().toISOString()}));
    for(const peer of record.nativeDom.participants){
        peer.entityId=peer.entityHex&&peer.entityHex.length%2===0?Buffer.from(peer.entityHex,'hex').toString('utf8'):null;
        delete peer.entityHex;
    }
    record.nativeFlowScopes=Array.from(scopes);
}
async function dispatch(page,status){
    await page.goto(status.startUrl,{waitUntil:'networkidle',timeout:45000});
    const fresh=page.locator('input[name="freshSessionConfirmed"]');if(await fresh.count())await fresh.check();
    const confirm=page.getByRole('button',{name:/Continue with this request/i});if(await confirm.count()){await confirm.click();await page.waitForLoadState('networkidle');}
    const user=page.locator('input[name="j_username"]');if(await user.count()){
        await user.fill(process.env.REFERENCE_USERNAME||'samlscope-m0-user');await page.locator('input[name="j_password"]').fill(process.env.REFERENCE_PASSWORD||'samlscope-m0-password');
        await page.locator('button[type="submit"]').first().click();await page.waitForLoadState('networkidle');}
}
try{
    if(!/^run_[0-9A-HJKMNP-TV-Z]{26}$/.test(run)||!/^plan_[0-9A-HJKMNP-TV-Z]{26}$/.test(plan))throw new Error('Unsafe identity');
    browser=await chromium.launch({headless:true,channel:'chrome'});const context=await browser.newContext({locale:'en-US'});
    if((await context.cookies()).length)throw new Error('Not fresh');const page=await context.newPage();
    const requests=new Map();
    page.on('request',request=>{
        const url=new URL(request.url());if(!((url.origin===IDP&&(url.pathname.endsWith('/SLO')||url.pathname.includes('/Logout')||url.pathname.includes('/PropagateLogout')||url.pathname.endsWith('.js')))
            ||(url.origin===BASE&&/\/(?:sp|idp)\/slo(?:-fail)?$/.test(url.pathname))))return;
        const scope=flowScope(url);if(scope)scopes.add(scope);
        const key=url.searchParams.get('SessionKey');if(key){sessionKeys.add(key);frameKeys.set(request.frame(),sha(Buffer.from(key)));}
        const frameKey=frameKeys.get(request.frame());
        const row={origin:url.origin,path:url.pathname,method:request.method(),resourceType:request.resourceType(),urlSha256:sha(Buffer.from(url.href)),requestedAt:new Date().toISOString(),
            ...(scope?{flowScopeSha256:scope}:{}),...(frameKey?{sessionKeySha256:frameKey}:{})};
        const fields=request.method()==='POST'?new URLSearchParams(request.postData()??''):url.searchParams;
        if(fields.has('SAMLRequest'))row.samlRequest=xmlSummary(request.method()==='POST'?Buffer.from(fields.get('SAMLRequest'),'base64'):inflateRawSync(Buffer.from(fields.get('SAMLRequest'),'base64')));
        if(fields.has('SAMLResponse'))row.samlResponse=xmlSummary(request.method()==='POST'?Buffer.from(fields.get('SAMLResponse'),'base64'):inflateRawSync(Buffer.from(fields.get('SAMLResponse'),'base64')));
        requests.set(request,row);record.nativeResources.push(row);
    });
    page.on('requestfailed',request=>{const row=requests.get(request);if(row){row.failedAt=new Date().toISOString();row.failureCode=request.failure()?.errorText?.replace(/[^A-Za-z_:]/g,'').slice(0,120);}});
    page.on('response',response=>{
        const row=requests.get(response.request());if(row)pending.push((async()=>{row.status=response.status();row.respondedAt=new Date().toISOString();
            const location=response.headers().location;if(location){const target=new URL(location,response.url());const scope=flowScope(target);if(scope){row.redirectFlowScopeSha256=scope;scopes.add(scope);}}
            if(response.status()!==200)return;
            const raw=await response.body();row.bytes=raw.length;row.sha256=sha(raw);
            if(response.request().resourceType()==='script')return;
            const body=raw.toString();
            if(row.path.endsWith('/PropagateLogout')){
                const tags=body.match(/<input\b[^>]*>/gi)??[];const saml=tags.filter(tag=>/name=["']SAMLRequest["']/i.test(tag));
                if(saml.length===1){const encoded=saml[0].match(/\bvalue=["']([^"']+)["']/i)?.[1];if(encoded)row.generatedRequest=xmlSummary(Buffer.from(encoded,'base64'));}
            }
            if(body.includes('sessionTracker')&&body.includes('/profile/PropagateLogout')){
                const participants=[];
                for(const tag of body.match(/<iframe\b[^>]*>/gi)??[]){
                    const src=tag.match(/\bsrc=["']([^"']+)["']/i)?.[1]?.replaceAll('&amp;','&');if(!src)continue;
                    const url=new URL(src,response.url()),key=url.searchParams.get('SessionKey');if(!key)continue;sessionKeys.add(key);
                    const entityHex=tag.match(/result_([0-9a-f]+)/i)?.[1];if(!entityHex)throw new Error('Native participant binding unavailable');
                    participants.push({entityId:Buffer.from(entityHex,'hex').toString(),sessionKeySha256:sha(Buffer.from(key))});
                }
                const sanitized=sanitize(body),name='native-propagation-context.html';
                fs.writeFileSync(path.join(folder,name),sanitized,{flag:'wx',mode:0o600});
                record.nativePropagationContext={file:name,sha256:sha(Buffer.from(sanitized)),flowScopeSha256:row.flowScopeSha256,participants,recordedAt:new Date().toISOString()};
            }
            try{const result=JSON.parse(body);if(Object.keys(result).length===1&&['Success','Failure'].includes(result.result)){
                row.nativeResult=result.result;const file='native-result-'+row.sessionKeySha256+'.json';
                fs.writeFileSync(path.join(folder,file),raw,{flag:'wx',mode:0o600});row.bodyFile=file;
            }}catch(error){if(error.code==='EEXIST')throw error;}
        })());
    });
    stage='primary-login';await dispatch(page,input.initialProbe);record.steps.push({stage,at:new Date().toISOString()});
    const logout=await api('/api/runs/'+run+'/active-probe');
    if(logout.caseId!=='IIP-IDP17-a-idp-01'||logout.state!=='READY'||logout.requiresFreshSession)throw new Error('Missing exact queued logout');
    record.logoutAction=logout.actionId;
    for(const suffix of ['fail','remain','remain2']){
        stage='participant-'+suffix;await api('/api/runs/'+run+'/target-initiated',{kind:'UNSOLICITED_SSO'});
        await page.goto(IDP+'/idp/profile/SAML2/Unsolicited/SSO?providerId='+encodeURIComponent(BASE+'/p/'+plan+'/sp-'+suffix),{waitUntil:'networkidle',timeout:45000});
        if(new URL(page.url()).origin!==BASE)throw new Error('Participant login not returned');record.steps.push({stage,at:new Date().toISOString()});
    }
    stage='logout';await api('/api/runs/'+run+'/target-initiated',{kind:'TARGET_LOGOUT'});await dispatch(page,logout);
    let settledThrough=0;
    for(let i=0;i<60;i++){
        const status=await api('/api/runs/'+run+'/active-probe');
        if(status.actionId!==logout.actionId||status.state!=='AWAITING_RESPONSE')record.initiatorCompleted=status.actionId!==logout.actionId;
        settledThrough=await settlePending(pending,settledThrough);
        await observeNativeDom(page);
        record.fullChainObservation=propagationObservation(record);
        if(record.initiatorCompleted&&record.fullChainObservation.settled)break;
        // Ordinary visible native buttons only. Do not invoke internal events or iframe URLs.
        const button=page.locator('button#logout_propagate');
        if(await button.count()){
            record.steps.push({stage:'native-global-confirmation',participants:await page.locator('form#propagate_form ol li').allTextContents(),at:new Date().toISOString()});
            await button.click({timeout:2500});
        }
        await page.waitForTimeout(500);
    }
    await settlePending(pending,settledThrough);stage='native-final';
    await observeNativeDom(page);record.fullChainObservation=propagationObservation(record);
    record.finalPage={origin:new URL(page.url()).origin,path:new URL(page.url()).pathname,
        text:await page.locator('body').innerText().catch(()=>''),recordedAt:new Date().toISOString()};
    // Only a sanitized native page is retained, never cookies, credentials, SessionKey or CSRF.
    if(new URL(page.url()).origin===IDP){
        const sanitized=sanitize(await page.content()).replace(/(SessionKey(?:=|%3D))[^&"'\s<>]*/gi,'$1[REDACTED]');
        fs.writeFileSync(path.join(folder,'native-final.html'),sanitized,{flag:'wx',mode:0o600});record.finalPage.bodySha256=sha(Buffer.from(sanitized));}
    record.status=record.initiatorCompleted&&record.fullChainObservation.settled?'observations-settled':'not-observed';
    record.affectsVerdict=false;record.finishedAt=new Date().toISOString();
}catch(error){record.status='failed';record.failureStage=stage;record.failureCode=error.constructor.name;process.exitCode=1;}
finally{await browser?.close();fs.writeFileSync(path.join(folder,'browser-original.json'),JSON.stringify(record,null,2)+'\n',{flag:'wx',mode:0o600});console.log(record.status,record.failureStage||'');}
