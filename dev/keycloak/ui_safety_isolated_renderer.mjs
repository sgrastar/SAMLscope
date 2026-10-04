/** Diagnostic-only native HTML renderer differential. Never visits a product URL or uses credentials. */
import fs from 'node:fs';
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
const {chromium}=createRequire(import.meta.url)(process.env.SAMLSCOPE_PLAYWRIGHT_MODULE);
const sha=b=>createHash('sha256').update(b).digest('hex'),now=()=>new Date().toISOString();
const [inputFile,outputFile]=process.argv.slice(2),inputBytes=fs.readFileSync(inputFile),input=JSON.parse(inputBytes),html=Buffer.from(input.publicHtmlBase64,'base64').toString('utf8');
if(input.counterfactualCalibrationOnly!==true||input.variant!=='ui-safety-information-javascript'||input.href!=="javascript:alert('SAMLscope-UI-safety-v1')"||sha(Buffer.from(html))!==input.publicHtmlSha256||typeof input.nativeContentSecurityPolicy!=='string'||!input.nativeContentSecurityPolicy||input.nativePolicyCaptureType!=='after-restoration-readback-not-historic-native-response-header')throw new Error('Isolated original binding invalid');
const browser=await chromium.launch({channel:'chrome',headless:true}),records=[],startedAt=now();
try{
 for(const selectedPath of ['isolated-stock-native-renderer','isolated-unsanitized-information-anchor']){
  const context=await browser.newContext(),page=await context.newPage(),dialogs=[];
  try{
   page.on('dialog',async d=>{dialogs.push({type:d.type(),probeToken:d.message()==='SAMLscope-UI-safety-v1',recordedAt:now(),source:'isolated-renderer'});await d.dismiss();});
   await page.route('**/*',r=>new URL(r.request().url()).origin==='http://127.0.0.1:18482'?r.fulfill({status:200,contentType:'text/html',headers:{'content-security-policy':input.nativeContentSecurityPolicy},body:html}):r.abort());
   const begin=now();await page.goto('http://127.0.0.1:18482/native-consent-projection',{waitUntil:'load',timeout:15000});
   const before=await page.evaluate(()=>document.documentElement.outerHTML);
   if(selectedPath==='isolated-unsanitized-information-anchor')await page.evaluate(href=>{const scope=document.querySelector('#kc-oauth');if(!scope)throw new Error('Native grant scope absent');const anchor=document.createElement('a');anchor.id='samlscope-isolated-unsafe';anchor.setAttribute('href',href);anchor.textContent='Isolated information URL';scope.appendChild(anchor);},input.href);
   const after=await page.evaluate(()=>document.documentElement.outerHTML);
   if(selectedPath==='isolated-unsanitized-information-anchor')await page.locator('#samlscope-isolated-unsafe').click();
   await page.waitForTimeout(100);records.push({selectedPath,counterfactualCalibrationOnly:true,href:input.href,sourceHtmlSha256:sha(Buffer.from(html)),nativeContentSecurityPolicy:input.nativeContentSecurityPolicy,renderedContentSecurityPolicy:input.nativeContentSecurityPolicy,policyMutated:false,beforeHtmlBase64:Buffer.from(before).toString('base64'),beforeHtmlSha256:sha(Buffer.from(before)),afterHtmlBase64:Buffer.from(after).toString('base64'),afterHtmlSha256:sha(Buffer.from(after)),startedAt:begin,completedAt:now(),dialogs});
  }finally{await context.close();}
 }
 if(records[0].dialogs.length!==0||records[1].dialogs.length!==1||!records[1].dialogs[0].probeToken)throw new Error('Isolated renderer differential detection absent');
 fs.writeFileSync(outputFile,JSON.stringify({schema:'samlscope-keycloak-ui-safety-isolated-renderer-v1',counterfactualCalibrationOnly:true,actualProductFinding:false,controlsAdopted:false,runId:input.runId,targetMetadataSha256:input.targetMetadataSha256,fixtureSha256:input.fixtureSha256,variant:input.variant,nativePolicyCaptureType:input.nativePolicyCaptureType,nativePolicyOriginalSha256:input.nativePolicyOriginalSha256,nativeContentSecurityPolicy:input.nativeContentSecurityPolicy,inputSha256:sha(inputBytes),rendererSourceSha256:sha(fs.readFileSync(new URL(import.meta.url))),browserVersion:browser.version(),startedAt,completedAt:now(),records,productConfigurationWrites:0,samlRequests:0,credentialPosts:0,isolatedBrowserContexts:2},null,2)+'\n',{flag:'wx'});
}finally{await browser.close();}
