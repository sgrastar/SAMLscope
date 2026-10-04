#!/usr/bin/env python3
"""Complete only the normal Suite prerequisite; preserve the earlier expiry proof unmodified."""
import argparse,hashlib,json,os,pathlib,re,subprocess,sys,urllib.request,xml.etree.ElementTree as E
REPO=pathlib.Path(__file__).resolve().parents[2];sys.path[:0]=[str(REPO/'dev/shibboleth'),str(REPO/'dev/keycloak')]
from reference_flow import Client
CONTAINER='samlscope-reference-shibboleth';BASE='http://localhost:18080';CONFIG='/opt/reference-idp/conf/metadata-providers.xml';SHA=lambda b:hashlib.sha256(b).hexdigest()
def save(p,value):p.write_text(json.dumps(value,indent=2)+'\n')
def docker(*args,data=None):return subprocess.run(['docker','exec','-i',CONTAINER,*args],input=data,capture_output=True,check=True,timeout=60).stdout
def api(path):
 with urllib.request.urlopen(BASE+path,timeout=30) as r:return json.loads(r.read())
def complete(run,out,client=None):
 assert re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run);out=pathlib.Path(out);out.mkdir(parents=True,exist_ok=False);before=api('/api/runs/'+run+'/transcript');save(out/'transcript-before.json',before);plan=api('/api/runs/'+run)['planId'];assert re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan)
 original=docker('cat',CONFIG);(out/'original-providers.xml').write_bytes(original);temporary='/opt/reference-idp/metadata/validity-baseline-'+run+'.xml';assert not docker('sh','-c','test -e '+temporary+' && echo exists || true').strip()
 with urllib.request.urlopen(BASE+'/p/'+plan+'/metadata',timeout=30) as r:fixture=r.read()
 (out/'fixture.xml').write_bytes(fixture);namespace='urn:mace:shibboleth:2.0:metadata';xsi='http://www.w3.org/2001/XMLSchema-instance';E.register_namespace('',namespace);E.register_namespace('xsi',xsi);root=E.fromstring(original);root.insert(0,E.Element('{'+namespace+'}MetadataProvider',dict(id='ValidityBaseline'+run,**{'{'+xsi+'}type':'FilesystemMetadataProvider','metadataFile':temporary})));configured=E.tostring(root);(out/'configured-providers.xml').write_bytes(configured)
 changed=written=False;operations=[];failures=[];counts=dict(credentialPosts=0,nativeSamlRequestGets=0,nativeSamlRequestPosts=0)
 client=client or Client();request=client.request
 def observed(url,fields=None):
  if fields and ('password' in fields or 'j_password' in fields):counts['credentialPosts']+=1
  if url.startswith('http://localhost:18280/'):
   if fields and 'SAMLRequest' in fields:counts['nativeSamlRequestPosts']+=1
   elif 'SAMLRequest=' in url:counts['nativeSamlRequestGets']+=1
  return request(url,fields)
 client.request=observed
 def write(path,raw,label):
  operations.append(dict(operation='write',label=label,path=path,sha256=SHA(raw),readBack=False));docker('sh','-c','cat > '+path,data=raw);assert docker('cat',path)==raw;operations[-1]['readBack']=True
 def reload(label):
  operations.append(dict(operation='reload',label=label));(out/(label+'-reload.txt')).write_bytes(docker('/opt/reference-idp/bin/reload-service.sh','-id','shibboleth.MetadataResolverService','-u','http://localhost:8080/idp'))
 try:
  written=True;write(temporary,fixture,'native-baseline-metadata');changed=True;write(CONFIG,configured,'native-baseline-provider');reload('apply');(out/'configured-readback.xml').write_bytes(docker('cat',CONFIG));result=client.flow(BASE+'/p/'+plan+'/start/m0-roundtrip?run='+run,None,os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'));save(out/'flow.json',dict(receipt=result));assert result=='recorded';state=api('/api/runs/'+run);assert state['status']=='COMPLETED';save(out/'run-public-state.json',{k:state[k] for k in ['id','planId','status','targetToSuiteReachability']})
 finally:
  client.request=request
  if changed:
   try:assert docker('cat',CONFIG)==configured;write(CONFIG,original,'restore-provider');reload('restore')
   except Exception as error:failures.append(type(error).__name__)
  if written and not failures:docker('rm','--',temporary)
  final=docker('cat',CONFIG);(out/'final-providers.xml').write_bytes(final);removed=not docker('sh','-c','test -e '+temporary+' && echo exists || true').strip();restored=not failures and final==original and removed;save(out/'operations.json',operations);save(out/'restoration.json',dict(restored=restored,failures=failures,originalSha256=SHA(original),finalSha256=SHA(final),temporaryRemoved=removed));save(out/'operation-counts.json',dict(counts,productConfigurationWrites=sum(r['operation']=='write' for r in operations),metadataReloads=sum(r['operation']=='reload' for r in operations),productRestarts=0,personOperations=0));assert restored
 after=api('/api/runs/'+run+'/transcript');save(out/'transcript-after.json',after);assert [e for e in after if e['id'] in {e['id'] for e in before}]==before;added=[e for e in after if e['id'] not in {e['id'] for e in before}];save(out/'added-transcript.json',added);requests=[e for e in added if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest'];responses=[e for e in added if e['direction']=='INBOUND' and e['samlSummary'].get('type')=='Response'];assert len(requests)==len(responses)==1 and responses[0]['samlSummary'].get('inResponseTo')==requests[0]['samlSummary'].get('id');save(out/'operation-counts-reconciled.json',dict(counts,observedRequestWrapperOnly=True,actualNativeProtocolGets=sum(e['method']=='GET' for e in requests),actualNativeProtocolPosts=sum(e['method']=='POST' for e in requests),actualProtocolSubmissions=len(requests),methodCountSource='actual-recorder-requests',productConfigurationWrites=sum(r['operation']=='write' for r in operations),metadataReloads=sum(r['operation']=='reload' for r in operations),productRestarts=0,personOperations=0));save(out/'baseline-proof.json',dict(runId=run,requestReference=requests[0]['id'],responseReference=responses[0]['id'],protocolSubmissions=1,ordinaryBaselineOnly=True,expiryPairsResent=0,originalTranscriptUnchanged=True,credentialsPersisted=False));return client
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',required=True);p.add_argument('--output',required=True,type=pathlib.Path);a=p.parse_args();complete(a.run,a.output);print('Ordinary baseline only completed; native provider exactly restored')
