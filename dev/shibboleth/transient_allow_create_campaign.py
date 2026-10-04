#!/usr/bin/env python3
"""Capture one native policy and six outbox AllowCreate inputs; restore once.

Cookies and credentials exist only in the memory of one reference-flow client.
This driver records public request-bound HTTP facts and never assigns a verdict.
"""
import argparse,base64,hashlib,json,os,pathlib,subprocess,sys,urllib.request
from subject_confirmation_campaign import REPO,batch,snapshot,profile_snapshot,save,NOW,SHA
sys.path.insert(0,str(REPO/'dev/keycloak'))
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from reference_flow import Client
from browser_probe_selection import prepare_and_skip
from capture_run_originals import capture
CASE='IIP-SSO01-fp-idp-01'
KEYS=['transient-allow-create-'+v for v in ['true','false','omitted']]+['implicit-transient-allow-create-'+v for v in ['true','false','omitted']]
BASE='http://localhost:18080'
class NativeClient(Client):
 def __init__(self):
  super().__init__();self.records=[];self.credential_posts=0
 def request(self,url,fields=None):
  from urllib.parse import urlsplit
  from xml.etree.ElementTree import fromstring
  observation=None
  if urlsplit(url).netloc=='localhost:18280' and fields:
   if 'j_password' in fields or 'password' in fields:self.credential_posts+=1
   if 'SAMLRequest' in fields:
    raw=base64.b64decode(fields['SAMLRequest'],validate=True);root=fromstring(raw)
    if root.tag!='{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest':raise ValueError('Unexpected target operation')
    observation=dict(requestId=root.get('ID'),requestSha256=SHA(raw),requestUrl=url,startedAt=NOW())
  final,html,status=super().request(url,fields)
  if observation:
   observation.update(responseUrl=final,responseStatus=status,responseBodySha256=SHA(html.encode()),completedAt=NOW(),nativeMessageSecurityError='Message Security Error' in html,samlResponseFormPresent='name="SAMLResponse"' in html)
   self.records.append(observation)
  return final,html,status
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 (out/'collector.py').write_bytes(pathlib.Path(__file__).read_bytes());snapshot(out,'original',True)
 client=NativeClient();original_flow=batch.flow;steps=[];extra_writes=extra_reloads=0;run=None;attempted=0
 credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
 def observed_flow(*args,**kwargs):
  nonlocal extra_writes,extra_reloads,run,attempted
  run=args[0];snapshot(out,'before-protocol');profile_snapshot(out,'before-protocol')
  # Native negative control uses the metadata collector's assertion-free rejection exporter.
  from metadata_native_observation import MetadataNativeClient
  reject_records=[];native=MetadataNativeClient(reject_records,out/'browser/control');native.jar=client.jar;native.op=client.op
  kwargs['client_factory']=lambda:native
  try:original_flow(*args,**kwargs)
  finally:
   save(out/'normal-native-http-observations.json',dict(runId=run,variant='control',records=reject_records,verdictAssigned=False))
   snapshot(out,'after-protocol');profile_snapshot(out,'after-protocol')
  entity=BASE+'/p/'+json.loads((out/'browser/created.json').read_bytes())['run']['planId']
  with urllib.request.urlopen(entity+'/metadata',timeout=30) as response:fixture=response.read()
  (out/'matrix-sp-metadata.xml').write_bytes(fixture)
  path='/opt/reference-idp/metadata/algorithm-'+run+'.xml';extra_writes+=1;batch.write(path,fixture);(out/'matrix-sp-metadata-readback.xml').write_bytes(batch.docker('cat',path));extra_reloads+=1;batch.reload(out,'matrix')
  effective=batch.docker('/opt/reference-idp/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',entity);(out/'matrix-native-effective-sp-metadata.xml').write_bytes(effective)
  save(out/'matrix-native-effective-sp-read.json',dict(runId=run,entityId=entity,recordedAt=NOW(),sha256=SHA(effective),exitCode=0))
  snapshot(out,'before-matrix');profile_snapshot(out,'before-matrix');save(out/'tests-start-matrix.json',batch.api('/api/runs/'+run+'/tests/start',{}))
  sent=0
  for _ in range(450):
   status=batch.api('/api/runs/'+run+'/active-probe')
   if sent==6:break
   if status['state']!='READY':raise ValueError('Scenario not ready: '+status['state'])
   if status.get('caseId')!=CASE:
    steps.append(prepare_and_skip(BASE,run,status,batch.api));save(out/'steps.json',steps);continue
   before={e['id'] for e in batch.api('/api/runs/'+run+'/transcript')};attempted+=1;started=NOW();receipt=client.flow(status['startUrl'],None,*credentials);finished=NOW();after=batch.api('/api/runs/'+run+'/active-probe')
   entries=batch.api('/api/runs/'+run+'/transcript');new=[e['id'] for e in entries if e['id'] not in before]
   steps.append(dict(caseId=CASE,actionId=status['actionId'],key=KEYS[sent],receipt=receipt,transcriptIds=new,prepared=True,sentToTarget=True,nextState=after['state'],dispatchStartedAt=started,dispatchCompletedAt=finished));save(out/'steps.json',steps)
   if receipt!='recorded' or after.get('actionId')==status['actionId']:raise ValueError('Native scenario did not advance')
   sent+=1
  if sent!=6:raise ValueError('Six policy inputs not complete')
  snapshot(out,'after-matrix');profile_snapshot(out,'after-matrix')
 batch.flow=observed_flow;sys.argv=['import_metadata_batch.py','--output',str(out/'browser'),'--variants','control','--profile','browser_sso_idp','--capture-native-originals']
 try:batch.main()
 finally:
  snapshot(out,'final')
  save(out/'matrix-native-http-observations.json',dict(runId=run,records=client.records,privateCredentialsExported=False))
  save(out/'additional-operation-counts.json',dict(metadataWrites=extra_writes,reloads=extra_reloads,matrixProtocolAttempts=attempted,credentialPosts=client.credential_posts,normalCredentialPostsCounted=False,humanOperations=0,productRestarts=0,suiteOnlyPreparedAborts=sum(x.get('sentToTarget') is False for x in steps)))
  if run:
   for suffix in ['result.json','transcript','protocol-evidence']:save(out/(suffix if '.' in suffix else suffix+'.json'),batch.api('/api/runs/'+run+'/'+suffix))
   capture(out,run,json.loads((out/'transcript.json').read_bytes()))
  if json.loads((out/'original/classpath-sha256.json').read_bytes())!=json.loads((out/'final/classpath-sha256.json').read_bytes()):raise ValueError('Native runtime changed')
 print(run,'six AllowCreate inputs captured; native provider restored; no adopted verdict')
if __name__=='__main__':main()
