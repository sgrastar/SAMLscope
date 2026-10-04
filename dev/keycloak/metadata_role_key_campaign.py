#!/usr/bin/env python3
"""Native full dual-role XML conversion, same-client epochs, eleven probes and one shared login."""
import argparse,base64,datetime,hashlib,json,os,pathlib,re,subprocess,sys,urllib.request,urllib.parse,urllib.error,xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2];sys.path[:0]=[str(REPO/'dev/keycloak'),str(REPO/'dev/reference-acceptance')]
from registered_signer_campaign import SharedNormalClient,reject
from reference_flow import parse_forms
from attribute_policy_capability_absence import product_token
from import_metadata_batch import api,save,BASE
from browser_probe_selection import prepare_and_skip
from capture_run_originals import capture
CASE='IIP-MD06-a2-idp-01';CAMPAIGN='native-role-key-consumption';CONTAINER='samlscope-reference-keycloak';SUITE='samlscope-reference-suite';ADMIN='http://localhost:18180/admin/realms/samlscope';TARGET='http://localhost:18180/realms/samlscope'
VARIANTS=('role-keys-sp-first-explicit-a','role-keys-idp-first-explicit-b','role-keys-sp-first-omitted-a','role-keys-idp-first-omitted-b')
FIXTURES=('explicit-a-normal','explicit-a-peer-key','explicit-a-encryption-key','explicit-a-invalid-signature','explicit-b-normal','explicit-b-peer-key','explicit-b-encryption-key','omitted-a-normal','omitted-a-peer-key','omitted-b-normal','omitted-b-peer-key')
SHA=lambda b:hashlib.sha256(b).hexdigest();NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def canonical(n):return (json.dumps(n,sort_keys=True,separators=(',',':'))+'\n').encode()
def variant(f):return VARIANTS[0] if f.startswith('explicit-a-') else VARIANTS[1] if f.startswith('explicit-b-') else VARIANTS[2] if f.startswith('omitted-a-') else VARIANTS[3]
def public_terminal(page):return len(page.encode())<=262144 and re.search(r'<\s*input\b|SAMLResponse|SAMLRequest|Authorization\s*:|Cookie\s*:',page,re.I) is None
class RoleClient(SharedNormalClient):
 def request(self,url,fields=None):
  result=super().request(url,fields)
  if fields and 'SAMLRequest' in fields:
   forms=[f for f in parse_forms(result[1]) if 'SAMLResponse' in f.fields]
   if len(forms)>1:raise ValueError('Ambiguous native SAML response form')
   self.last_protocol_http['samlResponseFormPresent']=len(forms)==1
   if forms:self.last_protocol_http['responseSamlSha256']=SHA(base64.b64decode(forms[0].fields['SAMLResponse'],validate=True))
  return result
def normalised_native(n):return dict(requestMethod=n['method'],requestUrl=n['requestUrl'],requestId=n['requestId'],requestSha256=n['requestSha256'],startedAt=n['startedAt'],completedAt=n['finishedAt'],responseUrl=n['responseUrl'],responseStatus=n['responseStatus'],responseBodyBytes=n['responseBodyBytes'],responseBodySha256=n['responseBodySha256'],samlResponseFormPresent=n.get('samlResponseFormPresent',False),**({'responseSamlSha256':n['responseSamlSha256']} if n.get('samlResponseFormPresent') else {}))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--min-free-mib',type=int,default=96);a=p.parse_args();space=os.statvfs(REPO)
 if a.min_free_mib<32 or space.f_bavail*space.f_frsize<a.min_free_mib*1024*1024:p.error('Insufficient disk before native settings/protocol/login')
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);receipt=out/'receipt';receipt.mkdir();(out/'collector-source.py').write_bytes(pathlib.Path(__file__).read_bytes());refs={};ops=[];observations=[];skips=[];client=RoleClient();token=product_token();token_reads=1;plan=run=entity=db=None;baseline=selected=0;restoration={'restored':False};created=None
 def native(path,method='GET',body=None,xml=False):
  nonlocal token,token_reads
  raw=body if isinstance(body,bytes) else None if body is None else canonical(body)
  if raw is not None and not xml:reject(json.loads(raw))
  for attempt in range(2):
   op=dict(method=method,url=ADMIN+path,startedAt=NOW(),productSettingWrite=method in {'PUT','DELETE'} or method=='POST' and path=='/clients');ops.append(op);save(out/'operations.json',ops)
   req=urllib.request.Request(ADMIN+path,data=raw,method=method,headers={'Authorization':'Bearer '+token,'Content-Type':'application/xml' if xml else 'application/json'})
   try:
    with urllib.request.urlopen(req,timeout=40) as response:status,reply,location=response.status,response.read(),response.headers.get('Location')
   except urllib.error.HTTPError as response:status,reply,location=response.code,response.read(),response.headers.get('Location')
   op.update(status=status,finishedAt=NOW());save(out/'operations.json',ops)
   if status!=401:break
   token=product_token();token_reads+=1
  value=json.loads(reply) if reply else None;redactions=[]
  if method=='GET' and re.fullmatch('/clients/[0-9a-f-]{36}',path) and isinstance(value,dict):
   for name in ['secret','registrationAccessToken']:
    if name in value:del value[name];redactions.append('$.'+name)
   reply=canonical(value)
  reject(value);record=dict(op,response_base64=base64.b64encode(reply).decode(),response_sha256=SHA(reply))
  if raw is not None:record.update(request_base64=base64.b64encode(raw).decode(),request_sha256=SHA(raw))
  if method=='GET' and re.fullmatch('/clients/[0-9a-f-]{36}',path):record.update(response_projection='native-client-public-readback-v1',redactions=redactions)
  return value,record,location,reply
 def runtime():
  fmt='{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}}}';n=json.loads(subprocess.check_output(['docker','inspect','--format',fmt,CONTAINER],timeout=20));assert n['running'] is True;return n
 def inspect_original(name):
  fmt='[{"Id":{{json .Id}},"Image":{{json .Image}},"State":{"Running":{{json .State.Running}},"StartedAt":{{json .State.StartedAt}}},"Config":{}}]';raw=subprocess.check_output(['docker','inspect','--format',fmt,CONTAINER],timeout=20);assert json.loads(raw)[0]['State']['Running'] is True;(receipt/name).write_bytes(raw)
 def services():return subprocess.check_output(['docker','exec',CONTAINER,'sha256sum','/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar'],timeout=25).decode().split()[0]
 def policy():return {name:native('/client-policies/'+name)[0] for name in ['policies','profiles']}
 def record(label,kind,**value):
  n=dict(schema='samlscope-keycloak-role-key-original-v1',runId=run,campaignId=CAMPAIGN,targetMetadataSha256=SHA((receipt/'target-metadata.xml').read_bytes()),recordedAt=NOW(),kind=kind,**value);reject(n);raw=canonical(n);before={e['id'] for e in api('/api/runs/'+run+'/transcript')};request=urllib.request.Request(BASE+'/p/'+plan+'/sp/paos?run='+run,data=raw,method='POST',headers={'Content-Type':'application/json'})
  with urllib.request.urlopen(request,timeout=40) as response:assert response.status==204
  entries=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in before and e.get('decodedSamlRef')];assert len(entries)==1;file='native-original-'+label+'.json';(receipt/file).write_bytes(raw);refs[label]=dict(reference=entries[0]['id'],sha256=SHA(raw),file=file);return n
 def inventory(label):
  values,http,_,_=native('/clients?clientId='+urllib.parse.quote(entity,safe='')+'&briefRepresentation=true');assert values==[];return record(label,'native-role-key-inventory',entityId=entity,native=http,runtime=runtime(),policies=policy(),nativeServicesSha256=services())
 def state(label,v):
  values,http,_,_=native('/clients/'+db);assert http['status']==200 and values['id']==db and values['clientId']==entity;return record(label,'native-role-key-state',variant=v,entityId=entity,clientDatabaseId=db,native=http,runtime=runtime(),policies=policy(),nativeServicesSha256=services())
 def convert(v,xml):
  values,http,_,raw=native('/client-description-converter','POST',xml,True);assert http['status']==200 and values['clientId']==entity and values['protocol']=='saml' and not values.get('id');(receipt/(v+'-converter-output.json')).write_bytes(raw);
  if v!='baseline':
   root=ET.fromstring(xml);sp=root.find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor')
   for purpose in ['signing','encryption']:
    expected={SHA(base64.b64decode(''.join(k.find('.//{http://www.w3.org/2000/09/xmldsig#}X509Certificate').text.split()))) for k in sp.findall('{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor') if not k.get('use') or k.get('use')==purpose};cert=values.get('attributes',{}).get('saml.'+purpose+'.certificate')
    if not cert or SHA(base64.b64decode(''.join(cert.split()))) not in expected:raise ValueError('Native role/purpose import prerequisite absent; no product write or login')
  record(v+'-conversion','native-role-key-conversion',variant=v,entityId=entity,fixtureSha256=SHA(xml),native=http);return values,raw
 def apply(v,parsed):
  configured=json.loads(json.dumps(parsed));configured.setdefault('attributes',{}).update({'saml.client.signature':'true','saml.encrypt':'true'});_,http,_,_=native('/clients/'+db,'PUT',configured);assert http['status']==204;record(v+'-apply','native-role-key-apply',variant=v,entityId=entity,clientDatabaseId=db,native=http,nativePolicy=dict(assertionEncryption=True,signatureVerification=True,keysModified=False))
 try:
  response=api('/api/plans',dict(name='Keycloak shared-session role/key and purpose scope',profile='metadata_idp',targetKind='IDP',targetEntityId=TARGET,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=30,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',response);plan=response['plan']['plan']['id'];entity=BASE+'/p/'+plan;created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);save(receipt/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));subprocess.run(['docker','cp',SUITE+':/data/target-metadata/'+run+'.xml',str(receipt/'target-metadata.xml')],check=True,capture_output=True,timeout=30);(out/'target-metadata.xml').write_bytes((receipt/'target-metadata.xml').read_bytes());inspect_original('target-container-inspect-start.json');initial=inventory('initial')
  with urllib.request.urlopen(entity+'/metadata',timeout=30) as response:xml=response.read()
  (receipt/'baseline-fixture.xml').write_bytes(xml);base,base_raw=convert('baseline',xml);parsed={};prepared={}
  # All native conversions precede product writes and the first test-user login.
  for v in VARIANTS:
   save(out/(v+'-campaign.json'),api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=[v],pollingDelaySeconds=0)));lab=api('/api/runs/'+run+'/metadata-lab')
   with urllib.request.urlopen(lab['automaticStartUrl'],timeout=30) as response:assert response.status==202
   with urllib.request.urlopen(lab['metadataUrl'],timeout=30) as response:xml=response.read()
   root=ET.fromstring(xml);assert root.find('{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor') is not None and root.find('{urn:oasis:names:tc:SAML:2.0:metadata}IDPSSODescriptor') is not None;(receipt/(v+'-fixture.xml')).write_bytes(xml);parsed[v],_=convert(v,xml);rows=[e for e in api('/api/runs/'+run+'/transcript') if e.get('samlSummary',{}).get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==v and e['samlSummary'].get('feed')=='live'];assert len(rows)==1;prepared[v]=rows[0]
  _,creation,location,_=native('/clients','POST',base_raw);assert creation['status']==201 and location;db=location.rsplit('/',1)[-1];assert re.fullmatch('[0-9a-f-]{36}',db);record('creation','native-role-key-create',entityId=entity,clientDatabaseId=db,native=creation);user=os.getenv('REFERENCE_USERNAME','samlscope-m0-user');password=os.getenv('REFERENCE_PASSWORD','samlscope-m0-password');old={e['id'] for e in api('/api/runs/'+run+'/transcript')};before=len(client.arrivals)+client.protocol_posts;result=client.flow(entity+'/start/m0-roundtrip?run='+run,None,user,password);baseline=len(client.arrivals)+client.protocol_posts-before;assert result=='recorded' and baseline==1 and client.credential_posts==1;save(receipt/'baseline.json',dict(receipt=result,protocolSubmissions=baseline,credentialPosts=1,outboundReferences=[e['id'] for e in api('/api/runs/'+run+'/transcript') if e['id'] not in old and e['direction']=='OUTBOUND' and e.get('samlSummary',{}).get('type')=='AuthnRequest']))
  save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));current=None;epoch=None
  for _ in range(400):
   if selected==11:break
   status=api('/api/runs/'+run+'/active-probe')
   if status['state']!='READY' and any(x.get('caseId')==CASE and x.get('kind')=='CONFIGURATION' for x in api('/api/runs/'+run+'/interactions')):save(out/'configure.json',api('/api/runs/'+run+'/cases/'+CASE+'/configure',dict(value='confirmed')));continue
   assert status['state']=='READY','Selected native role-key outbox unavailable'
   if status.get('caseId')!=CASE:skips.append(prepare_and_skip(BASE,run,status,api));save(out/'suite-only-skips.json',skips);continue
   assert status.get('requiresFreshSession') is False;f=FIXTURES[selected];v=variant(f)
   if v!=current:
    if epoch is not None:state(current+'-after',current);epoch['completedAt']=NOW();observations.append(epoch)
    epoch=dict(variant=v,startedAt=NOW(),preparedReference=prepared[v]['id'],fetchReference=prepared[v]['samlSummary']['fetchTranscriptId'],exchanges=[]);apply(v,parsed[v]);state(v+'-before',v);current=v
   action=status['actionId'];old={e['id'] for e in api('/api/runs/'+run+'/transcript')};before=client.protocol_posts
   def terminal(url,page,code,reason):
    if not public_terminal(page):raise ValueError('Unsafe native terminal body; forms stay in memory')
    api('/api/runs/'+run+'/active-probe/browser-response',dict(actionId=action,status=code,url=url,body=page))
   result=client.flow(status['startUrl'],None,user,password,terminal_observer=terminal);entries=api('/api/runs/'+run+'/transcript');rq=[e for e in entries if e['id'] not in old and e['direction']=='OUTBOUND' and e.get('correlationId')==action and e.get('samlSummary',{}).get('type')=='AuthnRequest'];assert len(rq)==1 and client.protocol_posts-before==1;rs=[e for e in entries if e['direction']=='INBOUND' and (e.get('samlSummary',{}).get('inResponseTo')=='_'+action or e.get('correlationId')==action and e.get('samlSummary',{}).get('type')=='BrowserResponseObservation')];assert len(rs)==1;n=normalised_native(client.last_protocol_http);x=dict(fixtureId=f,requestReference=rq[0]['id'],responseReference=rs[0]['id'],nativeHttp=[n]);epoch['exchanges'].append(x);record(f+'-http','native-role-key-http',fixtureId=f,requestReference=rq[0]['id'],responseReference=rs[0]['id'],actionId=action,native=n);save(out/'current-epoch.json',epoch)
   if f.endswith('normal'):assert rs[0]['method']!='BROWSER'
   after=api('/api/runs/'+run+'/active-probe')
   if after.get('state')=='AWAITING_RESPONSE' and after.get('actionId')==action:api('/api/runs/'+run+'/active-probe/abort',{})
   selected+=1
  assert selected==11;state(current+'-after',current);epoch['completedAt']=NOW();observations.append(epoch);save(out/'observations.json',observations)
 finally:
  try:
   if db:
    _,http,_,_=native('/clients/'+db,'DELETE');assert http['status']==204;record('deletion','native-role-key-delete',entityId=entity,clientDatabaseId=db,native=http);final=inventory('restoration');restoration=dict(restored=final['runtime']==initial['runtime'] and final['policies']==initial['policies'],clientDatabaseId=db)
   inspect_original('target-container-inspect-end.json')
  except Exception as error:restoration=dict(restored=False,errorType=type(error).__name__)
  count=len(client.arrivals)+client.protocol_posts;costs=dict(restored=restoration.get('restored') is True,nativeConfigurationWrites=sum(x['productSettingWrite'] for x in ops),restorationWrites=sum(x['method']=='DELETE' for x in ops),initialBaselineSubmissions=baseline,selectedProbeAttempts=selected,outboxProtocolSubmissions=count-baseline,protocolSubmissions=count,credentialPosts=client.credential_posts,personOperations=0,productRestarts=0,suiteOnlySkippedActions=len(skips),adminTokenRequests=token_reads);save(receipt/'operation-counts.json',costs);save(receipt/'restoration.json',restoration);save(out/'restoration.json',restoration)
  if run:entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
 if not restoration.get('restored') or len(observations)!=4:raise ValueError('Incomplete campaign is not adoptable')
 for e in entries:
  if e['method']=='BROWSER':
   assert e['bodyRef']=='transcripts/'+run+'/'+e['id']+'.body';raw=subprocess.check_output(['docker','exec',SUITE,'cat','/data/'+e['bodyRef']],timeout=25);assert len(raw)==e['bodyBytes'] and public_terminal(raw.decode());(receipt/('browser-'+e['id']+'.body')).write_bytes(raw)
 files={f.name:SHA(f.read_bytes()) for f in receipt.iterdir() if f.is_file()};save(receipt/'manifest.json',dict(schema='samlscope-metadata-role-key-consumption-v1',adapter='keycloak-native-role-key-consumption-v1',campaignId=CAMPAIGN,runId=run,planId=plan,entityId=entity,clientDatabaseId=db,targetMetadataSha256=SHA((receipt/'target-metadata.xml').read_bytes()),observations=observations,nativeOriginals=refs,originals=files));print(json.dumps(dict(status='collected-not-adopted',runId=run,counts=costs)))
if __name__=='__main__':main()
