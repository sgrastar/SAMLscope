#!/usr/bin/env python3
"""One authenticated client measures retained-metadata expiry; every setting is restored."""
import argparse,datetime,hashlib,importlib.util,json,os,pathlib,re,subprocess,sys,time,urllib.request,xml.etree.ElementTree as ET,zipfile,io
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'dev/keycloak'),str(REPO/'dev/reference-acceptance'),str(REPO/'dev/shibboleth')]
from import_metadata_batch import api,save,BASE,recorded_exchange
from reference_flow import Client
CONTAINER='samlscope-reference-shibboleth'
def docker(*args,data=None):return subprocess.run(['docker','exec','-i',CONTAINER,*args],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=90).stdout
from metadata_native_observation import MetadataNativeClient
from signature_audit_format import signature_audit,FORMAT
from public_runtime_capture import capture_target
from capture_run_originals import capture
from metadata_validity_baseline_recovery import complete as complete_baseline
NS='urn:mace:shibboleth:2.0:metadata';XSI='http://www.w3.org/2001/XMLSchema-instance'
PROVIDERS='/opt/reference-idp/conf/metadata-providers.xml';AUDIT='/opt/reference-idp/conf/audit.xml';PROPERTIES='/opt/reference-idp/conf/idp.properties'
VARIANTS=['live-validity-root','live-validity-parent','live-validity-child'];SHA=lambda b:hashlib.sha256(b).hexdigest();NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',required=True,type=pathlib.Path);p.add_argument('--lifetime',type=int,default=30);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);receipt=out/'receipt';receipt.mkdir()
 original={PROVIDERS:docker('cat',PROVIDERS),AUDIT:docker('cat',AUDIT),PROPERTIES:docker('cat',PROPERTIES)}
 configured={AUDIT:signature_audit(original[AUDIT])}
 for path,kind in [(PROVIDERS,'providers'),(AUDIT,'audit')]: (receipt/('original-'+kind+'.xml')).write_bytes(original[path])
 # Policy read-back exports exactly this public setting and full-file hashes, never other properties.
 def projection(raw):return b'\n'.join(line for line in raw.splitlines() if re.match(rb'^\s*idp\.policy\.clockSkew\s*[=:]',line))+b'\n'
 (receipt/'original-policy.txt').write_bytes(projection(original[PROPERTIES]));(receipt/'configured-policy.txt').write_bytes(projection(original[PROPERTIES]));(receipt/'configured-audit.xml').write_bytes(configured[AUDIT])
 ops=[];changed=[];errors=[];observations=[];http=[];login_count=0;run=None;plan=None;temp=None;client=MetadataNativeClient(http,receipt)
 original_request=client.request
 def request(url,fields=None):
  nonlocal login_count
  if fields and ('password' in fields or 'j_password' in fields):login_count+=1
  return original_request(url,fields)
 client.request=request
 def write(path,raw,label):
  row=dict(operation='write',label=label,path=path,recordedAt=NOW(),sha256=SHA(raw),readBack=False);ops.append(row);save(out/'operations.json',ops);docker('sh','-c','cat > '+path,data=raw);assert docker('cat',path)==raw;row['readBack']=True;save(out/'operations.json',ops)
 def restart(label):
  row=dict(operation='restart',label=label,recordedAt=NOW(),completed=False);ops.append(row);save(out/'operations.json',ops);subprocess.run(['docker','restart',CONTAINER],check=True,capture_output=True,timeout=60);docker('/usr/local/tomcat/bin/catalina.sh','start');deadline=time.monotonic()+90
  while time.monotonic()<deadline:
   try:
    with urllib.request.urlopen('http://localhost:18280/idp/shibboleth',timeout=3) as r:
     if r.status==200:row['completed']=True;save(out/'operations.json',ops);return
   except Exception:pass
   time.sleep(1)
  raise RuntimeError('Native endpoint unavailable after restart')
 def reload(label):
  row=dict(operation='reload',label=label,recordedAt=NOW(),completed=False);ops.append(row);save(out/'operations.json',ops);(receipt/(label+'-reload.txt')).write_bytes(docker('/opt/reference-idp/bin/reload-service.sh','-id','shibboleth.MetadataResolverService','-u','http://localhost:8080/idp'));row['completed']=True;save(out/'operations.json',ops)
 def clock(name):
  started=NOW();raw=docker('date','-u','+%Y-%m-%dT%H:%M:%S.%NZ');completed=NOW();(receipt/(name+'-clock.txt')).write_bytes(raw);save(receipt/(name+'-clock.json'),dict(command=['date','-u','+%Y-%m-%dT%H:%M:%S.%NZ'],clockDomain='native-product-os-UTC',hostStartedAt=started,hostCompletedAt=completed,nativeInstant=raw.decode().strip(),nativeClockSha256=SHA(raw)));return datetime.datetime.fromisoformat(raw.decode().strip().replace('Z','+00:00'))
 def query(name):
  command=['/opt/reference-idp/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',entity];r=subprocess.run(['docker','exec',CONTAINER,*command],capture_output=True,timeout=40)
  (receipt/(name+'-metadata-stdout.txt')).write_bytes(r.stdout);(receipt/(name+'-metadata-stderr.txt')).write_bytes(r.stderr);save(receipt/(name+'-metadata-query.json'),dict(command=command,exitCode=r.returncode,entityId=entity,recordedAt=NOW(),stdoutSha256=SHA(r.stdout),stderrSha256=SHA(r.stderr)))
  return r.returncode
 def clock_boundary(phase):
  classes=[('abstract-resolver','opensaml-saml-impl-5.2.3.jar','org.opensaml.saml.metadata.resolver.impl.AbstractMetadataResolver'),('saml2-support','opensaml-saml-api-5.2.3.jar','org.opensaml.saml.saml2.common.SAML2Support'),('entity-validity','opensaml-saml-impl-5.2.3.jar','org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl'),('group-validity','opensaml-saml-impl-5.2.3.jar','org.opensaml.saml.saml2.metadata.impl.EntitiesDescriptorImpl')];rows=[];cached={}
  for kind,jar,name in classes:
   path='/usr/local/tomcat/webapps/idp/WEB-INF/lib/'+jar
   if jar not in cached:cached[jar]=docker('cat',path)
   raw=cached[jar];cls=zipfile.ZipFile(io.BytesIO(raw)).read(name.replace('.','/')+'.class');record=dict(kind=kind,className=name,classSha256=SHA(cls),jar=jar,jarSha256=SHA(raw))
   if phase=='start':(receipt/('native-'+jar)).write_bytes(raw);(receipt/('native-'+kind+'.class')).write_bytes(cls);(receipt/('native-'+kind+'-javap.txt')).write_bytes(docker('javap','-classpath',path,'-c','-p',name))
   rows.append(record)
  save(receipt/('native-validity-boundary-'+phase+'.json'),rows)
 def arm(variant,label,install):
  save(out/(label+'-campaign.json'),api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=[variant],pollingDelaySeconds=0)));state=api('/api/runs/'+run+'/metadata-lab')
  with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as r:assert r.status==202
  with urllib.request.urlopen(state['metadataUrl'],timeout=30) as r:raw=r.read()
  (receipt/(label+'-suite-prepared.xml')).write_bytes(raw)
  if install:write(temp,raw,'fixture-'+variant);(receipt/(variant+'-fixture.xml')).write_bytes(raw);reload(variant)
  return state,raw
 def send(state,variant,label,invalid=False):
  start=state['automaticStartUrl']+('&signatureControl=invalid' if invalid else '');old={e['id'] for e in api('/api/runs/'+run+'/transcript')};before=len(http);flow=client.flow(start,None,username,password);entries=api('/api/runs/'+run+'/transcript');issued=[e for e in entries if e['id'] not in old and e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest' and e['samlSummary'].get('variant')==variant];assert len(issued)==1
  request_entry=issued[0];matches=[e for e in entries if e['direction']=='INBOUND' and e['samlSummary'].get('type')=='Response' and e['samlSummary'].get('inResponseTo')==request_entry['samlSummary']['id']]
  record=dict(label=label,variant=variant,requestReference=request_entry['id'],responseReference=matches[0]['id'] if len(matches)==1 else None,receipt=flow,nativeHttp=http[before:],invalidSignature=invalid);save(receipt/(label+'-exchange.json'),record);return record
 username=os.environ.get('REFERENCE_USERNAME','samlscope-m0-user');password=os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password')
 try:
  for path in [AUDIT]:changed.append(path);write(path,configured[path],'prepare-'+path.rsplit('/',1)[-1])
  restart('prepare-native-audit')
  created=api('/api/plans',dict(name='Shibboleth retained metadata validity shared-session campaign',profile='metadata_idp',targetKind='IDP',targetEntityId='http://localhost:18280/idp/shibboleth',metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=a.lifetime,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',created);plan=created['plan']['plan']['id'];entity=BASE+'/p/'+plan;created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));temp='/opt/reference-idp/metadata/validity-'+run+'.xml'
  if docker('sh','-c','test -e '+temp+' && echo present || true').strip():raise ValueError('Temporary source already exists')
  # Complete the ordinary Suite prerequisite before expiry epochs, with this same client.
  # The initial credential is then reused by all three positive/expiry pairs.
  complete_baseline(run,out/'initial-baseline',client=client)
  ET.register_namespace('',NS);ET.register_namespace('xsi',XSI);root=ET.fromstring(original[PROVIDERS]);root.insert(0,ET.Element('{'+NS+'}MetadataProvider',dict(id='Validity'+run,**{'{'+XSI+'}type':'FilesystemMetadataProvider','metadataFile':temp,'requireValidMetadata':'true'})));configured[PROVIDERS]=ET.tostring(root);(receipt/'configured-providers.xml').write_bytes(configured[PROVIDERS]);capture_target(receipt,'shibboleth','start');clock_boundary('start');inventory=[]
  for index,node in enumerate(ET.fromstring(original[PROVIDERS]).iter('{'+NS+'}MetadataProvider')):
   if node.get('metadataFile') is None:continue
   path=node.get('metadataFile').replace('%{idp.home}','/opt/reference-idp');raw=docker('cat',path);name='other-provider-'+str(index)+'.xml';(receipt/name).write_bytes(raw);inventory.append(dict(path=path,file=name,sha256=SHA(raw)))
  save(receipt/'other-provider-inventory.json',inventory)
  for index,variant in enumerate(VARIANTS):
   state,fixture=arm(variant,variant+'-before',True)
   if index==0:changed.append(PROVIDERS);write(PROVIDERS,configured[PROVIDERS],'prepare-provider');reload('prepare-provider')
   for path in configured:assert docker('cat',path)==configured[path]
   (receipt/(variant+'-before-source.xml')).write_bytes(docker('cat',temp));(receipt/(variant+'-before-providers.xml')).write_bytes(docker('cat',PROVIDERS));(receipt/(variant+'-before-policy.txt')).write_bytes(projection(docker('cat',PROPERTIES)));clock(variant+'-before');query(variant+'-before')
   if index==0:control=send(state,variant,'invalid-signature-control',True)
   before=send(state,variant,variant+'-before');clock(variant+'-before-after-send');assert before['responseReference'] is not None,'Normal valid metadata control failed; no extra logins'
   xml=ET.fromstring(fixture);times=[datetime.datetime.fromisoformat(e.get('validUntil').replace('Z','+00:00')) for e in xml.iter() if e.tag in ['{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor','{urn:oasis:names:tc:SAML:2.0:metadata}EntitiesDescriptor'] and e.get('validUntil')];expiry=min(times)
   while clock(variant+'-waiting')<=expiry:time.sleep(1)
   # Re-arm only the Suite transport. Its newer publication is never installed on the target.
   state,_=arm(variant,variant+'-after-unconsumed',False);clock(variant+'-after-before-query');query(variant+'-after');clock(variant+'-after-before-send');log_before=docker('cat','/opt/reference-idp/logs/idp-process.log');after=send(state,variant,variant+'-after');log_after=docker('cat','/opt/reference-idp/logs/idp-process.log');assert log_after.startswith(log_before);delta=log_after[len(log_before):].decode();lines=[line for line in delta.splitlines() if 'Validity'+run in line and entity in line and 'no longer valid' in line];(receipt/(variant+'-after-probe-process.log')).write_text('\n'.join(lines)+'\n');clock(variant+'-after');(receipt/(variant+'-after-source.xml')).write_bytes(docker('cat',temp));(receipt/(variant+'-after-providers.xml')).write_bytes(docker('cat',PROVIDERS));(receipt/(variant+'-after-policy.txt')).write_bytes(projection(docker('cat',PROPERTIES)));observations.append(dict(variant=variant,before=before,after=after));save(out/'observations.json',observations)
  request_ids={e['samlSummary'].get('id') for e in api('/api/runs/'+run+'/transcript') if e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest'};lines=[]
  for line in docker('cat','/opt/reference-idp/logs/idp-audit.log').decode().splitlines():
   if 'SAMLscope-signature-v1|' not in line:continue
   fields=line.split('SAMLscope-signature-v1|',1)[1].split('|')
   if len(fields)==8 and fields[0] in request_ids:lines.append('SAMLscope-signature-v1|'+'|'.join(fields))
  (receipt/'native-request-bound-audit.log').write_text('\n'.join(lines)+'\n');capture_target(receipt,'shibboleth','end');clock_boundary('end')
  for item in inventory:assert SHA(docker('cat',item['path']))==item['sha256']
  save(receipt/'other-provider-final-readback.json',inventory)
 finally:
  for path in reversed(changed):
   try:
    assert docker('cat',path)==configured[path],'Concurrent native configuration mutation';write(path,original[path],'restore-'+path.rsplit('/',1)[-1])
   except Exception as e:errors.append(type(e).__name__)
  if not errors and changed:
   try:restart('restore-native-settings')
   except Exception as e:errors.append(type(e).__name__)
  if temp is not None and not errors:docker('rm','--',temp)
  for path,kind in [(PROVIDERS,'providers'),(AUDIT,'audit')]: (receipt/('final-'+kind+'.xml')).write_bytes(docker('cat',path))
  final_properties=docker('cat',PROPERTIES);(receipt/'final-policy.txt').write_bytes(projection(final_properties));restored=not errors and all(docker('cat',path)==raw for path,raw in original.items());save(out/'restoration.json',dict(restored=restored,errors=errors,original={p:SHA(v) for p,v in original.items()},final={p:SHA(docker('cat',p)) for p in original}));save(out/'operation-counts.json',dict(restored=restored,personOperations=0,credentialPosts=login_count,productWrites=sum(x['operation']=='write' for x in ops),restorationWrites=sum(x['operation']=='write' and x['label'].startswith('restore-') for x in ops),productRestarts=sum(x['operation']=='restart' for x in ops),metadataReloads=sum(x['operation']=='reload' for x in ops),protocolSubmissions=len(http)+1,ordinaryBaselineSubmissions=1,expiryProtocolSubmissions=len(http),unconsumedSuiteRearms=len(observations)))
  if run is not None:
   entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries);save(out/'protocol-evidence.json',api('/api/runs/'+run+'/protocol-evidence'))
   try:save(out/'result.json',api('/api/runs/'+run+'/result.json'))
   except Exception as pending:save(out/'result-not-yet-generated.json',dict(errorType=type(pending).__name__,requiresProfileTestStart=True,originalsCaptured=True))
  if not restored:raise RuntimeError('Native settings restoration incomplete')
 print(run,'native retained metadata expiry measured and restored; no verdict inferred',flush=True)
if __name__=='__main__':main()
