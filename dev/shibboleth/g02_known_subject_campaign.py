#!/usr/bin/env python3
"""Run all approved G02 inputs with two native, explicitly known long identifiers.

The native transformation is scoped to this new Suite SP. It establishes the
requested-principal prerequisite; G02.b/c string preservation is not claimed.
Credentials stay only in the existing browser driver's memory.
"""
import argparse,datetime,hashlib,importlib.util,json,pathlib,subprocess,sys,time,urllib.request,xml.etree.ElementTree as ET

REPO=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('shib_g02_native_browser',REPO/'dev/shibboleth/browser_chain_campaign.py')
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
docker=driver.docker;SAVE=driver.save;SHA=lambda b:hashlib.sha256(b).hexdigest()
NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
CONTAINER='samlscope-reference-shibboleth'
PATHS={'c14n':'/opt/reference-idp/conf/c14n/subject-c14n.xml','audit':'/opt/reference-idp/conf/audit.xml'}
AUDIT='SAMLscope-G02-known-v1|%I|%SP|%u|%S|%b|%P'
BEANS='http://www.springframework.org/schema/beans';UTIL='http://www.springframework.org/schema/util';P='http://www.springframework.org/schema/p'
VALUE='aZ09'*64
G02='IIP-G02-a-idp-01';UNKNOWN='IIP-SSO07-b-idp-01'

def preparation(originals,entity,principal):
 if not entity.startswith(driver.BASE+'/p/plan_') or not principal or '$' in principal or '\\' in principal:raise ValueError('Invalid native subject scope')
 root=ET.fromstring(originals['c14n'])
 def bean(id):
  found=[n for n in root if n.get('id')==id]
  if len(found)!=1:raise ValueError('Ambiguous native canonicalization bean')
  return found[0]
 flows=bean('shibboleth.SAMLSubjectCanonicalizationFlows');transforms=[n for n in flows if n.get('bean')=='c14n/SAML2Transform']
 if len(transforms)!=1:raise ValueError('Missing native SAML2 transform')
 flows.remove(transforms[0]);flows.insert(0,transforms[0])
 formats=bean('shibboleth.NameTransformFormats')
 for kind in ['persistent','transient']:
  value='urn:oasis:names:tc:SAML:2.0:nameid-format:'+kind
  if any(n.text==value for n in formats):raise ValueError('Reference format already transformed')
  ET.SubElement(formats,'{'+BEANS+'}value').text=value
 predicate=bean('shibboleth.NameTransformPredicate')
 if predicate.get('parent')!='shibboleth.Conditions.RelyingPartyId':raise ValueError('Unexpected native scope predicate')
 candidates=predicate.find('{'+BEANS+'}constructor-arg[@name="candidates"]/{'+BEANS+'}list')
 if candidates is None or list(candidates):raise ValueError('Existing native direct transformation scope')
 ET.SubElement(candidates,'{'+BEANS+'}value').text=entity
 name_transforms=bean('shibboleth.NameTransforms')
 if list(name_transforms):raise ValueError('Existing native name transformation')
 ET.SubElement(name_transforms,'{'+BEANS+'}bean',{'parent':'shibboleth.Pair','{'+P+'}first':'^'+VALUE+'$','{'+P+'}second':principal})
 audit=ET.fromstring(originals['audit']);entries=audit.findall('.//{'+UTIL+'}map[@id="shibboleth.AuditFormattingMap"]/{'+BEANS+'}entry[@key="Shibboleth-Audit"]')
 if len(entries)!=1:raise ValueError('Ambiguous native audit configuration')
 entries[0].set('value',AUDIT)
 return {'c14n':ET.tostring(root,encoding='utf-8',xml_declaration=True),'audit':ET.tostring(audit,encoding='utf-8',xml_declaration=True)}

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=pathlib.Path,required=True);args=parser.parse_args()
 folder=args.output.resolve();folder.mkdir(parents=True,exist_ok=False);child=folder/'browser'
 originals={k:docker('cat',p) for k,p in PATHS.items()};configured=None;changed=[];operations=[];plan=None
 for k,raw in originals.items():(folder/('original-'+k+'.xml')).write_bytes(raw)
 def write(k,raw,label):
  item=dict(operation='product-config-write',label=label,path=PATHS[k],startedAt=NOW(),sha256=SHA(raw),readBack=False);operations.append(item);SAVE(folder/'operations.json',operations)
  docker('sh','-c','cat > '+PATHS[k],data=raw)
  if docker('cat',PATHS[k])!=raw:raise RuntimeError('Native setting readback differs')
  item.update(readBack=True,finishedAt=NOW());SAVE(folder/'operations.json',operations)
 def restart(label):
  item=dict(operation='product-restart',label=label,startedAt=NOW(),completed=False);operations.append(item);SAVE(folder/'operations.json',operations)
  subprocess.run(['docker','restart',CONTAINER],check=True,timeout=60,capture_output=True);docker('/usr/local/tomcat/bin/startup.sh')
  until=time.monotonic()+120
  while time.monotonic()<until:
   try:
    with urllib.request.urlopen('http://localhost:18280/idp/shibboleth',timeout=3) as response:
     if response.status==200:item.update(completed=True,finishedAt=NOW());SAVE(folder/'operations.json',operations);return
   except Exception:pass
   time.sleep(1)
  raise RuntimeError('Native IdP startup failed')
 def readback(label):
  record=dict(recordedAt=NOW(),files={})
  for k,p in PATHS.items():
   raw=docker('cat',p)
   if raw!=configured[k]:raise RuntimeError('Native setting changed during campaign')
   file=label+'-'+k+'.xml';(folder/file).write_bytes(raw);record['files'][k]=dict(file=file,sha256=SHA(raw))
  SAVE(folder/(label+'-readback.json'),record)
 original_api=driver.api
 def campaign_api(path,payload=None):
  nonlocal configured,plan
  result=original_api(path,payload)
  if path=='/api/plans':
   plan=result['plan']['plan']['id'];entity=driver.BASE+'/p/'+plan
   configured=preparation(originals,entity,driver.USER)
   SAVE(folder/'native-subject-binding.json',dict(schema='samlscope-shibboleth-g02-known-subject-v1',targetEntityId='http://localhost:18280/idp/shibboleth',
    suiteEntityId=entity,principal=driver.USER,inputValue=VALUE,inputCodePoints=len(VALUE),formats=['persistent','transient'],purpose='native-requested-principal-prerequisite',preservationClaimed=False))
   for k,raw in configured.items():
    (folder/('configured-'+k+'.xml')).write_bytes(raw);changed.append(k);write(k,raw,'apply-'+k)
   restart('apply-known-subject');readback('before-run')
   driver.capture_target_runtime(folder,'shibboleth','start')
  if path.endswith('/tests/start'):readback('before-protocol')
  return result
 driver.api=campaign_api;errors=[]
 try:
  sys.argv=[str(REPO/'dev/shibboleth/browser_chain_campaign.py'),'--output',str(child),'--only-cases',G02+','+UNKNOWN,'--stop-after-case',UNKNOWN]
  driver.main();readback('after-protocol')
  transcript=json.loads((child/'transcript.json').read_bytes());manifest={r['id']:r for r in json.loads((child/'decoded-manifest.json').read_bytes())};ids=set()
  for entry in transcript:
   if entry.get('samlSummary',{}).get('type')=='AuthnRequest':ids.add(ET.fromstring((child/manifest[entry['id']]['file']).read_bytes()).get('ID'))
  lines=[]
  for line in docker('cat','/opt/reference-idp/logs/idp-audit.log').decode().splitlines():
   if AUDIT.split('|')[0]+'|' not in line:continue
   fields=line.split(AUDIT.split('|')[0]+'|',1)[1].split('|')
   if len(fields)==6 and fields[0] in ids:lines.append(AUDIT.split('|')[0]+'|'+'|'.join(fields))
  (folder/'native-request-bound-audit.log').write_text('\n'.join(lines)+'\n')
  # Public native source originals show the configured built-in decoder path.
  jar='/usr/local/tomcat/webapps/idp/WEB-INF/lib/idp-conf-impl-5.2.3.jar'
  raw=docker('cat',jar);(folder/'native-idp-conf-impl.jar').write_bytes(raw)
  SAVE(folder/'native-source.json',dict(path=jar,sha256=SHA(raw),subjectCanonicalizationResource='net/shibboleth/idp/conf/subject-c14n-system.xml'))
 finally:
  for k in reversed(changed):
   try:
    if docker('cat',PATHS[k])!=configured[k]:raise RuntimeError('Concurrent native change')
    write(k,originals[k],'restore-'+k)
   except Exception as e:errors.append(k+':'+type(e).__name__)
  if changed and not errors:
   try:restart('restore-known-subject')
   except Exception as e:errors.append('restart:'+type(e).__name__)
  finals={k:docker('cat',p) for k,p in PATHS.items()}
  for k,raw in finals.items():(folder/('final-'+k+'.xml')).write_bytes(raw)
  restored=not errors and finals==originals
  SAVE(folder/'restoration.json',dict(restored=restored,errors=errors,original={k:SHA(v) for k,v in originals.items()},final={k:SHA(v) for k,v in finals.items()}))
  SAVE(folder/'operation-counts.json',dict(product_configuration_writes=sum(i['operation']=='product-config-write' for i in operations),
   restoration_writes=sum(i['operation']=='product-config-write' and i['label'].startswith('restore-') for i in operations),
   product_restarts=sum(i['operation']=='product-restart' for i in operations),human_operations=0,restored=restored,child_counts_separate=True))
  driver.capture_target_runtime(folder,'shibboleth','end')
  if not restored:raise RuntimeError('Native c14n restoration incomplete')
 print('All selected G02/unknown-subject flows recorded; native settings restored')

if __name__=='__main__':main()
