#!/usr/bin/env python3
"""Accepted A/rollover/B metadata, actual POST/PAOS use, one memory browser session.

Collection only: no target verdict, no receipt installation. Original native cached
HTTP bytes select the Suite MetadataPrepared record; freshly regenerated XML never
stands in for that original. All settings are restored in finally, including failed
preflight/setup attempts. Public metadata SOAP advertising is a measured fixture
precondition, not a claim that the product advertises ECP by default.
"""
import argparse, base64, datetime, hashlib, importlib.util, json, os, re, shutil, subprocess, sys, time, traceback
from pathlib import Path
import urllib.parse, urllib.request, xml.etree.ElementTree as E, zlib

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'dev/shibboleth'),str(REPO/'dev/keycloak'),str(REPO/'dev/reference-acceptance')]
_spec=importlib.util.spec_from_file_location('application_suite_api',REPO/'dev/keycloak/import_metadata_batch.py')
_suite=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_suite)
api,save,BASE,flow=_suite.api,_suite.save,_suite.BASE,_suite.flow
from metadata_native_observation import MetadataNativeClient
from reference_flow import Client,parse_forms
from browser_probe_selection import prepare_and_skip
from capture_run_originals import capture
from registered_signer_campaign import recorded, public_terminal, reject_sensitive
import metadata_certificate_trust_scope as trust_scope

CONTAINER='samlscope-reference-shibboleth';SUITE='samlscope-reference-suite'
PROVIDERS='/opt/reference-idp/conf/metadata-providers.xml';AUDIT='/opt/reference-idp/conf/audit.xml'
PUBLIC='/opt/reference-idp/metadata/idp-metadata.xml';AUDIT_LOG='/opt/reference-idp/logs/idp-audit.log'
TARGET='http://localhost:18280/idp/shibboleth';ECP=TARGET.rsplit('/shibboleth',1)[0]+'/profile/SAML2/SOAP/ECP'
MD='urn:oasis:names:tc:SAML:2.0:metadata';P='urn:oasis:names:tc:SAML:2.0:protocol';DS='http://www.w3.org/2000/09/xmldsig#'
N='urn:mace:shibboleth:2.0:metadata';XSI='http://www.w3.org/2001/XMLSchema-instance'
POST='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST';PAOS='urn:oasis:names:tc:SAML:2.0:bindings:PAOS';SOAP='urn:oasis:names:tc:SAML:2.0:bindings:SOAP'
BROWSER='http://shibboleth.net/ns/profiles/saml2/sso/browser';ECP_PROFILE='http://shibboleth.net/ns/profiles/saml2/sso/ecp'
FORMAT='SAMLscope-application-v1|%I|%II|%III|%SP|%e|%S|%XX|%b|%bb|%P|%T'
CASES=('IIP-MD06-a-idp-01','IIP-MD06-ab-idp-01')
VARIANTS=('control','multiple-signing-keys-first','no-valid-until')
FIXTURES=('new-key-explicit-acs','new-key-default-acs','new-key-second-acs','new-key-redirect','old-key-new-acs','rollover-first-key-new-acs','rollover-second-key-new-acs','new-key-old-acs','new-key-invalid-signature')
SLO_FIXTURES=('new-key-slo-route','old-key-slo-route','new-key-invalid-signature-slo-route')
ECP_FIXTURES={
 'multiple-signing-keys-first':('fixture-ecp-metadata-rollover-first-paos','fixture-ecp-metadata-rollover-second-paos','fixture-ecp-metadata-rollover-unadvertised-paos'),
 'no-valid-until':('fixture-ecp-metadata-b-paos','fixture-ecp-metadata-b-invalid-signature-paos','fixture-ecp-metadata-b-old-key-paos')}
SCHEMA='samlscope-shibboleth-metadata-application-v1';ADAPTER='shibboleth-native-accepted-metadata-application-v1';CAMPAIGN='native-metadata-supersession'
SHA=lambda raw:hashlib.sha256(raw).hexdigest();NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')

def docker(*args,data=None):
 return subprocess.run(['docker','exec','-i',CONTAINER,*args],input=data,capture_output=True,check=True,timeout=90).stdout

def soap_metadata(raw):
 root=E.fromstring(raw)
 if root.tag!='{'+MD+'}EntityDescriptor' or root.get('entityID')!=TARGET or root.findall('./{'+DS+'}Signature'):
  raise ValueError('Expected the unsigned public reference IdP metadata; never invalidate a signed document')
 roles=root.findall('./{'+MD+'}IDPSSODescriptor')
 if len(roles)!=1:raise ValueError('Ambiguous target IdP role')
 if any(n.get('Binding')==SOAP for n in roles[0].findall('./{'+MD+'}SingleSignOnService')):
  raise ValueError('Fresh explicit ECP-advertisement fixture expected')
 services=[i for i,n in enumerate(roles[0]) if n.tag=='{'+MD+'}SingleSignOnService']
 if not services:raise ValueError('Original target SSO endpoints missing')
 roles[0].insert(max(services)+1,E.Element('{'+MD+'}SingleSignOnService',{'Binding':SOAP,'Location':ECP}))
 return E.tostring(root,encoding='utf-8',xml_declaration=True)

def application_audit(raw):
 root=E.fromstring(raw);ns='http://www.springframework.org/schema/beans';util='http://www.springframework.org/schema/util'
 maps=[n for n in root if n.tag=='{'+util+'}map' and n.get('id')=='shibboleth.AuditFormattingMap']
 if len(maps)!=1:raise ValueError('Native audit formatting map unavailable')
 entries=[n for n in maps[0] if n.tag=='{'+ns+'}entry' and n.get('key')=='Shibboleth-Audit']
 if len(entries)!=1:raise ValueError('Native audit formatting entry ambiguous')
 entries[0].set('value',FORMAT)
 return E.tostring(root,encoding='utf-8',xml_declaration=True)

def provider_configuration(raw,run,source,backing,wait):
 root=E.fromstring(raw)
 if root.tag!='{'+N+'}MetadataProvider' or root.get('{'+XSI+'}type')!='ChainingMetadataProvider':raise ValueError('Native provider chain required')
 if any(n.get('id')=='Application'+run for n in root.iter()):raise ValueError('Fresh provider identity already exists')
 E.register_namespace('',N);E.register_namespace('xsi',XSI)
 root.insert(0,E.Element('{'+N+'}MetadataProvider',{'id':'Application'+run,'{'+XSI+'}type':'FileBackedHTTPMetadataProvider','metadataURL':source,'backingFile':backing,'minRefreshDelay':'PT%dS'%wait,'maxRefreshDelay':'PT%dS'%(wait*2),'refreshDelayFactor':'0.75'}))
 return E.tostring(root,encoding='utf-8',xml_declaration=True)

def preflight_fixture(raw,entity,variant,run):
 root=E.fromstring(raw)
 if root.tag!='{'+MD+'}EntityDescriptor' or root.get('entityID')!=entity:raise ValueError('Fixture entity does not belong to Plan')
 roles=root.findall('./{'+MD+'}SPSSODescriptor')
 if len(roles)!=1 or not root.findall('./{'+DS+'}Signature'):raise ValueError('Signed full SP role required')
 acs=roles[0].findall('./{'+MD+'}AssertionConsumerService')
 required={0:POST,1:POST,2:PAOS,3:'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'}
 if len(acs)!=4 or {int(n.get('index')):n.get('Binding') for n in acs}!=required:raise ValueError('Full advertised endpoint/binding matrix must be retained')
 for n in acs:
  u=urllib.parse.urlsplit(n.get('Location',''))
  if u.hostname not in {'localhost','127.0.0.1'} or urllib.parse.parse_qs(u.query)!={'mdv':[variant],'run':[run]}:raise ValueError('Fixture ACS correlation unavailable')
 return root

def entity_run(entity,location):
 values=urllib.parse.parse_qs(urllib.parse.urlsplit(location).query).get('run',[])
 if len(values)!=1 or not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',values[0]):raise ValueError('Fixture Run missing')
 return values[0]

def actual_slots(result,run,digest):
 if result['run']['id']!=run or result['profile']['id']!='metadata-idp' or result['target']['metadata_digest']!='sha256:'+digest:raise ValueError('Actual Run/profile/target digest mismatch')
 slots={c['id']:c for r in result['requirements'] for c in r['cases']}
 if not all(c in slots for c in CASES):raise ValueError('Both approved case slots required before remaining probes')
 return {c:slots[c] for c in CASES}

def validate_prepared_originals(folder,entity):
 """Offline actual Suite schema/signature validation, before native settings/login."""
 source=REPO/'dev/reference-acceptance/ValidateMetadataApplicationPreparedFixtures.java'
 runtime=REPO/'api/build/install/samlscope/lib';classpath=os.pathsep.join(str(p) for p in sorted(runtime.glob('*.jar')))
 if not classpath:raise ValueError('Pinned public fixture validation runtime unavailable')
 java=Path(os.environ.get('JAVA_HOME','/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home'))/'bin'
 classes=folder/'prepared-validation-classes';classes.mkdir()
 report=dict(schema='samlscope-public-metadata-preparation-validation-v1',sourceSha256=SHA(source.read_bytes()),
  samlJarSha256=SHA((runtime/'saml-0.1.0.jar').read_bytes()),startedAt=NOW(),nativeSettings=0,protocolSends=0,credentialPosts=0)
 try:
  compile=subprocess.run([str(java/'javac'),'-cp',classpath,'-d',str(classes),str(source)],capture_output=True,timeout=40)
  report.update(compilerExit=compile.returncode,compilerStdoutSha256=SHA(compile.stdout),compilerStderrSha256=SHA(compile.stderr))
  if compile.returncode:raise ValueError('Public preparation validator compile failed')
  check=subprocess.run([str(java/'java'),'-cp',str(classes)+os.pathsep+classpath,'ValidateMetadataApplicationPreparedFixtures',str(folder),entity],capture_output=True,timeout=40)
  report.update(validationExit=check.returncode,stdout=check.stdout.decode(),stderrSha256=SHA(check.stderr),finishedAt=NOW())
  if check.returncode:raise ValueError('Public metadata original failed schema/signature validation')
 finally:save(folder/'prepared-original-validation.json',report)

def resume_case_preflight(state,run):
 if state.get('runId')!=run or set(state.get('cases',{}))!=set(CASES):raise ValueError('Foreign/missing prior case slot')
 for value in state['cases'].values():
  if value['status']!='RUNNING' or value['phase']!='runner-queued-front-channel' or value['outcome'] is not None or value['outboxCount']!=0:
   raise ValueError('Only formally queued, never-dispatched own cases can resume collection')

def select_native_prepared(entries,run,variant,cache_sha,source,lower,upper):
 """Bind cached bytes to the latest native fetch in this publication's host window.

 Identical fixture bytes may be prepared by older native polls or Suite-only
 preflight reads. Their presence does not make the current cache non-native.
 Only actual source URL/native User-Agent fetches are candidates; a tied latest
 observation, foreign history or missing binding remains unqualified.
 """
 indexed={}
 for entry in entries:
  if entry.get('runId')!=run or entry['id'] in indexed:raise ValueError('Foreign or duplicate transcript history')
  indexed[entry['id']]=entry
 candidates=[]
 for prepared in entries:
  summary=prepared.get('samlSummary',{})
  if summary.get('type')!='MetadataPrepared' or summary.get('feed')!='live' or summary.get('variant')!=variant or summary.get('metadataSha256')!=cache_sha:continue
  fetch=indexed.get(summary.get('fetchTranscriptId'))
  if not fetch or fetch.get('url')!=source or fetch.get('samlSummary',{}).get('type')!='MetadataFetch':continue
  agent=fetch.get('headers',{}).get('User-Agent',[])
  if not isinstance(agent,list) or not any(isinstance(value,str) and 'Shibboleth/' in value for value in agent):continue
  timestamp=float(prepared['timestamp']);fetched=float(fetch['timestamp'])
  if lower<=fetched<=timestamp<=upper:candidates.append((prepared,fetch))
 if not candidates:raise ValueError('Native cache original fetch is missing from the publication window')
 latest=max(float(value[0]['timestamp']) for value in candidates)
 selected=[value for value in candidates if float(value[0]['timestamp'])==latest]
 if len(selected)!=1:raise ValueError('Native cache original fetch is ambiguous within the publication window')
 prepared,fetch=selected[0]
 return prepared,fetch,dict(lowerHostEpoch=lower,upperHostEpoch=upper,latestNativePreparedTimestamp=latest,
  candidatePreparedReferences=[value[0]['id'] for value in candidates],candidateFetchReferences=[value[1]['id'] for value in candidates])

def collect_native_audit(receipt,entries,decoded,directory):
 """Retain request-bound public native audit even for an interrupted attempt."""
 indexed={entry['id']:entry for entry in entries};ids=set()
 for record in decoded:
  if indexed[record['id']]['direction']!='OUTBOUND':continue
  try:root=E.fromstring((directory/record['file']).read_bytes())
  except E.ParseError:continue
  requests=([root] if root.tag in {'{'+P+'}AuthnRequest','{'+P+'}LogoutRequest'} else root.findall('.//{'+P+'}AuthnRequest')+root.findall('.//{'+P+'}LogoutRequest'))
  ids.update(node.get('ID') for node in requests if node.get('ID'))
 lines=[]
 for line in docker('cat',AUDIT_LOG).decode().splitlines():
  if line.startswith('SAMLscope-application-v1|'):
   fields=line.split('|')
   if len(fields)==12 and fields[1] in ids:lines.append(line)
 (receipt/'native-application-audit.log').write_text('\n'.join(lines)+'\n')

def reuse_rollover(previous,receipt,run):
 """Copy actual earlier same-Run rollover originals without changing their epoch."""
 probes=json.loads((previous/'probes.json').read_bytes());phases=json.loads((previous/'phases.json').read_bytes());epochs=json.loads((previous/'epochs.json').read_bytes())
 expected=set(ECP_FIXTURES['multiple-signing-keys-first']);rows=[row for row in probes if row.get('fixture') in expected]
 phases=[row for row in phases if row.get('variant')=='multiple-signing-keys-first']
 selected={row['beforeEpoch']['reference'] for row in rows}|{row['afterEpoch']['reference'] for row in rows}
 for phase in phases:selected.update((phase['beforeEpoch']['reference'],phase['afterEpoch']['reference']))
 epochs=[row for row in epochs if row['reference'] in selected]
 if len(rows)!=3 or {row['fixture'] for row in rows}!=expected or len(phases)!=1 or len(epochs)!=4:raise ValueError('Prior complete rollover group unavailable')
 entries=json.loads((previous/'transcript.json').read_bytes());ids={entry['id'] for entry in entries if entry.get('runId')==run}
 if any(row['requestReference'] not in ids for row in rows) or any(row['reference'] not in ids for row in epochs):raise ValueError('Prior rollover original belongs to another Run')
 source=previous/'receipt';destination=receipt/'prior-rollover'
 if any(path.is_symlink() for path in source.rglob('*')):raise ValueError('Unsafe prior rollover original')
 shutil.copytree(source,destination)
 for source_file in source.rglob('*'):
  if source_file.is_file() and SHA(source_file.read_bytes())!=SHA((destination/source_file.relative_to(source)).read_bytes()):raise ValueError('Prior rollover original copy differs')
 for name in ('flow-multiple-signing-keys-first.json','native-http.json','operations.json','operation-counts.json','restoration.json','phases.json','probes.json','epochs.json'):
  (destination/name).write_bytes((previous/name).read_bytes())
 manifest=dict(schema='samlscope-native-prior-rollover-reuse-v1',runId=run,priorFolder=str(previous),
  priorFiles={name:SHA((previous/name).read_bytes()) for name in ('probes.json','phases.json','epochs.json','transcript.json','operations.json','operation-counts.json','restoration.json')},
  originalEpochReferences=[row['reference'] for row in epochs],newTargetSubmissions=0,
  runtimeRelabelled=False,actionRelabelled=False,nativeRoot='prior-rollover/native')
 save(receipt/'prior-rollover-reuse.json',manifest)
 return rows,phases,epochs

def current_resume_state(folder,run):
 source=REPO/'dev/reference-acceptance/ReadMetadataApplicationStoredConclusions.java'
 runtime=REPO/'api/build/install/samlscope/lib';classpath=os.pathsep.join(str(p) for p in sorted(runtime.glob('*.jar')))
 java=Path(os.environ.get('JAVA_HOME','/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home'))/'bin'
 classes=folder/'resume-state-classes';classes.mkdir();remote='/tmp/metadata-application-state-'+run
 subprocess.run([str(java/'javac'),'-cp',classpath,'-d',str(classes),str(source)],capture_output=True,check=True,timeout=40)
 try:
  subprocess.run(['docker','exec',SUITE,'mkdir','-p',remote],capture_output=True,check=True,timeout=40)
  subprocess.run(['docker','cp',str(classes)+'/com',SUITE+':'+remote],capture_output=True,check=True,timeout=40)
  result=subprocess.run(['docker','exec',SUITE,'java','-cp','/opt/samlscope/lib/*:'+remote,'com.samlscope.runner.cases.ReadMetadataApplicationStoredConclusions',run],capture_output=True,check=True,timeout=40)
  (folder/'resume-execution-preflight.json').write_bytes(result.stdout);value=json.loads(result.stdout);resume_case_preflight(value,run);return value
 finally:subprocess.run(['docker','exec',SUITE,'rm','-rf',remote],capture_output=True,timeout=40)

def native_runtime():
 value=json.loads(subprocess.run(['docker','inspect',CONTAINER],capture_output=True,check=True,timeout=30).stdout)[0]
 return dict(id=value['Id'],image=value['Image'],startedAt=value['State']['StartedAt'],running=value['State']['Running'],mounts=value['Mounts'])

def existing_sources(raw,entity,directory):
 rows=[]
 for index,provider in enumerate(E.fromstring(raw).iter('{'+N+'}MetadataProvider')):
  kind=provider.get('{'+XSI+'}type')
  if kind=='ChainingMetadataProvider':continue
  if kind!='FilesystemMetadataProvider' or provider.get('metadataFile') is None:raise ValueError('Existing native source is not closed before settings/login')
  path=provider.get('metadataFile').replace('%{idp.home}','/opt/reference-idp')
  if not path.startswith('/opt/reference-idp/metadata/') or '..' in Path(path).parts:raise ValueError('Unsafe existing native source path')
  original=docker('cat',path)
  if any(n.get('entityID')==entity for n in E.fromstring(original).iter('{'+MD+'}EntityDescriptor')):raise ValueError('Fresh peer already exists in a native source')
  name='existing-provider-'+str(index)+'.xml';(directory/name).write_bytes(original);rows.append(dict(path=path,file=name,sha256=SHA(original)))
 return rows

def restore_native(original,changed,inventory,backing,entity,native,receipt,write,restart):
 """Attempt every owned restoration even if a read/restart/query fails.

 A failure is retained as a failed restoration; it never erases operation costs or
 promotes an unparseable native query to proof that the peer has disappeared.
 """
 failures=[];final_sources=[];peer_query=None
 names={PROVIDERS:'providers',AUDIT:'audit',PUBLIC:'public-metadata'}
 for path in (PROVIDERS,AUDIT,PUBLIC):
  try:
   if path in changed:write(path,original[path],'restore-'+names[path])
   raw=docker('cat',path);(receipt/('final-'+names[path]+'.xml')).write_bytes(raw)
   if raw!=original[path]:raise ValueError('Native exact restoration failed')
  except Exception as error:failures.append(dict(path=path,errorType=type(error).__name__))
 if any(path in changed for path in (PROVIDERS,AUDIT)):
  try:restart('restore-application-audit')
  except Exception as error:failures.append(dict(operation='restart',errorType=type(error).__name__))
 if backing:
  try:
   docker('rm','-f',backing)
   if docker('sh','-c','test -e '+backing+' && echo exists || true').strip():raise ValueError('Native cache remains')
  except Exception as error:failures.append(dict(operation='remove-native-cache',errorType=type(error).__name__))
 for member in inventory:
  try:
   raw=docker('cat',member['path']);final_sources.append(dict(path=member['path'],sha256=SHA(raw)))
   if SHA(raw)!=member['sha256']:raise ValueError('Existing native metadata source changed')
  except Exception as error:failures.append(dict(operation='existing-source-readback',errorType=type(error).__name__))
 if entity:
  command=['/opt/reference-idp/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',entity]
  try:
   completed=subprocess.run(['docker','exec',CONTAINER,*command],capture_output=True,timeout=40)
   (native/'restored-peer-query.stdout').write_bytes(completed.stdout);(native/'restored-peer-query.stderr').write_bytes(completed.stderr)
   peer_query=dict(command=command,exitCode=completed.returncode,stdoutSha256=SHA(completed.stdout),stderrSha256=SHA(completed.stderr),recordedAt=NOW())
   save(native/'restored-peer-query.json',peer_query)
   if any(n.get('entityID')==entity for n in E.fromstring(completed.stdout).iter('{'+MD+'}EntityDescriptor')):
    failures.append(dict(operation='restored-peer-still-present',errorType='ValueError'))
  except E.ParseError:
   # The original CLI failure output is retained. Only the later reader can
   # qualify a source-pinned explicit "no entity" error as the absence proof.
   peer_query['requiresNativeAbsenceQualification']=True;save(native/'restored-peer-query.json',peer_query)
  except Exception as error:failures.append(dict(operation='restored-peer-query',errorType=type(error).__name__))
 try:save(receipt/'final-runtime.json',native_runtime())
 except Exception as error:failures.append(dict(operation='final-runtime-readback',errorType=type(error).__name__))
 return dict(restored=not failures,failures=failures,backingFileRemoved=bool(backing and not failures),existingSources=final_sources,
  original={names[p]:SHA(raw) for p,raw in original.items()},
  final={names[p]:SHA((receipt/('final-'+names[p]+'.xml')).read_bytes()) for p in original if (receipt/('final-'+names[p]+'.xml')).exists()},recordedAt=NOW())

class SharedClient(MetadataNativeClient):
 def __init__(self,records,directory):
  super().__init__(records,directory);self.credential_posts=0;self.baseline_get_attempts=0;self.target_redirect_attempts=0;self.redirect_responses={}
  owner=self
  class NativeResponseRedirect(urllib.request.HTTPRedirectHandler):
   def redirect_request(self,req,fp,code,msg,headers,newurl):
    location=urllib.parse.urlsplit(newurl)
    if location.hostname not in {'localhost','127.0.0.1'}:raise ValueError('Nonlocal native redirect refused before transport')
    if location.port==18280 and 'SAMLRequest=' in location.query:
     values=urllib.parse.parse_qs(location.query);raw=zlib.decompress(base64.b64decode(values['SAMLRequest'][0]),-15);root=E.fromstring(raw)
     if root.tag not in {'{'+P+'}AuthnRequest','{'+P+'}LogoutRequest'}:raise ValueError('Unexpected native Redirect request')
     owner.target_redirect_attempts+=1
     owner.records.append(dict(requestId=root.get('ID'),requestSha256=SHA(raw),requestUrl=newurl,requestMethod='GET',rawQuerySha256=SHA(location.query.encode()),startedAt=NOW(),redirectIssuedBy=req.full_url,observation='native-target-redirect-submission'))
    if urllib.parse.urlsplit(req.full_url).port==18280 and 'SAMLResponse=' in location.query:
     values=urllib.parse.parse_qs(location.query);raw=zlib.decompress(base64.b64decode(values['SAMLResponse'][0]),-15);root=E.fromstring(raw)
     if root.tag!='{'+P+'}LogoutResponse':raise ValueError('Unexpected native response Redirect: retain partial evidence')
     owner.redirect_responses[root.get('InResponseTo')]=dict(responseStatus=code,responseUrl=newurl,responseSamlSha256=SHA(raw),responseRawQuerySha256=SHA(location.query.encode()),responseBinding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',responseReceivedAt=NOW())
    return super().redirect_request(req,fp,code,msg,headers,newurl)
  self.op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),NativeResponseRedirect())
 def request(self,url,fields=None):
  host=urllib.parse.urlsplit(url)
  if fields and any(k in fields for k in ('password','j_password')):
   if self.credential_posts:raise ValueError('Unexpected extra login: retain prerequisites failure without repeating user effort')
   self.credential_posts+=1
  redirect=None
  if fields is None and host.port==18280 and 'SAMLRequest=' in (host.query or ''):
   values=urllib.parse.parse_qs(host.query);raw=zlib.decompress(base64.b64decode(values['SAMLRequest'][0]),-15);root=E.fromstring(raw)
   redirect=dict(requestId=root.get('ID'),requestSha256=SHA(raw),requestUrl=url,requestMethod='GET',rawQuerySha256=SHA(host.query.encode()),startedAt=NOW());self.target_redirect_attempts+=1
  slo=None
  if fields and host.port==18280 and 'SAMLRequest' in fields:
   raw=base64.b64decode(fields['SAMLRequest'],validate=True);root=E.fromstring(raw)
   if root.tag=='{'+P+'}LogoutRequest':slo=dict(requestId=root.get('ID'),requestSha256=SHA(raw),requestUrl=url,requestMethod='POST',startedAt=NOW())
  result=Client.request(self,url,fields) if slo else super().request(url,fields)
  if slo:
   final,page,status=result;slo.update(responseUrl=final,responseStatus=status,responseBodySha256=SHA(page.encode()),completedAt=NOW())
   replies=[f for f in parse_forms(page) if 'SAMLResponse' in f.fields]
   if len(replies)==1:slo['responseSamlSha256']=SHA(base64.b64decode(replies[0].fields['SAMLResponse'],validate=True))
   if slo['requestId'] in self.redirect_responses:slo.update(self.redirect_responses.pop(slo['requestId']))
   self.records.append(slo)
  if fields and host.port==18280 and 'SAMLRequest' in fields:
   final,page,status=result
   if status>=400 and public_terminal(page):
    root=E.fromstring(base64.b64decode(fields['SAMLRequest'],validate=True));name='native-rejection-'+root.get('ID')+'.html'
    (self.directory/name).write_bytes(page.encode())
    if not self.records or self.records[-1].get('requestId')!=root.get('ID'):raise ValueError('Native public body/request binding mismatch')
    self.records[-1]['responseBodyFile']=name
  if redirect:
   final,page,status=result;forms=[f for f in parse_forms(page) if 'SAMLResponse' in f.fields]
   redirect.update(responseUrl=final,responseStatus=status,responseBodySha256=SHA(page.encode()),completedAt=NOW())
   if len(forms)==1:redirect['responseSamlSha256']=SHA(base64.b64decode(forms[0].fields['SAMLResponse'],validate=True))
   if status>=400 and public_terminal(page):
    name='native-rejection-'+redirect['requestId']+'.html';(self.directory/name).write_bytes(page.encode());redirect['responseBodyFile']=name
   self.records.append(redirect)
  return result

def collect(output,wait=5,resume_folder=None):
 out=Path(output).resolve();out.mkdir(parents=True,exist_ok=False);receipt=out/'receipt';receipt.mkdir();native=receipt/'native';native.mkdir()
 ops=[];states=[];probes=[];phases=[];steps=[];errors=[];changed=set();run=plan=None;created=None;credential_values=None;basic_calls=0;inventory=[]
 (out/'collector-source.py').write_bytes(Path(__file__).read_bytes())
 original={path:docker('cat',path) for path in (PROVIDERS,AUDIT,PUBLIC)}
 names={PROVIDERS:'providers',AUDIT:'audit',PUBLIC:'public-metadata'}
 for path,raw in original.items():(receipt/('original-'+names[path]+'.xml')).write_bytes(raw)
 save(receipt/'initial-runtime.json',native_runtime())
 previous=None
 if resume_folder is not None:
  previous=Path(resume_folder).absolute()
  if any(p.is_symlink() for p in [previous,*previous.parents]):raise ValueError('Unsafe prior attempt')
  previous=previous.resolve();prior= json.loads((previous/'restoration.json').read_bytes())
  prior_state_name='execution-resume-preflight.json' if (previous/'execution-resume-preflight.json').is_file() else 'resume-execution-preflight.json'
  state=json.loads((previous/prior_state_name).read_bytes())
  if prior['restored'] is not True or prior['original']!=prior['final']:raise ValueError('Prior restoration is not qualified')
  if any(original[p]!=(previous/'receipt'/('original-'+names[p]+'.xml')).read_bytes() for p in original):raise ValueError('Native original differs from restored prior attempt')
  resume_case_preflight(state,json.loads((previous/'created.json').read_bytes())['run']['id'])
  preserve=['created.json','plan.json','baseline.json','restoration.json',prior_state_name,'transcript.json','decoded-manifest.json','operation-counts.json','operations.json']
  save(out/'prior-attempt-lineage.json',dict(folder=str(previous),files={name:SHA((previous/name).read_bytes()) for name in preserve},sameRun=True,priorCookieReused=False,authenticationBoundary='new empty in-memory cookie jar; any credential attempt belongs to this new attempt'))
 http=[];client=SharedClient(http,receipt);source=backing=None;configured={};publication_lower=None;reused_rollover=False
 def persist():save(out/'operations.json',ops);save(out/'phases.json',phases);save(out/'probes.json',probes);save(out/'native-http.json',http);save(out/'steps.json',steps)
 def write(path,raw,label):
  row=dict(operation='product-config-write',label=label,path=path,sha256=SHA(raw),bytes=len(raw),recordedAt=NOW(),readBack=False);ops.append(row);persist();docker('sh','-c','cat > '+path,data=raw)
  if docker('cat',path)!=raw:raise ValueError('Native write readback differs')
  row['readBack']=True;row['completedAt']=NOW();persist()
 def restart(label):
  row=dict(operation='product-restart',label=label,recordedAt=NOW(),completed=False);ops.append(row);persist();subprocess.run(['docker','restart',CONTAINER],capture_output=True,check=True,timeout=90);docker('/usr/local/tomcat/bin/startup.sh')
  deadline=time.monotonic()+110
  while time.monotonic()<deadline:
   try:
    with urllib.request.urlopen(TARGET,timeout=3) as response:
     if response.status==200:row['completed']=True;row['completedAt']=NOW();persist();return
   except Exception:pass
   time.sleep(1)
  raise ValueError('Native restart health unavailable')
 def reload_provider(label):
  row=dict(operation='native-provider-reload',label=label,recordedAt=NOW(),completed=False);ops.append(row);persist()
  command=['/opt/reference-idp/bin/reload-service.sh','-u','http://localhost:8080/idp','-id','shibboleth.MetadataResolverService']
  completed=subprocess.run(['docker','exec',CONTAINER,*command],capture_output=True,timeout=90)
  (native/(label+'-reload.stdout')).write_bytes(completed.stdout);(native/(label+'-reload.stderr')).write_bytes(completed.stderr)
  row.update(command=command,exitCode=completed.returncode,completedAt=NOW(),stdoutSha256=SHA(completed.stdout),stderrSha256=SHA(completed.stderr));persist()
  if completed.returncode:raise ValueError('Native metadata service reload failed')
  # CLI acknowledgement wording is not a conformance oracle. The subsequent
  # actual backing bytes plus mdquery/effective-profile originals establish use.
  row['completed']=True;persist()
 def unchanged():
  for path,raw in configured.items():
   if docker('cat',path)!=raw:raise ValueError('Concurrent native configuration mutation')
 def clock(label):
  before=NOW();raw=docker('date','-u','+%Y-%m-%dT%H:%M:%S.%NZ');after=NOW();name=label+'-clock.json';save(native/name,dict(schema='samlscope-native-clock-v1',startedAt=before,finishedAt=after,command=['date','-u','+%Y-%m-%dT%H:%M:%S.%NZ'],stdout=raw.decode().strip(),stdoutSha256=SHA(raw)));return name
 def epoch(label,variant,with_scope=False):
  started=NOW();before=clock(label+'-before');unchanged();cache=docker('cat',backing);cache_completed=time.time();cache_file=label+'-cached-metadata.xml';(native/cache_file).write_bytes(cache);preflight_fixture(cache,BASE+'/p/'+plan,variant,run)
  entries=api('/api/runs/'+run+'/transcript')
  prepared,fetch,selection=select_native_prepared(entries,run,variant,SHA(cache),source,publication_lower,cache_completed)
  command=['/opt/reference-idp/bin/mdquery.sh','-u','http://localhost:8080/idp','-e',BASE+'/p/'+plan];effective=docker(*command);lookup=label+'-effective-metadata.xml';(native/lookup).write_bytes(effective)
  profile_files={}
  for p_id,p_label in ((BROWSER,'browser'),(ECP_PROFILE,'ecp')):
   data=docker('/opt/reference-idp/bin/dumpconfig.sh','-u','http://localhost:8080/idp','--saml2','-r',BASE+'/p/'+plan,'-P',p_id);obj=json.loads(data);reject_sensitive(obj);filename=label+'-'+p_label+'-profile.json';(native/filename).write_bytes(data);profile_files[p_label]=filename
  if with_scope:trust_scope.capture(native,label,BASE+'/p/'+plan)
  runtime=native_runtime()
  after=clock(label+'-after');value=dict(schema='samlscope-shibboleth-metadata-application-original-v1',kind='native-accepted-metadata-epoch',runId=run,campaignId=CAMPAIGN,targetMetadataSha256=SHA((out/'target-metadata.xml').read_bytes()),recordedAt=NOW(),label=label,variant=variant,startedAt=started,finishedAt=NOW(),clockBeforeFile=before,clockAfterFile=after,runtime=runtime,sourceUrl=source,cacheFile=cache_file,cacheSha256=SHA(cache),preparedReference=prepared['id'],fetchReference=fetch['id'],preparedSelection=selection,queryCommand=command,queryFile=lookup,querySha256=SHA(effective),profiles=profile_files,configurationSha256={names[p]:SHA(docker('cat',p)) for p in configured},fullTrustScope=with_scope)
  ref=recorded(receipt,created,value,label);states.append(dict(label=label,variant=variant,**ref));save(out/'epochs.json',states);return value,ref
 def wait_fetch(variant,lower):
  deadline=time.monotonic()+wait*8+35
  while time.monotonic()<deadline:
   unchanged()
   try:
    raw=docker('cat',backing);entries=api('/api/runs/'+run+'/transcript')
    select_native_prepared(entries,run,variant,SHA(raw),source,lower,time.time());return
   except (subprocess.CalledProcessError,ValueError):pass
   time.sleep(1)
  raise ValueError('Native cached accepted epoch unavailable: '+variant)
 def ecp_group(label,variant):
  nonlocal basic_calls
  state=api('/api/runs/'+run+'/metadata-lab');original_run=api('/api/runs/'+run);lab=original_run['context']['metadata_lab']
  if not state['campaignComplete'] or state['ingestionMode']!='AUTOMATIC_POLLING' or state['campaignVariants']!=[variant] or lab['campaign_index']!=1:raise ValueError('ECP group must retain completed polling publication')
  value,before=epoch(label+'-ecp-before',variant);previous={e['id'] for e in api('/api/runs/'+run+'/transcript')};basic_calls+=1
  results=api('/api/runs/'+run+'/ecp-probe',dict(username=credential_values[0],password=credential_values[1]));save(out/(label+'-ecp-results.json'),results)
  value,after=epoch(label+'-ecp-after',variant);added=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in previous]
  rows=[]
  if len(results)!=3:raise ValueError('Whole ECP group incomplete')
  for fixture,result in zip(ECP_FIXTURES[variant],results):
   action=result['actionId'];requests=[e for e in added if e['direction']=='OUTBOUND' and e.get('correlationId')==action]
   if len(requests)!=1:raise ValueError('ECP action must have one original outbox request')
   replies=[e for e in added if e['direction']=='INBOUND' and e.get('correlationId')==action]
   rows.append(dict(fixture=fixture,actionId=action,requestReference=requests[0]['id'],responseReferences=[e['id'] for e in replies],beforeEpoch=before,afterEpoch=after,collectionResult=result))
  if len(rows)!=3:raise ValueError('Whole ECP group incomplete')
  probes.extend(rows);persist()
 try:
  configured[PUBLIC]=soap_metadata(original[PUBLIC]);(receipt/'configured-public-metadata.xml').write_bytes(configured[PUBLIC])
  if previous is None:
   response=api('/api/plans',dict(name='Shibboleth accepted metadata full POST/PAOS application',profile='metadata_idp',targetKind='IDP',targetEntityId=TARGET,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=wait,testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',response);plan=response['plan']['plan']['id'];created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',created);run=created['run']['id']
  else:
   for name in ('plan.json','created.json','baseline.json'):(out/name).write_bytes((previous/name).read_bytes())
   response=json.loads((out/'plan.json').read_bytes());created=json.loads((out/'created.json').read_bytes());plan=response['plan']['plan']['id'];run=created['run']['id']
   if state['runId']!=run or created['run']['planId']!=plan:raise ValueError('Prior case/Plan/Run binding differs')
   current_resume_state(out,run)
  source='http://samlscope-reference-suite:8080/p/'+plan+'/metadata/live?run='+run;backing='/opt/reference-idp/metadata/application-'+run+'.xml'
  if docker('sh','-c','test -e '+backing+' && echo exists || true').strip():raise ValueError('Fresh native cache path required')
  save(out/'planned-case-preflight.json',dict(runId=run,planId=plan,profile='metadata_idp',requiredCaseIds=list(CASES),formalSlotsConfirmed=False))
  inventory=existing_sources(original[PROVIDERS],BASE+'/p/'+plan,receipt);save(receipt/'existing-provider-inventory.json',inventory)
  # Prepare every original descriptor before any product write; the final selected
  # A campaign replaces this Suite-only preparation sequence before native setup.
  for variant in VARIANTS:
   api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=[variant],pollingDelaySeconds=wait))
   with urllib.request.urlopen(BASE+'/p/'+plan+'/metadata/live?run='+run,timeout=30) as response:raw=response.read()
   preflight_fixture(raw,BASE+'/p/'+plan,variant,run);(out/('prepared-preflight-'+variant+'.xml')).write_bytes(raw)
  validate_prepared_originals(out,BASE+'/p/'+plan)
  if previous is not None and json.loads((previous/'probes.json').read_bytes()):
   rows,prior_phases,prior_epochs=reuse_rollover(previous,receipt,run)
   collect_native_audit(receipt/'prior-rollover',json.loads((previous/'transcript.json').read_bytes()),json.loads((previous/'decoded-manifest.json').read_bytes()),previous)
   probes.extend([{**row,'reusedFromPriorAttempt':True,'nativeRoot':'prior-rollover/native'} for row in rows]);phases.extend([{**row,'reusedFromPriorAttempt':True,'nativeRoot':'prior-rollover/native'} for row in prior_phases]);states.extend([{**row,'nativeRoot':'prior-rollover/native'} for row in prior_epochs]);reused_rollover=True;persist()
  changed.add(PUBLIC);write(PUBLIC,configured[PUBLIC],'prepare-public-ecp-advertisement')
  with urllib.request.urlopen(TARGET,timeout=30) as response:
   if response.read()!=configured[PUBLIC]:raise ValueError('Published metadata differs from native file')
  if previous is None:save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
  else:(out/'preflight.json').write_bytes((previous/'preflight.json').read_bytes())
  subprocess.run(['docker','cp',SUITE+':/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],capture_output=True,check=True,timeout=40)
  if previous is not None and (out/'target-metadata.xml').read_bytes()!=(previous/'target-metadata.xml').read_bytes():raise ValueError('Existing Run target snapshot changed')
  final_provider=provider_configuration(original[PROVIDERS],run,source,backing,wait)
  configured[PROVIDERS]=final_provider if previous is not None else provider_configuration(original[PROVIDERS],run,BASE.replace('localhost:18080','samlscope-reference-suite:8080')+'/p/'+plan+'/metadata',backing,wait);configured[AUDIT]=application_audit(original[AUDIT])
  if previous is not None:api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['control'],pollingDelaySeconds=wait))
  for path in (PROVIDERS,AUDIT):
   (receipt/('configured-'+names[path]+'.xml')).write_bytes(configured[path]);changed.add(path);write(path,configured[path],'prepare-'+names[path])
  credential_values=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
  # M0 uses the ordinary Plan key. Keep the manual control publication until the
  # baseline completes; polling keys belong to later epochs and must not be substituted.
  restart('prepare-application-audit')
  if previous is None:
   deadline=time.monotonic()+wait*8+35
   while time.monotonic()<deadline:
    try:
     ordinary=docker('cat',backing);root=E.fromstring(ordinary)
     if root.tag!='{'+MD+'}EntityDescriptor' or root.get('entityID')!=BASE+'/p/'+plan:raise ValueError('Wrong native baseline entity')
     if any(urllib.parse.urlsplit(n.get('Location','')).query for n in root.findall('.//{'+MD+'}AssertionConsumerService')):raise ValueError('Initial normal metadata must use ordinary ACS values')
     entries=api('/api/runs/'+run+'/transcript');break
    except subprocess.CalledProcessError:pass
    time.sleep(1)
   else:raise ValueError('Native baseline metadata unavailable')
   (native/'baseline-cached-metadata.xml').write_bytes(ordinary)
   baseline_previous={e['id'] for e in entries};baseline_started=NOW();baseline=client.flow(BASE+'/p/'+plan+'/start/m0-roundtrip?run='+run,None,*credential_values)
   baseline_entries=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in baseline_previous]
   if baseline!='recorded' or api('/api/runs/'+run)['status']!='COMPLETED':raise ValueError('One initial M0 flow must complete before metadata campaigns')
   save(out/'baseline.json',dict(receipt=baseline,startedAt=baseline_started,completedAt=NOW(),references=[e['id'] for e in baseline_entries],metadataSha256=SHA(ordinary),nativeProviderSha256=SHA(configured[PROVIDERS]),nativeSourceUrl=BASE.replace('localhost:18080','samlscope-reference-suite:8080')+'/p/'+plan+'/metadata'))
   save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
   (receipt/'baseline-providers.xml').write_bytes(configured[PROVIDERS]);configured[PROVIDERS]=final_provider;(receipt/'configured-providers.xml').write_bytes(final_provider)
   write(PROVIDERS,final_provider,'prepare-application-provider');reload_provider('activate-application-provider')
  else:
   for name in ('baseline-cached-metadata.xml',):(native/name).write_bytes((previous/'receipt/native'/name).read_bytes())
   (receipt/'baseline-providers.xml').write_bytes((previous/'receipt/baseline-providers.xml').read_bytes());(out/'tests-start.json').write_bytes((previous/'tests-start.json').read_bytes())
  result=api('/api/runs/'+run+'/result.json');actual_slots(result,run,SHA((out/'target-metadata.xml').read_bytes()));save(out/'actual-case-slot-preflight.json',result)
  for index,variant in enumerate(VARIANTS):
   if reused_rollover and variant=='multiple-signing-keys-first':continue
   lower=time.time();state=api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=[variant],pollingDelaySeconds=wait));save(out/('stage-'+variant+'-selection.json'),dict(state=state,run=api('/api/runs/'+run)))
   publication_lower=lower
   with urllib.request.urlopen(state['automaticStartUrl'],timeout=30) as response:response.read()
   wait_fetch(variant,lower);before_value,before=epoch(variant+'-before',variant,with_scope=index==0)
   result_file=out/('flow-'+variant+'.json');flow(run,result_file,suite_signature_control=index==2,login_inputs=credential_values,client_factory=lambda:client)
   after_value,after=epoch(variant+'-after',variant)
   phases.append(dict(variant=variant,beforeEpoch=before,afterEpoch=after,flowFile=result_file.name));persist()
   if index in (1,2):ecp_group(variant,variant)
  epoch('browser-matrix-before','no-valid-until');seen=False
  for _ in range(800):
   status=api('/api/runs/'+run+'/active-probe')
   if seen and status.get('caseId')!=CASES[0]:break
   if status['state']!='READY':raise ValueError('Native browser collection is not ready')
   if status.get('caseId')!=CASES[0]:steps.append(prepare_and_skip(BASE,run,status,api));persist();continue
   seen=True;value,before=epoch('browser-'+str(len([p for p in probes if p.get('browser')]))+'-before','no-valid-until');previous={e['id'] for e in api('/api/runs/'+run+'/transcript')}
   def terminal(url,page,code,reason):
    if not public_terminal(page):raise ValueError('Sensitive or ambiguous terminal page refused before Recorder')
    api('/api/runs/'+run+'/active-probe/browser-response',dict(actionId=status['actionId'],status=code,url=url,body=page))
   result=client.flow(status['startUrl'],None,*credential_values,terminal_observer=terminal);value,after=epoch('browser-'+str(len([p for p in probes if p.get('browser')]))+'-after','no-valid-until');added=[e for e in api('/api/runs/'+run+'/transcript') if e['id'] not in previous]
   requests=[e for e in added if e['direction']=='OUTBOUND' and e.get('samlSummary',{}).get('action_id')==status['actionId']]
   if len(requests)!=1:raise ValueError('Browser outbox request ambiguous')
   request=requests[0];probes.append(dict(browser=True,fixture=request['samlSummary']['fixture_id'],actionId=status['actionId'],sourceCaseId=status['caseId'],requestReference=request['id'],beforeEpoch=before,afterEpoch=after,receipt=result));persist()
   after_status=api('/api/runs/'+run+'/active-probe')
   if after_status.get('actionId')==status['actionId']:raise ValueError('Original browser evidence did not complete collection')
  browser=[p for p in probes if p.get('browser')]
  if not seen or len(browser)!=12 or {p['fixture'] for p in browser}!=set(FIXTURES+SLO_FIXTURES):raise ValueError('Full approved browser and SLO route collection incomplete')
  epoch('browser-matrix-after','no-valid-until',with_scope=True)
 except Exception as error:
  frames=[dict(file=Path(frame.filename).name,line=frame.lineno,function=frame.name) for frame in traceback.extract_tb(error.__traceback__)]
  errors.append(dict(type=type(error).__name__,message='Collection stopped; inspect the public operation originals.',stackFrames=frames));save(out/'collection-errors.json',errors)
 finally:
  credential_values=None
  restoration=restore_native(original,changed,inventory,backing,BASE+'/p/'+plan if run and plan else None,native,receipt,write,restart)
  save(out/'restoration.json',restoration)
  save(out/'operation-counts.json',dict(productConfigurationWrites=sum(o['operation']=='product-config-write' for o in ops),restorationWrites=sum(o['operation']=='product-config-write' and o['label'].startswith('restore-') for o in ops),productRestarts=sum(o['operation']=='product-restart' for o in ops),nativeProviderReloads=sum(o['operation']=='native-provider-reload' for o in ops),personOperations=0,credentialPosts=client.credential_posts,basicGroupCalls=basic_calls,basicScopedTargetSubmissions=sum(not p.get('browser') and not p.get('reusedFromPriorAttempt') for p in probes),priorBasicSubmissionsReused=sum(not p.get('browser') and p.get('reusedFromPriorAttempt') is True for p in probes),nativeBrowserPostAttempts=sum(h['requestMethod']=='POST' for h in http),nativeBrowserRedirectAttempts=client.target_redirect_attempts,allCredentialValuesPersisted=False,sameAuthenticatedClient=True,failedAttemptsIncluded=True))
  persist()
  if run:
   try:
    entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries);save(out/'result.json',api('/api/runs/'+run+'/result.json'));collect_native_audit(receipt,entries,json.loads((out/'decoded-manifest.json').read_bytes()),out)
   except Exception as error:save(out/'export-error.json',dict(errorType=type(error).__name__))
  if not restoration['restored']:raise ValueError('Native restoration incomplete; no adoption')
 if errors:raise ValueError('Collection attempt failed; originals retained')
 for name in ('operations.json','operation-counts.json','restoration.json','phases.json','probes.json','native-http.json','actual-case-slot-preflight.json','baseline.json'):(receipt/name).write_bytes((out/name).read_bytes())
 save(receipt/'manifest.json',dict(schema=SCHEMA,adapter=ADAPTER,campaignId=CAMPAIGN,runId=run,planId=plan,entityId=BASE+'/p/'+plan,targetMetadataSha256=SHA((out/'target-metadata.xml').read_bytes()),sourceUrl=source,backingFile=backing,epochReferences=states,phases=phases,probes=probes,files={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()}))
 print(run,'accepted native A/rollover/B original collection complete; exact restoration confirmed',flush=True)

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--refresh-wait-seconds',type=int,default=5);parser.add_argument('--resume-run-folder',type=Path);a=parser.parse_args()
 if not 2<=a.refresh_wait_seconds<=30:parser.error('Refresh wait must be 2..30 seconds')
 collect(a.output,a.refresh_wait_seconds,a.resume_run_folder)
