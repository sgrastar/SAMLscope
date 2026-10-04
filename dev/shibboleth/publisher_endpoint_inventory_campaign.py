#!/usr/bin/env python3
"""Capture a real publisher epoch and selected native ECP endpoint, restoring every write.

The hosted publication is never overlaid. Native profile selection, loaded peer metadata,
source closure and a signed ordinary Response are separate originals. This collector
does not assign a conformance outcome, and never exports a private key or login state.
"""
import argparse, base64, datetime, hashlib, importlib.util, json, os, pathlib, re, shutil, subprocess, sys, urllib.request, xml.etree.ElementTree as ET, zipfile
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'dev/keycloak'),str(REPO/'dev/reference-acceptance'),str(REPO/'dev/shibboleth')]
from import_metadata_batch import api, save, BASE
from algorithm_preference_campaign import recorded, canonical
from capture_run_originals import capture
from preflight_observation_adoption import approved_case, scope_preflight
spec=importlib.util.spec_from_file_location('publisher_shib_m0',REPO/'dev/shibboleth/full_ui_metadata_campaign.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
TARGET='http://localhost:18280/idp/shibboleth';CONTAINER=native.CONTAINER;SUITE='samlscope-reference-suite'
PROVIDERS=native.PROVIDERS;RP='/opt/reference-idp/conf/relying-party.xml'
CASE='IIP-MD05-c1-idp-01';CAMPAIGN='native-metadata-publisher-key-inventory';ADAPTER='shibboleth-stock-publisher-endpoints-v1'
SCHEMA='samlscope-native-publisher-original-v1';SHA=lambda b:hashlib.sha256(b).hexdigest();NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
MD='urn:oasis:names:tc:SAML:2.0:metadata';N=native.NAMESPACE;XSI=native.XSI;P='http://www.springframework.org/schema/p';B='http://www.springframework.org/schema/beans'
PROFILES={'browser':'http://shibboleth.net/ns/profiles/saml2/sso/browser','ecp':'http://shibboleth.net/ns/profiles/saml2/sso/ecp'}
SOURCE_ENTRIES=['net/shibboleth/idp/conf/webflow-config.xml','net/shibboleth/idp/conf/relying-party-system.xml',
 'net/shibboleth/idp/flows/saml/saml2/sso-ecp-flow.xml','net/shibboleth/idp/flows/saml/saml2/sso-ecp-beans.xml',
 'net/shibboleth/idp/flows/saml/saml2/sso-abstract-flow.xml']
def require(ok,reason):
 if not ok:raise ValueError(reason)
def identifier(value,kind):
 require(isinstance(value,str) and re.fullmatch(kind+r'_[0-9A-HJKMNP-TV-Z]{26}',value),'Unsafe Suite '+kind+' identity');return value
def public_xml(raw):
 root=ET.fromstring(raw);require(b'PRIVATE KEY' not in raw,'Private material refused')
 for node in root.iter():
  names=[node.tag.split('}')[-1],*[name.split('}')[-1] for name in node.attrib]]
  for index,name in enumerate(names):
   # This servlet element declares public cookie policy, never cookie contents.
   if index==0 and name=='cookie-config':continue
   require(not re.search(r'password|passwd|secret|authorization|cookie|token|credential|private[-_.]?key',name,re.I),'Private XML field refused')
  if node.tag.split('}')[-1]=='property' and 'name' in node.attrib:
   require(not re.search(r'password|passwd|secret|authorization|cookie|token|credential|private[-_.]?key',node.attrib['name'],re.I),'Private XML property refused')
 return raw
def peer_override(raw,entity):
 ET.register_namespace('',B);ET.register_namespace('p',P);ET.register_namespace('c','http://www.springframework.org/schema/c');ET.register_namespace('util','http://www.springframework.org/schema/util');ET.register_namespace('xsi',XSI)
 root=ET.fromstring(raw);lists=root.findall('{http://www.springframework.org/schema/util}list')
 selected=[x for x in lists if x.get('id')=='shibboleth.RelyingPartyOverrides'];require(len(selected)==1,'Native RP override container ambiguous')
 require(not any(entity in v for n in root.iter() for v in n.attrib.values()),'Fresh peer already has an override')
 bean=ET.SubElement(selected[0],'{'+B+'}bean',{'id':'PublisherEndpointPeer','parent':'RelyingPartyByName','{http://www.springframework.org/schema/c}relyingPartyIds':entity})
 configs=ET.SubElement(ET.SubElement(bean,'{'+B+'}property',{'name':'profileConfigurations'}),'{'+B+'}list')
 ET.SubElement(configs,'{'+B+'}bean',{'parent':'SAML2.SSO','{'+P+'}signResponses':'true'})
 for name in ['SAML2.ECP','SAML2.Logout','SAML2.ArtifactResolution']:ET.SubElement(configs,'{'+B+'}ref',{'bean':name})
 return public_xml(ET.tostring(root,encoding='utf-8',xml_declaration=True))
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True,type=pathlib.Path);a=parser.parse_args()
 out=a.output.resolve();out.mkdir(parents=True,exist_ok=False);receipt=out/'receipt';receipt.mkdir();commands=[];ops=[];reads=[];refs={};expected={};touched=set();failed=None
 (receipt/'collector.py').write_bytes(pathlib.Path(__file__).read_bytes())
 def command(*args,data=None,check=True,purpose='public-native-read'):
  row=dict(purpose=purpose,executable=args[0],startedAt=NOW(),completed=False);commands.append(row);save(out/'native-command-counts.json',commands)
  result=subprocess.run(['docker','exec','-i',CONTAINER,*args],input=data,capture_output=True,timeout=45)
  row.update(completedAt=NOW(),completed=True,exitCode=result.returncode);save(out/'native-command-counts.json',commands)
  require(not check or result.returncode==0,'Native command failed; private stderr not exported');return result
 def raw(path):return command('cat',path).stdout
 def record(label,kind,**fields):
  value=dict(schema=SCHEMA,kind=kind,runId=run,campaignId=CAMPAIGN,targetMetadataSha256=SHA(target),recordedAt=NOW(),**fields)
  ref=recorded(receipt,created,value,label);ref['file']='native-originals/'+label+'.json';refs[label]=ref;return value
 def publication(label):
  row=dict(url=TARGET,method='GET',startedAt=NOW());reads.append(row);save(out/'publication-reads.json',reads)
  with urllib.request.urlopen(urllib.request.Request(TARGET,headers={'Cache-Control':'no-cache'}),timeout=30) as r:status=r.status;value=r.read(1048577)
  row.update(finishedAt=NOW(),responseStatus=status,sha256=SHA(value));save(out/'publication-reads.json',reads)
  require(status==200 and value==target and value==raw('/opt/reference-idp/metadata/idp-metadata.xml'),'Actual product publication changed or differs from native file')
  path='publication-'+label+'.xml';(receipt/path).write_bytes(value);return path,dict(method='GET',url=TARGET,responseStatus=status,publicationSha256=SHA(value),nativeStartedAt=row['startedAt'],nativeFinishedAt=row['finishedAt'])
 def write(path,value,label):
  if path in expected:require(raw(path)==expected[path],'Concurrent native change; no overwrite')
  else:require(command('test','-e',path,check=False).returncode==1,'Fresh owned source already exists')
  public_xml(value);row=dict(operation='write',path=path,label=label,sha256=SHA(value),startedAt=NOW(),completed=False);ops.append(row);save(out/'operations.json',ops)
  touched.add(path);expected[path]=value;command('sh','-c','cat > '+path,data=value,purpose='native-configuration-write')
  require(raw(path)==value,'Native write/readback mismatch');row.update(completed=True,finishedAt=NOW());save(out/'operations.json',ops)
 def reload(service,label):
  row=dict(operation='reload',service=service,label=label,startedAt=NOW(),completed=False);ops.append(row);save(out/'operations.json',ops)
  result=command('/opt/reference-idp/bin/reload-service.sh','-id',service,'-u','http://localhost:8080/idp',purpose='native-service-reload');(receipt/(label+'-reload.txt')).write_bytes(result.stdout)
  row.update(completed=True,finishedAt=NOW());save(out/'operations.json',ops)
 def state(label,epoch,active):
  start=NOW();runtime=native.runtime();require(runtime==initial_runtime,'Native runtime changed')
  files={}
  for name,path in {'global':'/opt/reference-idp/conf/global.xml','services':'/opt/reference-idp/conf/services.xml','relying-party':RP,'providers':PROVIDERS,'web':'/usr/local/tomcat/webapps/idp/WEB-INF/web.xml'}.items():
   value=public_xml(raw(path));file='state-'+label+'-'+name+'.xml';(receipt/file).write_bytes(value);files[path]=dict(file=file,sha256=SHA(value))
  classpath=command('sh','-c','sha256sum /usr/local/tomcat/webapps/idp/WEB-INF/lib/*.jar').stdout.decode().splitlines();pins={row.split()[1]:row.split()[0] for row in classpath};require(pins==classpath_pins,'Native classpath changed')
  overrides=command('sh','-c','for d in /usr/local/tomcat/webapps/idp/WEB-INF/classes /opt/reference-idp/system /opt/reference-idp/flows; do if test -d "$d"; then find "$d" -type f; fi; done').stdout.decode().splitlines()
  require(not any(p.startswith('/usr/local/tomcat/') or p.startswith('/opt/reference-idp/system/') or '/SAML2/' in p or '/saml/' in p for p in overrides),'Endpoint/source override not qualified')
  properties=command('sh','-c','find /opt/reference-idp/conf -type f -name "*.properties" -exec sha256sum {} +; sha256sum /opt/reference-idp/credentials/secrets.properties').stdout.decode().splitlines();properties={row.split()[1]:row.split()[0] for row in properties}
  selected={}
  for path in properties:
   for line in raw(path).decode().splitlines():
    line=line.strip()
    if not line or line.startswith(('#','!')) or '=' not in line:continue
    key,value=map(str.strip,line.split('=',1))
    if key in ['idp.additionalProperties','idp.webflows','idp.entityID.metadataFile','idp.service.relyingparty.resources'] or key.startswith('idp.profile.'):
     require(key not in selected,'Duplicate native property');selected[key]=value
  require(set(selected)<= {'idp.additionalProperties'} and selected.get('idp.additionalProperties','/credentials/secrets.properties')=='/credentials/secrets.properties','Unknown endpoint/profile property override')
  processes=command('sh','-c','for f in /proc/[0-9]*/cmdline; do tr "\\000" " " < "$f"; printf "\\n"; done').stdout.decode();java=[x for x in processes.splitlines() if 'org.apache.catalina.startup.Bootstrap' in x and 'tr ' not in x];require(len(java)==1,'Native server process ambiguous')
  environment=json.loads(subprocess.run(['docker','inspect',CONTAINER],capture_output=True,check=True,timeout=20).stdout)[0]['Config'].get('Env',[]);private_scope='\n'.join(java+environment)
  process_scope=dict(nativeJavaProcessObserved=True,endpointOverridePresent=bool(re.search(r'-Didp\.(?:profile\.|webflows|entityID\.metadataFile|service\.relyingparty\.resources|additionalProperties)',private_scope)),customAgentPresent='-javaagent' in private_scope,privateFieldsExported=False)
  require(not process_scope['endpointOverridePresent'] and not process_scope['customAgentPresent'],'Native process endpoint override not qualified')
  profiles={};peer=None
  if active:
   for name,profile in PROFILES.items():
    cmd=['/opt/reference-idp/bin/dumpconfig.sh','-u','http://localhost:8080/idp','--saml2','-r',entity,'-P',profile];value=command(*cmd,purpose='native-selected-profile-readback').stdout
    parsed=json.loads(value);require(set(parsed)=={'RelyingPartyConfiguration','ProfileConfiguration'} and parsed['ProfileConfiguration'].get('id')==profile,'Native selected profile differs')
    require(all(isinstance(v,(str,bool,int)) and not re.search('password|secret|cookie|token|private|credential',k,re.I) for g in parsed.values() for k,v in g.items()),'Private selected profile refused')
    file='state-'+label+'-'+name+'-profile.json';(receipt/file).write_bytes(value);profiles[name]=dict(file=file,sha256=SHA(value),command=cmd)
   cmd=native.query_command(entity);peer=command(*cmd,purpose='native-loaded-peer-readback').stdout;require(ET.fromstring(peer).get('entityID')==entity,'Native selected peer differs')
   file='state-'+label+'-selected-peer.xml';(receipt/file).write_bytes(peer);peer=dict(file=file,sha256=SHA(peer),command=cmd)
  value=dict(schema='samlscope-shibboleth-public-publisher-state-v1',entityId=TARGET,peerEntityId=entity,runtime=runtime,configurationFiles=files,classpathSha256=pins,sourceOverrides=overrides,propertiesSha256=properties,selectedProperties=selected,processScope=process_scope,selectedProfiles=profiles,selectedPeer=peer,temporaryPresent=command('test','-e',temporary,check=False).returncode==0)
  file='state-'+label+'.json';data=canonical(value);(receipt/file).write_bytes(data);record(label,'native-role-inventory',epochId=epoch,adapter=ADAPTER,readbackFile=file,readbackSha256=SHA(data),runtime=runtime,nativeStartedAt=start,nativeFinishedAt=NOW());return value
 initial_runtime=native.runtime();original={PROVIDERS:public_xml(raw(PROVIDERS)),RP:public_xml(raw(RP))};expected.update(original)
 classpath_pins={row.split()[1]:row.split()[0] for row in command('sh','-c','sha256sum /usr/local/tomcat/webapps/idp/WEB-INF/lib/*.jar').stdout.decode().splitlines()}
 jars=receipt/'native-source';jars.mkdir();archive=REPO/'build/acceptance/reference-20261001/shibboleth-subject-confirmation-v184-r4/native-jars'
 for name in ['idp-conf-impl','idp-profile-impl','idp-admin-impl','idp-saml-api','idp-saml-impl','opensaml-saml-impl','opensaml-saml-api']:
  path='/usr/local/tomcat/webapps/idp/WEB-INF/lib/'+name+'-5.2.3.jar';source=archive/(name+'.jar');require(SHA(source.read_bytes())==classpath_pins[path],'Native archive differs');shutil.copy2(source,jars/(name+'.jar'))
 with zipfile.ZipFile(jars/'idp-conf-impl.jar') as z:
  for name in SOURCE_ENTRIES:(jars/pathlib.Path(name).name).write_bytes(z.read(name))
 plan=api('/api/plans',dict(name='Shibboleth actual native publisher endpoint inventory',profile='metadata_idp',targetKind='IDP',targetEntityId=TARGET,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint='One shared native publisher baseline',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',plan);pid=identifier(plan['plan']['plan']['id'],'plan');entity=BASE+'/p/'+pid
 created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=identifier(created['run']['id'],'run');require(created['run']['planId']==pid,'Foreign Run/Plan binding');save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}));target=subprocess.run(['docker','exec',SUITE,'cat','/data/target-metadata/'+run+'.xml'],capture_output=True,check=True,timeout=30).stdout
 (receipt/'target-metadata.xml').write_bytes(target);(out/'target-metadata.xml').write_bytes(target);approved,digests=approved_case(CASE,REPO)
 require(approved['mode']=='CONFIG' and approved['role']=='idp','Approved native publisher case differs')
 api_digest=subprocess.check_output(['docker','exec',SUITE,'sha256sum','/opt/samlscope/lib/api-0.1.0.jar'],timeout=30).decode().split()[0]
 runtime_api=out/'deployed-api.jar';subprocess.run(['docker','cp',SUITE+':/opt/samlscope/lib/api-0.1.0.jar',str(runtime_api)],capture_output=True,check=True);require(SHA(runtime_api.read_bytes())==api_digest,'Deployed scope archive changed')
 with zipfile.ZipFile(runtime_api) as z:profile=z.read('profiles/metadata_idp.json')
 (receipt/'planned-profile.json').write_bytes(profile);slots=[x for x in json.loads(profile)['cases'] if x['id']==CASE];require(len(slots)==1 and slots[0]['digest']==approved['case_digest'],'Actual approved case is not deployed')
 save(out/'planned-scope.json',dict(runId=run,caseId=CASE,caseDigest=approved['case_digest'],deployedApiSha256=api_digest,catalogDigests=digests,targetMetadataSha256=SHA(target)))
 with urllib.request.urlopen(entity+'/metadata',timeout=30) as r:fixture=public_xml(r.read())
 (receipt/'fixture.xml').write_bytes(fixture);temporary='/opt/reference-idp/metadata/publisher-endpoint-'+run+'.xml'
 ET.register_namespace('',N);ET.register_namespace('xsi',XSI)
 tree=ET.fromstring(original[PROVIDERS]);tree.insert(0,ET.Element('{'+N+'}MetadataProvider',{'id':'PublisherEndpoint'+run,'{'+XSI+'}type':'FilesystemMetadataProvider','metadataFile':temporary}));configured=public_xml(ET.tostring(tree,encoding='utf-8',xml_declaration=True));configured_rp=peer_override(original[RP],entity)
 client=native.M0Client();baseline=None;epoch=None
 try:
  initial=state('initial','initial',False);publication('initial')
  start=NOW();write(temporary,fixture,'register-peer');write(PROVIDERS,configured,'register-providers');write(RP,configured_rp,'register-peer-signing');reload('shibboleth.MetadataResolverService','apply-metadata');reload('shibboleth.RelyingPartyResolverService','apply-profile');end=NOW()
  record('transition','native-configuration-transition',epochId='stock-selected-peer',configurationPurpose='same-run-peer-registration-and-signed-baseline',nativeStartedAt=start,nativeFinishedAt=end)
  before=state('before','stock-selected-peer',True);from_time=NOW();pubfile,pub=publication('selected');record('publication','native-publication',epochId='stock-selected-peer',**pub)
  ids={e['id'] for e in api('/api/runs/'+run+'/transcript')};start=NOW();result=client.flow(entity+'/start/m0-roundtrip?run='+run,None,os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'));end=NOW()
  history=api('/api/runs/'+run+'/transcript');requests=[e for e in history if e['id'] not in ids and e['direction']=='OUTBOUND' and e['samlSummary'].get('type')=='AuthnRequest'];require(result=='recorded' and len(requests)==1,'One native baseline request was not completed')
  request=requests[0];responses=[e for e in history if e['id'] not in ids and e['direction']=='INBOUND' and e['samlSummary'].get('type')=='Response' and e['samlSummary'].get('inResponseTo')==request['samlSummary']['id']];require(len(responses)==1,'Native baseline response ambiguous');response=responses[0]
  baseline=dict(requestReference=request['id'],responseReference=response['id'],nativeStartedAt=start,nativeFinishedAt=end,fixtureFile='fixture.xml');record('baseline','native-peer-baseline',epochId='stock-selected-peer',**baseline);until=NOW();after=state('after','stock-selected-peer',True)
  epoch=dict(id='stock-selected-peer',startedAt=from_time,finishedAt=until,beforeOriginal='before',afterOriginal='after',publicationOriginal='publication',publicationFile=pubfile,transition='explicit-native-peer-registration',transitionOriginal='transition',baselineOriginal='baseline')
  save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}));save(out/'result-before.json',api('/api/runs/'+run+'/result.json'));preflight=scope_preflight(CASE,out/'result-before.json');save(out/'formal-slot-preflight.json',preflight);require(preflight['scope_ready'],'Formal approved case scope is unavailable')
 except Exception as e:failed=type(e).__name__;save(out/'failure.json',dict(exceptionClass=failed))
 finally:
  if RP in touched:write(RP,original[RP],'restore-profile');reload('shibboleth.RelyingPartyResolverService','restore-profile')
  if PROVIDERS in touched:write(PROVIDERS,original[PROVIDERS],'restore-providers');reload('shibboleth.MetadataResolverService','restore-metadata')
  if temporary in touched:
   require(raw(temporary)==fixture,'Owned native source changed before cleanup');command('rm','--',temporary,purpose='owned-native-source-removal');require(command('test','-e',temporary,check=False).returncode==1,'Owned source remains');ops.append(dict(operation='remove',label='restore-peer',path=temporary,completed=True,finishedAt=NOW()));save(out/'operations.json',ops)
  restored=state('restored','restored',False);restored_file,restored_pub=publication('restored');require(all(raw(p)==v for p,v in original.items()) and native.runtime()==initial_runtime,'Native restoration failed')
  counts=dict(productSettings=sum(x['operation']=='write' and not x['label'].startswith('restore-') for x in ops),configurationRestorations=sum(x['operation']=='write' and x['label'].startswith('restore-') for x in ops),metadataReloads=sum(x['operation']=='reload' for x in ops),nativePublicCalls=len(commands),credentialPosts=client.credential_posts,samlSubmissions=client.saml_attempts,personOperations=0,productRestarts=0)
  record('restoration','native-publisher-restoration',restored=True,restoredPublicationFile=restored_file,restoredPublicationSha256=SHA(target),operationCounts=counts,temporaryPath=temporary);save(out/'operation-counts.json',counts|dict(restored=True))
  entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
  manifest=dict(schema='samlscope-native-metadata-publisher-key-inventory-v1',campaignId=CAMPAIGN,adapter=ADAPTER,runId=run,planId=pid,entityId=TARGET,peerEntityId=entity,targetMetadataSha256=SHA(target),recorderUrl=entity+'/sp/paos?run='+run,selectedPath='stock-current-role',counterfactualCalibrationOnly=False,epochs=[] if epoch is None else [epoch],originals=refs,baseline=baseline)
  manifest['files']={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file()};save(receipt/'manifest.json',manifest)
 if failed:raise ValueError('Native campaign failed and restoration completed; public failure originals retained')
 print('Native publisher epoch captured and restored; no conformance outcome assigned')
if __name__=='__main__':main()
