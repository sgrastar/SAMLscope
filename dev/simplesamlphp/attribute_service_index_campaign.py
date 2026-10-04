#!/usr/bin/env python3
"""Native attribute-service index 0/1/0 experiment, one login and exact restoration.

Original Suite metadata is passed to the installed native parser. Native standard
filters supply the controlled surname and OID mapping; no Suite XML conversion
or authentication-source credential change is performed. Native state remains
in memory and only sanitized public transport originals are persisted.
"""
import argparse,json,os,subprocess,time,urllib.request
from pathlib import Path
from transient_allow_create_campaign import REPO,CONTAINER,IDP,PREFIX,api,save,BASE,native,batch,raw,settled,ConfigurationBatch,SOURCES as BASE_SOURCES,STATE,NativeClient,SESSION,sha,now,inspect_identity
from subject_confirmation_campaign import POLICY as BASE_POLICY
from metadata_replacement_campaign import arm
from import_metadata_batch import flow
from native_ui_privacy import sanitized,contains_state_secret
from capture_run_originals import capture
SOURCES={**BASE_SOURCES,'attribute-add':'modules/core/src/Auth/Process/AttributeAdd.php','attribute-map':'modules/core/src/Auth/Process/AttributeMap.php','name2oid-map':'attributemap/name2oid.php'}
POLICY=BASE_POLICY.replace("echo json_encode([", "$users=[];foreach($a['users']??[] as $key=>$attrs){$parts=explode(':',$key,2);if(count($parts)!==2)throw new \\RuntimeException('Invalid native principal');$users[]=['principal'=>$parts[0],'uid'=>$attrs['uid']??null];}\necho json_encode(['publicPrincipals'=>$users,'credentialsExcluded'=>true,")
FILTERS="\n$metadata[%s]['authproc'] = [40=>['class'=>'core:AttributeAdd','sn'=>'samlscope-reference-surname'],45=>['class'=>'core:AttributeMap','name2oid']];"
def configuration(data,entity):return data['php'].encode()+(FILTERS%repr(entity)).encode()
def readback(out,label,configs,entity,client=None):
 f=out/label;f.mkdir()
 for name,c in configs.items():(f/(name+'.php')).write_bytes(settled(c.container_path,c.expected))
 (f/'policy.json').write_bytes(subprocess.check_output(['docker','exec',CONTAINER,'php','-r',POLICY,IDP,entity],timeout=30));save(f/'observed.json',dict(recordedAt=now()))
 if client is not None:
  cookies={c.name:c.value for c in client.jar if c.domain in ['localhost.local','localhost','127.0.0.1']}
  r=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',SESSION],input=json.dumps(dict(cookies=cookies,entity=IDP)).encode(),capture_output=True,timeout=30)
  if r.returncode:raise ValueError('Native public authenticated session unavailable')
  (f/'session.json').write_bytes(r.stdout)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 remote=batch('saml20-sp-remote.php');hosted=batch('saml20-idp-hosted.php');override=ConfigurationBatch(PREFIX/'config-override.php');override.container_path='/var/simplesamlphp/config/config-override.php';configs=dict(remote=remote,hosted=hosted,override=override)
 for name,c in configs.items():
  if raw(c.container_path)!=c.original:raise ValueError('Native configuration not restored at campaign entry')
  (out/(name+'-original.php')).write_bytes(c.original)
 for name,path in SOURCES.items():(out/('native-'+name+'.php')).write_bytes(raw('/var/simplesamlphp/'+path))
 for name,value in [('policy',POLICY),('session',SESSION),('state',STATE),('parser',native.PHP)]:(out/('native-'+name+'-command.php')).write_text(value)
 for name,file in [('collector.py',Path(__file__)),('native-client-collector.py',Path(__file__).with_name('subject_confirmation_campaign.py')),('native-http-client.py',Path(__file__).with_name('keyvalue_runtime_campaign.py')),('native-ui-privacy.py',Path(__file__).with_name('native_ui_privacy.py'))]:(out/name).write_bytes(file.read_bytes())
 save(out/'identity-before.json',inspect_identity());records=[];responses={};requests={};states=[];client=NativeClient(records,responses,requests,states);run=None;parsers=protocol=0;operations=[]
 credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
 try:
  plan=api('/api/plans',dict(name='SimpleSAMLphp native attribute-service selector',profile='browser_sso_idp',targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];entity=BASE+'/p/'+pid
  created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
  save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['control'],pollingDelaySeconds=0)));f=out/'control';f.mkdir();state,fixture=arm(run,f,'control');parsers+=1
  parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=30);(f/'parser.stdout').write_bytes(parsed.stdout);(f/'parser.stderr').write_bytes(parsed.stderr)
  if parsed.returncode:raise ValueError('Native baseline import failed')
  remote.apply(configuration(json.loads(parsed.stdout),entity));time.sleep(3);readback(out,'control-before',configs,entity);protocol+=2;flow(run,f/'flow.json',suite_signature_control=True,login_inputs=credentials,client_factory=lambda **kw:client);readback(out,'control-after',configs,entity,client);save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
  installed=None
  for index,selector in enumerate([0,1,0]):
   f=out/('index-'+str(index));f.mkdir();save(f/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=['attribute-policy-indexed'],pollingDelaySeconds=0)));state,fixture=arm(run,f,'attribute-policy-indexed')
   if installed is None:
    parsers+=1;parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',native.PHP,entity,'default'],input=fixture,capture_output=True,timeout=30);(f/'parser.stdout').write_bytes(parsed.stdout);(f/'parser.stderr').write_bytes(parsed.stderr)
    if parsed.returncode:raise ValueError('Native indexed metadata import failed')
    installed=configuration(json.loads(parsed.stdout),entity);remote.apply(installed);time.sleep(3)
   readback(out,'index-'+str(index)+'-before',configs,entity,client);protocol+=1;started=now();flow(run,f/'flow.json',attribute_service_index=selector,login_inputs=credentials,client_factory=lambda **kw:client);completed=now();readback(out,'index-'+str(index)+'-after',configs,entity,client)
   operations.append(dict(condition=['index-zero','index-one','index-zero-repeat'][index],selector=selector,flowStartedAt=started,flowCompletedAt=completed));save(out/'operations.json',operations)
 finally:
  restore={}
  for name,c in configs.items():restore[name]=c.restore();(out/(name+'-final.php')).write_bytes(settled(c.container_path,c.original))
  for name,path in SOURCES.items():(out/('native-'+name+'-after.php')).write_bytes(raw('/var/simplesamlphp/'+path))
  save(out/'restoration.json',restore);save(out/'identity-after.json',inspect_identity());save(out/'native-state-observations.json',dict(runId=run,observations=states));h=out/'native-http-originals';h.mkdir()
  for row in records:
   ident=row['request_id'];page=sanitized(responses[ident].decode(),None).encode()
   if contains_state_secret(page.decode()):raise ValueError('Native authentication state leaked')
   (h/(ident+'.html')).write_bytes(page);row['persisted_body_sha256']=sha(page);row['body_sanitized']=page!=responses[ident];xml,body=requests[ident];(h/(ident+'.request.xml')).write_bytes(xml);(h/(ident+'.request.body')).write_bytes(body)
  save(out/'native-http-observations.json',dict(runId=run,records=records,productVerdictAssigned=False));save(out/'operation-counts.json',dict(productConfigurationWriteAttempts=sum(c.write_count for c in configs.values()),configurationApplyWrites=sum(c.applied_count for c in configs.values()),restorationWrites=sum(c.restoration_writes for c in configs.values()),nativeParserInvocations=parsers,protocolOperationsAttempted=protocol,nativeSessionReadbacks=len(list(out.glob('*/session.json'))),runCreations=int(run is not None),credentialPosts=client.credentialPosts,productRestarts=0,humanOperations=0,restored=all(v['restored'] for v in restore.values())))
  if run:
   for suffix in ['result.json','protocol-evidence','transcript']:save(out/(suffix if '.' in suffix else suffix+'.json'),api('/api/runs/'+run+'/'+suffix))
   capture(out,run,json.loads((out/'transcript.json').read_bytes()));subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True)
  if not all(v['restored'] for v in restore.values()):raise ValueError('Native exact restoration failed')
 print(run,'native service selectors 0/1/0; restored; no adoption')
if __name__=='__main__':main()
