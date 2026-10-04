#!/usr/bin/env python3
"""Native MDIOP admission matrix, with one baseline SSO and exact configuration restoration.

The product's own parser validates the original XML and creates its native SP metadata.
Admission says nothing about later key use, certificate trust or signature enforcement.
"""
import argparse,base64,hashlib,json,os,subprocess,sys,time,urllib.request,xml.etree.ElementTree as ET
from datetime import datetime,timezone
from pathlib import Path
from persistent_nameid_normal_campaign import REPO,CONTAINER,IDP,api,save,BASE,native,batch,raw,settled
from metadata_replacement_campaign import arm,READBACK
from keyvalue_runtime_campaign import KeyValueClient,inspect_identity
from consent_ui_campaign import sanitized
from import_metadata_batch import flow
sys.path.insert(0,str(REPO/'dev/keycloak'))
from algorithm_preference_campaign import recorded
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_run_originals import capture
from verify_mdiop_acceptance import REQUIRED_FIXTURES
REQUIRED=['control']+sorted(REQUIRED_FIXTURES)
PHP=native.PHP.replace("'php'=>'$metadata[", "'metadata'=>$metadata,'php'=>'$metadata[")
SOURCES={'parser':'src/SimpleSAML/Metadata/SAMLParser.php','metadata-handler':'src/SimpleSAML/Metadata/MetaDataStorageHandler.php',
 'flatfile':'src/SimpleSAML/Metadata/MetaDataStorageSource.php','xml':'src/SimpleSAML/Utils/XML.php'}
def sha(value):return hashlib.sha256(value).hexdigest()
def now():return datetime.now(timezone.utc).isoformat()
def encoded(raw):return dict(base64=base64.b64encode(raw).decode(),sha256=sha(raw))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
 remote=batch('saml20-sp-remote.php');original=settled(remote.container_path,remote.original);(out/'original-sp-config.php').write_bytes(original)
 commands=dict(parser=PHP,readback=READBACK);sources={label:raw('/var/simplesamlphp/'+path) for label,path in SOURCES.items()}
 for label,value in sources.items():(out/('native-'+label+'.php')).write_bytes(value)
 for label,value in commands.items():(out/('native-'+label+'-command.php')).write_text(value)
 (out/'collector.py').write_bytes(Path(__file__).read_bytes());identity=inspect_identity();save(out/'identity-before.json',identity)
 run=None;operations=[];members=[];counts=dict(nativeParserInvocations=0,protocolOperationsAttempted=0,nativeOriginalRecorderWrites=0)
 records=[];responses={};requests={}
 credentials=(os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
 try:
  plan=api('/api/plans',dict(name='SimpleSAMLphp complete native MDIOP admission',profile='metadata_idp',targetKind='IDP',targetEntityId=IDP,metadataSourceKind='URL',metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,testUserHint=credentials[0],requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True));save(out/'plan.json',plan);pid=plan['plan']['plan']['id'];entity=BASE+'/p/'+pid
  if entity.encode() in original:raise ValueError('Fresh entity already configured')
  created=api('/api/plans/'+pid+'/runs',{});save(out/'created.json',created);run=created['run']['id'];save(out/'preflight.json',api('/api/runs/'+run+'/preflight',{}))
  subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+run+'.xml',str(out/'target-metadata.xml')],check=True,capture_output=True);targetHash=sha((out/'target-metadata.xml').read_bytes())
  def record(value,label):
   counts['nativeOriginalRecorderWrites']+=1;return recorded(out,created,dict(schema='samlscope-ssp-mdiop-native-original-v1',runId=run,targetEntityId=IDP,targetMetadataSha256=targetHash,**value),label)
  beforeRef=record(dict(kind='baseline',recordedAt=now(),configuration=encoded(original),runtime=identity,sources={k:encoded(v) for k,v in sources.items()},commands=commands,collectorSha256=sha((out/'collector.py').read_bytes())),'baseline')
  save(out/'campaign.json',api('/api/runs/'+run+'/metadata-lab/automatic-polling',dict(variants=REQUIRED,pollingDelaySeconds=0)))
  controls=[]
  for variant in REQUIRED:
   folder=out/variant;folder.mkdir();row=dict(variant=variant,status='incomplete',startedAt=now());operations.append(row);save(out/'operations.json',operations)
   state,fixture=arm(run,folder,variant);counts['nativeParserInvocations']+=1
   parsed=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',PHP,entity,'default'],input=fixture,capture_output=True,timeout=30)
   (folder/'parser.stdout').write_bytes(parsed.stdout);(folder/'parser.stderr').write_bytes(parsed.stderr);row['parserReturncode']=parsed.returncode;save(out/'operations.json',operations)
   if parsed.returncode:raise ValueError('Native representation not admitted; no verdict')
   conversion=json.loads(parsed.stdout);remote.apply(conversion['php'].encode());time.sleep(3);installed=settled(remote.container_path,remote.expected)
   readback=subprocess.check_output(['docker','exec',CONTAINER,'php','-r',READBACK,entity],timeout=30);(folder/'configuration.php').write_bytes(installed);(folder/'readback.json').write_bytes(readback)
   memberRef=record(dict(kind='admission',variant=variant,peerEntityId=entity,fixtureSha256=sha(fixture),parser=dict(returncode=parsed.returncode,input=encoded(fixture),stdout=encoded(parsed.stdout),stderr=encoded(parsed.stderr)),configuration=encoded(installed),readback=encoded(readback),recordedAt=now()),variant+'-admission')
   members.append(dict(variant=variant,fixtureSha256=sha(fixture),native=memberRef))
   if variant=='control':
    for label,mutated,lookup in [('missing-sp-role',ET.tostring(ET.Element('{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor',dict(entityID=entity))),entity),('foreign-entity',fixture,entity+'/foreign')]:
     counts['nativeParserInvocations']+=1;negative=subprocess.run(['docker','exec','-i',CONTAINER,'php','-r',PHP,lookup,'default'],input=mutated,capture_output=True,timeout=30)
     control=record(dict(kind='parser-control',control=label,peerEntityId=entity,lookupEntityId=lookup,fixtureSha256=sha(fixture),input=encoded(mutated),returncode=negative.returncode,stdout=encoded(negative.stdout),stderr=encoded(negative.stderr),recordedAt=now()),label)
     controls.append(dict(control=label,native=control));save(folder/(label+'.json'),dict(returncode=negative.returncode,inputSha256=sha(mutated)))
     if negative.returncode==0:raise ValueError('Native parser negative control did not reject')
    counts['protocolOperationsAttempted']+=2
    flow(run,folder/'flow.json',suite_signature_control=True,login_inputs=credentials,client_factory=lambda **kw:KeyValueClient(records,responses,requests));save(out/'tests-start.json',api('/api/runs/'+run+'/tests/start',{}))
   else:
    pending=api('/api/runs/'+run+'/metadata-lab')
    if pending['campaignIndex']!=state['campaignIndex']:raise ValueError('Admission-only operation unexpectedly advanced')
    with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'],data=b''),timeout=30) as response:response.read()
    row['orchestrationAdvancedWithoutProductVerdict']=True
   row.update(status='native-admitted',completedAt=now());save(out/'operations.json',operations);print(variant+' native admission recorded',flush=True)
 finally:
  restoration=remote.restore();final=settled(remote.container_path,original);(out/'final-sp-config.php').write_bytes(final);save(out/'restoration.json',restoration);after=inspect_identity();save(out/'identity-after.json',after)
  counts.update(productConfigurationWriteAttempts=remote.write_count,configurationApplyWrites=remote.applied_count,restorationWrites=remote.restoration_writes,runCreations=int(run is not None),productRestarts=0,humanOperations=0,runtimeKeyInterpretationProven=False,restored=restoration['restored'] and final==original and after==identity);save(out/'operation-counts.json',counts)
  if run:
   finalRef=record(dict(kind='restoration',recordedAt=now(),configuration=encoded(final),runtime=after,sources={k:encoded(raw('/var/simplesamlphp/'+path)) for k,path in SOURCES.items()},restored=restoration['restored']),'restoration')
   # Public native HTTP controls contain no cookies, credentials or login-state tokens.
   http=out/'native-http-originals';http.mkdir()
   for item in records:
    ident=item['request_id'];body=sanitized(responses[ident].decode(),None).encode();(http/(ident+'.html')).write_bytes(body);item['persisted_body_sha256']=sha(body);item['body_sanitized']=body!=responses[ident]
    xml,body=requests[ident];(http/(ident+'.request.xml')).write_bytes(xml);(http/(ident+'.request.body')).write_bytes(body)
   save(out/'native-http-observations.json',dict(runId=run,records=records,productVerdictAssigned=False))
   entries=api('/api/runs/'+run+'/transcript');save(out/'transcript.json',entries);capture(out,run,entries)
   for member in members:
    prepared=[e for e in entries if e['samlSummary'].get('type')=='MetadataPrepared' and e['samlSummary'].get('variant')==member['variant'] and e['samlSummary'].get('metadataSha256')==member['fixtureSha256']]
    if len(prepared)!=1:raise ValueError('Prepared native original ambiguous')
    member['preparedReference']=prepared[0]['id']
   if len(members)==len(REQUIRED) and counts['restored']:
    save(out/'qualified-receipt.json',dict(schema='samlscope-ssp-mdiop-representation-v1',adapter='ssp-native-parser-admission-v1',runId=run,campaignId='metadata-fixture-refresh',targetEntityId=IDP,targetMetadataSha256=targetHash,members=members,parserControls=controls,baseline=beforeRef,restoration=finalRef))
   try:save(out/'result-before.json',api('/api/runs/'+run+'/result.json'))
   except RuntimeError:pass
  save(out/'operation-counts.json',counts)
  if not counts['restored']:raise ValueError('Native restoration incomplete')
 print(run+' complete native matrix restored; no verdict adopted',flush=True)
if __name__=='__main__':main()
