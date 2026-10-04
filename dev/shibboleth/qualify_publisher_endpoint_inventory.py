#!/usr/bin/env python3
"""Capture isolated native builder controls; never change the running IdP configuration."""
import argparse, datetime, hashlib, importlib.util, json, pathlib, re, shutil, subprocess, sys, xml.etree.ElementTree as ET
REPO=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'));sys.path.insert(0,str(REPO/'dev/keycloak'))
from algorithm_preference_campaign import recorded, canonical
from capture_run_originals import capture
spec=importlib.util.spec_from_file_location('publisher_m0',REPO/'dev/shibboleth/full_ui_metadata_campaign.py');native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native)
SHA=lambda b:hashlib.sha256(b).hexdigest();NOW=lambda:datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
def require(ok,why):
 if not ok:raise ValueError(why)
def save(p,v):
 require(not p.exists(),'Immutable output exists');p.write_bytes(canonical(v))
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=pathlib.Path);a=p.parse_args();out=a.folder.absolute();require(not any(x.is_symlink() for x in [out,*out.parents]),'Unsafe evidence root');out=out.resolve();receipt=out/'receipt';require(not receipt.is_symlink() and not any(x.is_symlink() for x in receipt.rglob('*')),'Unsafe input originals');m=json.loads((receipt/'manifest.json').read_bytes());created=json.loads((out/'created.json').read_bytes());run=m['runId']
 require(isinstance(run,str) and re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run),'Unsafe native helper identity')
 require(isinstance(m['planId'],str) and re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',m['planId']),'Unsafe Suite Plan identity')
 require(m['adapter']=='shibboleth-stock-publisher-endpoints-v1' and created['run']['id']==run and created['run']['planId']==m['planId'],'Wrong native campaign');require('controls' not in m,'Native controls already captured')
 before=json.loads((receipt/'state-before.json').read_bytes());runtime=native.runtime();require(runtime==before['runtime'],'Native runtime differs from selected epoch')
 libs=receipt/'native-libraries'
 if not libs.exists():
  libs.mkdir();subprocess.run(['docker','cp',native.CONTAINER+':/usr/local/tomcat/webapps/idp/WEB-INF/lib/.',str(libs)],check=True,capture_output=True,timeout=90)
 pins=before['classpathSha256'];require({p.name:SHA(p.read_bytes()) for p in libs.iterdir()}=={pathlib.Path(k).name:v for k,v in pins.items()},'Copied native classpath differs')
 target=ET.fromstring((receipt/'target-metadata.xml').read_bytes());fixture=ET.fromstring((receipt/'fixture.xml').read_bytes());MD='{urn:oasis:names:tc:SAML:2.0:metadata}';DS='{http://www.w3.org/2000/09/xmldsig#}'
 role=target.find(MD+'IDPSSODescriptor');keys={}
 for purpose,use in [('signing','signing'),('encryption','encryption')]:
  rows=[x for x in role.findall(MD+'KeyDescriptor') if x.get('use')==use];require(rows,'Native public key unavailable');keys[purpose]=''.join(rows[-1].find('.//'+DS+'X509Certificate').text.split())
 keys['transport-authentication']=''.join(fixture.find('.//'+DS+'X509Certificate').text.split())
 endpoint=role.find(MD+'SingleSignOnService');value=dict(schema='samlscope-shibboleth-publisher-control-input-v1',purpose='oracle-calibration-only',entityId=m['entityId'],roleKeys=[dict(purpose=k,certificateDerBase64=v) for k,v in keys.items()],endpoints=[dict(kind='SingleSignOnService',binding=endpoint.get('Binding'),location=endpoint.get('Location'))])
 controls=receipt/'controls';controls.mkdir();save(controls/'input.json',value);source=REPO/'dev/shibboleth/ObserveShibbolethPublisherControls.java';shutil.copyfile(source,controls/source.name)
 owned='/tmp/samlscope-publisher-controls-'+run;require(subprocess.run(['docker','exec',native.CONTAINER,'test','-e',owned],capture_output=True).returncode==1,'Owned helper path exists');operations=[]
 def command(args,purpose):
  row=dict(purpose=purpose,command=args,startedAt=NOW(),runtimeBefore=native.runtime());operations.append(row)
  r=subprocess.run(args,capture_output=True,timeout=90);row.update(finishedAt=NOW(),exitCode=r.returncode,runtimeAfter=native.runtime())
  require(r.returncode==0,'Native control subprocess failed: '+r.stderr.decode()[-1500:]);return r
 env=['env','-u','JAVA_OPTS','-u','SHIB_OPTS','-u','CLASSPATH','-u','JAVA_TOOL_OPTIONS','-u','JDK_JAVA_OPTIONS']
 try:
  subprocess.run(['docker','exec',native.CONTAINER,'mkdir',owned],check=True,capture_output=True)
  for name in ['input.json',source.name]:subprocess.run(['docker','cp',str(controls/name),native.CONTAINER+':'+owned+'/'+name],check=True,capture_output=True)
  cp='/usr/local/tomcat/webapps/idp/WEB-INF/lib/*'
  command(['docker','exec',native.CONTAINER,*env,'javac','--release','17','-sourcepath','','-cp',cp,'-d',owned+'/classes',owned+'/'+source.name],'compile-native-control')
  command(['docker','exec',native.CONTAINER,*env,'java','-cp',owned+'/classes:'+cp,'ObserveShibbolethPublisherControls',owned+'/input.json',owned+'/output'],'execute-native-control')
  subprocess.run(['docker','cp',native.CONTAINER+':'+owned+'/output/.',str(controls)],check=True,capture_output=True)
 finally:
  subprocess.run(['docker','exec',native.CONTAINER,'rm','-rf','--',owned],check=True,capture_output=True)
  require(subprocess.run(['docker','exec',native.CONTAINER,'test','-e',owned],capture_output=True).returncode==1,'Owned helper cleanup failed')
  save(controls/'attempt-operations.json',dict(invocations=operations,ownedHelperRemoved=True,productSettings=0,samlSubmissions=0,credentialPosts=0,personOperations=0))
 require(native.runtime()==runtime,'Native runtime changed during isolated control');save(controls/'invocations.json',operations)
 observation=json.loads((controls/'observation.json').read_bytes());require(observation['productVersion']=='5.2.3','Native product version differs')
 def record(label,kind,**fields):
  value=dict(schema='samlscope-native-publisher-original-v1',kind=kind,runId=run,campaignId=m['campaignId'],targetMetadataSha256=m['targetMetadataSha256'],recordedAt=NOW(),**fields)
  ref=recorded(receipt,created,value,label);ref['file']='native-originals/'+label+'.json';m['originals'][label]=ref
 record('controls','native-publisher-detector-control',purpose='oracle-calibration-only',positiveControlIds=['iip-md05-c1-idp-01-positive'],negativeControlIds=['iip-md05-c1-idp-01-negative'],inputSha256=SHA((controls/'input.json').read_bytes()),positiveOutputSha256=SHA((controls/'positive.xml').read_bytes()),negativeOutputSha256=SHA((controls/'negative.xml').read_bytes()),sourceSha256=SHA(source.read_bytes()),invocationsSha256=SHA((controls/'invocations.json').read_bytes()),observationSha256=SHA((controls/'observation.json').read_bytes()),nativeClasspathSha256=pins,ownedHelperRemoved=True)
 shutil.copyfile(out/'operations.json',receipt/'operations.json');shutil.copyfile(out/'operation-counts.json',receipt/'operation-counts.json');shutil.copyfile(out/'publication-reads.json',receipt/'publication-reads.json')
 record('operations','native-publisher-operation-ledger',operationsSha256=SHA((receipt/'operations.json').read_bytes()),countsSha256=SHA((receipt/'operation-counts.json').read_bytes()),publicationReadsSha256=SHA((receipt/'publication-reads.json').read_bytes()),isolatedNativeControlExecutions=1,isolatedNativeControlCompilations=1,productSettings=0,samlSubmissions=0,credentialPosts=0,personOperations=0)
 m['controls']=dict(original='controls',inputFile='controls/input.json',positiveOutputFile='controls/positive.xml',negativeOutputFile='controls/negative.xml',sourceFile='controls/'+source.name,invocationsFile='controls/invocations.json',observationFile='controls/observation.json')
 from algorithm_preference_campaign import api
 entries=api('/api/runs/'+run+'/transcript');(out/'transcript.json').write_bytes(canonical(entries));capture(out,run,entries)
 m['files']={str(p.relative_to(receipt)):SHA(p.read_bytes()) for p in receipt.rglob('*') if p.is_file() and p.name!='manifest.json'};(receipt/'manifest.json').write_bytes(canonical(m))
 save(out/'native-controls-qualification.json',dict(runId=run,nativeProductVersion='5.2.3',nativeLibraryCount=len(pins),nativeBuilderExecutions=1,nativeCompilations=1,ownedHelperRemoved=True,productSettings=0,samlSubmissions=0,credentialPosts=0,personOperations=0))
 print('Native controls and original operation ledger captured; product settings unchanged')
if __name__=='__main__':main()
