#!/usr/bin/env python3
"""Install only flat public originals for the Shibboleth six-input campaign."""
import argparse,hashlib,json,pathlib,subprocess
SHA=lambda b:hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=pathlib.Path);p.add_argument('--add-calibration',action='store_true');p.add_argument('--add-audit',action='store_true');a=p.parse_args();root=a.root.resolve();out=root/'receipt';out.mkdir(exist_ok=a.add_calibration or a.add_audit);files={}
 def copy(source,name):
  raw=source.read_bytes()
  if (out/name).exists():assert (out/name).read_bytes()==raw
  else:(out/name).write_bytes(raw)
  files[name]=SHA(raw)
 for phase in ['original','before-protocol','after-protocol','before-matrix','after-matrix','final']:
  for path in (root/phase).iterdir():copy(path,phase+'-'+path.name)
 for path in (root/'native-jars').iterdir():copy(path,'native-'+path.name)
 browser=root/'browser'
 for name in ['created.json','plan.json','original-providers.xml','configured-providers.xml','configured-providers-readback.xml','final-providers.xml','restoration.json','operation-counts.json','target-container-inspect-start.json','target-container-inspect-end.json']:copy(browser/name,name)
 for source,name in [('fixture.xml','control.fixture.xml'),('native-effective-sp-metadata.xml','native-effective-sp-metadata.xml'),('native-effective-sp-metadata-read.json','native-effective-sp-metadata-read.json')]:copy(browser/'control'/source,name)
 for name in ['matrix-sp-metadata.xml','matrix-sp-metadata-readback.xml','matrix-native-effective-sp-metadata.xml','matrix-native-effective-sp-read.json','normal-native-http-observations.json','matrix-native-http-observations.json','additional-operation-counts.json','steps.json','collector.py']:copy(root/name,name)
 if a.add_calibration or a.add_audit:
  for path in (root/'calibration').iterdir():
   if path.suffix in ['.xml','.java'] or path.name=='producer.json':copy(path,path.name)
 if a.add_audit:
  for source,name in [('audit-public.log','audit-public.log'),('observed.json','audit-public-observed.json'),('collector.py','audit-public-collector.py')]:copy(root/'native-audit-public'/source,name)
 http=json.loads((root/'normal-native-http-observations.json').read_bytes());rejected=next(x for x in http['records'] if x['nativeMessageSecurityError']);copy(browser/'control'/rejected['responseBodyFile'],'native-rejection.html')
 entries=json.loads((root/'transcript.json').read_bytes());flow=json.loads((browser/'control/flow.json').read_bytes());run=json.loads((browser/'created.json').read_bytes())['run']['id'];target=(browser/'target-metadata.xml').read_bytes()
 def ref(kind,corr=None):return next(e['id'] for e in entries if e['samlSummary'].get('type')==kind and (corr is None or e.get('correlationId')==corr))
 matrix=[]
 for step in json.loads((root/'steps.json').read_bytes()):
  if step.get('sentToTarget') is not True:continue
  req=next(e for e in entries if e['id'] in step['transcriptIds'] and e['samlSummary'].get('type')=='AuthnRequest');resp=next(e for e in entries if e['id'] in step['transcriptIds'] and e['samlSummary'].get('type')=='Response');matrix.append(dict(key=step['key'],requestReference=req['id'],responseReference=resp['id']))
 m=dict(schema='samlscope-shibboleth-transient-allow-create-v1',runId=run,campaignId='native-transient-allow-create',targetEntityId='http://localhost:18280/idp/shibboleth',targetMetadataSha256=SHA(target),fetchReference=ref('MetadataFetch'),metadataReference=ref('MetadataPrepared'),positiveRequestReference=ref('AuthnRequest',flow['positive_exchange']['request_id']),negativeRequestReference=ref('AuthnRequest',flow['negative_control']['exchange']['request_id']),positiveResponseReference=ref('Response',flow['positive_exchange']['request_id']),matrix=matrix,files=files)
 marker=root/(run+'.shibboleth-transient-allow-create.json')
 if a.add_calibration or a.add_audit:
  backup=root/(run+'.shibboleth-transient-allow-create.pre-'+('audit' if a.add_audit else 'calibration')+'.json');assert not backup.exists();backup.write_bytes(marker.read_bytes())
 marker.write_text(json.dumps(m,sort_keys=True,indent=2)+'\n');remote='/data/transient-allow-create-evidence/'+run+'.shibboleth-transient-allow-create';suite='samlscope-reference-suite'
 subprocess.run(['docker','exec',suite,'mkdir','-p','/data/transient-allow-create-evidence'],check=True,capture_output=True)
 if a.add_calibration or a.add_audit:
  for host in out.iterdir():subprocess.run(['docker','cp',str(host),suite+':'+remote+'/'+host.name],check=True,capture_output=True)
  subprocess.run(['docker','cp',str(marker),suite+':'+remote+'.json'],check=True,capture_output=True)
 else:
  for host,path in [(out,remote),(marker,remote+'.json')]:subprocess.run(['docker','cp',str(host),suite+':'+path],check=True,capture_output=True)
 for name,digest in {**files,remote+'.json':SHA(marker.read_bytes())}.items():assert SHA(subprocess.check_output(['docker','exec',suite,'cat',name if name.startswith('/') else remote+'/'+name]))==digest
 (root/'receipt-installation.json').write_text(json.dumps(dict(runId=run,manifestSha256=SHA(marker.read_bytes()),files=files,readBack=True,productConfigurationWrites=0,protocolOperations=0),sort_keys=True,indent=2)+'\n')
 print(run,'public originals installed/read-back',len(files))
if __name__=='__main__':main()
