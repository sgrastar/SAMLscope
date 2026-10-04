#!/usr/bin/env python3
"""Install flat public originals; no secret configuration or decrypted assertion is persisted."""
import argparse,json,pathlib,hashlib,subprocess,shutil
SHA=lambda b:hashlib.sha256(b).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('root',type=pathlib.Path);a=p.parse_args();r=a.root.resolve();out=r/'subject-confirmation-receipt';out.mkdir(exist_ok=False);files={}
 def copy(source,name):
  raw=source.read_bytes();(out/name).write_bytes(raw);files[name]=SHA(raw)
 for phase in ['original','before-protocol','after-protocol','final']:
  for path in (r/phase).iterdir():copy(path,phase+'-'+path.name)
 for path in (r/'native-jars').iterdir():copy(path,'native-'+path.name)
 b=r/'browser'
 for name in ['created.json','plan.json','original-providers.xml','configured-providers.xml','configured-providers-readback.xml','final-providers.xml','restoration.json','operation-counts.json','target-container-inspect-start.json','target-container-inspect-end.json']:copy(b/name,name)
 for source,dest in [('fixture.xml','control.fixture.xml'),('native-effective-sp-metadata.xml','native-effective-sp-metadata.xml'),('native-effective-sp-metadata-read.json','native-effective-sp-metadata-read.json'),('native-http-observations.json','native-http-observations.json')]:copy(b/'control'/source,dest)
 http=json.loads((b/'control/native-http-observations.json').read_text());bad=next(row for row in http['records'] if row.get('nativeMessageSecurityError'));copy(b/'control'/bad['responseBodyFile'],'native-rejection.html')
 for path in (r/'calibration-r4').glob('*'):
  if path.suffix in ['.xml','.java'] or path.name=='producer.json':copy(path,path.name)
 t=json.loads((b/'transcript.json').read_text());flow=json.loads((b/'control/flow.json').read_text());run=json.loads((b/'created.json').read_text())['run']['id'];target=(b/'target-metadata.xml').read_bytes()
 def ref(kind,corr=None):return next(e['id'] for e in t if e['samlSummary'].get('type')==kind and (corr is None or e.get('correlationId')==corr))
 manifest=dict(schema='samlscope-shibboleth-subject-confirmation-v1',runId=run,campaignId='native-subject-confirmation',targetEntityId='http://localhost:18280/idp/shibboleth',targetMetadataSha256=SHA(target),metadataReference=ref('MetadataPrepared'),fetchReference=ref('MetadataFetch'),positiveRequestReference=ref('AuthnRequest',flow['positive_exchange']['request_id']),negativeRequestReference=ref('AuthnRequest',flow['negative_control']['exchange']['request_id']),positiveResponseReference=ref('Response'),files=files)
 marker=r/(run+'.shibboleth-subject-confirmation.json');marker.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
 remote='/data/subject-confirmation-evidence/'+run+'.shibboleth-subject-confirmation'
 subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p','/data/subject-confirmation-evidence'],check=True)
 subprocess.run(['docker','cp',str(out),'samlscope-reference-suite:'+remote],check=True)
 subprocess.run(['docker','cp',str(marker),'samlscope-reference-suite:'+remote+'.json'],check=True)
 for name,digest in {**files,remote+'.json':SHA(marker.read_bytes())}.items():
  path=name if name.startswith('/') else remote+'/'+name
  raw=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',path]);assert SHA(raw)==digest
 (r/'receipt-installation.json').write_text(json.dumps(dict(runId=run,manifestSha256=SHA(marker.read_bytes()),files=files,readBack=True,productConfigurationWrites=0,protocolOperations=0),sort_keys=True,indent=2)+'\n')
 print('Public native originals installed and read-back matched',len(files))
if __name__=='__main__':main()
