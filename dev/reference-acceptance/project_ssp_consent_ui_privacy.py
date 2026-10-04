#!/usr/bin/env python3
"""Remove language-link native state values, preserve old hashes and reproduce the full case."""
import argparse,hashlib,json,subprocess,sys,tempfile
from pathlib import Path
REPO=Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'dev/simplesamlphp'))
from native_ui_privacy import sanitized,contains_state_secret
from export_ssp_consent_ui import export
from verify_ssp_consent_ui_acceptance import locate,replay,capture_runtime,sha,read,require,case
from import_metadata_batch import api,save
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);a=p.parse_args();folder=locate(a.root);projection=folder/'privacy-projection-v176';projection.mkdir(exist_ok=False)
 oldManifest=read(folder/'originals/manifest.json');oldDigest=sha((folder/'originals/manifest.json').read_bytes());oldReport=read(folder/'production-reader-replay-v174.json');oldInstall=read(folder/'receipt-installation-v174.json');formal=case(read(folder/'evaluation-v174/result.json'))
 protected={}
 for file in [folder/'transcript.json',folder/'decoded-manifest.json',*list((folder/'decoded').iterdir()),*list((folder/'evaluation-v174').glob('*.json'))]:protected[str(file.relative_to(folder))]=sha(file.read_bytes())
 require(oldDigest not in json.dumps(formal),'Formal case contains manifest SHA; explicit new adoption is required')
 for name,source in [('original-manifest.json','originals/manifest.json'),('original-production-reader-replay-v174.json','production-reader-replay-v174.json'),('original-receipt-installation-v174.json','receipt-installation-v174.json')]:
  (projection/name).write_bytes((folder/source).read_bytes())
 records=[]
 for index in range(1,7):
  attempt=folder.parent/('ssp-native-consent-ui-v172-r'+str(index))
  for file in sorted(attempt.rglob('*.html')):
   if 'originals' in file.relative_to(attempt).parts:continue
   raw=file.read_bytes();projected=sanitized(raw.decode()).encode()
   if raw==projected:continue
   require(not contains_state_secret(projected.decode()),'Projection leaves native state material');file.write_bytes(projected)
   records.append(dict(file=str(file.relative_to(folder.parent)),beforeSha256=sha(raw),afterSha256=sha(projected),removed='AuthState/StateId parameters and opaque native state identifier',purpose='Native UI public HTML; authentication state is irrelevant to display-name precedence, public getter/source and signed SAML correlation'))
  path=attempt/'native-http-observations.json'
  if path.exists():
   http=read(path)
   for row in http['records']:
    original=attempt/'native-http-originals'/(row['request_id']+'.html')
    if original.exists():row['persisted_body_sha256']=sha(original.read_bytes());row['body_sanitized']=row['persisted_body_sha256']!=row['response_body_sha256']
   save(path,http)
  path=attempt/'native-ui-observations.json'
  if path.exists():
   observed=read(path)
   for row in observed['observations']:
    originals=[p for p in attempt.glob('*/ui/'+row['requestId']+'.html')]
    require(len(originals)==1,'Public UI HTML identity ambiguous');row['bodySha256']=sha(originals[0].read_bytes())
   save(path,observed)
 with tempfile.TemporaryDirectory(prefix='ssp-consent-privacy-export-') as name:
  regenerated=Path(name)/'originals';newManifest=export(folder,regenerated);require(set(oldManifest['files'])==set(newManifest['files']),'Projection changes original set');changed=[]
  for file in regenerated.iterdir():
   if file.name=='manifest.json':continue
   if oldManifest['files'][file.name]!=newManifest['files'][file.name]:
    require(file.name.endswith('.html') or file.name in ['native-ui-observations.json','native-http-observations.json'],'Projection changes a semantic original');changed.append(file.name)
   (folder/'originals'/file.name).write_bytes(file.read_bytes())
  (folder/'originals/manifest.json').write_bytes((regenerated/'manifest.json').read_bytes())
 current=replay(folder);require(current['production_outcome']==oldReport['production_outcome'] and {k:v for k,v in current.items() if k!='manifestSha256'}=={k:v for k,v in oldReport.items() if k!='manifestSha256'},'Projection changes production case/negative controls')
 save(folder/'production-reader-replay-v174.json',current);target=oldInstall['path'];installed=[]
 for name in sorted(set(newManifest['files'])|{'manifest.json'}):
  file=folder/'originals'/name;raw=file.read_bytes();observed=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',target+'/'+name])
  if name in set(changed)|{'manifest.json'}:
   require(sha(observed)==(oldDigest if name=='manifest.json' else oldManifest['files'][name]),'Runtime projection starting original differs');subprocess.run(['docker','exec','-i','samlscope-reference-suite','sh','-c','cat > "$1"','sh',target+'/'+name],input=raw,check=True,capture_output=True);observed=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',target+'/'+name])
  require(observed==raw,'Runtime public projection readback differs');installed.append(dict(file=name,sha256=sha(observed)))
 save(folder/'receipt-installation-v174.json',dict(runId=oldInstall['runId'],path=target,records=installed,readBackVerified=True,reusedExact=False,privacyProjection=True))
 capture_runtime(folder,'runtime-privacy-v176');deployed=replay(folder,'runtime-privacy-v176');require(deployed==current,'Actual deployed Reader differs from archived original Reader after projection');save(folder/'production-reader-replay-privacy-v176.json',deployed)
 run=oldInstall['runId'];evaluation=folder/'evaluation-privacy-v176';evaluation.mkdir();before=api('/api/runs/'+run+'/transcript');require(before==read(folder/'transcript.json'),'Original transcript changed');save(evaluation/'transcript-before.json',before);save(evaluation/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));save(evaluation/'result.json',api('/api/runs/'+run+'/result.json'));save(evaluation/'transcript.json',api('/api/runs/'+run+'/transcript'))
 require(case(read(evaluation/'result.json'))==formal and read(evaluation/'transcript.json')==before,'Projection changes formal outcome or original transcript');require(all(sha((folder/name).read_bytes())==digest for name,digest in protected.items()),'Projection modifies protected originals')
 report=dict(schema='samlscope-native-consent-state-privacy-projection-v1',runId=run,files=records,oldManifestSha256=oldDigest,newManifestSha256=sha((folder/'originals/manifest.json').read_bytes()),changedManifestFiles=changed,formalCaseManifestHashAbsent=True,caseOutcomeIdentical=True,originalDecodedSamlAndTranscriptUnchanged=True,protectedFiles=protected,runtimeProjectionWrites=len(changed)+1,runtimeProjectionReadback=True,productConfigurationWrites=0,protocolSends=0,humanOperations=0,formalEvaluations=1,actualDeployedRuntime='runtime-privacy-v176')
 save(projection/'projection.json',report);print('Native StateId/AuthState public projection completed, exact formal case and signed originals unchanged')
if __name__=='__main__':main()
