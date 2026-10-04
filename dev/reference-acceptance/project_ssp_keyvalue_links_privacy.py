#!/usr/bin/env python3
"""Chain public native state-link projection without retaining pre-projection bodies."""
import argparse,json,subprocess,sys,tempfile
from pathlib import Path
REPO=Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'dev/simplesamlphp'))
from native_ui_privacy import parameters_only,contains_state_secret
from export_ssp_keyvalue_runtime_receipt import export
from verify_ssp_keyvalue_runtime_acceptance import locate,sha,read,require,replay,capture_runtime,rows
from import_metadata_batch import api,save
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path);a=p.parse_args();folder=locate(a.root);projection=folder/'privacy-projection-v176';projection.mkdir(exist_ok=False)
 oldManifest=read(folder/'originals/manifest.json');oldDigest=sha((folder/'originals/manifest.json').read_bytes());oldReplay=read(folder/'production-reader-replay.json');oldInstall=read(folder/'receipt-installation.json');formal=rows(read(folder/'evaluation/result.json'))
 for name,source in [('original-manifest.json','originals/manifest.json'),('original-production-reader-replay.json','production-reader-replay.json'),('original-receipt-installation.json','receipt-installation.json')]:
  (projection/name).write_bytes((folder/source).read_bytes())
 protected={str(file.relative_to(folder)):sha(file.read_bytes()) for file in [folder/'transcript.json',folder/'decoded-manifest.json',*[folder/r['file'] for r in read(folder/'decoded-manifest.json')],*folder.glob('evaluation/*.json')]}
 require(all(oldDigest not in json.dumps(row) for row in formal.values()),'Formal outcomes contain original manifest SHA')
 records=[];changed=set()
 for index in [1,2,3]:
  attempt=folder.parent/('ssp-native-keyvalue-runtime-v170-r'+str(index));http={r['request_id']:r for r in read(attempt/'native-http-observations.json')['records']}
  for file in sorted((attempt/'native-http-originals').glob('*.html')):
   raw=file.read_bytes();projected=parameters_only(raw.decode()).encode()
   if raw==projected:continue
   obs=http[file.stem];require(obs['response_status']==200 and not obs['saml_response_form_present'] and obs['native_signature_rejection'] is None,'Privacy link occurs in used native error proof')
   require(not contains_state_secret(projected.decode()),'Native state projection incomplete');file.write_bytes(projected)
   row=dict(file=str(file.relative_to(folder.parent)),requestId=file.stem,beforeSha256=sha(raw),afterSha256=sha(projected),reason='Unused positive login HTML; signed final SAML and native error originals remain unchanged')
   if index==3 and file.name in oldManifest['files']:
    require((folder/'originals'/file.name).read_bytes()==raw,'Export original differs');(folder/'originals'/file.name).write_bytes(projected);changed.add(file.name);row['exportedFile']=file.name
   records.append(row)
 with tempfile.TemporaryDirectory(prefix='ssp-keyvalue-link-export-') as name:
  regenerated=Path(name)/'originals';manifest=export(folder,regenerated);require(set(manifest['files'])==set(oldManifest['files']),'Original set changes')
  for file in regenerated.iterdir():
   if file.name!='manifest.json':require((folder/'originals'/file.name).read_bytes()==file.read_bytes(),'Projection changes used source original')
  require(all(name in changed or digest==manifest['files'][name] for name,digest in oldManifest['files'].items()),'Projection changes used original')
  (folder/'originals/manifest.json').write_bytes((regenerated/'manifest.json').read_bytes())
 current=replay(folder);require({k:v for k,v in current.items() if k!='manifestSha256'}=={k:v for k,v in oldReplay.items() if k!='manifestSha256'},'Projection changes production outcomes/controls');save(folder/'production-reader-replay.json',current)
 target=oldInstall['path'];installed=[]
 for name in sorted(set(manifest['files'])|{'manifest.json'}):
  raw=(folder/'originals'/name).read_bytes();observed=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',target+'/'+name])
  if name in changed|{'manifest.json'}:
   require(sha(observed)==(oldDigest if name=='manifest.json' else oldManifest['files'][name]),'Runtime original differs before projection');subprocess.run(['docker','exec','-i','samlscope-reference-suite','sh','-c','cat > "$1"','sh',target+'/'+name],input=raw,check=True,capture_output=True);observed=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',target+'/'+name])
  require(observed==raw,'Runtime projected original differs');installed.append(dict(file=name,sha256=sha(observed)))
 save(folder/'receipt-installation.json',dict(runId=oldInstall['runId'],path=target,records=installed,readBackVerified=True,reusedExact=False,privacyProjection=True))
 capture_runtime(folder,'runtime-privacy-v176');deployed=replay(folder,'runtime-privacy-v176');require(deployed==current,'Deployed and archived Reader outcomes differ');save(folder/'production-reader-replay-privacy-v176.json',deployed)
 run=oldInstall['runId'];evaluation=folder/'evaluation-privacy-v176';evaluation.mkdir();before=api('/api/runs/'+run+'/transcript');require(before==read(folder/'transcript.json'),'Original transcript differs');save(evaluation/'transcript-before.json',before);save(evaluation/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));save(evaluation/'result.json',api('/api/runs/'+run+'/result.json'));save(evaluation/'transcript.json',api('/api/runs/'+run+'/transcript'))
 require(rows(read(evaluation/'result.json'))==formal and read(evaluation/'transcript.json')==before,'Formal result/proof changes');require(all(sha((folder/name).read_bytes())==digest for name,digest in protected.items()),'Protected proof changes')
 save(projection/'projection.json',dict(schema='samlscope-unused-login-state-link-privacy-projection-v1',runId=run,files=records,oldManifestSha256=oldDigest,newManifestSha256=sha((folder/'originals/manifest.json').read_bytes()),changedManifestFiles=sorted(changed),protectedFiles=protected,caseOutcomesIdentical=True,formalRowsUnchanged=True,originalDecodedSamlAndTranscriptUnchanged=True,runtimeProjectionWrites=len(changed)+1,runtimeProjectionReadBack=True,productConfigurationWrites=0,protocolSends=0,humanOperations=0,formalEvaluations=1))
 print('Unused native state-link projection chained; all three formal outcomes and controls unchanged')
if __name__=='__main__':main()
