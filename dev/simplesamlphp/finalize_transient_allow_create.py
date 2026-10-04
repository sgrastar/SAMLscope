#!/usr/bin/env python3
"""Place full transient native originals and formally reevaluate the BROWSER case without attestation."""
import argparse,json,hashlib,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'dev/keycloak'))
from import_metadata_batch import api,save
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--runtime',default='runtime-v184');a=p.parse_args();folder=a.folder.resolve();originals=folder/'originals';manifest=json.loads((originals/'manifest.json').read_bytes());run=manifest['runId'];target='/data/transient-allow-create-evidence/'+run;out=folder/'evaluation';out.mkdir(exist_ok=True);assert not any((out/n).exists() for n in ['transcript-before.json','result-before.json','evaluation.json','result.json'])
 sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'dev/reference-acceptance'));from ssp_ui_stored_outcome import capture,verify
 for short in ['fp']:
  case='IIP-SSO01-'+short+'-idp-01';name='evaluation/stored-before-'+short+'.json'
  if (folder/name).exists():verify(folder,a.runtime,name,run,case)
  else:capture(folder,a.runtime,name,run,case)
 before=api('/api/runs/'+run+'/transcript');assert before==json.loads((folder/'transcript.json').read_bytes());save(out/'transcript-before.json',before);save(out/'result-before.json',api('/api/runs/'+run+'/result.json'));subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p',target],check=True,capture_output=True);records=[]
 for file in sorted(originals.iterdir()):
  subprocess.run(['docker','cp',str(file),'samlscope-reference-suite:'+target+'/'+file.name],check=True,capture_output=True);actual=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',target+'/'+file.name]);assert actual==file.read_bytes();records.append(dict(file=file.name,sha256=sha(actual)))
 save(folder/'receipt-installation.json',dict(runId=run,path=target,records=records,readBackVerified=True));save(out/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));save(out/'result.json',api('/api/runs/'+run+'/result.json'));save(out/'transcript.json',api('/api/runs/'+run+'/transcript'));assert json.loads((out/'transcript.json').read_bytes())==before
 for short in ['fp']:capture(folder,a.runtime,'evaluation/stored-after-'+short+'.json',run,'IIP-SSO01-'+short+'-idp-01')
 save(out/'operation-counts.json',dict(receiptPlacementFiles=len(records),receiptReadbackFiles=len(records),formalEvaluations=1,publicStoredReadbackPlacements=4,productConfigurationWrites=0,protocolSends=0,humanOperations=0,configurationConfirmations=0,attestations=0,transcriptUnchanged=True));print(run,'native transient AllowCreate formally evaluated; transcript unchanged')
if __name__=='__main__':main()
