#!/usr/bin/env python3
"""Place original native safety evidence and formally reevaluate without additional target actions."""
import argparse,json,hashlib,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'dev/keycloak'))
from import_metadata_batch import api,save
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);a=p.parse_args();folder=a.folder.resolve();originals=folder/'originals';manifest=json.loads((originals/'manifest.json').read_bytes());run=manifest['runId'];target='/data/ui-safety-evidence/'+run;out=folder/'evaluation';out.mkdir(exist_ok=True);assert not any((out/name).exists() for name in ["transcript-before.json","result-before.json","evaluation.json","result.json"])
 sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'dev/reference-acceptance'));from ssp_ui_stored_outcome import capture,verify
 if (out/'stored-before.json').exists():verify(folder,'runtime-v178','evaluation/stored-before.json',run,'IIP-MD05-fg-idp-01')
 else:capture(folder,'runtime-v178','evaluation/stored-before.json',run,'IIP-MD05-fg-idp-01')
 before=api('/api/runs/'+run+'/transcript');assert before==json.loads((folder/'transcript.json').read_bytes());save(out/'transcript-before.json',before);save(out/'result-before.json',api('/api/runs/'+run+'/result.json'));subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p',target],check=True,capture_output=True);records=[]
 for file in sorted(originals.iterdir()):
  subprocess.run(['docker','cp',str(file),'samlscope-reference-suite:'+target+'/'+file.name],check=True,capture_output=True);actual=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',target+'/'+file.name]);assert actual==file.read_bytes();records.append(dict(file=file.name,sha256=sha(actual)))
 save(folder/'receipt-installation.json',dict(runId=run,path=target,records=records,readBackVerified=True));save(out/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));save(out/'result.json',api('/api/runs/'+run+'/result.json'));save(out/'transcript.json',api('/api/runs/'+run+'/transcript'));assert json.loads((out/'transcript.json').read_bytes())==before
 capture(folder,'runtime-v178','evaluation/stored-after.json',run,'IIP-MD05-fg-idp-01')
 save(out/'operation-counts.json',dict(receiptPlacementFiles=len(records),receiptReadbackFiles=len(records),formalEvaluations=1,productConfigurationWrites=0,protocolSends=0,humanOperations=0,transcriptUnchanged=True));print(run,'native safety formally evaluated; transcript unchanged')
if __name__=='__main__':main()
