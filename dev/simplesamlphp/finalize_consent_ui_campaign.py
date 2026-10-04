#!/usr/bin/env python3
"""Install native UI public originals and formally re-evaluate without sending SAML."""
import argparse,hashlib,io,json,subprocess,sys,tarfile
from pathlib import Path
REPO=Path(__file__).resolve().parents[2];sys.path.insert(0,str(REPO/'dev/keycloak'));from import_metadata_batch import api,save
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);p.add_argument('--evaluation-name',default='evaluation');p.add_argument('--installation-name',default='receipt-installation.json');a=p.parse_args();folder=a.folder.resolve();originals=folder/'originals';manifest=json.loads((originals/'manifest.json').read_bytes());run=manifest['runId'];target='/data/ui-display-evidence/'+run
    files=sorted(originals.iterdir());assert {f.name for f in files}==set(manifest['files'])|{'manifest.json'} and all(f.is_file() and not f.is_symlink() for f in files)
    evaluation=folder/a.evaluation_name;evaluation.mkdir(exist_ok=False);before=api('/api/runs/'+run+'/transcript');assert before==json.loads((folder/'transcript.json').read_bytes())
    save(evaluation/'transcript-before.json',before);save(evaluation/'result-before.json',api('/api/runs/'+run+'/result.json'))
    existing=subprocess.run(['docker','exec','samlscope-reference-suite','test','-e',target],capture_output=True).returncode==0
    data=io.BytesIO()
    with tarfile.open(fileobj=data,mode='w') as archive:
        for f in files:
            raw=f.read_bytes();info=tarfile.TarInfo(f.name);info.size=len(raw);info.mode=0o600;archive.addfile(info,io.BytesIO(raw))
    if not existing:
        subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p',target],check=True,capture_output=True)
        subprocess.run(['docker','exec','-i','samlscope-reference-suite','tar','-xf','-','-C',target],input=data.getvalue(),check=True,capture_output=True)
    records=[]
    for f in files:
        observed=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',target+'/'+f.name]);assert observed==f.read_bytes();records.append(dict(file=f.name,sha256=sha(observed)))
    assert not (folder/a.installation_name).exists();save(folder/a.installation_name,dict(runId=run,path=target,records=records,readBackVerified=True,reusedExact=existing))
    save(evaluation/'protocol-evidence-before.json',api('/api/runs/'+run+'/protocol-evidence'))
    save(evaluation/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}));after=api('/api/runs/'+run+'/transcript');assert after==before
    save(evaluation/'transcript.json',after);save(evaluation/'result.json',api('/api/runs/'+run+'/result.json'));save(evaluation/'protocol-evidence.json',api('/api/runs/'+run+'/protocol-evidence'))
    save(evaluation/'operation-counts.json',dict(apiGets=6,protocolEvidenceEvaluations=1,receiptPlacement=int(not existing),receiptReadBack=1,originalReadBackFiles=len(files),productConfigurationWrites=0,productRestarts=0,protocolSends=0,humanOperations=0,transcriptUnchanged=True))
    counts=[json.loads((folder.parent/('ssp-native-consent-ui-v172-r'+str(i))/'operation-counts.json').read_bytes()) for i in range(1,7)]
    summary={key:sum(row[key] for row in counts) for key in ['productConfigurationWriteAttempts','configurationApplyWrites','restorationWrites','nativeParserInvocations','protocolOperationsAttempted','runCreations','productRestarts','humanOperations']}
    formal_counts=[json.loads((path/'operation-counts.json').read_bytes()) for path in folder.glob('evaluation*') if (path/'operation-counts.json').exists()]
    summary.update(nativeParserInvocations=summary['nativeParserInvocations']+4,nativeBrowserObservationAttempts=6,nativeBrowserObservations=4,
        formalEvaluations=sum(r['protocolEvidenceEvaluations'] for r in formal_counts),formalApiGets=sum(r['apiGets'] for r in formal_counts),independentLiveApiGets=2,
        receiptPlacement=sum(r['receiptPlacement'] for r in formal_counts),receiptReadBack=sum(r['receiptReadBack'] for r in formal_counts),attempts=[dict(folder='ssp-native-consent-ui-v172-r'+str(i),**row) for i,row in enumerate(counts,1)])
    if (folder/'batch-summary.json').exists():save(folder/'batch-summary-v173-initial.json',json.loads((folder/'batch-summary.json').read_bytes()))
    save(folder/'batch-summary.json',summary);print(run,'native consent UI formally evaluated; transcript unchanged')
if __name__=='__main__':main()
