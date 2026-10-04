#!/usr/bin/env python3
"""Install immutable native originals, then formally evaluate without protocol actions."""
import argparse,hashlib,io,json,re,subprocess,sys,tarfile
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/keycloak'));from import_metadata_batch import api,save
SUITE='samlscope-reference-suite'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def install(folder):
    originals=folder/'originals';manifest=json.loads((originals/'manifest.json').read_bytes());run=manifest['runId']
    assert re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',run)
    target='/data/metadata-keyvalue-evidence/'+run;names={p.name for p in originals.iterdir()}
    assert names==set(manifest['files'])|{'manifest.json'} and all(p.is_file() and not p.is_symlink() for p in originals.iterdir())
    existing=subprocess.run(['docker','exec',SUITE,'test','-e',target],capture_output=True).returncode==0
    if existing:
        assert set(subprocess.check_output(['docker','exec',SUITE,'ls','-1',target]).decode().splitlines())==names
    else:
        data=io.BytesIO()
        with tarfile.open(fileobj=data,mode='w') as archive:
            for p in sorted(originals.iterdir()):
                raw=p.read_bytes();info=tarfile.TarInfo(p.name);info.size=len(raw);info.mode=0o600;archive.addfile(info,io.BytesIO(raw))
        subprocess.run(['docker','exec',SUITE,'mkdir','-p',target],check=True,capture_output=True)
        subprocess.run(['docker','exec','-i',SUITE,'tar','-xf','-','-C',target],input=data.getvalue(),check=True,capture_output=True)
    records=[]
    for p in sorted(originals.iterdir()):
        observed=subprocess.check_output(['docker','exec',SUITE,'cat',target+'/'+p.name]);assert observed==p.read_bytes()
        records.append(dict(file=p.name,sha256=sha(observed)))
    save(folder/'receipt-installation.json',dict(runId=run,path=target,records=records,readBackVerified=True,reusedExact=existing))
    return not existing,len(records)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);a=p.parse_args();folder=a.folder.resolve()
    evaluation=folder/'evaluation';evaluation.mkdir(exist_ok=False);run=json.loads((folder/'created.json').read_bytes())['run']['id']
    before=api('/api/runs/'+run+'/transcript');assert before==json.loads((folder/'transcript.json').read_bytes())
    save(evaluation/'transcript-before.json',before);save(evaluation/'result-before.json',api('/api/runs/'+run+'/result.json'))
    placed,count=install(folder);save(evaluation/'protocol-evidence-before.json',api('/api/runs/'+run+'/protocol-evidence'))
    save(evaluation/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}))
    after=api('/api/runs/'+run+'/transcript');assert after==before
    save(evaluation/'transcript.json',after);save(evaluation/'result.json',api('/api/runs/'+run+'/result.json'))
    save(evaluation/'protocol-evidence.json',api('/api/runs/'+run+'/protocol-evidence'))
    save(evaluation/'operation-counts.json',dict(apiGets=6,protocolEvidenceEvaluations=1,receiptPlacement=int(placed),receiptReadBack=1,
        originalReadBackFiles=count,productConfigurationWrites=0,productRestarts=0,protocolSends=0,humanOperations=0,transcriptUnchanged=True))
    print(run,'native KeyValue formally re-evaluated, transcript unchanged')
if __name__=='__main__':main()
