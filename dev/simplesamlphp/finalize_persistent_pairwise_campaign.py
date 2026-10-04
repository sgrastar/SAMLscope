"""Formally finish the evidence-ready pairwise case without any probe-chain sends."""
import argparse
from pathlib import Path
import json
import sys

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/keycloak'))
from import_metadata_batch import api,save
sys.path.insert(0,str(REPO/'dev/simplesamlphp'))
from install_persistent_pairwise_receipt import install

p=argparse.ArgumentParser(description=__doc__);p.add_argument('folder',type=Path);args=p.parse_args()
folder=args.folder.resolve()
evaluation=folder/'evaluation';evaluation.mkdir(exist_ok=False)
run=json.loads((folder/'primary/created.json').read_bytes())['run']['id']
before=api('/api/runs/'+run+'/transcript')
if before!=json.loads((folder/'primary/transcript.json').read_bytes()):raise ValueError('Original transcript changed before adoption')
save(evaluation/'transcript-before.json',before)
save(evaluation/'result-before.json',api('/api/runs/'+run+'/result.json'))
install(folder)
save(evaluation/'protocol-evidence-before.json',api('/api/runs/'+run+'/protocol-evidence'))
save(evaluation/'evaluation.json',api('/api/runs/'+run+'/protocol-evidence/evaluate',{}))
after=api('/api/runs/'+run+'/transcript')
if after!=before:raise ValueError('Formal adoption changed original transcript')
save(evaluation/'transcript.json',after)
save(evaluation/'result.json',api('/api/runs/'+run+'/result.json'))
save(evaluation/'protocol-evidence.json',api('/api/runs/'+run+'/protocol-evidence'))
save(evaluation/'operation-counts.json',dict(apiGets=6,protocolEvidenceEvaluations=1,receiptPlacement=1,
    productConfigurationWrites=0,productRestarts=0,protocolSends=0,humanOperations=0,transcriptUnchanged=True))
print(run,'pairwise formally re-evaluated with unchanged transcript')
