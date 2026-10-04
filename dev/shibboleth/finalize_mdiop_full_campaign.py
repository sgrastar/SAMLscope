#!/usr/bin/env python3
"""Archive the final native MDIOP Run/runtime and formally evaluate its full case."""
import argparse
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'dev/reference-acceptance'))
from capture_terminal_http_runtime import api,capture_suite
from verify_terminal_http_acceptance import find_case
from verify_shibboleth_mdiop_full_acceptance import catalog_projection,CATALOG_SHA256

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
NOW=lambda:datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
CASE='IIP-MD05-c-idp-01'


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=Path)
    folder=parser.parse_args().folder.resolve();run=json.loads((folder/'created.json').read_text())['run']['id']
    original=json.loads((folder/'transcript.json').read_text())
    if api('/api/runs/'+run+'/transcript')!=original:raise ValueError('Recorder originals changed')
    if not json.loads((folder/'restoration.json').read_text())['restored']:raise ValueError('Native restoration unproven')
    started=NOW();capture_suite(folder)
    path=folder/'suite-store-0.1.0.jar'
    subprocess.run(['docker','cp','samlscope-reference-suite:/opt/samlscope/lib/store-0.1.0.jar',str(path)],check=True,capture_output=True)
    (folder/'store-runtime.json').write_text(json.dumps(dict(path='/opt/samlscope/lib/store-0.1.0.jar',file=path.name,sha256=SHA(path.read_bytes())),indent=2)+'\n')
    result=json.loads((folder/'evaluation-terminal-http-v1/result.json').read_text());case=find_case(result,CASE)
    if (case['outcome'],case['verdict'],case['reason_code'],case['attested'])!=('SATISFIED','PASS','metadata.fixture-probe.satisfied',False):
        raise ValueError('Full MDIOP result not proven: '+str(case))
    unchanged=api('/api/runs/'+run+'/transcript')==original
    if not unchanged:raise ValueError('Formal evaluation changed Recorder originals')
    (folder/'formal-mdiop-evaluation.json').write_text(json.dumps(dict(runId=run,startedAt=started,finishedAt=NOW(),transcriptUnchanged=True,case=case),indent=2)+'\n')
    catalog=(REPO/'tests/cases.yaml').read_bytes()
    if SHA(catalog)!=CATALOG_SHA256:raise ValueError('Approved catalog changed')
    (folder/'approved-cases-original.yaml').write_bytes(catalog)
    (folder/'approved-cases-projection.json').write_text(json.dumps(catalog_projection(catalog),sort_keys=True,indent=2)+'\n')
    helper=REPO/'dev/reference-acceptance/VerifyShibbolethMdiopFullEvidence.java'
    shutil.copyfile(helper,folder/'replay-helper-original.java')
    (folder/'replay-helper-original.json').write_text(json.dumps(dict(file='replay-helper-original.java',sha256=SHA(helper.read_bytes())),indent=2)+'\n')
    print(run,CASE,'full native representation family formally PASS; transcript unchanged')


if __name__=='__main__':main()
