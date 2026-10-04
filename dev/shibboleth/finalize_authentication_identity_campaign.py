#!/usr/bin/env python3
"""Capture installed identity Reader, formally evaluate immutable Run, and archive helper."""
import argparse
from datetime import datetime, timezone
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

CASE='IIP-SSO01-ae-idp-01'
NOW=lambda:datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=Path)
    out=parser.parse_args().folder.resolve();child=out/'browser'
    run=json.loads((out/'campaign.json').read_text())['runId']
    original=json.loads((child/'transcript.json').read_text())
    if api('/api/runs/'+run+'/transcript')!=original:raise ValueError('Recorder originals changed')
    started=NOW();capture_suite(child)
    path=child/'suite-store-0.1.0.jar'
    subprocess.run(['docker','cp','samlscope-reference-suite:/opt/samlscope/lib/store-0.1.0.jar',str(path)],
        check=True,capture_output=True)
    (child/'store-runtime.json').write_text(json.dumps(dict(path='/opt/samlscope/lib/store-0.1.0.jar',
        file=path.name,sha256=SHA(path.read_bytes())),indent=2)+'\n')
    result=json.loads((child/'evaluation-terminal-http-v1/result.json').read_text());case=find_case(result,CASE)
    if (case['outcome'],case['verdict'],case['reason_code'],case['attested'])!=('SATISFIED','PASS','configuration.identity.native-controls-observed',False):
        raise ValueError('Actual deployed Reader does not prove identity controls: '+str(case))
    if api('/api/runs/'+run+'/transcript')!=original:raise ValueError('Formal evaluation changed Recorder')
    (child/'formal-authentication-identity-evaluation.json').write_text(json.dumps(dict(runId=run,
        startedAt=started,finishedAt=NOW(),transcriptUnchanged=True,case=case),indent=2)+'\n')
    print(run,CASE,'PASS from native originals; transcript unchanged')


if __name__=='__main__':main()
