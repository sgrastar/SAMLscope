#!/usr/bin/env python3
"""Reevaluate native v67 key originals for MD05.cd without changing or contacting the product."""
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

CASE='IIP-MD05-cd-idp-01'
SOURCE='reference-20260918/shibboleth-native-key-selection-v67'
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
NOW=lambda:datetime.now(timezone.utc).isoformat().replace('+00:00','Z')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=Path)
    folder=parser.parse_args().folder.resolve();source=REPO/'build/acceptance'/SOURCE
    if folder.exists():raise ValueError('Refusing to replace historical reuse capture')
    shutil.copytree(source,folder);child=folder/'metadata_idp'
    raw=(child/'qualified-metadata-key-receipt.json').read_bytes();receipt=json.loads(raw);run=receipt['runId']
    original=json.loads((child/'transcript.json').read_text())
    if api('/api/runs/'+run+'/transcript')!=original:raise ValueError('Historical Recorder originals changed')
    destination='/data/metadata-key-evidence/'+run+'.json'
    actual=subprocess.run(['docker','exec','samlscope-reference-suite','cat',destination],capture_output=True)
    writes=0
    if actual.returncode:
        subprocess.run(['docker','exec','samlscope-reference-suite','mkdir','-p','/data/metadata-key-evidence'],check=True,capture_output=True)
        subprocess.run(['docker','cp',str(child/'qualified-metadata-key-receipt.json'),'samlscope-reference-suite:'+destination],check=True,capture_output=True)
        writes=1
    elif actual.stdout!=raw:raise ValueError('Current receipt differs from immutable source; refusing overwrite')
    actual=subprocess.check_output(['docker','exec','samlscope-reference-suite','cat',destination])
    if actual!=raw:raise ValueError('Receipt placement read-back differs')
    (folder/'receipt-placement-readback.json').write_text(json.dumps(dict(runId=run,destination=destination,
        sha256=SHA(actual),readBackMatched=True,evidenceFileWrites=writes),indent=2)+'\n')
    (folder/'reused-evidence-provenance.json').write_text(json.dumps(dict(sourceCampaign=SOURCE,
        sourceReceiptSha256=SHA(raw),sourceTranscriptSha256=SHA((child/'transcript.json').read_bytes()),
        sourceRawOriginalsUnchanged=True,targetWrites=0,targetRestarts=0,targetSubmissions=0,humanOperations=0,
        suiteReceiptWrites=writes,formalEvaluatePosts=1),indent=2)+'\n')
    started=NOW();capture_suite(child)
    jar=child/'suite-store-0.1.0.jar'
    subprocess.run(['docker','cp','samlscope-reference-suite:/opt/samlscope/lib/store-0.1.0.jar',str(jar)],check=True,capture_output=True)
    (child/'store-runtime.json').write_text(json.dumps(dict(path='/opt/samlscope/lib/store-0.1.0.jar',file=jar.name,sha256=SHA(jar.read_bytes())),indent=2)+'\n')
    result=json.loads((child/'evaluation-terminal-http-v1/result.json').read_text());case=find_case(result,CASE)
    if (case['outcome'],case['verdict'],case['reason_code'],case['attested'])!=('SATISFIED','PASS','metadata.keys.selection-observed',False):
        raise ValueError('Hint-free native result remains unproven: '+str(case))
    if api('/api/runs/'+run+'/transcript')!=original:raise ValueError('Formal evaluation changed Recorder originals')
    (child/'formal-hintfree-key-evaluation.json').write_text(json.dumps(dict(runId=run,startedAt=started,finishedAt=NOW(),transcriptUnchanged=True,case=case),indent=2)+'\n')
    helper=REPO/'dev/reference-acceptance/VerifyShibbolethHintFreeKeyEvidence.java'
    shutil.copyfile(helper,folder/'replay-helper-original.java')
    (folder/'replay-helper-original.json').write_text(json.dumps(dict(file='replay-helper-original.java',sha256=SHA(helper.read_bytes())),indent=2)+'\n')
    print(run,CASE,'native original representations formally PASS; zero product operations')


if __name__=='__main__':main()
