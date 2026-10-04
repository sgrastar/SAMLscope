#!/usr/bin/env python3
"""Archive deployed native UI Reader and formal re-evaluation; no product operations."""
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
from capture_terminal_http_runtime import capture_suite,api
from verify_terminal_http_acceptance import find_case
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
NOW=lambda:datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
CASES=['IIP-MD05-'+part+'-idp-01' for part in ['fb','fg','fh','fj']]

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('folder',type=Path)
    folder=parser.parse_args().folder.resolve();receipt=folder/'receipt';archive=folder/'reader-v177';archive.mkdir()
    run=json.loads((receipt/'created.json').read_text())['run']['id'];original=json.loads((receipt/'transcript.json').read_text())
    if api('/api/runs/'+run+'/transcript')!=original:raise ValueError('Recorder original changed')
    for file in ['created.json','transcript.json']:shutil.copy2(receipt/file,archive/file)
    started=NOW();capture_suite(archive)
    jar=archive/'suite-store-0.1.0.jar';subprocess.run(['docker','cp','samlscope-reference-suite:/opt/samlscope/lib/store-0.1.0.jar',str(jar)],check=True,capture_output=True)
    (archive/'store-runtime.json').write_text(json.dumps(dict(path='/opt/samlscope/lib/store-0.1.0.jar',file=jar.name,sha256=SHA(jar.read_bytes())),indent=2)+'\n')
    helper=REPO/'dev/reference-acceptance/VerifyShibbolethNativeUiEvidence.java';shutil.copy2(helper,archive/'replay-helper-original.java')
    (archive/'replay-helper-original.json').write_text(json.dumps(dict(file='replay-helper-original.java',sha256=SHA(helper.read_bytes())),indent=2)+'\n')
    # Preserve the exact collection/helper sources. These are public input-only processes.
    provenance=[]
    for name in ['native_ui_campaign.py','observe_native_ui.mjs','verify_native_ui_slot_control.mjs','NativeUiConsumerValues.java','capture_native_ui_getters.py','install_native_ui_receipt.py']:
        raw=(REPO/'dev/shibboleth'/name).read_bytes();destination=archive/('source-'+name);destination.write_bytes(raw)
        provenance.append(dict(source='dev/shibboleth/'+name,file=destination.name,sha256=SHA(raw)))
    (archive/'collection-source-manifest.json').write_text(json.dumps(provenance,indent=2)+'\n')
    result=json.loads((archive/'evaluation-terminal-http-v1/result.json').read_text());cases={id:find_case(result,id) for id in CASES}
    for id,case in cases.items():
        expected='VIOLATED' if '-fj-' in id else 'SATISFIED_WITH_NOTE'
        if case['outcome']!=expected or case['attested'] is not False:raise ValueError('Actual deployed Reader differs '+id+': '+str(case))
    if api('/api/runs/'+run+'/transcript')!=original:raise ValueError('Formal re-evaluation changed Recorder')
    (archive/'formal-native-ui-evaluation.json').write_text(json.dumps(dict(runId=run,startedAt=started,finishedAt=NOW(),
        transcriptUnchanged=True,cases=cases,productWrites=0,productRestarts=0,protocolSends=0,humanOperations=0),indent=2)+'\n')
    print(run,{id:case['verdict'] for id,case in cases.items()},'no new product operations')

if __name__=='__main__':main()
