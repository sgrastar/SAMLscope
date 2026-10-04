#!/usr/bin/env python3
"""Re-evaluate the primary immutable Run and capture the actual deployed persistent oracle."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
from capture_terminal_http_runtime import capture_suite, api
from verify_terminal_http_acceptance import find_case
sys.path.insert(0, str(Path(__file__).resolve().parent))
from install_persistent_nameid_receipt import install

EXPECTED = {
    'IIP-SSO05-a-idp-01': 'browser.normal-flow.persistent-nameid-returned',
    'IIP-SSO05-a2-idp-01': 'browser.normal-flow.persistent-nameid-length',
    'IIP-SSO05-a3-idp-01': 'idp.persistent-pairwise.observed',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    args = parser.parse_args()
    folder = args.folder.resolve()
    install(folder)
    primary = folder / 'primary'
    created = json.loads((primary / 'created.json').read_text())['run']
    run = created['id']
    original = json.loads((primary / 'transcript.json').read_text())
    if api('/api/runs/' + run + '/transcript') != original:
        raise RuntimeError('Primary transcript no longer equals its Recorder originals')
    started = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    capture_suite(primary)
    subprocess.run(['docker', 'cp', 'samlscope-reference-suite:/opt/samlscope/lib/store-0.1.0.jar',
                    str(primary / 'suite-store-0.1.0.jar')], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (primary / 'store-runtime.json').write_text(json.dumps(dict(path='/opt/samlscope/lib/store-0.1.0.jar',
        file='suite-store-0.1.0.jar', sha256=hashlib.sha256((primary / 'suite-store-0.1.0.jar').read_bytes()).hexdigest()), indent=2) + '\n')
    result = json.loads((primary / 'evaluation-terminal-http-v1/result.json').read_text())
    cases = {case: find_case(result, case) for case in EXPECTED}
    for case, reason in EXPECTED.items():
        found = cases[case]
        if (found['outcome'], found['verdict'], found['reason_code'], found['attested']) != ('SATISFIED', 'PASS', reason, False):
            raise RuntimeError('Formal persistent result remains unproven: ' + case)
    (primary / 'formal-persistent-evaluation.json').write_text(json.dumps(dict(runId=run,
        startedAt=started, finishedAt=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        transcriptUnchanged=original == api('/api/runs/' + run + '/transcript'), cases=cases), indent=2) + '\n')
    print(run, 'three persistent cases formally satisfied; transcript unchanged', flush=True)


if __name__ == '__main__':
    main()
