#!/usr/bin/env python3
"""Install a native metadata-rejection receipt into the running Suite and re-evaluate its Run."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

BASE = 'http://localhost:18080'
CONTAINER = 'samlscope-reference-suite'
DESTINATION = '/data/metadata-rejection-evidence'
ADAPTERS = {'shibboleth-resolver', 'simplesamlphp-parser', 'simplesamlphp-native-mdq',
            'simplesamlphp-native-mdq-positive',
            'simplesamlphp-native-mdq-signature',
            'keycloak-import', 'shibboleth-idp'}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def api(path, body=None):
    request = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(),
                                     headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.load(response)


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--evaluation-dir', type=Path, required=True)
    parser.add_argument('--case', required=True, help='Case ID whose outcome must be adopted')
    args = parser.parse_args()
    receipt_path = args.receipt.resolve()
    raw = receipt_path.read_bytes()
    receipt = json.loads(raw)
    run = receipt['runId']
    if receipt.get('schema') != 'samlscope-native-metadata-rejection-receipt-v1':
        raise ValueError('Unsupported receipt schema')
    if receipt.get('restored') is not True or receipt.get('evidenceAdapter') not in ADAPTERS:
        raise ValueError('Unsupported or unverified receipt')
    if not receipt.get('rejections'):
        raise ValueError('Receipt records no rejection')
    out = args.evaluation_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    save(out / 'status-before.json', api('/api/runs/' + run + '/protocol-evidence'))
    before = api('/api/runs/' + run + '/transcript')
    save(out / 'transcript-before.json', before)
    subprocess.run(['docker', 'exec', CONTAINER, 'mkdir', '-p', DESTINATION], check=True, capture_output=True)
    subprocess.run(['docker', 'cp', str(receipt_path), CONTAINER + ':' + DESTINATION + '/' + run + '.json'],
                   check=True, capture_output=True)
    readback = subprocess.check_output(['docker', 'exec', CONTAINER, 'sha256sum', DESTINATION + '/' + run + '.json'],
                                       timeout=30).decode().split()[0]
    if readback != SHA(raw):
        raise RuntimeError('Installed receipt read-back differs')
    save(out / 'receipt-installation.json', dict(run=run, sha256=SHA(raw), read_back=True))
    save(out / 'evaluation.json', api('/api/runs/' + run + '/protocol-evidence/evaluate', {}))
    after = api('/api/runs/' + run + '/transcript')
    save(out / 'transcript.json', after)
    save(out / 'result.json', api('/api/runs/' + run + '/result.json'))
    if {e['id']: e for e in before} != {e['id']: e for e in after}:
        raise RuntimeError('Run transcript changed during re-evaluation')
    case = next((row for row in api('/api/runs/' + run + '/protocol-evidence')['cases']
                 if row.get('caseId') == args.case), None)
    save(out / 'case-status.json', case)
    completed = next((row for row in json.loads((out / 'evaluation.json').read_text())['completed']
                      if row.get('caseId') == args.case), None)
    if completed is None and (case is None or not case.get('ready')):
        raise RuntimeError(f'{args.case} was neither completed nor ready: {case}')
    print('Receipt installed;', args.case, 'completed' if completed else 'ready', 'for', run)


if __name__ == '__main__':
    main()
