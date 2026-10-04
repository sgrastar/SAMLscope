#!/usr/bin/env python3
"""Install a prepared native key-selection receipt into the running Suite and re-evaluate its Run."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request

BASE = 'http://localhost:18080'
CONTAINER = 'samlscope-reference-suite'
DESTINATION = '/data/metadata-key-evidence'
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
    args = parser.parse_args()
    receipt_path = args.receipt.resolve()
    raw = receipt_path.read_bytes()
    receipt = json.loads(raw)
    run = receipt['runId']
    if receipt.get('restored') is not True or receipt.get('evidenceAdapter') not in {
            'keycloak-native-event', 'simplesamlphp-native-http', 'shibboleth-audit'}:
        raise ValueError('Unsupported or unverified receipt')
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
    save(out / 'status-after.json', api('/api/runs/' + run + '/protocol-evidence'))
    if {e['id']: e for e in before} != {e['id']: e for e in after}:
        raise RuntimeError('Run transcript changed during re-evaluation')
    print('Receipt installed and Run re-evaluated:', run)


if __name__ == '__main__':
    main()
