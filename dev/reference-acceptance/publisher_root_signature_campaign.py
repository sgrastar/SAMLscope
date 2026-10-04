#!/usr/bin/env python3
"""Collect an unauthenticated publisher response and compare it with the Run snapshot."""
import argparse
import hashlib
import json
import shutil
import subprocess
import urllib.request
from pathlib import Path

BASE = 'http://localhost:18080'
TARGETS = {
    'keycloak': ('http://localhost:18180/realms/samlscope',
                 'http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
                 'http://localhost:18180/realms/samlscope/protocol/saml/descriptor'),
    'shibboleth': ('http://localhost:18280/idp/shibboleth',
                   'http://samlscope-reference-shibboleth:8080/idp/shibboleth',
                   'http://localhost:18280/idp/shibboleth'),
    'simplesamlphp': ('http://localhost:18380/idp',
                      'http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
                      'http://localhost:18380/simplesaml/module.php/saml/idp/metadata'),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def request(path, body=None):
    raw = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, raw, headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def save(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def run_campaign(product, output, source_folder):
    output = Path(output).resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError('Evidence directory must be empty')
    output.mkdir(parents=True, exist_ok=True)
    entity, _, external = TARGETS[product]
    source_folder = Path(source_folder).resolve()
    for name in ('plan.json', 'created.json', 'result.json', 'target-metadata.xml'):
        shutil.copy2(source_folder / name, output / ('run-target-metadata.xml' if name == 'target-metadata.xml' else name))
    plan = json.loads((output / 'plan.json').read_text())
    if plan['plan']['plan']['target']['entityId'] != entity:
        raise ValueError('Source campaign targeted another product')
    created = json.loads((output / 'created.json').read_text())
    run = created['run']['id']
    if json.loads((output / 'result.json').read_text())['run']['id'] != run:
        raise ValueError('Source result belongs to another Run')
    direct = urllib.request.Request(external, method='GET')
    with urllib.request.urlopen(direct, timeout=30) as response:
        status = response.status
        published = response.read()
        save(output / 'response-headers.json', dict(status=status, contentType=response.headers.get('Content-Type')))
    (output / 'response.xml').write_bytes(published)
    save(output / 'request.json', dict(url=external, method='GET', authorizationSent=False, cookieSent=False))
    snapshot = (output / 'run-target-metadata.xml').read_bytes()
    if status != 200 or snapshot != published:
        save(output / 'snapshot-mismatch.json', dict(status=status, snapshotSha256=sha(snapshot),
                                                       publishedSha256=sha(published)))
        return run, False
    manifest = dict(schema='samlscope-publisher-root-signature-v1', runId=run,
                    sourceUrl=external, requestSha256=sha((output / 'request.json').read_bytes()),
                    responseSha256=sha(published), statusCode=200)
    save(output / 'manifest.json', manifest)
    target = '/data/metadata-rejection-evidence/' + run + '.publisher'
    subprocess.run(['docker', 'exec', 'samlscope-reference-suite', 'mkdir', '-p', target], check=True)
    for name in ('manifest.json', 'request.json', 'response.xml'):
        subprocess.run(['docker', 'cp', str(output / name), 'samlscope-reference-suite:' + target + '/' + name], check=True)
    checked = subprocess.check_output(['docker', 'exec', 'samlscope-reference-suite', 'sha256sum',
                                       *[target + '/' + name for name in ('manifest.json', 'request.json', 'response.xml')]],
                                      text=True)
    values = [line.split()[0] for line in checked.splitlines()]
    expected = [sha((output / name).read_bytes()) for name in ('manifest.json', 'request.json', 'response.xml')]
    if values != expected:
        raise ValueError('Receipt read-back mismatch')
    source_counts = source_folder / 'operation-counts.json'
    save(output / 'receipt-install.json', dict(readBackSha256=values, productConfigurationWrites=0,
                                               productRestarts=0, humanOperations=0,
                                               sourceCampaignOperations=json.loads(source_counts.read_text())
                                               if source_counts.exists() else None))
    save(output / 'evaluation.json', request('/api/runs/' + run + '/protocol-evidence/evaluate', {}))
    with urllib.request.urlopen(BASE + '/api/runs/' + run + '/result.json', timeout=30) as response:
        (output / 'adopted-result.json').write_bytes(response.read())
    evaluation = output / 'evaluation'
    evaluation.mkdir()
    (evaluation / 'result.json').write_bytes((output / 'adopted-result.json').read_bytes())
    return run, True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--product', choices=sorted(TARGETS), required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--source-folder', required=True)
    args = parser.parse_args()
    print(run_campaign(args.product, args.output, args.source_folder))
