#!/usr/bin/env python3
"""Export a native SimpleSAMLphp MDQ rejection from one restored Run."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from datetime import datetime, timedelta, timezone

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
SUITE = 'samlscope-reference-suite'
PRODUCT = 'samlscope-reference-ssp'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign-dir', type=Path, required=True)
    parser.add_argument('--variant', choices=('expired', 'schema-global-element-families'), default='expired')
    args = parser.parse_args()
    folder = args.campaign_dir.resolve()
    variant = args.variant
    run = json.loads((folder / 'created.json').read_text())['run']['id']
    transcript = json.loads((folder / 'transcript.json').read_text())
    if {entry['runId'] for entry in transcript} != {run}:
        raise ValueError('Transcript Run mismatch')
    restoration = json.loads((folder / 'restoration.json').read_text())
    original = (folder / 'original-config.php').read_bytes()
    final = (folder / 'final-config.php').read_bytes()
    if original != final or not restoration['restored'] or restoration['final_sha256'] != SHA(final):
        raise ValueError('Configuration was not restored')
    expired = folder / variant
    prepared = [entry for entry in transcript if entry['direction'] == 'OUTBOUND'
                and entry['samlSummary'].get('type') == 'MetadataPrepared'
                and entry['samlSummary'].get('variant') == variant]
    requests = [entry for entry in transcript if entry['direction'] == 'OUTBOUND'
                and entry['samlSummary'].get('type') == 'AuthnRequest'
                and entry['samlSummary'].get('variant') == variant]
    if len(prepared) != 2 or len(requests) != 1:
        raise ValueError('Unexpected expiry transcript shape')
    delivery = prepared[-1]
    request = requests[0]
    if request['timestamp'] >= delivery['timestamp']:
        raise ValueError('Product MDQ fetch did not follow request')
    entity = json.loads((folder / 'plan.json').read_text())['plan']['plan']['id']
    entity = 'http://localhost:18080/p/' + entity
    start = datetime.fromtimestamp(request['timestamp'] - 1, timezone.utc)
    end = datetime.fromtimestamp(delivery['timestamp'] + 10, timezone.utc)
    lines = subprocess.check_output(['docker', 'logs', '--since', start.isoformat(), '--until',
                                     end.isoformat(), PRODUCT], stderr=subprocess.STDOUT, timeout=30).decode().splitlines()
    marker = ('[critical] Uncaught Exception: Metadata for the entity [' + entity + '] expired '
              if variant == 'expired' else
              '[critical] Uncaught Exception: Must have at least one AuthzService in PDPDescriptor.')
    matches = [line for line in lines if marker in line]
    if len(matches) != 1:
        raise ValueError(f'Expected one native expiry record, found {len(matches)}')
    log = matches[0]
    (expired / 'native-rejection.log').write_text(log + '\n')
    decoded = folder / 'decoded'
    decoded.mkdir(exist_ok=True)
    manifest = []
    for entry in transcript:
        ref = entry.get('decodedSamlRef')
        if not ref:
            continue
        destination = decoded / (entry['id'] + '.xml')
        subprocess.run(['docker', 'cp', SUITE + ':/data/' + ref, str(destination)],
                       check=True, capture_output=True, timeout=30)
        manifest.append(dict(id=entry['id'], file='decoded/' + destination.name,
                             sha256=SHA(destination.read_bytes())))
    (folder / 'decoded-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    fixture = (expired / 'proxy-response.xml').read_bytes()
    if SHA(fixture) != next(row['sha256'] for row in manifest if row['id'] == delivery['id']):
        raise ValueError('Delivered expiry fixture is not the Run original')
    target = folder / 'target-metadata.xml'
    subprocess.run(['docker', 'cp', SUITE + ':/data/target-metadata/' + run + '.xml', str(target)],
                   check=True, capture_output=True, timeout=30)
    adapter = ('simplesamlphp-native-mdq' if variant == 'expired' else
               'simplesamlphp-native-mdq-positive')
    receipt = dict(schema='samlscope-native-metadata-rejection-receipt-v1', runId=run,
                   targetMetadataSha256=SHA(target.read_bytes()), restored=True,
                   evidenceAdapter=adapter,
                   rawEvidence=[dict(reference=row['id'], sha256=row['sha256']) for row in manifest],
                   rejections=[dict(variant=variant, fixtureSha256=SHA(fixture),
                                    nativeRejection=dict(source=adapter,
                                                         detailSha256=SHA(log.encode()),
                                                         logRecord=log, requestReference=request['id']))],
                   conditionIssues=[])
    receipt_name = ('native-rejection-receipt.json' if variant == 'expired'
                    else 'native-positive-rejection-receipt.json')
    (folder / receipt_name).write_text(json.dumps(receipt, indent=2) + '\n')
    print(run, SHA(log.encode()))


if __name__ == '__main__':
    main()
