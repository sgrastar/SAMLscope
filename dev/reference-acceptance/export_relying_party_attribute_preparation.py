#!/usr/bin/env python3
"""Export a local trusted-adapter receipt after native/protocol binding; no HTTP submission."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from verify_relying_party_attribute_experiment import verify


def export(folder, output):
    audited = verify(folder)
    prepared = json.loads((folder / 'preparation.json').read_text())
    native = prepared['native']
    # The validated native Requester rules inspect the RP identity and common uid-derived markers.
    # Hold the complete native configuration and driver login input fixed across the RP change.
    stable = hashlib.sha256(json.dumps(dict(policy=native['policy_sha256'],
        configuration=native['configuration_sha256'], source_attribute='uid'),
        sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    conditions = {'first': 'FIRST', 'second': 'SECOND', 'first-repeat': 'FIRST_REPEAT'}
    target = (folder / 'target-metadata.xml').read_bytes()
    receipt = dict(schema='samlscope-native-relying-party-attribute-receipt-v1', runId=audited['run'],
        targetEntityId=ET.fromstring(target).get('entityID'), targetMetadataSha256=hashlib.sha256(target).hexdigest(),
        preparation=dict(runId=audited['run'], experimentId='native-rp-policy-' + audited['run'],
            exchanges=[dict(condition=conditions[row['condition']], requestReference=row['request_reference'],
                responseReference=row['response_reference'], policyFingerprint=native['policy_sha256'],
                loginInputFingerprint=prepared['login_input_binding'], stableInputFingerprint=stable)
                for row in audited['exchanges']]),
        rawEvidence=[dict(reference=row['id'], sha256=row['sha256'])
            for row in json.loads((folder / 'decoded-manifest.json').read_text())])
    raw = (json.dumps(receipt, indent=2) + '\n').encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        if output.is_symlink() or output.read_bytes() != raw: raise ValueError('Receipt is immutable')
    else:
        with output.open('xb') as stream: stream.write(raw)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = export(args.evidence.resolve(), args.output.resolve())
    print('Exported local preparation for', result['runId'], '; no verdict submitted')
