#!/usr/bin/env python3
"""Audit local native preparation and exact protocol references; no conformance verdict."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shibboleth'))
from relying_party_attribute_preparation import recipe
from attribute_policy_preparation import canonical


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def verify(folder):
    def read(name): return json.loads((folder / name).read_text())
    run = read('created.json')['run']['id']
    restoration = read('restoration.json')
    if not restoration['restored'] or restoration['failures'] or not restoration['temporary_removed'] \
            or restoration['original_sha256'] != restoration['final_sha256']:
        raise ValueError('Native restoration unproven')
    prepared = read('preparation.json')
    native = prepared['native']
    if native['run'] != run or prepared['login_provenance'] != 'fixed-in-memory-driver-input':
        raise ValueError('Preparation scope unproven')
    files = {side: native['nodes']['metadata-providers'][0]['attributes']['metadataFile'] for side in ['first', 'second']}
    expected = {name: [canonical(node) for node in nodes] for name, nodes in recipe(run, native['entity_ids'], files).items()}
    if native['nodes'] != expected or native['policy_sha256'] != digest(json.dumps(expected,
            sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()):
        raise ValueError('Native policy meaning differs from recipe')
    protocol = read('production-observation.json')
    if protocol['run'] != run or protocol['issues'] or not protocol['same_attribute_input']:
        raise ValueError('Verified attribute exchanges unavailable')
    if protocol['transcript_sha256'] != digest((folder / 'transcript.json').read_bytes()) \
            or protocol['target_metadata_sha256'] != digest((folder / 'target-metadata.xml').read_bytes()):
        raise ValueError('Production observation originals changed')
    entries = read('transcript.json')
    by_id = {entry['id']: entry for entry in entries}
    if len(by_id) != len(entries) or any(entry['runId'] != run for entry in entries):
        raise ValueError('Transcript scope ambiguous')
    originals = {}
    for row in read('decoded-manifest.json'):
        path = (folder / row['file']).resolve()
        if path.parent != (folder / 'decoded').resolve() or row['id'] in originals:
            raise ValueError('Invalid original evidence path')
        raw = path.read_bytes()
        if digest(raw) != row['sha256'] or len(raw) != by_id[row['id']]['decodedSamlBytes']:
            raise ValueError('Original evidence changed')
        originals[row['id']] = raw
    observations = read('observations.json')
    if [row['condition'] for row in observations] != ['first', 'second', 'first-repeat'] or len(protocol['observations']) != 3:
        raise ValueError('Incomplete ordered comparison')
    used = set()
    bindings = []
    for observation, verified in zip(observations, protocol['observations']):
        if observation['before'] != native or observation['after'] != native \
                or observation['login_input_binding'] != prepared['login_input_binding']:
            raise ValueError('Native preparation or driver input changed')
        if verified['variant'] != observation['variant'] or verified['entity_id'] != observation['entity_id']:
            raise ValueError('Relying party association differs')
        refs = [ref['reference'] for ref in verified['evidence']]
        if len(refs) != 4 or set(refs[2:]) != set(observation['new_transcript_ids']) or used.intersection(refs[2:]):
            raise ValueError('Exchange provenance differs or reused')
        used.update(refs[2:])
        if originals[refs[1]] != (folder / 'fixture.xml').read_bytes():
            raise ValueError('Native imported aggregate differs from Recorder')
        request = ET.fromstring(originals[refs[2]])
        if request.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text != observation['entity_id']:
            raise ValueError('Original requester differs')
        side = 'second' if observation['condition'] == 'second' else 'first'
        if verified['markers'] != ['anchor', side] or observation['entity_id'] != native['entity_ids'][side]:
            raise ValueError('Entity-specific attribute difference unobserved')
        bindings.append(dict(condition=observation['condition'], entity_id=observation['entity_id'],
            request_reference=refs[2], response_reference=refs[3], markers=verified['markers']))
    return dict(run=run, native_preparation_bound=True, exchanges=bindings,
                same_attribute_input=True, verdict_adopted=False,
                reason='formal-case-registration-and-receipt-verification-pending')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    folder = parser.parse_args().evidence.resolve()
    report = verify(folder)
    with (folder / 'native-protocol-binding.json').open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print('Native preparation and protocol references bound; no verdict assigned')
