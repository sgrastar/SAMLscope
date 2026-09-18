"""Audit fixed-policy experimental evidence; deliberately does not return/adopt case outcomes."""
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

PREFIX = 'urn:samlscope:test:policy:'
EXPECTED = {
    'baseline': {'anchor'},
    'entity-present': {'anchor', 'entity'},
    'entity-absent': {'anchor'},
    'requested-required': {'anchor', 'required', 'optional'},
    'requested-optional': {'anchor', 'optional'},
    'requested-absent': {'anchor'},
    'index-zero': {'anchor', 'required', 'optional'},
    'index-one': {'anchor', 'surname'},
    'index-zero-repeat': {'anchor', 'required', 'optional'},
}


def verify(folder):
    folder = Path(folder)
    def load(name):
        return json.loads((folder / name).read_text())
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()
    observations, proof, operations = load('observations.json'), load('verified-attribute-evidence.json'), load('operations.json')
    restoration, result = load('restoration.json'), load('result.json')
    run = result['run']['id']
    assert proof['run'] == operations['run'] == run
    assert proof['result_sha256'] == digest(folder / 'result.json')
    assert proof['target_metadata_sha256'] == digest(folder / 'target-metadata.xml')
    assert 'sha256:' + proof['target_metadata_sha256'] == result['target']['metadata_digest']
    assert not proof['plaintext_persisted'] and not proof['private_key_exported']
    assert operations['restored'] and restoration['restored'] and restoration['temporary_file_removed']
    assert not restoration['failures'] and restoration['original_sha256'] == restoration['final_sha256']
    assert len(observations) == len(EXPECTED) == len(proof['observations']) == operations['completed_conditions']
    assert [o['label'] for o in observations] == list(EXPECTED)
    assert all(o['read_back'] for o in operations['operations'] if o['operation'] == 'write')
    assert all(r['completed'] for r in operations['reloads'])
    originals = {}
    for entry in load('decoded-manifest.json'):
        path = (folder / entry['file']).resolve()
        assert path.is_relative_to(folder.resolve())
        assert digest(path) == entry['sha256'] and entry['id'] not in originals
        originals[entry['id']] = ET.fromstring(path.read_bytes())
    transcripts = {e['id']: e for e in load('transcript.json')}
    assert len(transcripts) == len(load('transcript.json'))
    assert all(e['runId'] == run for e in transcripts.values())
    verified = {o['request']: o for o in proof['observations']}
    assert len(verified) == len(EXPECTED)
    fixed = observations[0]['configuration_before']
    indexed_hashes = set()
    response_order = []
    for observation in observations:
        label = observation['label']
        assert observation['run'] == run and observation['status'] == 'protocol-recorded'
        assert observation['configuration_before'] == observation['configuration_after'] == fixed
        assert observation['fixture_sha256'] == digest(folder / label / 'fixture.xml')
        flow = load(label + '/flow.json')
        assert flow['correlated_success'] and flow['positive_exchange']['success']
        refs = flow['positive_exchange']['transcript_ids']
        assert len(refs) == 2
        item = verified[refs[0]]
        assert item['response'] == refs[1] and item['variant'] == observation['variant']
        assert item['response_signature_verified'] and item['decrypted_assertions'] > 0
        request = originals[item['request']]
        response = originals[item['response']]
        assert response.get('InResponseTo') == request.get('ID') == flow['positive_exchange']['request_id']
        assert request.get('AssertionConsumerServiceURL') == response.get('Destination') == transcripts[item['response']]['url']
        assert transcripts[item['request']]['samlSummary']['metadataSignatureControl'] == 'valid'
        request_time = transcripts[item['request']]['timestamp']
        assert request_time <= transcripts[item['response']]['timestamp']
        prepared = [e for e in transcripts.values()
                    if e['direction'] == 'OUTBOUND' and e['samlSummary'].get('type') == 'MetadataPrepared'
                    and e['samlSummary'].get('variant') == observation['variant']
                    and e['timestamp'] <= request_time]
        assert prepared
        latest = max(prepared, key=lambda e: e['timestamp'])
        assert latest['samlSummary']['metadataSha256'] == observation['fixture_sha256']
        assert any(m['id'] == latest['id'] and m['sha256'] == observation['fixture_sha256']
                   for m in load('decoded-manifest.json'))
        fetch = transcripts[latest['samlSummary']['fetchTranscriptId']]
        assert fetch['direction'] == 'INBOUND' and fetch['samlSummary']['type'] == 'MetadataFetch'
        assert fetch['status'] == latest['status'] == 200 and fetch['timestamp'] <= latest['timestamp']
        assert latest['correlationId'] == fetch['id'] and latest['url'] == fetch['url']
        assert {a['name'][len(PREFIX):] for a in item['attributes'] if a['name'].startswith(PREFIX)} == EXPECTED[label]
        assert all(a['name_format'] == 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
                   for a in item['attributes'] if a['name'].startswith(PREFIX))
        selector = observation['selector']
        assert item['attribute_service_index'] == ('' if selector is None else str(selector))
        assert request.get('AttributeConsumingServiceIndex', '') == item['attribute_service_index']
        if selector is not None:
            indexed_hashes.add(observation['fixture_sha256'])
            response_order.append(transcripts[item['response']]['timestamp'])
    assert len(indexed_hashes) == 1 and response_order == sorted(response_order)
    assert len(set(response_order)) == len(response_order)
    assert all(o['metadata_write_skipped'] for o in observations[-2:])
    return dict(run=run, recorded_conditions=len(EXPECTED),
                candidate_cases=['IIP-IDP03-a-idp-01', 'IIP-IDP04-a-idp-01', 'IIP-IDP04-b-idp-01'],
                verdict_adopted=False, restored=True)


if __name__ == '__main__':
    print(json.dumps(verify(sys.argv[1]), ensure_ascii=False))
