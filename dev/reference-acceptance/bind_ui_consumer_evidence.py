#!/usr/bin/env python3
"""Bind native UI observations to exact original metadata and browser-sent requests; no verdict."""
import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
SAML = 'urn:oasis:names:tc:SAML:2.0:assertion'
PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol'
CONDITIONS = ['ui-consumer-display-all', 'ui-consumer-display-service', 'ui-consumer-display-entity',
              'ui-consumer-logo-localized', 'ui-consumer-logo-fallback']


def bind(folder):
    def read(name):
        return json.loads((folder / name).read_text())

    run = read('created.json')['run']['id']
    restoration = read('restoration.json')
    if not restoration['restored'] or not restoration['temporary_removed'] or restoration['failures']:
        raise ValueError('Native restoration incomplete')
    if restoration['original_sha256'] != restoration['final_sha256']:
        raise ValueError('Native restoration hash mismatch')
    operations = read('operations.json')
    if operations['run'] != run or not operations['restored']:
        raise ValueError('Operations belong to another or unrestored Run')
    entries = read('transcript.json')
    if len({e['id'] for e in entries}) != len(entries) or any(e['runId'] != run for e in entries):
        raise ValueError('Ambiguous or mixed Run transcripts')
    by_id = {e['id']: e for e in entries}
    originals = {}
    for row in read('decoded-manifest.json'):
        path = folder / row['file']
        if path.resolve().parent != (folder / 'decoded').resolve() or row['id'] in originals:
            raise ValueError('Invalid original evidence path or duplicate')
        raw = path.read_bytes()
        if SHA(raw) != row['sha256'] or row['id'] not in by_id:
            raise ValueError('Original evidence mismatch')
        if by_id[row['id']]['decodedSamlBytes'] != len(raw):
            raise ValueError('Original evidence length mismatch')
        originals[row['id']] = raw
    bound = []
    used_requests = set()
    for condition in CONDITIONS:
        observation = read(condition + '/browser-observation.json')
        receipt_raw = (folder / condition / 'native-import.json').read_bytes()
        receipt = json.loads(receipt_raw)
        fixture = (folder / condition / 'fixture.xml').read_bytes()
        if observation['run_id'] != run or observation['condition'] != condition or receipt['run'] != run:
            raise ValueError('Observation Run/condition mismatch')
        if observation['fixture_sha256'] != SHA(fixture) or receipt['fixture_sha256'] != SHA(fixture):
            raise ValueError('Fixture mismatch')
        if observation['import_receipt_sha256'] != SHA(receipt_raw):
            raise ValueError('Import receipt mismatch')
        if receipt['native_path'] != 'FilesystemMetadataProvider' or not receipt['file_read_back'] or not receipt['resolver_reload_completed']:
            raise ValueError('Native preparation unproven')
        for kind, label in [('write', condition), ('reload', condition), ('write', 'metadata-providers')]:
            matches = [o for o in operations['operations'] if o['operation'] == kind and o['label'] == label]
            if len(matches) != 1 or not matches[0].get('read_back' if kind == 'write' else 'completed'):
                raise ValueError('Native operation incomplete or ambiguous')
            if kind == 'write' and matches[0]['sha256'] != (SHA(fixture) if label == condition else receipt['provider_sha256']):
                raise ValueError('Native read-back mismatch')
        browser = observation['browser_request']
        if browser['status'] != 'captured':
            raise ValueError('Browser request missing or ambiguous')
        candidates = [e for e in entries if e['direction'] == 'OUTBOUND'
            and e.get('samlSummary', {}).get('type') == 'AuthnRequest'
            and e.get('samlSummary', {}).get('variant') == condition
            and e['id'] in originals and SHA(originals[e['id']]) == browser['decoded_sha256']]
        if len(candidates) != 1 or candidates[0]['id'] in used_requests:
            raise ValueError('Browser request has no unique original')
        request = candidates[0]
        used_requests.add(request['id'])
        xml = ET.fromstring(originals[request['id']])
        metadata = ET.fromstring(fixture)
        if xml.tag != '{' + PROTOCOL + '}AuthnRequest' or metadata.tag != '{' + MD + '}EntityDescriptor':
            raise ValueError('Unexpected XML root')
        issuer = xml.find('{' + SAML + '}Issuer')
        if issuer is None or issuer.text != metadata.attrib['entityID'] or xml.get('ID') != request['samlSummary']['id']:
            raise ValueError('Request identity mismatch')
        if xml.get('Destination') != request['url'] or request['url'] != observation['expected_origin'] + browser['endpoint_path']:
            raise ValueError('Request endpoint mismatch')
        if observation['expected_path'] != browser['endpoint_path']:
            raise ValueError('Observed page differs from the request endpoint')
        if request['method'] != browser['method'] or len(originals[request['id']]) != browser['decoded_bytes']:
            raise ValueError('Browser request method/length mismatch')
        prepared = [e for e in entries if e['direction'] == 'OUTBOUND'
            and e.get('samlSummary', {}).get('type') == 'MetadataPrepared'
            and e.get('samlSummary', {}).get('variant') == condition
            and e['id'] in originals and originals[e['id']] == fixture]
        if len(prepared) != 1:
            raise ValueError('Prepared fixture missing or ambiguous')
        prepared = prepared[0]
        fetched = by_id[prepared['samlSummary']['fetchTranscriptId']]
        if fetched['direction'] != 'INBOUND' or fetched['samlSummary']['type'] != 'MetadataFetch' or fetched['samlSummary']['variant'] != condition:
            raise ValueError('Metadata fetch mismatch')
        observed_at = datetime.fromisoformat(observation['observed_at'].replace('Z', '+00:00')).timestamp()
        if not fetched['timestamp'] <= prepared['timestamp'] <= request['timestamp'] <= observed_at:
            raise ValueError('Evidence chronology mismatch')
        bound.append(dict(condition=condition, fixture_sha256=SHA(fixture), request_reference=request['id'],
            metadata_reference=prepared['id'], fetch_reference=fetched['id'],
            observation_sha256=SHA((folder / condition / 'browser-observation.json').read_bytes()),
            status=observation['status'], selected_candidate=observation.get('selected_candidate'),
            reason=observation.get('reason'), accept_language=browser['accept_language'],
            document_language=observation.get('document_language')))
    return dict(schema='samlscope-ui-evidence-binding-v1', run=run, originals_bound=True,
        native_readback_bound=True, native_receipt_trust='local-adapter', verdict_adopted=False, observations=bound)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    result = bind(args.evidence.resolve())
    with (args.evidence / 'ui-evidence-binding.json').open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print('Bound', len(result['observations']), 'observations; no verdict assigned')
