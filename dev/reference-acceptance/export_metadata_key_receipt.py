#!/usr/bin/env python3
"""Bind native key-selection collection to original transcript bytes; Runner verifies signatures and decisions."""
import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

from metadata_key_matrix import KEY_CONDITIONS as VARIANTS
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def export(folder):
    read = lambda name: json.loads((folder / name).read_text())
    run = read('created.json')['run']['id']
    transcript = read('transcript.json')
    entries = {e['id']: e for e in transcript}
    if len(entries) != len(transcript) or any(e['runId'] != run for e in transcript):
        raise ValueError('Mixed or duplicated transcript')
    raw_refs = []
    originals = {}
    for row in read('decoded-manifest.json'):
        source = folder / row['file']
        path = source.resolve()
        if path.parent != (folder / 'decoded').resolve() or source.is_symlink():
            raise ValueError('Invalid original path')
        raw = path.read_bytes()
        if SHA(raw) != row['sha256'] or row['id'] not in entries or row['id'] in originals:
            raise ValueError('Original identity mismatch')
        originals[row['id']] = ET.fromstring(raw)
        raw_refs.append(dict(reference=row['id'], sha256=row['sha256']))
    audit = read('native-signature-audit.json')
    http = read('native-http-observations.json')
    if audit['run'] != run or http['run'] != run or audit['listener'] != 'samlscope-signature-observation':
        raise ValueError('Mixed native collection')
    campaign = folder.parent.parent
    restoration = json.loads((campaign / 'observer/restoration.json').read_text())
    if not all(restoration.get(k) for k in ('previously_absent', 'readback_verified', 'provider_removed',
            'realm_configuration_restored', 'product_restart_verified')) or restoration['failures']:
        raise ValueError('Observer restoration unproven')
    if SHA((campaign / 'observer/SignatureEventListenerFactory.java').read_bytes()) != restoration['source_sha256']:
        raise ValueError('Observer source mismatch')
    rows = []
    issues = []
    for variant in VARIANTS:
        try:
            imported = read(variant + '/import.json')
            fixture = (folder / variant / 'fixture.xml').read_bytes()
            prepared = [e for e in transcript if e['samlSummary'].get('type') == 'MetadataPrepared'
                        and e['samlSummary'].get('variant') == variant]
            if len(prepared) != 1 or imported['fixture']['sha256'] != SHA(fixture):
                raise ValueError('Fixture import identity mismatch')
            prepared = prepared[0]
            if prepared['id'] not in originals or next(r['sha256'] for r in raw_refs if r['reference'] == prepared['id']) != SHA(fixture):
                raise ValueError('Import differs from recorded original')
            entity = ET.fromstring(fixture).get('entityID')
            native = imported['import']['read_back']
            if (imported['import']['ui_status'] != 'client-settings-page'
                    or native['client_id'] != entity or not imported['cleanup']['read_back_absent']):
                raise ValueError('Native import/cleanup unproven')
            row = dict(variant=variant, metadataReference=prepared['id'],
                nativeImport=dict(fixtureSha256=SHA(fixture), entityId=entity,
                    uiStatus=imported['import']['ui_status'], readbackVerified=True),
                nativeClient=dict(clientId=entity, databaseId=imported['client']['database_id'],
                    removed=True, attributes=native['saml_attributes']))
            requests = [e for e in transcript if e['direction'] == 'OUTBOUND'
                and e['samlSummary'].get('type') == 'AuthnRequest' and e['samlSummary'].get('variant') == variant]
            if len(requests) != 2:
                raise ValueError('Request pair unavailable')
            for request in requests:
                identity = request['samlSummary']['id']
                slot = 'negative' if request['samlSummary'].get('metadataSignatureControl') == 'invalid' else 'positive'
                if slot in row or request['id'] not in originals:
                    raise ValueError('Request pair ambiguous')
                native_http = [r for r in http['records'] if r['request_id'] == identity]
                events = [r for r in audit['rows'] if r['request_id'] == identity]
                responses = [e for e in transcript if e['direction'] == 'INBOUND'
                    and e['samlSummary'].get('type') == 'Response' and e['id'] in originals
                    and originals[e['id']].get('InResponseTo') == identity]
                if len(native_http) != 1 or len(events) > 1 or len(responses) > 1 or (events and responses):
                    raise ValueError('Ambiguous native request decision')
                row[slot] = dict(requestReference=request['id'], nativeHttp=native_http[0])
                if events:
                    row[slot]['nativeEvent'] = events[0]
                if responses:
                    row[slot]['responseReference'] = responses[0]['id']
            if not {'positive', 'negative'} <= row.keys():
                raise ValueError('Missing request control')
            rows.append(row)
        except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
            issues.append(dict(variant=variant,code='native-condition-unavailable',
                               error_type=type(error).__name__,reason=str(error)))
    return dict(schema='samlscope-native-key-selection-receipt-v1', runId=run,
        targetMetadataSha256=SHA((folder / 'target-metadata.xml').read_bytes()), restored=True,
        collectedAt=restoration['finished_at'], observerSourceSha256=restoration['source_sha256'],
        nativeAuditSha256=SHA((folder / 'native-signature-audit.json').read_bytes()),
        rawEvidence=raw_refs, conditions=rows, conditionIssues=issues)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = export(args.evidence.resolve())
    with args.output.open('x') as stream:
        json.dump(receipt, stream, indent=2)
        stream.write('\n')
    print('Native key-selection receipt exported; Runner verification required')
