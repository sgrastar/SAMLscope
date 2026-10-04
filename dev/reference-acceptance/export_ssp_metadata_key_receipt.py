#!/usr/bin/env python3
"""Bind SimpleSAMLphp native parser, configuration readback and HTTP originals to key conditions."""
import argparse
import base64
import datetime
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
    http = read('native-http-observations.json')
    if http['run'] != run or http['product_verdict_assigned'] is not False:
        raise ValueError('Mixed native observation')
    restoration=json.loads((folder.parent/'restoration.json').read_text())
    if not restoration['restored'] or restoration['original_sha256']!=restoration['final_sha256']:
        raise ValueError('Native configuration restoration unproven')
    if read('baseline/flow.json')!='recorded':
        raise ValueError('Ordinary login control unavailable')
    collected=datetime.datetime.fromtimestamp((folder/'native-http-observations.json').stat().st_mtime,datetime.timezone.utc).isoformat()
    rows = []
    issues = []
    for variant in VARIANTS:
        try:
            imported = read(variant + '/import.json')
            fixture = (folder / variant / 'fixture.xml').read_bytes()
            prepared = [e for e in transcript if e['samlSummary'].get('type') == 'MetadataPrepared'
                        and e['samlSummary'].get('variant') == variant]
            if len(prepared) != 1 or imported['fixture_sha256'] != SHA(fixture):
                raise ValueError('Fixture import identity mismatch')
            prepared = prepared[0]
            if prepared['id'] not in originals or next(r['sha256'] for r in raw_refs if r['reference'] == prepared['id']) != SHA(fixture):
                raise ValueError('Import differs from recorded original')
            entity = ET.fromstring(fixture).get('entityID')
            parser_raw=(folder/variant/'parser-output.json').read_bytes()
            parsed=json.loads(parser_raw)
            if (imported['run']!=run or imported['entity_id']!=entity
                    or imported['import_path']!='native-parser-cli' or not imported['configuration_read_back']
                    or imported['validate_authnrequest'] is not True or parsed['validate_authnrequest'] is not True
                    or parsed['entity_id']!=entity or SHA(parser_raw)!=imported['parser_output_sha256']):
                raise ValueError('Native parser/configuration binding unproven')
            row=dict(variant=variant,metadataReference=prepared['id'],nativeImport=dict(
                fixtureSha256=SHA(fixture),entityId=entity,readbackVerified=True,source='native-parser-cli',
                parserOutputBase64=base64.b64encode(parser_raw).decode(),parserOutputSha256=SHA(parser_raw),
                configurationSha256=imported['configuration_sha256'],signaturePolicy=True))
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
                events = []
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
        evidenceAdapter='simplesamlphp-native-http',collectedAt=collected,
        configurationOriginalSha256=restoration['original_sha256'],configurationFinalSha256=restoration['final_sha256'],
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
    print('SimpleSAMLphp key-selection receipt exported; Runner verification required')
