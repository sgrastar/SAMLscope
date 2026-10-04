#!/usr/bin/env python3
"""Export native certificate observations for Runner to independently verify; no outcome supplied."""
import argparse
import hashlib
import json
from pathlib import Path
from diagnose_native_certificate_requests import diagnose


def export(folder):
    diagnose(folder)  # Recheck source hashes, original signatures, import readback and restoration.
    read = lambda name: json.loads((folder / name).read_text())
    proof = read('verified-certificate-requests.json')
    transcript = read('transcript.json')
    manifest = read('decoded-manifest.json')
    http = read('native-http-observations.json')['records']
    events = read('native-signature-audit.json')['rows']
    restoration = json.loads((folder.parent.parent / 'observer/restoration.json').read_text())
    rows = []
    for observation in proof['observations']:
        variant = observation['variant']
        imported = read(variant + '/import.json')
        prepared = [e for e in transcript if e['samlSummary'].get('type') == 'MetadataPrepared'
                    and e['samlSummary'].get('variant') == variant]
        if len(prepared) != 1:
            raise ValueError('Ambiguous prepared metadata')
        row = dict(variant=variant, metadataReference=prepared[0]['id'], nativeClient=dict(
            clientId=imported['import']['read_back']['client_id'],
            databaseId=imported['client']['database_id'], removed=imported['cleanup']['read_back_absent'],
            attributes=imported['import']['read_back']['saml_attributes']))
        for request in observation['requests']:
            slot = 'negative' if request['negative_control'] else 'positive'
            if slot in row:
                raise ValueError('Duplicate request slot')
            matched_http = [r for r in http if r['request_id'] == request['request_id']]
            matched_events = [r for r in events if r['request_id'] == request['request_id']]
            responses = request['signed_success_responses']
            if len(matched_http) != 1 or len(matched_events) > 1 or len(responses) > 1:
                raise ValueError('Ambiguous request evidence')
            row[slot] = dict(requestReference=request['request'], nativeHttp=matched_http[0])
            if matched_events:
                row[slot]['nativeEvent'] = matched_events[0]
            if responses:
                row[slot]['responseReference'] = responses[0]
        if not {'positive', 'negative'} <= row.keys():
            raise ValueError('Missing signature control')
        rows.append(row)
    return dict(schema='samlscope-native-certificate-receipt-v1', runId=proof['run'],
        targetMetadataSha256=proof['target_metadata_sha256'], restored=True,
        collectedAt=restoration['finished_at'], observerSourceSha256=restoration['source_sha256'],
        nativeAuditSha256=hashlib.sha256((folder/'native-signature-audit.json').read_bytes()).hexdigest(),
        rawEvidence=[dict(reference=r['id'], sha256=r['sha256']) for r in manifest], conditions=rows)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = export(args.evidence.resolve())
    with args.output.open('x') as out:
        json.dump(receipt, out, indent=2)
        out.write('\n')
    print('Exported native certificate receipt; no verdict assigned')
