#!/usr/bin/env python3
"""Bind Shibboleth filesystem-provider import, request-bound audit rows and originals to key conditions."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shibboleth'))
from metadata_key_matrix import KEY_CONDITIONS as VARIANTS
from signature_audit_format import signature_audit, FORMAT

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
PROFILE = 'http://shibboleth.net/ns/profiles/saml2/sso/browser'
SHA256 = lambda value: isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def audit_row(row, request_id, entity):
    if (row.get('request_id') != request_id or row.get('sp') != entity
            or row.get('signed_inbound') != 'true' or row.get('binding') != 'POST'
            or row.get('profile') != PROFILE):
        raise ValueError('Native audit identity mismatch')
    datetime.datetime.fromisoformat(row['timestamp'].replace('Z', '+00:00'))
    return row


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
    audits = read('native-signature-audit.json')
    if audits['run'] != run or audits['format'] != FORMAT:
        raise ValueError('Mixed or unexpected native audit')
    audit_rows = {}
    for row in audits['rows']:
        if row.get('request_id') in audit_rows:
            raise ValueError('Duplicated native audit row')
        audit_rows[row['request_id']] = row
    restoration = read('restoration.json')
    if not restoration['restored'] or restoration['original_sha256'] != restoration['final_sha256']:
        raise ValueError('Native provider restoration unproven')
    campaign = json.loads((folder.parent / 'restoration.json').read_text())
    if not campaign['restored'] or campaign['original_sha256'] != campaign['final_sha256'] or campaign['failures']:
        raise ValueError('Native audit restoration unproven')
    original_audit = (folder.parent / 'original-audit.xml').read_bytes()
    configured_audit = (folder.parent / 'configured-audit.xml').read_bytes()
    if signature_audit(original_audit) != configured_audit or original_audit == configured_audit:
        raise ValueError('Request-bound audit configuration unproven')
    control = read('control/flow.json')
    if control.get('correlated_success') is not True:
        raise ValueError('Ordinary login positive control unavailable')
    configuration = (folder / 'configured-providers.xml').read_bytes()
    if SHA((folder / 'original-providers.xml').read_bytes()) != restoration['original_sha256']:
        raise ValueError('Provider configuration differs from restored state')
    collected = datetime.datetime.fromtimestamp((folder / 'native-signature-audit.json').stat().st_mtime,
                                                datetime.timezone.utc).isoformat()
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
            if (imported['run'] != run or imported['entity_id'] != entity
                    or imported['import_path'] != 'native-filesystem-provider'
                    or imported['configuration_read_back'] is not True
                    or imported['provider_reloaded'] is not True):
                raise ValueError('Native provider import binding unproven')
            for request in [e for e in transcript if e['direction'] == 'OUTBOUND'
                            and e['samlSummary'].get('type') == 'AuthnRequest'
                            and e['samlSummary'].get('variant') == variant]:
                row = audit_rows.get(request['samlSummary']['id'])
                if row is None:
                    raise ValueError('Request-bound native audit row unavailable')
                audit_row(row, request['samlSummary']['id'], entity)
            row = dict(variant=variant, metadataReference=prepared['id'], nativeImport=dict(
                fixtureSha256=SHA(fixture), entityId=entity, readbackVerified=True,
                source='native-filesystem-provider', configurationSha256=SHA(configuration),
                providerReloaded=True, signaturePolicy=True))
            requests = [e for e in transcript if e['direction'] == 'OUTBOUND'
                        and e['samlSummary'].get('type') == 'AuthnRequest' and e['samlSummary'].get('variant') == variant]
            if len(requests) != 2:
                raise ValueError('Request pair unavailable')
            for request in requests:
                identity = request['samlSummary']['id']
                slot = 'negative' if request['samlSummary'].get('metadataSignatureControl') == 'invalid' else 'positive'
                if slot in row or request['id'] not in originals:
                    raise ValueError('Request pair ambiguous')
                native_audit = [audit_rows[identity]] if identity in audit_rows else []
                responses = [e for e in transcript if e['direction'] == 'INBOUND'
                             and e['samlSummary'].get('type') == 'Response' and e['id'] in originals
                             and originals[e['id']].get('InResponseTo') == identity]
                if len(native_audit) != 1 or len(responses) > 1:
                    raise ValueError('Ambiguous native request decision')
                row[slot] = dict(requestReference=request['id'], nativeAudit=native_audit[0])
                if responses:
                    row[slot]['responseReference'] = responses[0]['id']
            if not {'positive', 'negative'} <= row.keys():
                raise ValueError('Missing request control')
            rows.append(row)
        except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
            issues.append(dict(variant=variant, code='native-condition-unavailable',
                               error_type=type(error).__name__, reason=str(error)))
    return dict(schema='samlscope-native-key-selection-receipt-v1', runId=run,
        targetMetadataSha256=SHA((folder / 'target-metadata.xml').read_bytes()), restored=True,
        evidenceAdapter='shibboleth-audit', collectedAt=collected, auditFormat=FORMAT,
        auditOriginalSha256=SHA(original_audit), auditConfiguredSha256=SHA(configured_audit),
        auditFinalSha256=campaign['final_sha256'], nativeAuditSha256=SHA((folder / 'native-signature-audit.json').read_bytes()),
        observerSourceSha256=SHA(configured_audit),
        providerOriginalSha256=restoration['original_sha256'], providerFinalSha256=restoration['final_sha256'],
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
    print('Shibboleth key-selection receipt exported; Runner verification required')
