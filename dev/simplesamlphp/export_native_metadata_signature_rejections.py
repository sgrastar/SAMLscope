#!/usr/bin/env python3
"""Bind native MDQ signature refusals to their recorded fixture and configuration originals."""
import argparse
import hashlib
import json
from pathlib import Path
import ssl

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
ADAPTER = 'simplesamlphp-native-mdq-signature'
SUPPORTED = {'unsigned', 'bad-signature', 'signed-other-key', 'xpath-identity',
             'xpath-exclude-role-descriptors', 'xpath-exclude-endpoints',
             'xpath-exclude-key-descriptors'}


def export(folder):
    folder = Path(folder).resolve()
    load = lambda path: json.loads((folder / path).read_text())
    run = load('created.json')['run']['id']
    signature_path = next((folder / name for name in
        ('signature-verification-receipt-repaired-v2.json', 'signature-verification-receipt.json')
        if (folder / name).is_file()))
    signature = json.loads(signature_path.read_text())
    assert signature['runId'] == run
    transcript = load('transcript-before-receipt.json')
    entries = {entry['id']: entry for entry in transcript}
    assert len(entries) == len(transcript)
    manifest = load('decoded-manifest.json')
    originals = {}
    for row in manifest:
        path = (folder / row['file']).resolve()
        assert path.parent == folder / 'decoded'
        raw = path.read_bytes()
        assert SHA(raw) == row['sha256'] and row['id'] not in originals
        originals[row['id']] = raw
    prepared = {entry['samlSummary']['variant']: entry for entry in transcript
        if entry['direction'] == 'OUTBOUND' and entry.get('samlSummary', {}).get('type') == 'MetadataPrepared'}
    validation_records = {}
    for reference, raw in originals.items():
        try:
            record = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(record, dict) or record.get('artifact') != 'metadata-signature-native-validation':
            continue
        variant = record.get('variant')
        if variant in SUPPORTED and record.get('outcome') == 'rejected':
            assert record['runId'] == run
            validation_records.setdefault(variant, []).append((reference, record))
    # A repaired invalid-signature control supersedes the old, unrelated trust key.
    invalid = next(item for item in signature['negativeControls'] if item['kind'] == 'invalid-signature')
    validation_records['bad-signature'] = [(invalid['nativeRejectionReference'],
        json.loads(originals[invalid['nativeRejectionReference']]))]
    rejections = []
    raw_refs = set()
    for variant in sorted(validation_records):
        if variant not in prepared:
            continue
        records = validation_records[variant]
        assert len(records) == 1, 'ambiguous native rejection: ' + variant
        reference, record = records[0]
        configuration_reference = record['configurationReference']
        effective_reference = record['effectiveConfigurationReference']
        assert SHA(originals[configuration_reference]) == record['configurationSha256']
        anchors = []
        for candidate, raw in originals.items():
            if not raw.startswith(b'-----BEGIN CERTIFICATE-----'):
                continue
            fingerprint = SHA(ssl.PEM_cert_to_DER_cert(raw.decode()))
            timestamp = entries[candidate]['timestamp']
            if (fingerprint == record['trustAnchorCertificateSha256']
                and entries[configuration_reference]['timestamp'] <= timestamp <= entries[reference]['timestamp']):
                anchors.append(candidate)
        assert len(anchors) == 1, 'ambiguous anchor original: ' + variant
        anchor_reference = anchors[0]
        configuration = dict(reference=configuration_reference,
            sha256=SHA(originals[configuration_reference]),
            effectiveReference=effective_reference, effectiveSha256=SHA(originals[effective_reference]),
            trustAnchorReference=anchor_reference,
            trustAnchorOriginalSha256=SHA(originals[anchor_reference]),
            trustAnchorCertificateSha256=record['trustAnchorCertificateSha256'],
            certificateLocation=record['certificateLocation'])
        fixture_reference = prepared[variant]['id']
        assert SHA(originals[fixture_reference]) == record['fixtureSha256']
        rejections.append(dict(variant=variant, fixtureSha256=record['fixtureSha256'],
            nativeRejection=dict(source=ADAPTER, reference=reference,
                detailSha256=SHA(originals[reference]), configurationReadBack=configuration)))
        raw_refs.update([reference, fixture_reference, configuration_reference,
                         effective_reference, anchor_reference])
    assert {'unsigned', 'bad-signature', 'signed-other-key'} <= {row['variant'] for row in rejections}
    restoration = load('restoration.json')
    assert restoration['restored'] and restoration['original_sha256'] == restoration['final_sha256']
    target = (folder / 'target-metadata.xml').read_bytes()
    receipt = dict(schema='samlscope-native-metadata-rejection-receipt-v1', runId=run,
        evidenceAdapter=ADAPTER, targetMetadataSha256=SHA(target), restored=True, conditionIssues=[],
        rawEvidence=[dict(reference=reference, sha256=SHA(originals[reference]))
                     for reference in sorted(raw_refs)], rejections=rejections)
    output = folder / 'qualified-metadata-rejection-receipt.json'
    raw = (json.dumps(receipt, indent=2) + '\n').encode()
    if output.exists() and output.read_bytes() != raw:
        raise RuntimeError('Refusing to replace a different qualified receipt')
    output.write_bytes(raw)
    return output, sorted(row['variant'] for row in rejections)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--campaign', required=True, type=Path)
    args = parser.parse_args()
    output, variants = export(args.campaign)
    print(output, ','.join(variants))
