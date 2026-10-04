#!/usr/bin/env python3
"""Export bound native browser evidence for the local Runner adapter, never an outcome."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from bind_ui_consumer_evidence import bind


def export(folder, target):
    bound = bind(folder)
    if bound['logo_comparison']['status'] != 'difference-observed':
        raise ValueError('Native differential observation unavailable')
    preparation = json.loads((folder / 'ui-language-preparation.json').read_text())
    rows = {row['condition']: row for row in bound['observations']}
    manifest = {row['id']: row for row in json.loads((folder / 'decoded-manifest.json').read_text())}
    observations = []
    for variant in ['ui-consumer-logo-localized', 'ui-consumer-logo-fallback']:
        row = rows[variant]
        # Validate the candidate mapping used by the browser against the original fixture.
        metadata = ET.fromstring((folder / variant / 'fixture.xml').read_bytes())
        logos = metadata.findall('.//{urn:oasis:names:tc:SAML:metadata:ui}Logo')
        mapping = {('localized' if logo.get('{http://www.w3.org/XML/1998/namespace}lang') else 'default'): logo.text for logo in logos}
        inputs = json.loads((folder / variant / 'browser-input.json').read_text())['observation']
        if inputs['kind'] != 'logo' or inputs['candidates'] != mapping:
            raise ValueError('Browser candidate mapping differs from original metadata')
        raw = (folder / variant / 'browser-observation.json').read_bytes()
        observations.append(dict(variant=variant, fetchReference=row['fetch_reference'],
            metadataReference=row['metadata_reference'], requestReference=row['request_reference'],
            metadataSha256=manifest[row['metadata_reference']]['sha256'],
            requestSha256=manifest[row['request_reference']]['sha256'],
            browserSha256=hashlib.sha256(raw).hexdigest(), browserBase64=base64.b64encode(raw).decode()))
    raw_target = target.read_bytes()
    return dict(schema='samlscope-native-ui-logo-receipt-v1', runId=bound['run'],
        targetMetadataSha256=hashlib.sha256(raw_target).hexdigest(),
        targetEntityId=ET.fromstring(raw_target).attrib['entityID'],
        nativePreparation=dict(source='local-adapter-verified', restored=True,
            propertiesSha256=preparation['properties_sha256'],
            fallbackLanguages=preparation['fallback_languages'], preferredLanguage=preparation['preferred_language']),
        observations=observations)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--target-metadata', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = export(args.evidence.resolve(), args.target_metadata)
    with args.output.open('x') as output:
        json.dump(result, output, indent=2)
        output.write('\n')
    print('Exported native UI receipt; no verdict assigned')
