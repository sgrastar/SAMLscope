#!/usr/bin/env python3
"""Export original-bound URL browser diagnostics; never accept a use/nonuse assertion."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from bind_ui_consumer_evidence import bind

SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def export(folder, target):
    bound = bind(folder, url_schemes=True)
    language = json.loads((folder/'ui-language-preparation.json').read_text())
    template = json.loads((folder/'native-ui-template.json').read_text())
    restoration = json.loads((folder/'restoration.json').read_text())
    if not restoration.get('language_settings_unchanged') or not restoration.get('template_unchanged'):
        raise ValueError('Native template/language stability unproven; do not backfill historical evidence')
    if language['preferred_language'] != 'en-US':
        raise ValueError('Unsupported native browser language')
    manifest = {row['id']: row for row in json.loads((folder/'decoded-manifest.json').read_text())}
    observations = []
    for row in bound['observations']:
        variant = row['condition']
        raw = (folder/variant/'browser-observation.json').read_bytes()
        observations.append(dict(variant=variant, fetchReference=row['fetch_reference'],
            metadataReference=row['metadata_reference'], requestReference=row['request_reference'],
            metadataSha256=manifest[row['metadata_reference']]['sha256'],
            requestSha256=manifest[row['request_reference']]['sha256'],
            browserSha256=SHA(raw), browserBase64=base64.b64encode(raw).decode()))
    target_raw = target.read_bytes()
    return dict(schema='samlscope-native-ui-url-receipt-v1', runId=bound['run'],
        targetMetadataSha256=SHA(target_raw), targetEntityId=ET.fromstring(target_raw).attrib['entityID'],
        nativePreparation=dict(source='local-adapter-verified', restored=True,
            propertiesSha256=language['properties_sha256'], preferredLanguage=language['preferred_language'],
            templateSha256=template['sha256'], templateUnchanged=True), observations=observations)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--target-metadata', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = export(args.evidence.resolve(), args.target_metadata)
    with args.output.open('x') as output:
        json.dump(receipt, output, indent=2)
        output.write('\n')
    print('Exported bound URL observations; no native nonuse claim or verdict assigned')
