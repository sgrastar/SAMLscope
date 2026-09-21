#!/usr/bin/env python3
"""Export original-bound native display observations; never supply an outcome."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from bind_ui_consumer_evidence import bind
from ui_display_comparison import CONDITIONS


def export(folder, target):
    bound = bind(folder, display_names_only=True)
    issues = bound['display_comparison']['issues']
    # A missing/known different selection may be examined by Runner. Unbound inputs may not.
    if any(not issue.endswith(':selection-unproven') for issue in issues):
        raise ValueError('Native display experiment inputs are not controlled')
    preparation = json.loads((folder / 'ui-language-preparation.json').read_text())
    template = json.loads((folder / 'native-ui-template.json').read_text())
    restoration = json.loads((folder / 'restoration.json').read_text())
    if not restoration.get('language_settings_unchanged') or not restoration.get('template_unchanged'):
        raise ValueError('Native UI configuration changed')
    rows = {row['condition']: row for row in bound['observations']}
    manifest = {row['id']: row for row in json.loads((folder / 'decoded-manifest.json').read_text())}
    observations = []
    for variant in CONDITIONS:
        row = rows[variant]
        raw = (folder / variant / 'browser-observation.json').read_bytes()
        observations.append(dict(variant=variant, fetchReference=row['fetch_reference'],
            metadataReference=row['metadata_reference'], requestReference=row['request_reference'],
            metadataSha256=manifest[row['metadata_reference']]['sha256'],
            requestSha256=manifest[row['request_reference']]['sha256'],
            browserSha256=hashlib.sha256(raw).hexdigest(), browserBase64=base64.b64encode(raw).decode()))
    raw_target = target.read_bytes()
    return dict(schema='samlscope-native-ui-display-receipt-v1', runId=bound['run'],
        targetMetadataSha256=hashlib.sha256(raw_target).hexdigest(),
        targetEntityId=ET.fromstring(raw_target).attrib['entityID'],
        nativePreparation=dict(source='local-adapter-verified', restored=True,
            propertiesSha256=preparation['properties_sha256'], preferredLanguage=preparation['preferred_language'],
            templateSha256=template['sha256'], templateUnchanged=True), observations=observations)


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
    print('Exported native display receipt; no verdict assigned')
