#!/usr/bin/env python3
"""Export an audited local-adapter receipt; never submit a verdict or expose a network input."""
import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from verify_attribute_policy_experiment import verify

CONDITIONS = {
    'baseline': 'BASELINE', 'entity-present': 'ENTITY_PRESENT', 'entity-absent': 'ENTITY_ABSENT',
    'requested-required': 'REQUESTED_REQUIRED', 'requested-optional': 'REQUESTED_OPTIONAL',
    'requested-absent': 'REQUESTED_ABSENT', 'index-zero': 'INDEX_ZERO',
    'index-one': 'INDEX_ONE', 'index-zero-repeat': 'INDEX_ZERO_REPEAT',
}


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def verify_input(path, label, entity):
    md = '{urn:oasis:names:tc:SAML:2.0:metadata}'
    saml = '{urn:oasis:names:tc:SAML:2.0:assertion}'
    mdattr = '{urn:oasis:names:tc:SAML:metadata:attribute}'
    fmt = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
    root = ET.fromstring(path.read_bytes())
    assert root.tag == md + 'EntityDescriptor' and root.get('entityID') == entity
    roles = root.findall(md + 'SPSSODescriptor')
    assert len(roles) == 1
    tags = root.findall(md + 'Extensions/' + mdattr + 'EntityAttributes')
    if label == 'entity-present':
        assert len(tags) == 1 and len(tags[0]) == 1
        attribute = tags[0][0]
        assert attribute.tag == saml + 'Attribute'
        assert attribute.attrib == {'Name': 'urn:samlscope:test:release-policy', 'NameFormat': fmt}
        assert len(attribute) == 1 and attribute[0].tag == saml + 'AttributeValue'
        assert attribute[0].text == 'release' and not len(attribute[0])
    else:
        assert not tags
    services = roles[0].findall(md + 'AttributeConsumingService')
    names = ['urn:oid:0.9.2342.19200300.100.1.1']
    if label.startswith('index-'):
        names.append('urn:oid:2.5.4.4')
    elif label not in {'requested-required', 'requested-optional'}:
        names = []
    assert len(services) == len(names)
    for index, (service, name) in enumerate(zip(services, names)):
        assert service.get('index') == str(index) and service.get('isDefault') == ('true' if index == 0 else 'false')
        attributes = service.findall(md + 'RequestedAttribute')
        assert len(attributes) == 1 and not len(attributes[0])
        assert attributes[0].attrib == {'Name': name, 'NameFormat': fmt,
                                       'isRequired': 'false' if label == 'requested-optional' else 'true'}


def export(folder, output):
    folder, output = Path(folder), Path(output)
    audited = verify(folder)
    if not audited['production_collector_observed'] or not audited['native_preparation_recorded']:
        raise ValueError('Production observation and native preparation are both required')
    def load(name):
        return json.loads((folder / name).read_text())
    prepared = load('preparation.json')
    observations = load('observations.json')
    result = load('result.json')
    # The validated native recipe reads the fixed requester, uid input and declared metadata fields.
    # Key/endpoint differences are not inputs to these narrowly validated AttributeInMetadata rules.
    fixed_inputs = dict(recipe=prepared['policy']['policy_sha256'], entity=prepared['entity_id'],
                        configuration=observations[0]['configuration_before'], source_attribute='uid')
    stable = hashlib.sha256(encode(fixed_inputs)).hexdigest()
    exchanges = []
    for observation in observations:
        verify_input(folder / observation['label'] / 'fixture.xml', observation['label'], prepared['entity_id'])
        flow = load(observation['label'] + '/flow.json')
        request, response = flow['positive_exchange']['transcript_ids']
        exchanges.append(dict(condition=CONDITIONS[observation['label']], requestReference=request,
            responseReference=response, policyFingerprint=prepared['policy']['policy_sha256'],
            loginInputFingerprint=prepared['login_input_binding'], stableInputFingerprint=stable))
    receipt = dict(schema='samlscope-native-attribute-policy-receipt-v1', runId=audited['run'],
        targetEntityId=result['target']['entity_id'],
        targetMetadataSha256=result['target']['metadata_digest'].removeprefix('sha256:'),
        preparation=dict(runId=audited['run'], experimentId='native-policy-' + audited['run'], exchanges=exchanges),
        rawEvidence=[dict(reference=m['id'], sha256=m['sha256']) for m in load('decoded-manifest.json')])
    raw = json.dumps(receipt, indent=2, ensure_ascii=False).encode() + b'\n'
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        if output.is_symlink() or output.read_bytes() != raw:
            raise ValueError('Preparation receipt is immutable; use a new experiment Run')
    else:
        with output.open('xb') as stream:
            stream.write(raw)
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    receipt = export(args.evidence, args.output)
    print('Exported audited preparation for', receipt['runId'], '; no verdict supplied')
