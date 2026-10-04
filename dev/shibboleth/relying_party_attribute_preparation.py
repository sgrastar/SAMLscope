"""Native two-requester policy recipe for IDP02.a; no write, reload, or verdict here."""
import hashlib
import json
import re
import xml.etree.ElementTree as ET
from attribute_policy_preparation import canonical, NAMESPACES

XSI = '{http://www.w3.org/2001/XMLSchema-instance}type'
FORMAT = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
MARKERS = ('anchor', 'first', 'second')


def recipe(run, entities, metadata_files):
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run):
        raise ValueError('Invalid experiment Run')
    if set(entities) != {'first', 'second'} or set(metadata_files) != set(entities):
        raise ValueError('Exactly two relying parties required')
    if len(set(entities.values())) != 2 or any(not value.strip() for value in entities.values()):
        raise ValueError('Distinct entity IDs required')
    if any(not value.startswith('/opt/reference-idp/metadata/')
            or '..' in value.split('/') for value in metadata_files.values()):
        raise ValueError('Native metadata files required')
    prefix = 'RelyingPartyAttributes' + run
    result = {name: [] for name in NAMESPACES}
    md, resolver, afp = (NAMESPACES[name] for name in ['metadata-providers', 'attribute-resolver', 'attribute-filter'])
    seen_files = set()
    for side in ['first', 'second']:
        provider = ET.Element('{' + md + '}MetadataProvider', {
            'id': prefix + '-' + side, XSI: 'FilesystemMetadataProvider', 'metadataFile': metadata_files[side]})
        if metadata_files[side] not in seen_files:
            result['metadata-providers'].append(provider)
            seen_files.add(metadata_files[side])
        policy = ET.Element('{' + afp + '}AttributeFilterPolicy', {'id': prefix + '-' + side})
        ET.SubElement(policy, '{' + afp + '}PolicyRequirementRule', {XSI: 'Requester', 'value': entities[side]})
        for marker in ['anchor', side]:
            ET.SubElement(policy, '{' + afp + '}AttributeRule', {
                'attributeID': prefix + '-' + marker, 'permitAny': 'true'})
        result['attribute-filter'].append(policy)
    for marker in MARKERS:
        definition = ET.Element('{' + resolver + '}AttributeDefinition', {'id': prefix + '-' + marker, XSI: 'Simple'})
        ET.SubElement(definition, '{' + resolver + '}InputAttributeDefinition', {'ref': 'uid'})
        ET.SubElement(definition, '{' + resolver + '}AttributeEncoder', {
            XSI: 'SAML2String', 'name': 'urn:samlscope:test:relying-party:' + marker,
            'nameFormat': FORMAT, 'encodeType': 'false'})
        result['attribute-resolver'].append(definition)
    return result


def prepare(originals, run, entities, metadata_files):
    """Retain existing native policies and add disjoint, exact-requester-scoped markers."""
    nodes = recipe(run, entities, metadata_files)
    result = {}
    ET.register_namespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance')
    for name, additions in nodes.items():
        ET.register_namespace('', NAMESPACES[name])
        root = ET.fromstring(originals[name])
        if root.tag != '{' + NAMESPACES[name] + '}' + {
                'metadata-providers': 'MetadataProvider', 'attribute-resolver': 'AttributeResolver',
                'attribute-filter': 'AttributeFilterPolicyGroup'}[name]:
            raise ValueError('Unexpected native configuration root')
        reserved = {node.get('id') for node in additions}
        if any(node.get('id') in reserved for node in root):
            raise ValueError('Reserved experiment node already exists')
        if name == 'metadata-providers':
            root[0:0] = additions
        else:
            root.extend(additions)
        result[name] = ET.tostring(root)
    return result


def verify_readback(expected, actual, run, entities, metadata_files):
    """Bind exact read-back and native semantics; hashes alone cannot prove a policy."""
    if set(expected) != set(NAMESPACES) or set(actual) != set(NAMESPACES):
        raise ValueError('Incomplete native configuration')
    if expected != actual:
        raise ValueError('Native configuration changed')
    extracted = {}
    for name, nodes in recipe(run, entities, metadata_files).items():
        root = ET.fromstring(actual[name])
        extracted[name] = []
        for node in nodes:
            found = [candidate for candidate in root if candidate.get('id') == node.get('id')]
            if len(found) != 1 or canonical(found[0]) != canonical(node):
                raise ValueError('Native requester policy differs from recipe')
            extracted[name].append(canonical(found[0]))
    raw = json.dumps(extracted, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return dict(schema='samlscope-native-relying-party-attributes-v1', run=run,
        entity_ids=dict(entities), nodes=extracted, policy_sha256=hashlib.sha256(raw).hexdigest(),
        configuration_sha256={name: hashlib.sha256(raw).hexdigest() for name, raw in actual.items()},
        verdict_adopted=False)
