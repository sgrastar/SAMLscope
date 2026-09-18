"""Extract only Suite-owned policy nodes from native read-back, without exporting full configuration."""
import hashlib
import json
import re
import xml.etree.ElementTree as ET

MARKERS = ('anchor', 'entity', 'required', 'optional', 'surname')
NAMESPACES = {
    'metadata-providers': 'urn:mace:shibboleth:2.0:metadata',
    'attribute-resolver': 'urn:mace:shibboleth:2.0:resolver',
    'attribute-filter': 'urn:mace:shibboleth:2.0:afp',
}


def canonical(node):
    # Preserve child ordering and non-whitespace text; ignore indentation only.
    return dict(tag=node.tag, attributes=dict(sorted(node.attrib.items())),
                text=(node.text or '').strip(), children=[canonical(child) for child in node])


def snapshot(configurations, run):
    result = {}
    for name, namespace in NAMESPACES.items():
        root = ET.fromstring(configurations[name])
        if name == 'attribute-resolver':
            ids = ['samlscopePolicy_' + marker for marker in MARKERS]
            tag = '{' + namespace + '}AttributeDefinition'
        else:
            ids = ['AttributePolicy' + run]
            tag = '{' + namespace + '}' + ('MetadataProvider' if name == 'metadata-providers' else 'AttributeFilterPolicy')
        selected = []
        for id_ in ids:
            nodes = [node for node in root if node.get('id') == id_]
            if len(nodes) != 1 or nodes[0].tag != tag:
                raise ValueError('Suite policy node is missing or ambiguous')
            selected.append(canonical(nodes[0]))
        result[name] = selected
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    return dict(schema='samlscope-native-attribute-policy-v1', nodes=result,
                policy_sha256=hashlib.sha256(encoded).hexdigest())


def verify_readback(expected, actual, run):
    expected_hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in expected.items()}
    actual_hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in actual.items()}
    if expected_hashes != actual_hashes:
        raise ValueError('Native configuration changed during experiment')
    extracted = snapshot(actual, run)
    if extracted != snapshot(expected, run):
        raise ValueError('Native policy read-back mismatch')
    return dict(configuration_sha256=actual_hashes, policy=extracted)


def verify_policy_semantics(policy, run, entity, metadata_file):
    """Validate the narrow native recipe; a matching hash alone cannot establish its meaning."""
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run):
        raise ValueError('Invalid experiment Run')
    if not entity or not metadata_file:
        raise ValueError('Policy scope is required')
    if set(policy) != {'schema', 'nodes', 'policy_sha256'} or policy['schema'] != 'samlscope-native-attribute-policy-v1':
        raise ValueError('Unsupported policy snapshot')
    nodes = policy['nodes']
    encoded = json.dumps(nodes, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()
    if hashlib.sha256(encoded).hexdigest() != policy['policy_sha256']:
        raise ValueError('Policy content hash mismatch')
    if set(nodes) != set(NAMESPACES):
        raise ValueError('Incomplete policy snapshot')
    xsi = '{http://www.w3.org/2001/XMLSchema-instance}type'
    fmt = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'

    def check(node, namespace, tag, attributes, child_count):
        if set(node) != {'tag', 'attributes', 'text', 'children'} or node['tag'] != '{' + namespace + '}' + tag:
            raise ValueError('Unexpected native policy node')
        if node['attributes'] != attributes or node['text'] or len(node['children']) != child_count:
            raise ValueError('Native policy behavior differs from the experiment recipe')
        return node['children']

    md, resolver, afp = (NAMESPACES[n] for n in ['metadata-providers', 'attribute-resolver', 'attribute-filter'])
    if len(nodes['metadata-providers']) != 1 or len(nodes['attribute-filter']) != 1 or len(nodes['attribute-resolver']) != len(MARKERS):
        raise ValueError('Policy nodes missing or duplicated')
    check(nodes['metadata-providers'][0], md, 'MetadataProvider', {
        'id': 'AttributePolicy' + run, xsi: 'FilesystemMetadataProvider', 'metadataFile': metadata_file}, 0)
    for marker, definition in zip(MARKERS, nodes['attribute-resolver']):
        children = check(definition, resolver, 'AttributeDefinition', {
            'id': 'samlscopePolicy_' + marker, xsi: 'Simple'}, 2)
        check(children[0], resolver, 'InputAttributeDefinition', {'ref': 'uid'}, 0)
        check(children[1], resolver, 'AttributeEncoder', {
            xsi: 'SAML2String', 'name': 'urn:samlscope:test:policy:' + marker,
            'nameFormat': fmt, 'encodeType': 'false'}, 0)
    rules = check(nodes['attribute-filter'][0], afp, 'AttributeFilterPolicy', {'id': 'AttributePolicy' + run}, 6)
    check(rules[0], afp, 'PolicyRequirementRule', {xsi: 'Requester', 'value': entity}, 0)
    for marker, rule in zip(MARKERS, rules[1:]):
        attributes = {'attributeID': 'samlscopePolicy_' + marker}
        if marker == 'anchor':
            attributes['permitAny'] = 'true'
            check(rule, afp, 'AttributeRule', attributes, 0)
            continue
        children = check(rule, afp, 'AttributeRule', attributes, 1)
        if marker == 'entity':
            expected = {xsi: 'EntityAttributeExactMatch', 'attributeName': 'urn:samlscope:test:release-policy',
                        'attributeNameFormat': fmt, 'attributeValue': 'release'}
        else:
            expected = {xsi: 'AttributeInMetadata',
                        'attributeName': 'urn:oid:2.5.4.4' if marker == 'surname' else 'urn:oid:0.9.2342.19200300.100.1.1',
                        'attributeNameFormat': fmt, 'onlyIfRequired': 'false' if marker == 'optional' else 'true',
                        'matchIfMetadataSilent': 'false'}
        check(children[0], afp, 'PermitValueRule', expected, 0)
    return policy['policy_sha256']
