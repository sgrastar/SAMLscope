"""Extract only Suite-owned policy nodes from native read-back, without exporting full configuration."""
import hashlib
import json
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
