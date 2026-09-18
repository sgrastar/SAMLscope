"""Native generator-list preparation, with exact ownership of the only permitted change.

The adapter must restore the original bytes and reload the native service after its experiment.
An empty generator list is a preparation attempt, not evidence that successful SSO omits NameID.
"""
import hashlib
import xml.etree.ElementTree as ET

UTIL = 'http://www.springframework.org/schema/util'
GENERATORS = 'shibboleth.SAML2NameIDGenerators'


def canonical(node):
    return (node.tag, tuple(sorted(node.attrib.items())), (node.text or '').strip(),
            tuple(canonical(child) for child in node))


def generator_list(root):
    matches = [node for node in root.iter() if node.get('id') == GENERATORS]
    if len(matches) != 1 or matches[0].tag != '{' + UTIL + '}list':
        raise ValueError('Ambiguous native SAML2 generator list')
    return matches[0]


def disabled_configuration(original):
    root = ET.fromstring(original)
    generators = generator_list(root)
    if not list(generators):
        raise ValueError('Baseline generator list is already empty')
    for child in list(generators):
        generators.remove(child)
    generators.text = None
    configured = ET.tostring(root, encoding='utf-8', xml_declaration=True)
    verify_transition(original, configured)
    return configured


def verify_transition(original, configured):
    """Require complete equality outside the selected native generator list."""
    before = ET.fromstring(original)
    after = ET.fromstring(configured)
    active = generator_list(before)
    inactive = generator_list(after)
    if not list(active) or list(inactive) or (inactive.text or '').strip():
        raise ValueError('Generator enable/disable transition unproven')
    count = len(active)
    for child in list(active):
        active.remove(child)
    active.text = None
    if canonical(before) != canonical(after):
        raise ValueError('Uncontrolled native setting changed')
    return dict(source='native-SAML2NameIDGenerators-list', generator_count_before=count,
                generator_count_after=0, original_sha256=hashlib.sha256(original).hexdigest(),
                configured_sha256=hashlib.sha256(configured).hexdigest(),
                scope='isolated-reference-idp-SAML2-generation', protocol_verified=False)
