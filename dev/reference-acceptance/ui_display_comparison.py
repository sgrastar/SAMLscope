"""Bind display-name candidates to native metadata. Missing UI remains uncertainty."""
from datetime import datetime
import hashlib
import json
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import xml.etree.ElementTree as ET

MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
UI = 'urn:oasis:names:tc:SAML:metadata:ui'
XML = 'http://www.w3.org/XML/1998/namespace'
CONDITIONS = ['ui-consumer-display-all', 'ui-consumer-display-service', 'ui-consumer-display-entity']
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def candidates(raw, condition):
    """Pinned English reference template; never infer missing names or choose among ambiguous roles."""
    root = ET.fromstring(raw)
    if root.tag != '{' + MD + '}EntityDescriptor' or not root.get('entityID'):
        raise ValueError('Display metadata entity unavailable')
    roles = root.findall('{' + MD + '}SPSSODescriptor')
    if len(roles) != 1 or condition not in CONDITIONS:
        raise ValueError('Display metadata role/condition ambiguous')
    role = roles[0]
    displays = role.findall('./{' + MD + '}Extensions/{' + UI + '}UIInfo/{' + UI + '}DisplayName')
    services = role.findall('./{' + MD + '}AttributeConsumingService/{' + MD + '}ServiceName')
    expected = {'ui-consumer-display-all': (1, 1), 'ui-consumer-display-service': (0, 1),
                'ui-consumer-display-entity': (0, 0)}[condition]
    if (len(displays), len(services)) != expected:
        raise ValueError('Display candidate presence differs from condition')
    mapping = {'entity': 'Login to ' + root.attrib['entityID']}
    endpoints = role.findall('{' + MD + '}AssertionConsumerService')
    hosts = {urlsplit(e.get('Location', '')).hostname for e in endpoints}
    if len(hosts) != 1 or None in hosts:
        raise ValueError('Display endpoint hostname ambiguous')
    mapping['hostname'] = 'Login to ' + next(iter(hosts))
    for token, elements in [('display', displays), ('service', services)]:
        if elements:
            node = elements[0]
            if node.get('{' + XML + '}lang') != 'en' or not node.text or not node.text.strip():
                raise ValueError('Display candidate language/value unavailable')
            mapping[token] = 'Login to ' + node.text
    if len({' '.join(v.split()) for v in mapping.values()}) != len(mapping):
        raise ValueError('Indistinguishable display candidates')
    return mapping


def compare(folder, bound):
    """Diagnostic only: formal Runner adoption and controls are separate gates."""
    issues, rows, fixed = [], [], []
    by_condition = {row['condition']: row for row in bound}
    previous = None
    service_values, fallback_values = set(), set()
    restoration = json.loads((folder / 'restoration.json').read_text())
    template_path = folder / 'native-ui-template.json'
    if not template_path.exists() or restoration.get('template_unchanged') is not True:
        issues.append('native-template-stability-unproven')
    else:
        template = json.loads(template_path.read_text())
        if template.get('path') != '/opt/reference-idp/views/login.vm' or template.get('provenance') != 'native-template-readback' or len(template.get('sha256', '')) != 64:
            issues.append('native-template-identity-unbound')
    for condition in CONDITIONS:
        part = folder / condition
        raw = (part / 'fixture.xml').read_bytes()
        supplied = json.loads((part / 'browser-input.json').read_text())['observation']
        browser = json.loads((part / 'browser-observation.json').read_text())
        row = by_condition[condition]
        mapping = candidates(raw, condition)
        if 'service' in mapping:
            service_values.add(mapping['service'])
        fallback_values.add((mapping['entity'], mapping['hostname']))
        mapping_hash = SHA(json.dumps({key: ' '.join(value.split()) for key, value in sorted(mapping.items())},
                                      ensure_ascii=False, separators=(',', ':')).encode())
        if browser.get('candidate_mapping_sha256') != mapping_hash:
            issues.append(condition + ':captured-candidate-mapping-unbound')
        if supplied['kind'] != 'display-name' or supplied['candidates'] != mapping or browser.get('kind') != 'display-name':
            issues.append(condition + ':candidate-mapping-unbound')
        if browser.get('selector') != 'header h1' or browser.get('preferred_language') != 'en-US' or row['accept_language'] != 'en-US':
            issues.append(condition + ':native-template-or-language-unbound')
        root = ET.fromstring(raw)
        # Hold every metadata setting fixed except the name candidates under examination.
        observed = datetime.fromisoformat(browser['observed_at'].replace('Z', '+00:00'))
        # Metadata expiry must still be valid at observation; generation timestamps and
        # the signed digest/value naturally differ when the candidates are changed.
        until = root.get('validUntil')
        if not until or datetime.fromisoformat(until.replace('Z', '+00:00')) <= observed:
            issues.append(condition + ':metadata-expired-or-unproven')
        root.attrib.pop('validUntil', None)
        ds = 'http://www.w3.org/2000/09/xmldsig#'
        for signature in root.findall('{' + ds + '}Signature'):
            for node in signature.iter():
                if node.tag in ['{' + ds + '}SignatureValue', '{' + ds + '}DigestValue']:
                    node.text = 'variable-signature-value'
        # Only the Suite campaign correlation parameter may vary in endpoint URLs.
        for node in root.iter():
            for attribute in ['Location', 'ResponseLocation']:
                if attribute not in node.attrib:
                    continue
                url = urlsplit(node.attrib[attribute])
                pairs = parse_qsl(url.query, keep_blank_values=True)
                variants = [value for key, value in pairs if key == 'mdv']
                runs = [value for key, value in pairs if key == 'run']
                if variants != [condition] or runs != [browser['run_id']]:
                    issues.append(condition + ':endpoint-correlation-unbound')
                else:
                    node.set(attribute, urlunsplit((url.scheme, url.netloc, url.path,
                        urlencode([(key, 'display-comparison' if key == 'mdv' else value) for key, value in pairs]), url.fragment)))
        # ServiceName cannot be omitted from an otherwise schema-valid consuming-service
        # descriptor. The fixture therefore removes its whole fixed optional-uid wrapper.
        for role in root.findall('{' + MD + '}SPSSODescriptor'):
            for service in role.findall('{' + MD + '}AttributeConsumingService'):
                attributes = service.findall('{' + MD + '}RequestedAttribute')
                if service.attrib != {'index': '0', 'isDefault': 'true'} or len(attributes) != 1 or len(service) != 2:
                    issues.append(condition + ':service-wrapper-uncontrolled')
                elif attributes[0].attrib != {'Name': 'urn:oid:0.9.2342.19200300.100.1.1', 'isRequired': 'false'} or len(attributes[0]):
                    issues.append(condition + ':service-attribute-uncontrolled')
                role.remove(service)
        for parent in root.iter():
            for child in list(parent):
                if child.tag in ['{' + UI + '}DisplayName', '{' + MD + '}ServiceName']:
                    parent.remove(child)
        # The generator omits now-empty UIInfo/Extensions and AttributeConsumingService containers.
        for parent in reversed(list(root.iter())):
            for child in list(parent):
                if child.tag in ['{' + UI + '}UIInfo', '{' + MD + '}Extensions', '{' + MD + '}AttributeConsumingService'] and not len(child) and not (child.text or '').strip():
                    parent.remove(child)
        fixed.append(SHA(ET.tostring(root)))
        observed = datetime.fromisoformat(browser['observed_at'].replace('Z', '+00:00'))
        if previous is not None and row['request_timestamp'] <= previous.timestamp():
            issues.append('conditions-reordered')
        previous = observed
        accepted = {'display'} if condition.endswith('-all') else {'service'} if condition.endswith('-service') else {'entity', 'hostname'}
        if row['status'] != 'observed' or row['selected_candidate'] not in accepted:
            issues.append(condition + ':selection-unproven')
        rows.append(dict(condition=condition, status=row['status'], selected_candidate=row['selected_candidate'],
                         observation_sha256=row['observation_sha256']))
    if len(service_values) != 1 or len(fallback_values) != 1:
        issues.append('candidate-values-changed-between-conditions')
    if len(set(fixed)) != 1:
        issues.append('uncontrolled-metadata-change')
    return dict(status='precedence-observed' if not issues else 'not-verified',
                issues=sorted(set(issues)), observations=rows, verdict_adopted=False,
                absence_is_nonuse_proof=False)
