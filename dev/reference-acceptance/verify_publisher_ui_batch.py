"""Verify explicit unpublished-UI note branches against the Run's original metadata."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

ADOPTED = {'IIP-MD05-f7-idp-01': 'Description', 'IIP-MD05-f8-idp-01': 'Logo',
           'IIP-MD05-fa-idp-01': 'InformationURL'}
ENTITIES = {'keycloak': 'http://localhost:18180/realms/samlscope',
            'shibboleth': 'http://localhost:18280/idp/shibboleth',
            'simplesamlphp': 'http://localhost:18380/idp'}
MD = '{urn:oasis:names:tc:SAML:2.0:metadata}'
UI = '{urn:oasis:names:tc:SAML:metadata:ui}'

def verify(root, product):
    folder = Path(root) / 'publisher-ui-scoped' / product
    path = folder / 'result.json'
    result = json.loads(path.read_text())
    assert result['run']['id'] == json.loads((folder/'created.json').read_text())['run']['id']
    raw = (folder/'metadata.xml').read_bytes()
    metadata = ET.fromstring(raw)
    assert metadata.tag == MD+'EntityDescriptor' and metadata.get('entityID') == ENTITIES[product]
    roles = metadata.findall(MD+'IDPSSODescriptor')
    assert roles
    cases = {c['id']: c for r in result['requirements'] for c in r['cases']}
    for case_id, element in ADOPTED.items():
        assert not any(role.findall('.//'+UI+element) for role in roles)
        case = cases[case_id]
        assert (case['outcome'], case['verdict'], case['reason_code']) == (
            'SATISFIED_WITH_NOTE', 'WARNING', 'metadata.publisher.ui-guidance-not-published')
        assert case['attested'] is False
        assert case['evidence'] == [{'kind': 'target-metadata',
                                    'reference': 'sha256:'+hashlib.sha256(raw).hexdigest()}]
    return path, cases
