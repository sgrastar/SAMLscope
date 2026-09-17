"""Verify metadata-driven ACS selection; unsupported signature-control attempts are not evidence."""
import json
import hashlib
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import xml.etree.ElementTree as ET
from verify_simplesamlphp_import_batch import verify as verify_native

EXPECTED = {'default-acs-first': 0, 'default-acs-second': 1, 'default-acs-implicit': 0,
            'default-acs-first-omitted': 1, 'default-acs-all-false': 0, 'default-acs-multiple-true': 0}
ADOPTED = {'IIP-IDP12-c-idp-01': list(EXPECTED)}
MD = '{urn:oasis:names:tc:SAML:2.0:metadata}'

def verify(root):
    path, cases = verify_native(root, folder='simplesamlphp-default-acs', adopted=ADOPTED,
                               require_signature_control=False)
    return verify_selection(path, cases)

def selection_mismatches(path, cases):
    mismatches = []
    folder = path.parent
    result = json.loads(path.read_text())
    run = result['run']['id']
    entries = {e['id']: e for e in json.loads((folder/'transcript.json').read_text())}
    originals = {e['id']: e for e in json.loads((folder/'decoded-manifest.json').read_text())}
    for variant, expected in EXPECTED.items():
        xml = ET.parse(folder/variant/'fixture.xml').getroot()
        endpoints = xml.find(MD+'SPSSODescriptor').findall(MD+'AssertionConsumerService')
        assert len(endpoints) > 1
        assert len({e.get('index') for e in endpoints}) == len(endpoints)
        true = [e for e in endpoints if e.get('isDefault') in ('true','1')]
        omitted = [e for e in endpoints if e.get('isDefault') is None]
        selected = (true or omitted or endpoints)[0]
        assert selected.get('index') == str(expected)
        flow = json.loads((folder/variant/'flow.json').read_text())
        request_id = flow['positive_exchange']['transcript_ids'][0]
        source = originals[request_id]
        raw = (folder/source['file']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == source['sha256']
        request = ET.fromstring(raw)
        assert request.tag == '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest'
        assert request.get('ID') == flow['positive_exchange']['request_id']
        assert not any(name in request.attrib for name in ('AssertionConsumerServiceURL', 'AssertionConsumerServiceIndex', 'ProtocolBinding'))
        assert request.find('{http://www.w3.org/2000/09/xmldsig#}Signature') is not None
        response_ids = flow['positive_exchange']['transcript_ids'][1:]
        assert response_ids
        for ref in response_ids:
            original = originals[ref]
            raw = (folder/original['file']).read_bytes()
            assert hashlib.sha256(raw).hexdigest() == original['sha256']
            response = ET.fromstring(raw)
            assert response.get('InResponseTo') == request.get('ID')
            assert response.find('{urn:oasis:names:tc:SAML:2.0:protocol}Status/{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode').get('Value') == 'urn:oasis:names:tc:SAML:2.0:status:Success'
            url = entries[ref]['url']
            assert response.get('Destination') == url
            assert url in [e.get('Location') for e in endpoints]
            if url != selected.get('Location'):
                mismatches.append({'variant':variant,'expected_url':selected.get('Location'),'observed_url':url})
            query = parse_qs(urlparse(url).query)
            assert query.get('run') == [run] and query.get('mdv') == [variant]
    return mismatches

def verify_selection(path, cases):
    assert not selection_mismatches(path, cases)
    return path, cases

if __name__ == '__main__':
    import sys
    verify(sys.argv[1]); print('Verified all default ACS selections and metadata-change control')
