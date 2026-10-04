"""Adopt the publisher signature warning only for a byte-identical HTTP Run snapshot."""
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

CASE = 'IIP-MD05-af-idp-01'
FOLDERS = {
    'keycloak': ('publisher-keycloak-v120', 'publisher-keycloak-source-v120b'),
    'shibboleth': ('publisher-shibboleth-v120b', 'shibboleth-dynamic-mdq-v8'),
    'simplesamlphp': ('publisher-ssp-v120', 'publisher-ssp-source-v120'),
}


def read(folder, name):
    return json.loads((folder / name).read_text())


def selected(result):
    return next(c for requirement in result['requirements'] for c in requirement['cases']
                if c['id'] == CASE)


def verify(root, product):
    folder_name, source_name = FOLDERS[product]
    folder = Path(root) / folder_name
    source = Path(root) / source_name
    result = read(folder, 'adopted-result.json')
    baseline = read(folder, 'result.json')
    run = result['run']['id']
    assert run == baseline['run']['id'] == read(folder, 'created.json')['run']['id']
    assert selected(baseline)['verdict'] == 'NOT_VERIFIED'
    case = selected(result)
    assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
        'VIOLATED', 'WARNING', 'metadata.publisher.root-signature-absent', False)
    assert read(source, 'restoration.json')['restored'] is True
    if product == 'keycloak':
        assert read(source, 'restoration.json')['cleanup']['read_back_absent'] is True
    else:
        restoration = read(source, 'restoration.json')
        assert restoration['original_sha256'] == restoration['final_sha256']
    original = (folder / 'response.xml').read_bytes()
    assert original == (folder / 'run-target-metadata.xml').read_bytes()
    root_xml = ET.fromstring(original)
    assert root_xml.tag == '{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor'
    assert not any(child.tag == '{http://www.w3.org/2000/09/xmldsig#}Signature' for child in root_xml)
    manifest = read(folder, 'manifest.json')
    source_url = manifest['sourceUrl']
    assert urlparse(source_url).scheme == 'http'
    assert urlparse(source_url).netloc == urlparse(root_xml.attrib['entityID']).netloc
    assert hashlib.sha256(original).hexdigest() == manifest['responseSha256']
    assert read(folder, 'request.json') == dict(url=source_url, method='GET',
                                                 authorizationSent=False, cookieSent=False)
    assert read(folder, 'response-headers.json')['status'] == 200
    receipt = read(folder, 'receipt-install.json')
    assert len(receipt['readBackSha256']) == 3
    assert receipt['productConfigurationWrites'] == receipt['productRestarts'] == receipt['humanOperations'] == 0
    assert case['evidence'] == [dict(kind='publisher-metadata', reference=run + '.publisher/manifest.json')]
    adopted = folder / 'evaluation/result.json'
    assert adopted.read_bytes() == (folder / 'adopted-result.json').read_bytes()
    return adopted, {CASE: case}


if __name__ == '__main__':
    import sys
    for product in FOLDERS:
        path, cases = verify(sys.argv[1], product)
        print(product, path, cases[CASE]['verdict'])
