"""Adopt IIP-MD05.ao only when a signed document without ds:KeyInfo is verified via the configured key.

The campaign configures the Suite polling key as the metadata trust anchor and serves a signed
document whose signature carries no KeyInfo certificate. Acceptance therefore proves the product
verified the signature against the out-of-band key. The Run's own Suite-issued corrupt-signature
control must be rejected.
"""
import base64
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

CASE = 'IIP-MD05-ao-idp-01'
VARIANT = 'no-key-info'
DS = 'http://www.w3.org/2000/09/xmldsig#'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(folder, name):
    return json.loads((folder / name).read_text())


def signature_has_keyinfo_certificate(fixture_xml):
    root = ET.fromstring(fixture_xml)
    for signature in root.iter('{%s}Signature' % DS):
        key_info = signature.find('{%s}KeyInfo' % DS)
        if key_info is not None and key_info.find('.//{%s}X509Certificate' % DS) is not None:
            return True
    return False


def verify(root, product='shibboleth'):
    assert product == 'shibboleth'
    folder = Path(root) / 'shibboleth-md05-consumer-sig-v79'
    result = read(folder, 'result.json')
    run = result['run']['id']
    assert run == read(folder, 'created.json')['run']['id']
    restoration = read(folder, 'restoration.json')
    assert restoration['restored'] and restoration['original_sha256'] == restoration['final_sha256']
    assert restoration['signature_certificate_removed']
    provider = (folder / 'configured-providers.xml').read_text()
    assert 'SignatureValidation' in provider and 'requireSignedRoot="true"' in provider
    assert 'failFastInitialization="false"' in provider
    assert not signature_has_keyinfo_certificate((folder / VARIANT / 'fixture.xml').read_text()), \
        'The tested document must omit the signature KeyInfo certificate'
    flow = read(folder / VARIANT, 'flow.json')
    assert flow['negative_control']['correlated_success'] is False, 'Corrupt suite signature must be rejected'
    assert flow['negative_control']['source'] == 'suite'
    assert flow['positive_exchange']['success'] is True, 'KeyInfo-less document must be accepted'
    entries = read(folder, 'transcript.json')
    fetched = [e for e in entries if e['samlSummary'].get('type') == 'MetadataFetch'
               and e['samlSummary'].get('variant') == VARIANT]
    used = [e for e in entries if e['direction'] == 'INBOUND'
            and e['samlSummary'].get('metadataProbeAccepted') is True
            and e['samlSummary'].get('statusCode') == 'urn:oasis:names:tc:SAML:2.0:status:Success'
            and ('mdv=' + VARIANT) in (e.get('url') or '')]
    assert len(fetched) == 1 and len(used) == 1
    cases = {c['id']: c for r in result['requirements'] for c in r['cases']}
    case = cases[CASE]
    assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
        'SATISFIED', 'PASS', 'metadata.key-info-omission.accepted', False)
    return folder / 'result.json', {CASE: case}


if __name__ == '__main__':
    import sys
    _, cases = verify(sys.argv[1], 'shibboleth')
    for name, row in cases.items():
        print(name, row['verdict'])
