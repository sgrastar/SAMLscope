"""Adopt IIP-MD03.b only when the product verifies against the configured key, not embedded KeyInfo.

The positive campaign trusts the out-of-band Suite key that signed the document while the metadata
embeds a different certificate in the signature KeyInfo. The product must accept that; the same
fixture under the embedded certificate as trust anchor must be rejected. The Run's own Suite-issued
corrupt-signature control must also be rejected.
"""
import base64
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

CASE = 'IIP-MD03-b-idp-01'
VARIANT = 'signed-other-key-primary-keyinfo'
DS = 'http://www.w3.org/2000/09/xmldsig#'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cert_fingerprint(pem_text):
    body = ''.join(line for line in pem_text.splitlines() if 'BEGIN' not in line and 'END' not in line)
    return sha(base64.b64decode(body))


def embedded_signature_certificate(fixture_xml):
    root = ET.fromstring(fixture_xml)
    for signature in root.iter('{%s}Signature' % DS):
        key_info = signature.find('{%s}KeyInfo' % DS)
        if key_info is None:
            continue
        cert = key_info.find('.//{%s}X509Certificate' % DS)
        if cert is not None and cert.text:
            return sha(base64.b64decode(''.join(cert.text.split())))
    raise ValueError('Signature KeyInfo certificate missing')


def read(folder, name):
    return json.loads((folder / name).read_text())


def verify(root, product='shibboleth'):
    assert product == 'shibboleth'
    root = Path(root)
    positive = root / 'shibboleth-md03b-signature-v78b'
    negative = root / 'shibboleth-md03b-negative-v78'
    result = read(positive, 'result.json')
    run = result['run']['id']
    assert run == read(positive, 'created.json')['run']['id']
    restoration = read(positive, 'restoration.json')
    assert restoration['restored'] and restoration['original_sha256'] == restoration['final_sha256']
    assert restoration['signature_certificate_removed']
    provider = (positive / 'configured-providers.xml').read_text()
    assert 'SignatureValidation' in provider and 'requireSignedRoot="true"' in provider
    assert 'failFastInitialization="false"' in provider
    anchor = cert_fingerprint((positive / 'signing-certificate.pem').read_text())
    embedded = embedded_signature_certificate((positive / VARIANT / 'fixture.xml').read_text())
    assert anchor != embedded, 'Fixture must embed a certificate different from the configured anchor'
    flow = read(positive / VARIANT, 'flow.json')
    assert flow['negative_control']['correlated_success'] is False, 'Corrupt suite signature must be rejected'
    assert flow['negative_control']['source'] == 'suite'
    assert flow['positive_exchange']['success'] is True, 'Configured-key document must be accepted'
    entries = read(positive, 'transcript.json')
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
        'SATISFIED', 'PASS', 'metadata.fixture-probe.satisfied', False)
    # Negative control: the same fixture under the embedded certificate as anchor must be refused.
    negative_result = read(negative, 'result.json')
    assert negative_result['run']['id'] == read(negative, 'created.json')['run']['id']
    negative_flow = read(negative / VARIANT, 'flow.json')
    assert negative_flow['positive_exchange']['success'] is False, 'Embedded-cert anchor must reject the document'
    negative_restoration = read(negative, 'restoration.json')
    assert negative_restoration['restored'] and negative_restoration['signature_certificate_removed']
    negative_case = {c['id']: c for r in negative_result['requirements'] for c in r['cases']}[CASE]
    assert negative_case['outcome'] == 'NOT_VERIFIED'
    return positive / 'result.json', {CASE: case}


if __name__ == '__main__':
    import sys
    _, cases = verify(sys.argv[1], 'shibboleth')
    for name, row in cases.items():
        print(name, row['verdict'])
