"""Record signed encryption headers and key-size advertisements; never claim decryption or a Verdict."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from native_algorithm_preparation import verify as verify_preparation

MD = '{urn:oasis:names:tc:SAML:2.0:metadata}'
ALG = '{urn:oasis:names:tc:SAML:metadata:algsupport}'
XENC = '{http://www.w3.org/2001/04/xmlenc#}'
XENC11 = '{http://www.w3.org/2009/xmlenc11#}'
DS = '{http://www.w3.org/2000/09/xmldsig#}'
SAML = '{urn:oasis:names:tc:SAML:2.0:assertion}'


def load(folder, name):
    return json.loads((folder / name).read_text())


def method(element):
    def algorithm(tag):
        values = element.findall(tag)
        return [v.get('Algorithm') for v in values]
    return dict(algorithm=element.get('Algorithm'), key_sizes=[v.text for v in element.findall(XENC + 'KeySize')],
                digests=algorithm(DS + 'DigestMethod'), mgfs=algorithm(XENC11 + 'MGF'))


def observe(folder):
    folder = Path(folder)
    proof = load(folder, 'verified-algorithm-signatures.json')
    result = load(folder, 'result.json')
    assert result['run']['id'] == proof['run']
    assert result['target']['metadata_digest'] == 'sha256:' + proof['target_metadata_sha256']
    manifest = {v['id']: v for v in load(folder, 'decoded-manifest.json')}
    observations = []
    for signed in proof['observations']:
        assert signed['signed_response_verified']
        variant = signed['variant']
        verify_preparation(folder, variant)
        fixture = ET.fromstring((folder / variant / 'fixture.xml').read_bytes())
        role = fixture.find(MD + 'SPSSODescriptor')
        assert role is not None
        advertised = [method(m) for k in role.findall(MD + 'KeyDescriptor') if k.get('use') != 'signing'
                      for m in k.findall(MD + 'EncryptionMethod')]
        limits = [dict(v.attrib) for v in role.findall(MD + 'Extensions/' + ALG + 'SigningMethod')]
        entry = manifest[signed['response']]
        raw = (folder / entry['file']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == entry['sha256']
        response = ET.fromstring(raw)
        observed = []
        for wrapper in response.findall(SAML + 'EncryptedAssertion'):
            observed.append(dict(data=[method(m) for d in wrapper.findall(XENC + 'EncryptedData')
                                       for m in d.findall(XENC + 'EncryptionMethod')],
                                 keys=[method(m) for k in wrapper.findall('.//' + XENC + 'EncryptedKey')
                                       for m in k.findall(XENC + 'EncryptionMethod')],
                                 decryption_verified=False))
        observations.append(dict(variant=variant, request=signed['request'], response=signed['response'],
            advertised_encryption=advertised, advertised_signing_limits=limits,
            signed_encrypted_assertions=observed, verified_signatures=signed['verified_signatures'],
            affects_verdict=False))
    report = dict(run=proof['run'], observations=observations,
        source_sha256={name: hashlib.sha256((folder / name).read_bytes()).hexdigest() for name in
                       ['operations.json', 'prepared-metadata-verification.json', 'verified-algorithm-signatures.json', 'decoded-manifest.json']},
        limitation='Signed algorithm headers and native preparation only. Matching private-key decryption and complete approved-case controls remain necessary.')
    (folder / 'encryption-selection-observations.json').write_text(json.dumps(report, indent=2) + '\n')
    return observations


if __name__ == '__main__':
    import sys
    for row in observe(sys.argv[1]):
        print(row['variant'], row['signed_encrypted_assertions'])
