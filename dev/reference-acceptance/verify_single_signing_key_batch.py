"""Independently verify the approved one-candidate-key branch using original certificates."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
from verify_publisher_ui_batch import ENTITIES, MD

CASE = 'IIP-MD05-ae-idp-01'
DS = '{http://www.w3.org/2000/09/xmldsig#}'

def verify(root, product):
    folder=Path(root)/'single-signing-key'/product
    path=folder/'result.json'
    result=json.loads(path.read_text())
    assert result['run']['id']==json.loads((folder/'created.json').read_text())['run']['id']
    raw=(folder/'metadata.xml').read_bytes()
    metadata=ET.fromstring(raw)
    assert metadata.tag==MD+'EntityDescriptor' and metadata.get('entityID')==ENTITIES[product]
    roles=metadata.findall(MD+'IDPSSODescriptor');assert roles
    keys=set()
    for role in roles:
        found=False
        for descriptor in role.findall(MD+'KeyDescriptor'):
            if descriptor.get('use')=='encryption':continue
            assert descriptor.get('use') in (None, 'signing')
            infos=descriptor.findall(DS+'KeyInfo');assert len(infos)==1
            assert all(e.tag in (DS+'X509Data',DS+'KeyName') for e in infos[0])
            containers=infos[0].findall(DS+'X509Data');assert len(containers)==1
            certificates=containers[0].findall(DS+'X509Certificate')
            assert len(certificates)==len(list(containers[0]))==1
            der=base64.b64decode(''.join(certificates[0].itertext()).replace('\n','').replace(' ',''),validate=True)
            parsed=subprocess.run(['openssl','x509','-inform','DER','-pubkey','-noout'],input=der,capture_output=True,check=True)
            assert b'BEGIN PUBLIC KEY' in parsed.stdout
            keys.add(parsed.stdout);found=True
        assert found
    assert len(keys)==1
    cases={c['id']:c for req in result['requirements'] for c in req['cases']}
    case=cases[CASE]
    assert (case['outcome'],case['verdict'],case['reason_code'])==(
        'SATISFIED_WITH_NOTE','WARNING','metadata.publisher.signing-key-unambiguous')
    assert case['attested'] is False
    assert case['evidence']==[{'kind':'target-metadata','reference':'sha256:'+hashlib.sha256(raw).hexdigest()}]
    return path,cases

if __name__=='__main__':
    import sys
    for product in ENTITIES:verify(sys.argv[1],product)
    print('Verified one signing-key candidate for all reference products')
