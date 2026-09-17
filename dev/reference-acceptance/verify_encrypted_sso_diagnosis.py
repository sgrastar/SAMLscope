"""Verify generation and decryption evidence without treating unobserved algorithms as failures."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

CASES = ['IIP-ALG04-a-idp-01','IIP-ALG04-b-idp-01','IIP-ALG06-b-idp-01','IIP-ALG06-c-idp-01','IIP-ALG06-d-idp-01']

def verify(root):
    folder=Path(root)/'simplesamlphp-normal-encrypted-sso'
    result=json.loads((folder/'result.json').read_text());run=result['run']['id']
    imported=json.loads((folder/'import.json').read_text())
    assert imported['run']==run and imported['assertion_encryption_override'] is True
    assert imported['configuration_written'] and imported['configuration_read_back'] and imported['restored']
    assert hashlib.sha256((folder/'fixture.xml').read_bytes()).hexdigest()==imported['fixture_sha256']
    assert hashlib.sha256((folder/'parser-output.json').read_bytes()).hexdigest()==imported['parser_output_sha256']
    parser=json.loads((folder/'parser-output.json').read_text())
    assert parser['assertion_encryption'] is True and parser['validate_authnrequest'] is True
    restored=json.loads((folder/'restoration.json').read_text())
    assert restored['restored'] and restored['original_sha256']==restored['final_sha256']
    cases={c['id']:c for req in result['requirements'] for c in req['cases']}
    assert cases['IIP-ALG06-a-idp-01']['reason_code']=='browser.encryption.rsa-oaep-mgf1p.decrypted'
    assert cases['IIP-ALG06-a-idp-01']['verdict']=='PASS'
    entries={e['id']:e for e in json.loads((folder/'transcript.json').read_text())}
    found=False
    for item in json.loads((folder/'decoded-manifest.json').read_text()):
        entry=entries[item['id']]
        if not entry['samlSummary'].get('normalFlowAccepted'):continue
        assert entry['runId']==run and entry['direction']=='INBOUND'
        raw=(folder/item['file']).read_bytes();assert hashlib.sha256(raw).hexdigest()==item['sha256']
        xml=ET.fromstring(raw)
        assert xml.findall('{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAssertion')
        assert not xml.findall('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
        algorithms={e.get('Algorithm') for e in xml.iter('{http://www.w3.org/2001/04/xmlenc#}EncryptionMethod')}
        assert algorithms=={'http://www.w3.org/2001/04/xmlenc#aes128-cbc','http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'}
        found=True
    assert found
    diagnostic=json.loads((folder/'protocol-evidence-diagnostics.json').read_text())
    selected={c['caseId']:c for c in diagnostic['cases'] if c['caseId'] in CASES}
    assert set(selected)==set(CASES)
    for case in selected.values():
        assert not case['ready'] and not case['completedObservations']
        details=case['details']
        assert details['decrypted_assertions']>=1
        assert details['observed_content_algorithms']==['aes128-cbc']
        assert details['observed_key_transport_algorithms']==['rsa-oaep-mgf1p']
        assert details['observation_state']=='required-algorithm-unobserved'
    return run,selected

if __name__=='__main__':
    import sys
    run,cases=verify(sys.argv[1]);print('Verified encrypted normal SSO and unresolved algorithm diagnostics:',run,len(cases))
