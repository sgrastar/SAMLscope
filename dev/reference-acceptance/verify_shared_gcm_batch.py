"""Require paired native-product GCM flows, decryption outcomes and wrong-key controls."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

SAML='urn:oasis:names:tc:SAML:2.0:assertion'
PROTOCOL='urn:oasis:names:tc:SAML:2.0:protocol'
XENC='http://www.w3.org/2001/04/xmlenc#'

def load(folder,name):return json.loads((folder/name).read_text())

def check(folder,bits,negative):
    result=load(folder,'result.json');run=result['run']['id']
    cases={c['id']:c for req in result['requirements'] for c in req['cases']}
    case_id='IIP-ALG04-'+('a' if bits==128 else 'b')+'-idp-01'
    case=cases[case_id]
    imported=load(folder,'import.json');evaluation=load(folder,'shared-key-evaluation.json')
    assert imported['run']==run and imported['status']=='completed-observation'
    assert imported['shared_key_bits']==bits
    assert imported['configuration_written'] and imported['configuration_read_back'] and imported['restored']
    assert hashlib.sha256((folder/'fixture.xml').read_bytes()).hexdigest()==imported['fixture_sha256']
    assert hashlib.sha256((folder/'parser-output.json').read_bytes()).hexdigest()==imported['parser_output_sha256']
    parser=load(folder,'parser-output.json')
    assert parser['validate_authnrequest'] is True and parser['assertion_encryption'] is True
    restored=load(folder,'restoration.json')
    assert restored['restored'] and restored['original_sha256']==restored['final_sha256']
    assert load(folder,'secret-scan.json')['passed'] is True
    assert evaluation['key_persisted'] is False and evaluation['wrong_key_control'] is negative
    assert (evaluation['input_sha256']!=imported['shared_key_sha256']) is negative
    entries={e['id']:e for e in load(folder,'transcript.json')}
    decoded={}
    for item in load(folder,'decoded-manifest.json'):
        raw=(folder/item['file']).read_bytes()
        assert hashlib.sha256(raw).hexdigest()==item['sha256']
        assert entries[item['id']]['runId']==run
        decoded[item['id']]=ET.fromstring(raw)
    requests={xml.get('ID'):eid for eid,xml in decoded.items()
        if xml.tag=='{'+PROTOCOL+'}AuthnRequest' and entries[eid]['direction']=='OUTBOUND'}
    responses=[]
    for eid,xml in decoded.items():
        entry=entries[eid]
        if entry['direction']!='INBOUND' or not entry['samlSummary'].get('normalFlowAccepted'):continue
        assert xml.tag=='{'+PROTOCOL+'}Response' and xml.get('InResponseTo') in requests
        assert xml.find('.//{'+PROTOCOL+'}StatusCode').get('Value')=='urn:oasis:names:tc:SAML:2.0:status:Success'
        assert xml.findall('{'+SAML+'}EncryptedAssertion') and not xml.findall('{'+SAML+'}Assertion')
        assert not xml.findall('.//{'+XENC+'}EncryptedKey')
        assert {e.get('Algorithm') for e in xml.iter('{'+XENC+'}EncryptionMethod')}=={
            'http://www.w3.org/2009/xmlenc11#aes'+str(bits)+'-gcm'}
        responses.append((requests[xml.get('InResponseTo')],eid))
    assert responses
    if negative:
        assert all(c['verdict']=='NOT_VERIFIED' for cid,c in cases.items() if cid.startswith('IIP-ALG04'))
        control=load(folder,'fixed-input-control.json')
        assert control=={'replacement_rejected':True,'status':400}
        remaining={c['caseId']:c for c in load(folder,'evaluation.json')['remaining']['cases']}
        details=remaining[case_id]['details']
        assert not remaining[case_id]['ready'] and details['encrypted_assertions_observed']>=1
        assert details['decrypted_assertions']==0
    else:
        assert case['verdict']=='PASS' and case['reason_code']=='browser.encryption.aes'+str(bits)+'-gcm.decrypted'
        assert case['evidence_class']=='PROTOCOL_OBSERVED' and not case['attested']
        evidence={e['reference'] for e in case['evidence'] if e['kind']=='transcript'}
        assert any({request,response}<=evidence for request,response in responses)
        assert {'caseId':case_id,'outcome':'SATISFIED'} in load(folder,'evaluation.json')['completed']
    return folder/'result.json',cases

def verify(root,bits):
    root=Path(root)
    positive=root/('simplesamlphp-shared-gcm'+str(bits))
    negative=root/('simplesamlphp-shared-gcm'+str(bits)+'-wrong-key-verified')
    result=check(positive,bits,False);check(negative,bits,True)
    assert load(positive,'result.json')['run']['id']!=load(negative,'result.json')['run']['id']
    return result

if __name__=='__main__':
    import sys
    for bits in [128,256]:
        path,cases=verify(sys.argv[1],bits);print('Verified paired native GCM evidence:',bits,path.parent.name)
