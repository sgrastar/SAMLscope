"""Adopt explicit-setting producer evidence only after original-bound cryptographic verification."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
X='{http://www.w3.org/2001/04/xmlenc#}'
X11='{http://www.w3.org/2009/xmlenc11#}'
DS='{http://www.w3.org/2000/09/xmldsig#}'
PHASES={'oaep11-sha256-aes256','oaep11-sha256-aes128','oaep10-sha256','oaep10-sha1','oaep11-sha1'}


def verify(root):
    folder=Path(root)/'keycloak-producer-algorithms-ecp'
    read=lambda name:json.loads((folder/name).read_text())
    result=read('result.json');proof=read('verified-native-producer.json');operations=read('operations.json')
    plan=read('plan.json')['plan']['plan'];run=result['run']['id']
    assert plan['profile']=='ecp_idp' and result['profile']['id']=='ecp-idp'
    assert run==proof['run']==operations['run']==read('created.json')['run']['id']
    assert operations['restored'] and not operations['failures'] and not operations['existing_clients_overwritten']
    for field,file in [('operations_sha256','operations.json'),('transcript_sha256','transcript.json'),
                       ('manifest_sha256','decoded-manifest.json'),('fixture_sha256','fixture.xml'),('target_metadata_sha256','target-metadata.xml')]:
        assert proof[field]==SHA((folder/file).read_bytes())
    assert result['target']['metadata_digest']=='sha256:'+proof['target_metadata_sha256']
    assert not proof['private_key_exported'] and not proof['plaintext_persisted']
    observations={o['phase']:o for o in proof['observations']};phases={p['phase']:p for p in operations['phases']}
    assert len(observations)==len(proof['observations'])==len(phases)==len(operations['phases'])==len(PHASES)
    assert set(observations)==set(phases)==PHASES
    manifest={e['id']:e for e in read('decoded-manifest.json')};assert len(manifest)==len(read('decoded-manifest.json'))
    combinations=set();evidence=set()
    for name,observed in observations.items():
        phase=phases[name];assert phase['run']==run and phase['receipt']=='recorded'
        assert phase['client_database_id']==operations['created_client_id']
        readback=read(name+'/native-readback.json')
        assert SHA((folder/name/'native-readback.json').read_bytes())==phase['readback_sha256']
        assert readback['id']==operations['created_client_id'] and readback['clientId']=='http://localhost:18080/p/'+plan['id']
        attrs=readback['attributes']
        for k in ['saml.client.signature','saml.server.signature','saml.assertion.signature','saml.encrypt']:assert attrs[k]=='true'
        assert attrs['saml.encryption.algorithm']==phase['requested']['data']
        assert attrs['saml.encryption.keyAlgorithm']==phase['requested']['transport']
        assert attrs['saml.encryption.digestMethod']==phase['requested']['digest']
        assert all(observed[k] is True for k in ['request_signature_verified','response_signature_verified','assertion_signature_verified','decrypted','wrong_key_rejected','tampered_response_rejected'])
        assert {observed['request'],observed['response']}<=set(phase['added_transcripts'])
        for reference in [observed['request'],observed['response']]:
            assert reference not in evidence;evidence.add(reference)
            item=manifest[reference];path=(folder/item['file']).resolve();assert path.parent==(folder/'decoded').resolve()
            assert SHA(path.read_bytes())==item['sha256']
        response=ET.parse(folder/manifest[observed['response']]['file']).getroot()
        methods=response.findall('.//'+X+'EncryptedKey/'+X+'EncryptionMethod');assert len(methods)==1
        digests=methods[0].findall(DS+'DigestMethod');mgfs=methods[0].findall(X11+'MGF');assert len(digests)<=1 and len(mgfs)<=1
        digest=digests[0].get('Algorithm') if digests else DS[1:-1]+'sha1'
        assert observed['transport_algorithm']==methods[0].get('Algorithm') and observed['digest_algorithm']==digest
        assert observed['mgf_algorithm']==(mgfs[0].get('Algorithm') if mgfs else None)
        combinations.add((observed['transport_algorithm'],digest))
    assert {(t,d) for t in [X[1:-1]+'rsa-oaep-mgf1p',X11[1:-1]+'rsa-oaep']
            for d in [DS[1:-1]+'sha1',X[1:-1]+'sha256']}<=combinations
    cases={c['id']:c for q in result['requirements'] for c in q['cases']}
    case=cases['IIP-ALG06-c-idp-01']
    assert (case['verdict'],case['reason_code'],case['attested'])==('PASS','browser.encryption.digest-combinations.decrypted',False)
    assert evidence<={e['reference'] for e in case['evidence'] if e['kind']=='transcript'}
    assert cases['IIP-ALG06-d-idp-01']['verdict']=='NOT_VERIFIED'
    return folder/'result.json',cases
