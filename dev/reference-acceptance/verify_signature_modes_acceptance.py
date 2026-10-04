"""Adopt signature-mode capability only from native configuration, original crypto proofs, and formal results."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

CASE='IIP-SSO04-a-idp-01'
MODES={'both','assertion-only','response-only'}
SHA=lambda raw:hashlib.sha256(raw).hexdigest()


def verify(root,product):
    assert product in {'keycloak','shibboleth','simplesamlphp'}
    folder=Path(root)/(product+'-signature-modes-v61')
    read=lambda name:json.loads((folder/name).read_text())
    run=read('created.json')['run']['id'];proof=read('verified-signature-modes.json');operations=read('operations.json')
    assert proof['run']==operations['run']==run and operations['restored']
    assert proof['verdict_adopted'] is False and proof['outcome']['outcome']=='SATISFIED'
    assert set(proof['outcome']['details']['observed_modes'])==MODES
    assert proof['outcome']['details']['missing_modes']==[] and proof['outcome']['details']['collection_issues']==[]
    for field,name in [('transcript_sha256','transcript.json'),('manifest_sha256','decoded-manifest.json'),
        ('target_metadata_sha256','target-metadata.xml'),('fixture_sha256','fixture.xml'),('operations_sha256','operations.json')]:
        assert proof[field]==SHA((folder/name).read_bytes())
    assert read('plan.json')['plan']['plan']['profile']=='browser_sso_idp'
    controls=proof['negative_controls']
    assert len(controls)==18 and set(controls.values())=={'NOT_VERIFIED'}
    entries={e['id']:e for e in read('transcript.json')}
    originals={m['id']:m for m in read('decoded-manifest.json')}
    for row in originals.values():
        path=(folder/row['file']).resolve();assert path.parent==(folder/'decoded').resolve()
        assert SHA(path.read_bytes())==row['sha256']
    phases=operations['phases'];assert len(phases)==3 and {p['phase'] for p in phases}==MODES
    seen=set();responses=set()
    for phase in phases:
        mode=phase['phase'];assert phase['receipt']=='recorded'
        expected=dict(response_signed=mode!='assertion-only',assertion_signed=mode!='response-only',encrypted=False)
        assert phase['requested']==expected
        ids=phase['added_transcripts'];assert len(ids)==2 and not seen.intersection(ids);seen.update(ids)
        matched=[entries[r] for r in ids if entries[r]['samlSummary'].get('type')=='Response']
        assert len(matched)==1;response=matched[0];responses.add(response['id'])
        xml=ET.parse(folder/originals[response['id']]['file']).getroot()
        ds='{http://www.w3.org/2000/09/xmldsig#}Signature';s='{urn:oasis:names:tc:SAML:2.0:assertion}'
        assertions=xml.findall(s+'Assertion');assert len(assertions)==1 and not xml.findall(s+'EncryptedAssertion')
        assert bool(xml.findall(ds))==expected['response_signed']
        assert bool(assertions[0].findall(ds))==expected['assertion_signed']
        assert {key.split(':',1)[1] for key in controls if key.startswith(response['id']+':')}=={
            'signature-value','wrong-audience','wrong-confirmation','wrong-issuer','duplicate-id','missing-response'}
        if product in {'keycloak','simplesamlphp'}:
            native=read(mode+'/native-readback.json')
            assert phase['readback_sha256']==SHA((folder/mode/'native-readback.json').read_bytes())
            if product=='keycloak':
                attrs=native['attributes']
                assert attrs['saml.server.signature']==str(expected['response_signed']).lower()
                assert attrs['saml.assertion.signature']==str(expected['assertion_signed']).lower()
                assert attrs['saml.encrypt']=='false'
            else:assert native==expected
        else:assert phase['configuration_readback'] is True
    if product=='keycloak':assert not operations['failures'] and not operations['existing_clients_overwritten']
    else:
        restore=read('restoration.json');assert restore['restored'] and restore['original_sha256']==restore['final_sha256']
        if product=='shibboleth':assert restore['temporary_removed'] and not restore['failures']
    result=read('adoption/result.json');after={e['id']:e for e in read('adoption/transcript.json')}
    assert entries==after
    assert result['run']['id']==run and result['target']['metadata_digest']=='sha256:'+proof['target_metadata_sha256']
    case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==CASE)
    assert (case['outcome'],case['verdict'],case['reason_code'])==('SATISFIED','PASS','browser.signature-modes.observed')
    assert case['attested'] is False
    references={(e['kind'],e['reference']) for e in case['evidence']}
    assert references=={(e['kind'],e['reference']) for e in proof['outcome']['evidence']}
    assert references=={('transcript',reference) for reference in seen}
    return folder/'adoption/result.json',{CASE:case}


if __name__=='__main__':
    import sys
    for product in ['keycloak','shibboleth','simplesamlphp']:
        _,cases=verify(sys.argv[1],product);print(product,cases[CASE]['verdict'])
