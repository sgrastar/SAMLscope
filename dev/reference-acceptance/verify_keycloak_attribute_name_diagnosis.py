"""Adopt the measured remaining condition, without inferring product-wide capability absence."""
import hashlib
import json
from pathlib import Path

CASE='IIP-IDP01-a-idp-01'


def verify(root):
    folder=Path(root)/'keycloak-attribute-name-capability'
    def read(name):return json.loads((folder/name).read_text())
    result=read('result.json');run=result['run']['id'];operations=read('operations.json')
    assert read('created.json')['run']['id']==operations['run']==run
    assert read('plan.json')['plan']['plan']['profile']=='browser_sso_idp'
    assert operations['restored'] and not operations['failures'] and operations['existing_clients_overwritten'] is False
    baseline,custom=read('observations.json')
    assert baseline['condition']=='baseline' and custom['condition']=='custom'
    assert not baseline['before']['protocolMappers']
    for row in [baseline,custom]:
        assert row['before']==row['after'] and row['flow']=='recorded'
        assert row['before']['id']==operations['created_client_id']
    a=dict(baseline['before']);b=dict(custom['before']);a.pop('protocolMappers');mappers=b.pop('protocolMappers')
    assert a==b
    expected=[dict(name='samlscope-capability-'+str(index),protocol='saml',protocolMapper='saml-user-property-mapper',
        consentRequired=False,config={'user.attribute':'firstName','attribute.name':name,
            'attribute.nameformat':'urn:samlscope:test:attribute-name-format'})
        for index,name in enumerate(['urn:samlscope:test:attribute-name','SAMLscope arbitrary attribute'])]
    assert sorted(mappers,key=lambda m:m['name'])==expected
    before=next(c for c in read('control-protocol-evidence.json')['cases'] if c['caseId']==CASE)
    assert not before['details']['observed_variants']
    cases={c['id']:c for req in result['requirements'] for c in req['cases']};case=cases[CASE]
    assert (case['outcome'],case['verdict'],case['reason_code'],case['attested'])==(
        'NOT_VERIFIED','NOT_VERIFIED','configuration.attribute-name.evidence-incomplete',False)
    details=read('configure.json')['outcome']['details']
    assert details['configuration_confirmed'] and not details['evidence_issues']
    assert set(details['observed_variants'])=={'urn-name','non-uri-name'}
    assert details['missing_variants']==['unknown-name-format']
    entries={row['id']:row for row in read('transcript.json')};manifest={row['id']:row for row in read('decoded-manifest.json')}
    expected_refs=set(baseline['new_transcript_ids'])|set(custom['new_transcript_ids'])
    assert len(expected_refs)==4 and {ref['reference'] for ref in case['evidence']}==expected_refs
    for reference in expected_refs:
        row=manifest[reference];path=(folder/row['file']).resolve()
        assert path.parent==(folder/'decoded').resolve()
        raw=path.read_bytes();assert hashlib.sha256(raw).hexdigest()==row['sha256']
        assert entries[reference]['runId']==run and entries[reference]['decodedSamlBytes']==len(raw)
    assert result['target']['metadata_digest']=='sha256:'+hashlib.sha256((folder/'target-metadata.xml').read_bytes()).hexdigest()
    return folder/'result.json',cases


if __name__=='__main__':
    import sys
    _,cases=verify(sys.argv[1]);print(CASE,cases[CASE]['verdict'],'unknown-name-format remains unverified')
