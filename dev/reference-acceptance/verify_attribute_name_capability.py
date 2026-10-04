"""Check native policy setup, baseline absence, signed output and exact restoration before adoption."""
import hashlib
import json
from pathlib import Path

CASE = 'IIP-IDP01-a-idp-01'
URN = 'urn:samlscope:test:attribute-name'
STRING = 'SAMLscope arbitrary attribute'
FORMAT = 'urn:samlscope:test:attribute-name-format'
REQUIRED = {'urn-name','non-uri-name','unknown-name-format'}


def load(folder, name):
    return json.loads((folder / name).read_text())


def verify(root, product):
    assert product in {'simplesamlphp','shibboleth'}
    suffix = 'simplesamlphp-attribute-name-capability' if product == 'simplesamlphp' else 'shibboleth-attribute-name-capability-registry'
    folder = Path(root) / suffix
    result = load(folder, 'result.json')
    assert load(folder, 'plan.json')['plan']['plan']['profile'] == 'browser_sso_idp'
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    case = cases[CASE]
    assert (case['verdict'],case['outcome'],case['reason_code'],case['attested']) == ('PASS','SATISFIED','configuration.attribute-name.capability-observed',False)
    receipt = load(folder, CASE+'-configure.json')['outcome']
    assert receipt['outcome'] == 'SATISFIED'
    details = receipt['details']
    assert details['configuration_confirmed'] and not details['evidence_issues'] and not details['missing_variants']
    assert set(details['observed_variants']) == set(details['required_variants']) == REQUIRED
    before = next(c for c in load(folder,'control-protocol-evidence.json')['cases'] if c['caseId']==CASE)
    assert not before['ready'] and not before['details']['observed_variants']
    assert set(before['details']['missing_variants']) == REQUIRED
    restoration = load(folder,'restoration.json')
    assert restoration['restored'] and restoration['original_sha256']==restoration['final_sha256']
    operations = load(folder,'operations.json')
    assert operations['run']==result['run']['id'] and operations['restored']
    if product=='simplesamlphp':
        assert restoration['configuration_write_attempts']==3 and restoration['restoration_write_attempts']==1
        assert operations['fixture_sha256']==hashlib.sha256((folder/'fixture.xml').read_bytes()).hexdigest()
        assert operations['parser_output_sha256']==hashlib.sha256((folder/'parser-output.json').read_bytes()).hexdigest()
        assert all(o['configuration_read_back'] for o in operations['operations'])
        assert operations['settings']=={'attribute_map':{'uid':STRING,'eduPersonAffiliation':URN},'name_format':FORMAT}
    else:
        assert restoration['temporary_file_removed'] and not restoration['failures']
        assert {r['label'] for r in operations['reloads']} >= {'attribute-registry','restore-attribute-registry'}
        assert all(o['read_back'] for o in operations['operations'] if o['operation']=='write')
    for original in load(folder,'decoded-manifest.json'):
        assert hashlib.sha256((folder/original['file']).read_bytes()).hexdigest()==original['sha256']
    proof = load(folder,'verified-attribute-evidence.json')
    assert proof['run']==result['run']['id']
    assert proof['result_sha256']==hashlib.sha256((folder/'result.json').read_bytes()).hexdigest()
    assert 'sha256:'+proof['target_metadata_sha256']==result['target']['metadata_digest']
    assert proof['target_metadata_sha256']==hashlib.sha256((folder/'target-metadata.xml').read_bytes()).hexdigest()
    assert not proof['plaintext_persisted'] and not proof['private_key_exported']
    evidence = {e['reference'] for e in case['evidence'] if e['kind']=='transcript'}
    assert len(proof['observations'])==2
    baseline, custom = proof['observations']
    assert not any(a['name'] in {URN,STRING} for a in baseline['attributes'])
    assert {URN,STRING} <= {a['name'] for a in custom['attributes']}
    assert any(a['name'] in {URN,STRING} and a['name_format']==FORMAT for a in custom['attributes'])
    for observed in proof['observations']:
        assert observed['response_signature_verified'] and {observed['request'],observed['response']} <= evidence
        if product=='shibboleth':assert observed['decrypted_assertions']>0
    return folder/'result.json',cases


if __name__=='__main__':
    import sys
    for product in ['simplesamlphp','shibboleth']:
        print(product, verify(sys.argv[1],product)[1][CASE]['verdict'])
