"""Qualify only the observed native RSA-OAEP capability; no algorithm inference from settings."""
import hashlib
import json
from pathlib import Path

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CASE = 'IIP-ALG06-a-idp-01'
PHASES = {'unencrypted-control', 'encrypted', 'encrypted-repeat'}


def verify(root):
    folder = Path(root)/'simplesamlphp-native-producer-encryption-normal'
    read = lambda name: json.loads((folder/name).read_text())
    result, proof, operations = [read(name) for name in
        ['result.json', 'verified-native-producer.json', 'operations.json']]
    plan = read('plan.json')['plan']['plan']
    run = result['run']['id']
    assert plan['profile'] == 'browser_sso_idp' and result['profile']['id'] == 'browser-sso-idp'
    assert run == proof['run'] == operations['run'] == read('created.json')['run']['id']
    assert operations['matrix'] == 'encryption' and operations['restored']
    restoration = read('restoration.json')
    assert restoration['restored'] and restoration['original_sha256'] == restoration['final_sha256']
    assert restoration['applied_conditions'] == 3 and restoration['restoration_write_attempts'] == 1
    for field, name in [('operations_sha256', 'operations.json'), ('transcript_sha256', 'transcript.json'),
            ('manifest_sha256', 'decoded-manifest.json'), ('fixture_sha256', 'fixture.xml'),
            ('target_metadata_sha256', 'target-metadata.xml')]:
        assert proof[field] == SHA((folder/name).read_bytes())
    assert result['target']['metadata_digest'] == 'sha256:' + proof['target_metadata_sha256']
    assert not proof['private_key_exported'] and not proof['plaintext_persisted'] and not proof['verdict_adopted']
    observed = {row['phase']: row for row in proof['observations']}
    phases = {row['phase']: row for row in operations['phases']}
    assert len(observed) == len(proof['observations']) == len(phases) == len(operations['phases']) == 3
    assert set(observed) == set(phases) == PHASES
    manifest = {row['id']: row for row in read('decoded-manifest.json')}
    assert len(manifest) == len(read('decoded-manifest.json'))
    evidence, used = set(), set()
    for name in PHASES:
        row, phase = observed[name], phases[name]
        assert phase['run'] == run and phase['receipt'] == 'recorded'
        native = read(name+'/native-readback.json')
        assert phase['readback_sha256'] == SHA((folder/name/'native-readback.json').read_bytes())
        assert native == phase['requested'] == dict(response_signed=True, assertion_signed=True,
                                                    encrypted=name != 'unencrypted-control')
        assert all(row[key] is True for key in ['request_signature_verified',
                   'response_signature_verified', 'assertion_signature_verified'])
        for reference in [row['request'], row['response']]:
            assert reference in phase['added_transcripts'] and reference not in used
            used.add(reference)
            original = manifest[reference]
            path = (folder/original['file']).resolve()
            assert path.parent == (folder/'decoded').resolve() and SHA(path.read_bytes()) == original['sha256']
        if name == 'unencrypted-control':
            assert row['encrypted'] is False
        else:
            assert row['transport_algorithm'] == 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'
            assert all(row[key] is True for key in ['decrypted', 'wrong_key_rejected', 'tampered_response_rejected'])
            evidence.update([row['request'], row['response']])
    cases = {case['id']: case for requirement in result['requirements'] for case in requirement['cases']}
    case = cases[CASE]
    assert (case['outcome'], case['verdict'], case['reason_code'], case['attested']) == (
        'SATISFIED', 'PASS', 'browser.encryption.rsa-oaep-mgf1p.decrypted', False)
    assert evidence == {ref['reference'] for ref in case['evidence'] if ref['kind'] == 'transcript'}
    return folder/'result.json', {CASE: case}


if __name__ == '__main__':
    import sys
    _, cases = verify(sys.argv[1])
    for case_id, case in cases.items():
        print(case_id, case['verdict'])
