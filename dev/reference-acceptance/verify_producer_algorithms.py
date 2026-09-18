"""Audit producer capability results against signed, decrypted browser-profile exchanges."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from native_algorithm_preparation import verify as verify_preparation

CASES = {'IIP-ALG04-b-idp-01': 'browser.encryption.aes256-gcm.decrypted',
         'IIP-ALG06-b-idp-01': 'browser.encryption.rsa-oaep.decrypted',
         'IIP-ALG06-c-idp-01': 'browser.encryption.digest-combinations.decrypted'}
X = '{http://www.w3.org/2001/04/xmlenc#}'
X11 = '{http://www.w3.org/2009/xmlenc11#}'
DS = '{http://www.w3.org/2000/09/xmldsig#}'


def load(folder, name):
    return json.loads((folder / name).read_text())


def verify(root):
    source = Path(root) / 'shibboleth-producer-algorithms'
    folder = Path(root) / 'shibboleth-producer-evaluation'
    result = load(folder, 'result.json')
    assert result['run']['id'] == load(source, 'result.json')['run']['id']
    assert load(source, 'plan.json')['plan']['plan']['profile'] == 'browser_sso_idp'
    assert result['target']['metadata_digest'] == 'sha256:' + hashlib.sha256((source / 'target-metadata.xml').read_bytes()).hexdigest()
    prepared = {o['variant']: o for o in load(source, 'prepared-metadata-verification.json')['receipts']}
    signed = {o['variant']: o for o in load(source, 'verified-algorithm-signatures.json')['observations']}
    decryption = load(source, 'verified-encryption-decryption.json')
    decrypted = {o['variant']: o for o in decryption['observations']}
    assert decryption['signed_evidence_sha256'] == hashlib.sha256((source / 'verified-algorithm-signatures.json').read_bytes()).hexdigest()
    manifest = {o['id']: o for o in load(source, 'decoded-manifest.json')}
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    combinations = set()
    observed = {}
    for variant, observation in signed.items():
        verify_preparation(source, variant)
        assert prepared[variant]['metadata_sha256'] == hashlib.sha256((source / variant / 'fixture.xml').read_bytes()).hexdigest()
        assert observation['signed_response_verified']
        proof = decrypted[variant]
        assert proof['response'] == observation['response'] and proof['decrypted_assertions'] > 0
        assert proof['advertised_key_matched'] and proof['wrong_key_rejected']
        assert not proof['private_key_exported'] and not proof['plaintext_persisted']
        original = manifest[observation['response']]
        raw = (source / original['file']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == original['sha256']
        response = ET.fromstring(raw)
        data = response.findall('.//' + X + 'EncryptedData/' + X + 'EncryptionMethod')
        keys = response.findall('.//' + X + 'EncryptedKey/' + X + 'EncryptionMethod')
        assert len(data) == len(keys) == 1
        digest = keys[0].find(DS + 'DigestMethod')
        combinations.add((keys[0].get('Algorithm'), 'http://www.w3.org/2000/09/xmldsig#sha1' if digest is None else digest.get('Algorithm')))
        observed[variant] = (data[0].get('Algorithm'), keys[0].get('Algorithm'))
    assert {(t, d) for t in ['http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p', 'http://www.w3.org/2009/xmlenc11#rsa-oaep'] for d in ['http://www.w3.org/2000/09/xmldsig#sha1', 'http://www.w3.org/2001/04/xmlenc#sha256']} <= combinations
    assert observed['algorithm-encryption-aes256-gcm'][0] == 'http://www.w3.org/2009/xmlenc11#aes256-gcm'
    for case_id, reason in CASES.items():
        case = cases[case_id]
        assert (case['verdict'], case['reason_code'], case['attested']) == ('PASS', reason, False)
        evidence = {e['reference'] for e in case['evidence'] if e['kind'] == 'transcript'}
        assert any({o['request'], o['response']} <= evidence for o in signed.values())
        if case_id == 'IIP-ALG06-c-idp-01':
            for variant in ['algorithm-oaep-10-sha1','algorithm-oaep-10-sha256','algorithm-oaep-11-sha1','algorithm-oaep-11-sha256']:
                assert {signed[variant]['request'], signed[variant]['response']} <= evidence
    # SHA-1 explicitly emitted by Shibboleth does not exercise the omitted-MGF variant.
    assert cases['IIP-ALG06-d-idp-01']['verdict'] == 'NOT_VERIFIED'
    return folder / 'result.json', cases


def verify_default_mgf_withdrawal(root):
    root = Path(root)
    source = root.parent / 'reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo'
    folder = root / 'keycloak-default-mgf-audit'
    old = load(source, 'result.json')
    cases = {c['id']: c for req in old['requirements'] for c in req['cases']}
    case = cases['IIP-ALG06-d-idp-01']
    assert case['verdict'] == 'PASS'
    evidence = {e['reference'] for e in case['evidence'] if e['kind'] == 'transcript'}
    entries = {e['id']: e for e in load(folder, 'transcript.json')}
    responses = {e for e in evidence if entries[e]['samlSummary'].get('type') == 'Response'}
    seen = set()
    for observation in load(folder, 'mgf-observations.json'):
        if observation['response'] not in responses:
            continue
        seen.add(observation['response'])
        entry = entries[observation['response']]
        assert entry['runId'] == old['run']['id'] and entry['samlSummary']['normalFlowAccepted']
        raw = (folder / observation['file']).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == observation['sha256']
        methods = ET.fromstring(raw).findall('.//' + X + 'EncryptedKey/' + X + 'EncryptionMethod')
        assert len(methods) == 1
        method = methods[0]
        assert method.get('Algorithm') == observation['transport']
        assert [m.get('Algorithm') for m in method.findall(X11 + 'MGF')] == observation['mgf']
        assert method.get('Algorithm') != 'http://www.w3.org/2009/xmlenc11#rsa-oaep' or method.findall(X11 + 'MGF')
    assert seen == responses and seen
    return {'reason': 'Approved omitted-MGF variant absent from adopted original responses',
            'withdrawn_run': old['run']['id'], 'original_result_sha256': hashlib.sha256((source / 'result.json').read_bytes()).hexdigest(),
            'audit_sha256': hashlib.sha256((folder / 'mgf-observations.json').read_bytes()).hexdigest()}


if __name__ == '__main__':
    import sys
    print(verify(sys.argv[1])[1]['IIP-ALG06-c-idp-01']['verdict'])
    print(verify_default_mgf_withdrawal(sys.argv[1]))
