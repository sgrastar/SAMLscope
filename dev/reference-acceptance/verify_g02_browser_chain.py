"""Verify fresh G02.a browser-campaign evidence before updating the unresolved ledger."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

CASE_ID = 'IIP-G02-a-idp-01'
CAMPAIGNS = {
    'keycloak': {
        'folder': 'browser-chain-keycloak-g02-v116-retry1',
        'image': 'sha256:3b10fef72bb11ab3860fe255e5833f97ec226e5bcb467df30549031d439e095a',
        'verdict': 'PASS',
        'reason': 'browser_fixture_satisfied',
    },
    'shibboleth': {
        'folder': 'browser-chain-shibboleth-g02-v116',
        'image': 'sha256:3b10fef72bb11ab3860fe255e5833f97ec226e5bcb467df30549031d439e095a',
        'verdict': 'NOT_VERIFIED',
        'reason': 'browser_fixture_partial',
    },
    'simplesamlphp': {
        'date': 'reference-20260929',
        'folder': 'browser-chain-ssp-g02-v116',
        'image': 'sha256:3b10fef72bb11ab3860fe255e5833f97ec226e5bcb467df30549031d439e095a',
        'verdict': 'PASS',
        'reason': 'browser_fixture_satisfied',
    },
}

CHARACTER_FIXTURES = {
    f'string-{kind}-{length}'
    for kind in ('ascii', 'boundary', 'cjk', 'combining', 'lf-literal', 'lf-reference',
                 'supplementary', 'tab-literal', 'tab-reference', 'xml-special')
    for length in (255, 256)
}
EXTENSION_FIXTURES = {
    f'extension-string-attribute-{kind}-{length}'
    for kind in ('ascii', 'boundary', 'cjk', 'combining', 'lf-reference', 'supplementary',
                 'tab-reference', 'xml-special')
    for length in (255, 256)
}
USER_DEFINED_FIXTURES = {
    f'{placement}-ascii-{length}'
    for placement in ('advice-string', 'attribute-value-string')
    for length in (255, 256)
}
NAMEID_FIXTURES = {'persistent-nameid-ascii-256', 'transient-nameid-ascii-256'}


def _read(folder: Path, name: str):
    return json.loads((folder / name).read_text())


def verify(root, product):
    if product not in CAMPAIGNS:
        raise ValueError(f'Unsupported G02 campaign product: {product}')
    expected = CAMPAIGNS[product]
    root = Path(root)
    folder = root.parent / expected.get('date', root.name) / expected['folder']
    result_path = folder / 'result.json'
    raw_result = result_path.read_bytes()
    result = json.loads(raw_result)
    run = result['run']['id']
    assert result['suite']['image_digest'] == expected['image'], (product, result['suite']['image_digest'])
    assert result['profile']['id'] == 'browser-sso-idp'
    assert _read(folder, 'created.json')['run']['id'] == run

    cases = {case['id']: case for requirement in result['requirements'] for case in requirement['cases']}
    case = cases[CASE_ID]
    assert case['verdict'] == expected['verdict'], (product, case['verdict'])
    assert case['reason_code'] == expected['reason'], (product, case['reason_code'])
    assert case['attested'] is False

    diagnostics = case.get('diagnostics', {})
    assert set(diagnostics.get('confirmed_character_fixtures', [])) == CHARACTER_FIXTURES
    assert set(diagnostics.get('responded_extension_string_fixtures', [])) == EXTENSION_FIXTURES
    assert len(diagnostics.get('confirmed_character_fixtures', [])) == len(CHARACTER_FIXTURES)
    assert len(diagnostics.get('responded_extension_string_fixtures', [])) == len(EXTENSION_FIXTURES)
    confirmed = set(diagnostics.get('confirmed_type_conditions', []))
    remaining = set(diagnostics.get('remaining_conditions', []))
    if product == 'keycloak':
        assert confirmed == {
            'persistent-nameid', 'transient-nameid', 'user-defined-advice-string',
            'user-defined-attribute-value-string', 'user-defined-extension-string-attribute'}
        assert not remaining
    elif product == 'shibboleth':
        assert confirmed == {
            'user-defined-advice-string', 'user-defined-attribute-value-string',
            'user-defined-extension-string-attribute'}
        assert remaining == {'persistent-nameid', 'transient-nameid'}
        assert set(diagnostics.get('unverifiable_fixtures', [])) == NAMEID_FIXTURES
    elif product == 'simplesamlphp':
        assert confirmed == {
            'persistent-nameid', 'transient-nameid', 'user-defined-advice-string',
            'user-defined-attribute-value-string', 'user-defined-extension-string-attribute'}
        assert not remaining
    else:
        assert confirmed == {'persistent-nameid', 'transient-nameid', 'user-defined-extension-string-attribute'}
        assert remaining == {'user-defined-advice-string', 'user-defined-attribute-value-string'}

    steps = _read(folder, 'steps.json')
    g02_steps = [step for step in steps if step.get('caseId') == CASE_ID and 'result' in step]
    assert len(g02_steps) == len(case.get('evidence', [])), (product, len(g02_steps), len(case.get('evidence', [])))
    assert all(step.get('result') == 'recorded' for step in g02_steps), product
    transcript = _read(folder, 'transcript.json')
    transcript_by_id = {entry['id']: entry for entry in transcript}
    assert len(transcript_by_id) == len(transcript)
    for ref in case.get('evidence', []):
        assert ref.get('kind') == 'transcript', (product, ref)
        entry_id = ref['reference'].removeprefix('transcript:')
        assert entry_id in transcript_by_id, (product, entry_id)
        assert transcript_by_id[entry_id]['runId'] == run, (product, entry_id)
    if product == 'simplesamlphp':
        assert _read(folder, 'initial-login.json')['receipt'] == 'recorded'
        assert (folder / 'parser.stderr').read_bytes() == b''
        operations = _read(folder, 'operations.json')
        assert operations[0]['operation'] == 'write' and operations[0]['read_back'] is True
        assert operations[-1] == {'step': 'resolve-probe', 'output': 'RESOLVED'}
        assert operations[-2] == {'step': 'apcu-clear', 'output': 'CLEARED'}
        assert operations[-3]['step'] == 'apache-graceful-reload' and operations[-3]['returncode'] == 0
        assert len(g02_steps) == 43
        manifest = {row['id']: row for row in _read(folder, 'decoded-manifest.json')}
        outbound = {
            entry['samlSummary']['action_id']: entry for entry in transcript
            if entry['direction'] == 'OUTBOUND'
            and (entry.get('samlSummary') or {}).get('scenario_case_id') == CASE_ID
        }
        assert len(outbound) == 43
        expected_fixtures = ({'baseline-success'} | CHARACTER_FIXTURES | EXTENSION_FIXTURES
                             | NAMEID_FIXTURES | USER_DEFINED_FIXTURES)
        assert {entry['samlSummary']['fixture_id'] for entry in outbound.values()} == expected_fixtures
        protocol = '{urn:oasis:names:tc:SAML:2.0:protocol}'
        assertion = '{urn:oasis:names:tc:SAML:2.0:assertion}'
        fixture_ns = '{urn:samlscope:fixture:string}'
        for step, ref in zip(g02_steps, case['evidence']):
            entry = transcript_by_id[ref['reference']]
            summary = entry['samlSummary']
            request = outbound[step['actionId']]
            original = manifest[request['id']]
            assert original['file'] == 'decoded/' + request['id'] + '.xml'
            raw_request = (folder / original['file']).read_bytes()
            assert hashlib.sha256(raw_request).hexdigest() == original['sha256']
            assert request['decodedSamlBytes'] == len(raw_request)
            root = ET.fromstring(raw_request)
            assert root.tag == protocol + 'AuthnRequest'
            assert root.get('ID') == '_' + step['actionId']
            fixture = request['samlSummary']['fixture_id']
            if fixture.startswith('string-'):
                value = root.get('ProviderName')
            elif fixture.startswith(('persistent-nameid-', 'transient-nameid-')):
                name_id = root.find(assertion + 'Subject/' + assertion + 'NameID')
                assert name_id is not None
                assert name_id.get('Format', '').endswith(':' + fixture.split('-')[0])
                value = name_id.text
            elif fixture.startswith('extension-string-attribute-'):
                extension = root.find(protocol + 'Extensions/' + fixture_ns + 'ExtensionString')
                assert extension is not None
                value = extension.get('value')
            elif fixture.startswith('advice-string-'):
                advice = root.find(protocol + 'Extensions/' + assertion + 'Assertion/'
                                   + assertion + 'Advice/' + fixture_ns + 'AdviceString')
                assert advice is not None
                value = advice.text
            elif fixture.startswith('attribute-value-string-'):
                attribute_value = root.find(protocol + 'Extensions/' + assertion + 'Assertion/'
                                            + assertion + 'AttributeStatement/' + assertion
                                            + 'Attribute/' + assertion + 'AttributeValue')
                assert attribute_value is not None
                assert attribute_value.get('{http://www.w3.org/2001/XMLSchema-instance}type') == 'f:MyStringType'
                value = attribute_value.text
            else:
                assert fixture == 'baseline-success'
                value = None
            if value is not None:
                assert len(value) == int(fixture.rsplit('-', 1)[1])
            assert entry['direction'] == 'INBOUND' and entry['method'] == 'POST'
            assert entry['correlationId'] == '_' + step['actionId']
            assert summary['inResponseTo'] == entry['correlationId']
            assert summary['type'] == 'Response' and summary['statusCode'].endswith(':Success')
            assert summary['activeProbeAccepted'] is True
            assert request['timestamp'] < entry['timestamp']

    if product == 'keycloak':
        imported = _read(folder, 'import.json')
        recovery = _read(folder, 'cleanup-recovery.json')
        assert imported['status'] == 'success'
        assert imported['import']['ui_status'] == 'client-settings-page'
        assert imported['import']['read_back']['client_id'] == imported['fixture']['entity_id']
        assert recovery['run_id'] == run
        assert recovery['pre_import_absence_checked_by_campaign'] is True
        assert recovery['delete_status'] == 204 and recovery['read_back_absent'] is True
        assert recovery['restored'] is True
        operation_counts = {
            'configuration_write_attempts': 1,
            'restoration_write_attempts': 1,
            'human_operations': 0,
            'probes': len([step for step in steps if 'result' in step]),
        }
    else:
        restoration = _read(folder, 'restoration.json')
        assert restoration['restored'] is True
        assert restoration['original_sha256'] == restoration['final_sha256']
        counts = _read(folder, 'operation-counts.json')
        assert counts['restored'] is True and counts['human_operations'] == 0
        operation_counts = dict(counts)
        operation_counts.setdefault('configuration_write_attempts', restoration.get('configuration_write_attempts', 0))
        operation_counts.setdefault('restoration_write_attempts', restoration.get('restoration_write_attempts', 0))

    proof = {
        'product': product,
        'run': run,
        'result_sha256': hashlib.sha256(raw_result).hexdigest(),
        'transcript_sha256': hashlib.sha256((folder / 'transcript.json').read_bytes()).hexdigest(),
        'evidence_refs': len(case.get('evidence', [])),
        'g02_steps': len(g02_steps),
        'verdict': case['verdict'],
        'reason_code': case['reason_code'],
        'confirmed_type_conditions': sorted(confirmed),
        'remaining_conditions': sorted(remaining),
        'operation_counts': operation_counts,
        'verdict_adopted_by_verifier': False,
    }
    (folder / 'g02-verification.json').write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n')
    return result_path, {CASE_ID: case}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--product', choices=sorted(CAMPAIGNS), required=True)
    args = parser.parse_args()
    _, selected = verify(args.root, args.product)
    case = selected[CASE_ID]
    print(args.product, case['verdict'], case['reason_code'])
