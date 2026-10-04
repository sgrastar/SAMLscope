"""Validate Shibboleth native filesystem-provider acceptance evidence before ledger adoption.

Each adopted case must be a positive metadata-consumption result whose every fixture was fetched
and actually used, whose Suite signature control was rejected by the IdP, and whose provider file
and configuration were restored verbatim. Rejections and inconclusive attempts are never adopted.
"""
import hashlib
import json
from pathlib import Path

ADOPTED = {
    'IIP-MD05-ff-idp-01': ['disco-hints-ipv6-cidr', 'disco-hints-ipv4-cidr'],
}


def verify(root, folder='shibboleth-md05ff-v99', adopted=None):
    adopted = ADOPTED if adopted is None else adopted
    final = Path(root) / folder
    result = json.loads((final / 'result.json').read_text())
    run = result['run']['id']
    restored = json.loads((final / 'restoration.json').read_text())
    assert restored['restored'] and restored['original_sha256'] == restored['final_sha256']
    entries = {e['id']: e for e in json.loads((final / 'transcript.json').read_text())}
    cases = {c['id']: c for r in result['requirements'] for c in r['cases']}
    for case_id, variants in adopted.items():
        case = cases[case_id]
        assert (case['verdict'], case['reason_code']) == ('PASS', 'metadata.fixture-probe.satisfied')
        assert set(variants).issubset(case['diagnostics']['used_variants'])
        for variant in ['control', *variants]:
            data = json.loads((final / variant / 'import.json').read_text())
            assert data['status'] == 'success' and data['restored'] and data['configuration_read_back']
            assert data['provider_reloaded'] and data['import_path'] == 'native-filesystem-provider'
            assert hashlib.sha256((final / variant / 'fixture.xml').read_bytes()).hexdigest() \
                == data['fixture_sha256']
            flow = json.loads((final / variant / 'flow.json').read_text())
            assert flow['run'] == run and flow['variant'] == variant
            assert flow['correlated_success'] and flow['positive_exchange']['success']
            negative = flow['negative_control']
            assert negative['source'] == 'suite' and negative['correlated_success'] is False
        for ref in case['evidence']:
            assert ref['kind'] == 'transcript'
            assert entries[ref['reference'].removeprefix('transcript:')]['runId'] == run
    return final / 'result.json', cases


if __name__ == '__main__':
    import sys
    verify(sys.argv[1])
    print('Verified native filesystem-provider evidence for', len(ADOPTED), 'cases')
