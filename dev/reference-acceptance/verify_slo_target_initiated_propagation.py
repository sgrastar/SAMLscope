"""Validate target-initiated logout propagation evidence before ledger adoption.

IIP-IDP17.r needs a run whose transcript has no Suite-initiated OUTBOUND LogoutRequest, so the
propagation rule takes the target-initiated branch. Adoption requires: exactly one induced
failing participant (HTTP 500), at least one remaining participant LogoutRequest after the
failure that the Suite answered, and the expected formal outcome.
"""
import hashlib
import json
from pathlib import Path

ADOPTED = {
    'IIP-IDP17-r-idp-01': ('PASS', 'slo.propagation.continue-after-failure'),
}


def verify(root, folder='shibboleth-slo-target-initiated', adopted=None):
    adopted = ADOPTED if adopted is None else adopted
    final = Path(root) / folder
    raw = (final / 'result.json').read_bytes()
    result = json.loads(raw)
    run = result['run']['id']
    entries = json.loads((final / 'transcript.json').read_text())
    by_id = {e['id']: e for e in entries}
    assert len(by_id) == len(entries)
    assert not [e for e in entries
                if e['direction'] == 'OUTBOUND'
                and (e['samlSummary'] or {}).get('type') == 'LogoutRequest'], 'Suite-initiated logout present'
    failing = [e for e in entries
               if (e['samlSummary'] or {}).get('type') == 'SloFailParticipant'
               and (e['samlSummary'] or {}).get('http_status') == 500]
    assert len(failing) == 1, len(failing)
    failure_at = failing[0]['timestamp']
    remaining = [e for e in entries
                 if e['direction'] == 'INBOUND'
                 and (e['samlSummary'] or {}).get('type') == 'LogoutRequest'
                 and e['timestamp'] > failure_at]
    assert remaining, 'no continuation after the induced failure'
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    selected = {}
    for case_id, want in adopted.items():
        case = cases[case_id]
        assert (case['verdict'], case['reason_code']) == want, (case_id, case['verdict'], case['reason_code'])
        assert case['attested'] is False
        assert case['evidence']
        for ref in case['evidence']:
            assert ref['kind'] == 'transcript'
            assert by_id[ref['reference'].removeprefix('transcript:')]['runId'] == run
        selected[case_id] = case
    return final / 'result.json', selected


if __name__ == '__main__':
    import sys
    _, cases = verify(sys.argv[1])
    for name, case in cases.items():
        print(name, case['verdict'])
