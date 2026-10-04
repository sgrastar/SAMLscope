"""Validate SLO evidence whose correlation depends on captured participant sessions.

The propagation harness establishes extra Suite participants through the target's unsolicited SSO
profile. A participant assertion is only recorded when the Suite prepared a single-use
unsolicited intent, so adoption requires: each participant Response recorded as accepted
(unsolicited), a target-issued LogoutRequest bound to the run, and the expected formal outcomes.
"""
import hashlib
import json
from pathlib import Path

ADOPTED = {
    'IIP-IDP17-n-idp-01': ('PASS', 'slo.logout-request.identifier-strong-match.satisfied'),
    'IIP-IDP17-u-idp-01': ('WARNING', 'slo.logout-request.not-on-or-after-bound.violated'),
}


def verify(root, folder='shibboleth-slo-webflow-v101', adopted=None):
    adopted = ADOPTED if adopted is None else adopted
    final = Path(root) / folder
    raw = (final / 'result.json').read_bytes()
    result = json.loads(raw)
    run = result['run']['id']
    entries = json.loads((final / 'transcript.json').read_text())
    by_id = {e['id']: e for e in entries}
    assert len(by_id) == len(entries)
    # The participant sessions must be present as accepted unsolicited Responses.
    participants = [e for e in entries
                    if e['direction'] == 'INBOUND'
                    and e['samlSummary'].get('normalFlowAccepted') is True
                    and e['samlSummary'].get('unsolicited') is True]
    assert len(participants) >= 2, len(participants)
    # A target-issued LogoutRequest must be bound to this run (Redirect query carries SAMLRequest).
    target_requests = [e for e in entries
                       if e['direction'] == 'INBOUND'
                       and 'SAMLRequest=' in (e.get('rawQuery') or '')
                       and '/sp/slo' in str(e.get('url'))]
    assert target_requests, 'no target-issued LogoutRequest recorded'
    for entry in target_requests:
        assert entry['runId'] == run
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
