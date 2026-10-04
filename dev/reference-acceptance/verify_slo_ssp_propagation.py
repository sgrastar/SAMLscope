"""Validate SimpleSAMLphp single-logout propagation evidence before ledger adoption.

The campaign registers two Suite participants (a failing /sp/slo-fail endpoint and a recorded
/sp/slo?run= endpoint) and establishes each participant's IdP session through the product's
unsolicited SSO profile against a single-use intent. The product's own logout then propagates
LogoutRequests to those participants. Adoption requires: both participant Responses recorded as
accepted unsolicited assertions, at least one target-issued HTTP-Redirect LogoutRequest, and the
expected formal outcomes.

IIP-IDP18.c's approved variant additionally requires the Suite participant's SLO request endpoint
to be configured for HTTP-Redirect only, so the participant bindings are asserted here.
"""
import hashlib
import json
from pathlib import Path

ADOPTED = {
    'IIP-IDP17-c-idp-01': ('WARNING', 'slo.propagation.choice-recorded'),
    'IIP-IDP18-c-idp-01': ('PASS', 'slo.redirect-request.observed'),
}


def verify(root, folder='ssp-slo-propagation-v3', adopted=None):
    adopted = ADOPTED if adopted is None else adopted
    final = Path(root) / folder
    raw = (final / 'result.json').read_bytes()
    result = json.loads(raw)
    run = result['run']['id']
    entries = json.loads((final / 'transcript.json').read_text())
    by_id = {e['id']: e for e in entries}
    assert len(by_id) == len(entries)
    participants = json.loads((final / 'participants.json').read_text())
    assert len(participants) == 2, len(participants)
    # IIP-IDP18.c's variant condition: the Suite participant endpoints are HTTP-Redirect only.
    for participant in participants:
        assert participant['bindings'] == ['redirect'], participant['bindings']
    # Each participant's IdP session must be recorded as an accepted unsolicited assertion.
    unsolicited = [e for e in entries
                   if e['direction'] == 'INBOUND'
                   and (e['samlSummary'] or {}).get('normalFlowAccepted') is True
                   and (e['samlSummary'] or {}).get('unsolicited') is True]
    assert len(unsolicited) >= 2, len(unsolicited)
    # The target must have issued an HTTP-Redirect LogoutRequest to a Suite participant.
    target_requests = [e for e in entries
                       if e['direction'] == 'INBOUND'
                       and e['method'] == 'GET'
                       and 'SAMLRequest=' in (e.get('rawQuery') or '')
                       and '/sp/slo' in str(e.get('url'))]
    assert target_requests, 'no target-issued HTTP-Redirect LogoutRequest recorded'
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
