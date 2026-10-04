"""Validate SimpleSAMLphp browser-chain evidence before ledger adoption.

The chain imports the Suite SP through the product's native metadata parser, completes an
SP-initiated success flow, and adds an IdP-initiated (unsolicited) success through the product's
SSOService against a prepared single-use intent. IIP-SSO01.g requires both success paths to carry
an Assertion; IIP-SSO01.z records the unsolicited success. Adoption requires: the SSP metadata
baseline restored byte-for-byte, an accepted unsolicited Response, an SP-initiated success, and
the expected formal outcomes.
"""
import hashlib
import json
from pathlib import Path

BASELINE_SHA256 = 'a04e059f24cda81aff7ecd8e77eb71c18df12477cd5086269eae29adc4c1a56b'
ADOPTED = {
    'IIP-SSO01-g-idp-01': ('PASS', 'browser.normal-flow.success-responses-have-assertions'),
    'IIP-SSO01-z-idp-01': ('WARNING', 'browser.normal-flow.unsolicited-sso-observed'),
}


def verify(root, folder='ssp-browser-chain-v2', adopted=None):
    adopted = ADOPTED if adopted is None else adopted
    final = Path(root) / folder
    raw = (final / 'result.json').read_bytes()
    result = json.loads(raw)
    run = result['run']['id']
    entries = json.loads((final / 'transcript.json').read_text())
    by_id = {e['id']: e for e in entries}
    assert len(by_id) == len(entries)
    restoration = json.loads((final / 'restoration.json').read_text())
    assert restoration['restored'] is True, restoration
    assert restoration['original_sha256'] == BASELINE_SHA256, restoration
    assert restoration['final_sha256'] == BASELINE_SHA256, restoration
    unsolicited = [e for e in entries
                   if e['direction'] == 'INBOUND'
                   and (e['samlSummary'] or {}).get('normalFlowAccepted') is True
                   and (e['samlSummary'] or {}).get('unsolicited') is True]
    assert len(unsolicited) == 1, len(unsolicited)
    sp_initiated = [e for e in entries
                    if e['direction'] == 'INBOUND'
                    and (e['samlSummary'] or {}).get('type') == 'Response'
                    and (e['samlSummary'] or {}).get('inResponseTo')
                    and str((e['samlSummary'] or {}).get('statusCode', '')).endswith(':Success')]
    assert sp_initiated, 'no SP-initiated success Response recorded'
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
