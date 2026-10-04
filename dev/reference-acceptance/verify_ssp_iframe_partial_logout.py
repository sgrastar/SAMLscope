"""Adopt only one independently correlated SimpleSAMLphp partial-logout processing.

The browser acknowledges the product's partial-logout Continue button. This verifier uses
the Run's decoded SAML originals and transcript chronology, not that button click, as the
grounds for the formal PartialLogout outcome. Continuation is not adopted: a repeat Run
with one logout click did not produce the later participant attempt.
"""

import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET


PROTOCOL = '{urn:oasis:names:tc:SAML:2.0:protocol}'
PARTIAL = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout'
SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
ADOPTED = {
    'IIP-IDP17-s-idp-01': ('PASS', 'slo.partial-logout.observed'),
}


def verify(root, folder='ssp-slo-iframe-v131i'):
    final = Path(root) / folder
    result_path = final / 'result.json'
    result = json.loads(result_path.read_text())
    run = result['run']['id']
    entries = json.loads((final / 'transcript.json').read_text())
    by_id = {entry['id']: entry for entry in entries}
    assert len(by_id) == len(entries) and all(entry['runId'] == run for entry in entries)
    manifest = json.loads((final / 'decoded-manifest.json').read_text())
    originals = {item['id']: item for item in manifest}
    assert len(originals) == len(manifest)

    def xml(entry):
        item = originals[entry['id']]
        path = (final / item['file']).resolve()
        assert path.is_relative_to(final.resolve()) and path.is_file()
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == item['sha256']
        assert entry['decodedSamlBytes'] == len(raw)
        return ET.fromstring(raw)

    def saml_type(entry):
        return (entry.get('samlSummary') or {}).get('type')

    assert sum(entry['direction'] == 'INBOUND'
               and (entry.get('samlSummary') or {}).get('normalFlowAccepted') is True
               and (entry.get('samlSummary') or {}).get('unsolicited') is True
               for entry in entries) >= 2
    initiators = [entry for entry in entries if entry['direction'] == 'OUTBOUND'
                  and saml_type(entry) == 'LogoutRequest']
    final_responses = [entry for entry in entries if entry['direction'] == 'INBOUND'
                       and saml_type(entry) == 'LogoutResponse']
    windows = []
    for initiator in initiators:
        request = xml(initiator)
        assert request.tag == PROTOCOL + 'LogoutRequest'
        responses = [entry for entry in final_responses
                     if xml(entry).get('InResponseTo') == request.get('ID')]
        for response in responses:
            assert xml(response).tag == PROTOCOL + 'LogoutResponse'
            windows.append((initiator, response))
    assert len(windows) == 1, 'Several completed processings cannot be mixed'
    initiator, final_response = windows[0]
    start, end = initiator['timestamp'], final_response['timestamp']
    assert start < end

    product_response = xml(final_response)
    status = product_response.find(PROTOCOL + 'Status')
    assert status is not None
    codes = [node.get('Value') for node in status.iter(PROTOCOL + 'StatusCode')]
    assert codes[:2] == [SUCCESS, PARTIAL], codes

    failures = [entry for entry in entries if start <= entry['timestamp'] <= end
                and entry['direction'] == 'INBOUND'
                and urlsplit(entry.get('url') or '').path.endswith('/sp/slo-fail')
                and entry['status'] == 500
                and saml_type(entry) == 'SloFailParticipant'
                and (entry.get('samlSummary') or {}).get('http_status') == 500]
    assert len(failures) == 1, 'Failure response must be unique inside this processing'
    failure = failures[0]
    browser = json.loads((final / 'iframe-chain-record.json').read_text())
    counts = json.loads((final / 'operation-counts.json').read_text())
    restoration = json.loads((final / 'restoration.json').read_text())
    assert browser['status'] == 'success'
    assert 'stopped-after-first-completed-partial-logout' in browser['steps']
    assert browser.get('partialLogoutContinues') == 1
    assert counts['browser_continue_clicks'] == 1 and counts['human_operations'] == 0
    assert counts['restored'] is True and restoration['restored'] is True
    assert restoration['original_sha256'] == restoration['final_sha256']
    assert counts['hosted_original_sha256'] == counts['hosted_final_sha256']
    assert counts['override_original_sha256'] == counts['override_final_sha256']

    cases = {case['id']: case for requirement in result['requirements']
             for case in requirement['cases']}
    selected = {}
    allowed = {initiator['id'], final_response['id'], failure['id']}
    for case_id, expected in ADOPTED.items():
        case = cases[case_id]
        assert (case['verdict'], case['reason_code']) == expected
        assert case['attested'] is False and case['evidence']
        referenced = {ref['reference'].removeprefix('transcript:') for ref in case['evidence']}
        assert all(ref['kind'] == 'transcript' for ref in case['evidence'])
        assert referenced <= allowed and referenced <= by_id.keys()
        assert final_response['id'] in referenced
        selected[case_id] = case
    return result_path, selected


if __name__ == '__main__':
    import sys
    _, verified = verify(sys.argv[1])
    for case_id, case in verified.items():
        print(case_id, case['verdict'])
