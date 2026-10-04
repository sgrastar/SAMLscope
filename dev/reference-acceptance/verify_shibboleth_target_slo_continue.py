"""Adopt continuation only inside one protocol-correlated logout processing.

Older local-logout Runs have no initiating request/final response boundary and return no
adoption. Their SAML originals remain diagnostic evidence, rather than proof that failure
and continuation belonged to the same logout operation.
"""

import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET


PROTOCOL = '{urn:oasis:names:tc:SAML:2.0:protocol}'
CASE = 'IIP-IDP17-r-idp-01'


def verify(root, folder='shibboleth-target-slo-v131'):
    final = Path(root) / folder
    path = final / 'result.json'
    result = json.loads(path.read_text())
    run = result['run']['id']
    entries = json.loads((final / 'transcript.json').read_text())
    by_id = {entry['id']: entry for entry in entries}
    assert len(by_id) == len(entries) and all(entry['runId'] == run for entry in entries)
    manifest = json.loads((final / 'decoded-manifest.json').read_text())
    originals = {item['id']: item for item in manifest}
    assert len(originals) == len(manifest)

    def xml(entry):
        item = originals[entry['id']]
        original = (final / item['file']).resolve()
        assert original.is_relative_to(final.resolve()) and original.is_file()
        raw = original.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == item['sha256']
        assert len(raw) == entry['decodedSamlBytes']
        return ET.fromstring(raw)

    def summary(entry):
        return entry.get('samlSummary') or {}

    initiators = [entry for entry in entries if entry['direction'] == 'OUTBOUND'
                  and summary(entry).get('type') == 'LogoutRequest']
    if len(initiators) != 1:
        return path, {}
    initiator = initiators[0]
    initiator_xml = xml(initiator)
    assert initiator_xml.tag == PROTOCOL + 'LogoutRequest' and initiator_xml.get('ID')
    final_responses = [entry for entry in entries if entry['direction'] == 'INBOUND'
                       and summary(entry).get('type') == 'LogoutResponse'
                       and xml(entry).get('InResponseTo') == initiator_xml.get('ID')]
    assert len(final_responses) == 1, 'One correlated final response is required'
    final_response = final_responses[0]
    start, end = initiator['timestamp'], final_response['timestamp']
    assert start < end

    def endpoint(value):
        parsed = urlsplit(value or '')
        assert parsed.scheme and parsed.netloc
        return parsed.scheme.lower(), parsed.netloc.lower(), parsed.path

    def request_endpoint(entry):
        assert endpoint(xml(entry).get('Destination')) == endpoint(entry['url'])

    assert sum(entry['direction'] == 'INBOUND'
               and summary(entry).get('normalFlowAccepted') is True
               and summary(entry).get('unsolicited') is True
               for entry in entries) >= 2
    failure = [entry for entry in entries if entry['direction'] == 'INBOUND'
               and start <= entry['timestamp'] <= end
               and urlsplit(entry.get('url') or '').path.endswith('/sp/slo-fail')
               and entry['status'] == 500
               and summary(entry).get('type') == 'SloFailParticipant'
               and summary(entry).get('http_status') == 500]
    assert len(failure) == 1
    failed_at = failure[0]['timestamp']
    request = xml(failure[0])
    assert request.tag == PROTOCOL + 'LogoutRequest'
    request_endpoint(failure[0])
    remaining = [entry for entry in entries if entry['direction'] == 'INBOUND'
                 and failed_at < entry['timestamp'] <= end
                 and endpoint(entry['url']) != endpoint(failure[0]['url'])
                 and urlsplit(entry.get('url') or '').path.endswith('/sp/slo')
                 and summary(entry).get('type') == 'LogoutRequest']
    assert remaining
    answered = []
    for entry in remaining:
        original = xml(entry)
        assert original.tag == PROTOCOL + 'LogoutRequest' and original.get('ID')
        request_endpoint(entry)
        assert sum(xml(other).get('ID') == original.get('ID') for other in entries
                   if summary(other).get('type') in {'LogoutRequest', 'SloFailParticipant'}) == 1
        for response in entries:
            if (response['direction'] == 'OUTBOUND'
                    and entry['timestamp'] <= response['timestamp'] <= end
                    and summary(response).get('type') == 'LogoutResponse'
                    and xml(response).tag == PROTOCOL + 'LogoutResponse'
                    and xml(response).get('InResponseTo') == original.get('ID')
                    and endpoint(xml(response).get('Destination')) == endpoint(response['url'])):
                answered.append((entry, response))
    assert answered, 'No correlated Suite response to the remaining participant'
    assert all(xml(entry).find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer') is not None
               for entry in remaining)

    browser = json.loads((final / 'probe-record.json').read_text())
    counts = json.loads((final / 'operation-counts.json').read_text())
    assert browser['run'] == run and 'idp-logout' in browser['steps']
    assert browser['outboundLogoutRequests'] == 1
    assert counts['restored'] is True and counts['browser_exit_code'] == 0
    assert counts['human_operations'] == 0
    assert counts['original_sha256'] == counts['final_sha256']
    assert hashlib.sha256((final / 'suite.xml.before').read_bytes()).hexdigest() == counts['original_sha256']
    assert hashlib.sha256((final / 'suite.xml.restored').read_bytes()).hexdigest() == counts['final_sha256']

    cases = {case['id']: case for requirement in result['requirements']
             for case in requirement['cases']}
    case = cases[CASE]
    assert (case['verdict'], case['reason_code']) == ('PASS', 'slo.propagation.continue-after-failure')
    assert case['attested'] is False and case['evidence']
    refs = {ref['reference'].removeprefix('transcript:') for ref in case['evidence']}
    assert all(ref['kind'] == 'transcript' for ref in case['evidence'])
    assert refs <= by_id.keys()
    assert {initiator['id'], final_response['id'], failure[0]['id']} <= refs
    assert any({entry['id'], response['id']} <= refs for entry, response in answered)
    return path, {CASE: case}


if __name__ == '__main__':
    import sys
    _, selected = verify(sys.argv[1])
    print(CASE, selected[CASE]['verdict'] if CASE in selected else 'NOT_VERIFIED (processing boundary unavailable)')
