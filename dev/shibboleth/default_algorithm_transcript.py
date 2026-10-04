"""Correlate public ALG08 originals; Recorder summaries are only locator hints."""
import hashlib
import re
import xml.etree.ElementTree as ET

P = 'urn:oasis:names:tc:SAML:2.0:protocol'
CASE = 'IIP-ALG08-c-idp-01'


def require(value, reason):
    if not value:
        raise ValueError(reason)


def original_root(entry, run, read_original, expected_sha=None):
    require(entry.get('runId') == run, 'Foreign Run original')
    reference = entry.get('id', '')
    require(re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}', reference), 'Invalid original reference')
    require(entry.get('decodedSamlRef') == f'transcripts/{run}/{reference}.saml.xml',
            'Unexpected original path')
    raw = read_original(entry)
    require(isinstance(raw, bytes) and len(raw) == entry.get('decodedSamlBytes'),
            'Original byte count mismatch')
    require(expected_sha is None or hashlib.sha256(raw).hexdigest() == expected_sha,
            'Original hash mismatch')
    require(b'<!DOCTYPE' not in raw and b'<!ENTITY' not in raw, 'Unexpected XML declaration')
    return ET.fromstring(raw)


def correlate_exchange(rows, prior_ids, run, fixture, action, http, read_original):
    require(len({row['id'] for row in rows}) == len(rows), 'Duplicate original reference')
    kind = 'LogoutRequest' if fixture in {'rsa15-encrypted-id', 'oaep-encrypted-id-control'} else 'AuthnRequest'
    issued = [row for row in rows if row['id'] not in prior_ids and row.get('direction') == 'OUTBOUND'
              and row.get('samlSummary', {}).get('scenario_case_id') == CASE
              and row.get('samlSummary', {}).get('fixture_id') == fixture]
    require(len(issued) == 1, 'One native input must have one outbox original')
    request = issued[0]
    require(request.get('correlationId') == action
            and request['samlSummary'].get('action_id') == action
            and request['samlSummary'].get('active_probe') is True
            and request['samlSummary'].get('type') == kind, 'Outbox action binding mismatch')
    root = original_root(request, run, read_original, http['requestSha256'])
    require(root.tag == f'{{{P}}}{kind}' and root.get('ID') == http['requestId']
            and root.get('ID') == '_' + action and request.get('method') == 'POST'
            and root.get('Destination') == http['requestUrl'] == request.get('url')
            and http.get('requestMethod') == 'POST', 'Native actual request binding mismatch')
    reply_kind = 'LogoutResponse' if kind == 'LogoutRequest' else 'Response'
    replies = []
    for entry in rows:
        if entry['id'] in prior_ids or entry.get('direction') != 'INBOUND':
            continue
        if entry.get('samlSummary', {}).get('type') != reply_kind:
            continue
        reply = original_root(entry, run, read_original)
        require(reply.tag == f'{{{P}}}{reply_kind}', 'Response summary disagrees with original')
        if reply.get('InResponseTo') == root.get('ID'):
            require(entry.get('samlSummary', {}).get('inResponseTo') == root.get('ID'),
                    'Response summary correlation disagrees with original')
            replies.append(entry)
    require(len(replies) <= 1, 'Ambiguous native reply')
    expected_response = http.get('responseSamlSha256')
    require(bool(replies) == (expected_response is not None), 'Native response was not recorded completely')
    if replies:
        original_root(replies[0], run, read_original, expected_response)
    return request, replies[0] if replies else None
