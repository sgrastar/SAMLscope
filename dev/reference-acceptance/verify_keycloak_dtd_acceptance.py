"""Verify product-native DTD rejection before ledger adoption."""

import hashlib
import json
import datetime as dt
from pathlib import Path
import xml.etree.ElementTree as ET

CASE = 'IIP-G03-b-idp-01'
IMAGE_V129 = 'sha256:ec37f94a3f36378f8cd5fb4fd16459e39fae3c1c204674ffd05909a085468809'
IMAGE_V130 = 'sha256:7a74b0fc602f145d0064de21fe4a4c50faf01e99140f0baf3977a2d0e9f16f8c'
IMAGE_V131 = 'sha256:9c959b3c231d12304e5435e48e2571b80a63ca89b7a5ec91be311cf45a2e0d88'
SIMPLE = '<!DOCTYPE samlp:AuthnRequest>'
EXTERNAL = '<!DOCTYPE samlp:AuthnRequest [<!ENTITY % samlscope SYSTEM "https://invalid.example/samlscope.dtd"> %samlscope;]>'


def read(folder, name):
    return json.loads((folder / name).read_text())


def case_of(result):
    return next(c for r in result['requirements'] for c in r['cases'] if c['id'] == CASE)


def verify(root, product='keycloak'):
    assert product in ('keycloak', 'ssp', 'shibboleth')
    folder = Path(root).parent.parent / 'reference-20260930' / (
        'shibboleth-g03-v130' if product == 'shibboleth' else f'{product}-g03-v129')
    path = folder / 'result.json'
    raw = path.read_bytes()
    result = json.loads(raw)
    before = read(folder, 'result-before-native.json')
    run = result['run']['id']
    assert run == before['run']['id'] == read(folder, 'created.json')['run']['id']
    assert before['suite']['image_digest'] == (IMAGE_V130 if product == 'shibboleth' else IMAGE_V129)
    assert result['suite']['image_digest'] == {'keycloak': IMAGE_V129, 'ssp': IMAGE_V130,
                                                'shibboleth': IMAGE_V131}[product]
    assert result['profile']['id'] == 'browser-sso-idp'
    case = case_of(result)
    old = case_of(before)
    assert old['verdict'] == 'NOT_VERIFIED' and old['reason_code'] == 'browser_fixture_partial'
    assert case['outcome'] == 'SATISFIED' and case['verdict'] == 'PASS'
    assert case['reason_code'] == 'idp.dtd.native-rejection-observed'
    assert case['attested'] is False and case['evidence_class'] == 'PROTOCOL_OBSERVED'
    assert read(folder, 'transcript.json') == read(folder, 'transcript-after-native.json')
    transcript = read(folder, 'transcript.json')
    by_id = {e['id']: e for e in transcript}
    assert len(by_id) == len(transcript)
    manifest = {e['id']: e for e in read(folder, 'decoded-manifest.json')}
    receipt = read(folder, 'native-dtd-rejection.json')
    assert receipt['runId'] == run
    assert receipt['adapter'] == {'keycloak': 'keycloak-native-parser',
                                  'ssp': 'simplesamlphp-native-parser',
                                  'shibboleth': 'shibboleth-native-parser'}[product]
    assert receipt['restored'] is True
    assert receipt['targetMetadataSha256'] == hashlib.sha256((folder / 'target-metadata.xml').read_bytes()).hexdigest()
    assert len(receipt['rejections']) == 2

    def original(entry):
        item = manifest[entry['id']]
        assert item['file'] == 'decoded/' + entry['id'] + '.xml'
        data = (folder / item['file']).read_bytes()
        assert hashlib.sha256(data).hexdigest() == item['sha256']
        assert entry['decodedSamlBytes'] == len(data) and entry['runId'] == run
        return data

    baseline = by_id[receipt['baselineRequest']]
    response = by_id[receipt['baselineResponse']]
    request_xml = ET.fromstring(original(baseline))
    response_xml = ET.fromstring(original(response))
    assert baseline['direction'] == 'OUTBOUND' and response['direction'] == 'INBOUND'
    assert request_xml.get('ID') == response_xml.get('InResponseTo') == response['correlationId']
    assert response['samlSummary']['statusCode'].endswith(':Success')
    assert response['samlSummary']['activeProbeAccepted'] is True
    assert {'kind': 'transcript', 'reference': response['id']} in case['evidence']

    seen = set()
    for row in receipt['rejections']:
        variant = row['variant']
        assert variant in {'dtd-authn-request', 'dtd-external-entity-authn-request'}
        assert variant not in seen
        seen.add(variant)
        entry = by_id[row['requestReference']]
        assert entry['direction'] == 'OUTBOUND'
        assert entry['samlSummary']['scenario_case_id'] == CASE
        assert entry['samlSummary']['fixture_id'] == variant
        assert entry['timestamp'] > response['timestamp']
        data = original(entry)
        assert row['requestSha256'] == hashlib.sha256(data).hexdigest()
        xml = data.decode()
        dtd = SIMPLE if variant == 'dtd-authn-request' else EXTERNAL
        assert dtd in xml
        if variant == 'dtd-external-entity-authn-request':
            assert '%samlscope;' in xml
        assert row['logSha256'] == hashlib.sha256(row['productLog'].encode()).hexdigest()
        if product == 'keycloak':
            assert 'ERROR [org.keycloak.saml.common]' in row['productLog']
            assert 'ParsingException' in row['productLog'] and 'DOCTYPE is disallowed' in row['productLog']
            rejected_at = dt.datetime.strptime(row['productLog'][:23], '%Y-%m-%d %H:%M:%S,%f').replace(
                tzinfo=dt.timezone.utc).timestamp()
            transport_result = 'no-response:Invalid Request'
        elif product == 'ssp':
            assert '[php:notice]' in row['productLog'] and '[critical] Uncaught Exception:' in row['productLog']
            assert 'Dangerous XML detected, DOCTYPE nodes are not allowed in the XML body' in row['productLog']
            rejected_at = dt.datetime.strptime(row['productLog'][1:32], '%a %b %d %H:%M:%S.%f %Y').replace(
                tzinfo=dt.timezone.utc).timestamp()
            transport_result = 'no-response:HTTP-500'
        else:
            assert 'ERROR [net.shibboleth.shared.xml.impl.BasicParserPool:72] - XML Parsing Error' in row['productLog']
            assert 'Caused by: org.xml.sax.SAXParseException;' in row['productLog']
            assert 'DOCTYPE is disallowed' in row['productLog']
            rejected_at = dt.datetime.strptime(row['productLog'][:23], '%Y-%m-%d %H:%M:%S,%f').replace(
                tzinfo=dt.timezone.utc).timestamp()
            transport_result = 'no-response:Stale Request'
        assert entry['timestamp'] <= rejected_at <= entry['timestamp'] + 5
        assert {'kind': 'transcript', 'reference': entry['id']} in case['evidence']
        action = entry['samlSummary']['action_id']
        assert any(step.get('actionId') == action and step.get('result') == transport_result
                   for step in read(folder, 'steps.json'))
        assert not any(e['direction'] == 'INBOUND' and e.get('correlationId') == '_' + action
                       for e in transcript)
    assert seen == {'dtd-authn-request', 'dtd-external-entity-authn-request'}
    restoration = read(folder, 'restoration.json')
    assert restoration['restored']
    if product == 'keycloak':
        imported = read(folder, 'import.json')
        assert imported['status'] == 'success'
        assert imported['import']['ui_status'] == 'client-settings-page'
        assert restoration['cleanup']['read_back_absent']
    else:
        assert not restoration['failures']
        assert restoration['original_sha256'] == restoration['final_sha256']
        if product == 'shibboleth':
            assert restoration['temporary_file_removed']
    return path, {CASE: case}


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--product', choices=('keycloak', 'ssp', 'shibboleth'), default='keycloak')
    args = p.parse_args()
    path, cases = verify(args.root, args.product)
    print(path, cases[CASE]['verdict'])
