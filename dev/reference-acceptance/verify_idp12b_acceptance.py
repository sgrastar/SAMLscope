"""Fail-closed adoption gate for the eight-condition IIP-IDP12.b campaign."""

import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

if not __debug__:
    raise RuntimeError('IDP12.b evidence verification requires assertions')

CASE = 'IIP-IDP12-b-idp-01'
D_CASE = 'IIP-IDP12-d-idp-01'
IMAGE = 'sha256:0f4bd62a6ebd217ed75bf8a7f986ce28d74cc6eb0a49fe20cade95a0b30d3955'
SOURCE_MANIFEST = '05aa4538d0d799e5caecf708ba197520b2a6253c49d1ba8d62ff4a2ba52cdc17'
PROJECT_JARS = {
    '/opt/samlscope/lib/api-0.1.0.jar': '83e9250453ff5a70e6babf94e175ecd9a7e67e5170f6d9e76db524cdface5b76',
    '/opt/samlscope/lib/core-0.1.0.jar': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe',
    '/opt/samlscope/lib/peer-0.1.0.jar': '25e947915452abfbb49c832a2624911f1a4d09ae2b01400865d97de98640ccdc',
    '/opt/samlscope/lib/runner-0.1.0.jar': 'dfda318c893dec8208724b96d1fd417de5b776340ef0ea54903e38939e084a94',
    '/opt/samlscope/lib/saml-0.1.0.jar': '83c92fc2277830aacc5d79deac74428c3cbf57707c9a919313362260a2c0e7a3',
    '/opt/samlscope/lib/store-0.1.0.jar': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece',
}
TARGET_IMAGES = {
    'keycloak': 'sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067',
    'shibboleth': 'sha256:3c1b1fa64c58258aefc9e38d4ae60e9f0340731318a472110ea56ce88c18a11a',
}
P = '{urn:oasis:names:tc:SAML:2.0:protocol}'
A = '{urn:oasis:names:tc:SAML:2.0:assertion}'
DS = '{http://www.w3.org/2000/09/xmldsig#}'
SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
FIXTURES = (
    'registered-url-signed-control', 'registered-url-unsigned',
    'unregistered-url-signed', 'unregistered-url-unsigned',
    'other-entity-url-signed', 'other-entity-url-unsigned',
    'unknown-index-signed', 'unknown-index-unsigned')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(folder, name):
    return json.loads((folder / name).read_text())


def one(items):
    assert len(items) == 1
    return items[0]


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def verify_suite_build(folder):
    evidence = folder.parent / 'idp12b-suite-v150'
    image = read(evidence, 'image-and-jars.json')
    assert image['image_id'] == IMAGE
    assert image['repo_digests'] == ['samlscope@' + IMAGE]
    assert {row['path']: row['sha256'] for row in image['project_jars']} == PROJECT_JARS
    source = read(evidence, 'source-manifest.json')
    assert source['source_manifest_sha256'] == SOURCE_MANIFEST
    assert sha(canonical(source['files'])) == SOURCE_MANIFEST


def verify_wire_signatures(folder, metadata_path, request_files):
    source = Path(__file__).with_name('VerifyIdp12bSignatures.java')
    with tempfile.TemporaryDirectory(prefix='idp12b-signatures-') as temporary:
        subprocess.run(['javac', '-d', temporary, str(source)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        command = ['java', '-cp', temporary, 'VerifyIdp12bSignatures',
                   str(metadata_path)]
        for path, signed in request_files:
            command.extend([str(path), str(signed).lower()])
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return json.loads(result.stdout)


def verify_target_runtime(folder, product):
    captures = []
    for phase in ('start', 'end'):
        summary = read(folder, 'target-runtime-' + phase + '.json')
        inspect_raw = (folder / ('target-container-inspect-' + phase + '.json')).read_bytes()
        version_raw = (folder / ('target-version-runtime-' + phase + '.txt')).read_bytes()
        assert summary['product'] == product
        assert summary['docker_inspect_sha256'] == sha(inspect_raw)
        assert summary['runtime_version']['sha256'] == sha(version_raw)
        inspected = json.loads(inspect_raw)
        assert isinstance(inspected, list) and len(inspected) == 1
        item = inspected[0]
        binding = summary['binding']
        assert binding['container_name'] == item['Name'].removeprefix('/')
        assert binding['container_id'] == item['Id']
        assert binding['configured_image'] == item['Config']['Image']
        assert binding['image_id'] == item['Image'] == TARGET_IMAGES[product]
        assert binding['container_started_at'] == item['State']['StartedAt']
        assert binding['running_at_capture'] is True and binding['host_port_bound'] is True
        if product == 'keycloak':
            assert item['Config']['Image'] == ('quay.io/keycloak/keycloak@'
                                               + TARGET_IMAGES[product])
            assert item['Config']['Image'] in binding['repo_digests']
            assert version_raw.decode().startswith('Keycloak 26.7.2\n')
            assert item['Config']['Labels']['org.opencontainers.image.version'] == '26.7.2'
        else:
            assert version_raw.decode().strip() == '5.2.3'
            source_raw = (folder / ('target-version-source-' + phase + '.txt')).read_bytes()
            assert summary['version_source']['sha256'] == sha(source_raw)
            source_value = source_raw.decode().strip()
            assert summary['version_source']['value'] == source_value
            installed = [line for line in source_value.splitlines()
                         if line.startswith('idp.installed.version=')]
            assert installed == ['idp.installed.version=5.2.3']
        captures.append(summary)
    first, second = captures
    assert first['binding'] == second['binding']
    assert first['runtime_version'] == second['runtime_version']
    if product == 'shibboleth':
        assert first['version_source'] == second['version_source']


def origin(value):
    parsed = urllib.parse.urlsplit(value)
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme.lower() == 'https' else 80)
    return parsed.scheme.lower(), (parsed.hostname or '').lower(), port


def verify_folder(folder, product):
    folder = Path(folder)
    assert product in {'keycloak', 'shibboleth'}
    result_path = folder / 'result.json'
    result_raw = result_path.read_bytes()
    result = json.loads(result_raw)
    verify_suite_build(folder)
    run = result['run']['id']
    plan = read(folder, 'plan.json')['plan']['plan']
    plan_id = plan['id']
    assert read(folder, 'created.json')['run']['id'] == run
    assert read(folder, 'created.json')['run']['planId'] == plan_id
    assert result['suite']['image_digest'] == IMAGE
    assert result['profile']['id'] == 'browser-sso-idp' and result['target']['role'] == 'IDP'
    assert plan['requestSigningMode'] == 'REQUIRED'
    expected_target = {'keycloak': 'http://localhost:18180/realms/samlscope',
                       'shibboleth': 'http://localhost:18280/idp/shibboleth'}[product]
    expected_sso = {'keycloak': expected_target + '/protocol/saml',
                    'shibboleth': 'http://localhost:18280/idp/profile/SAML2/POST/SSO'}[product]
    assert plan['target']['entityId'] == expected_target
    verify_target_runtime(folder, product)
    entity = 'http://localhost:18080/p/' + plan_id
    primary = entity + '/sp/acs/0'
    secondary = entity + '/sp/acs/1'
    hostile = entity + '/samlscope-other-sp/acs'
    other_entity = entity + '/other-entity'

    case = one([case for requirement in result['requirements'] for case in requirement['cases']
                if case['id'] == CASE])
    assert (case['outcome'], case['verdict'], case['reason_code']) == (
        'SATISFIED', 'PASS', 'idp.acs-probe.satisfied')
    assert case['evidence_class'] == 'PROTOCOL_OBSERVED' and case['attested'] is False
    evidence_ids = [item['reference'] for item in case['evidence']]
    assert len(evidence_ids) == len(set(evidence_ids)) == 8
    assert {item['kind'] for item in case['evidence']} == {'transcript'}

    native = read(folder, 'native-configuration.json')
    metadata_path = folder / ('suite-sp-metadata.xml' if product == 'keycloak' else 'fixture-main.xml')
    if product == 'shibboleth':
        # The installed main entity is the Suite plan metadata with only the
        # native unsigned-request capability toggled before aggregation.
        configured_main = ET.fromstring(metadata_path.read_bytes())
        configured_role = one(configured_main.findall(
            '{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor'))
        configured_role.set('AuthnRequestsSigned', 'false')
        assert native['requester_metadata_sha256'] == sha(ET.tostring(configured_main))
    assert native['requester_entity'] == entity
    assert native['registered_acs'] == [primary, secondary]
    assert native['other_entity'] == other_entity and native['hostile_acs'] == hostile
    assert native['accepts_signed_and_unsigned_requests'] is True
    if product == 'keycloak':
        original_raw = (folder / 'main-client-original.json').read_bytes()
        configured_raw = (folder / 'main-client-configured-readback.json').read_bytes()
        other_raw = (folder / 'other-client-configured-readback.json').read_bytes()
        original, configured, other = map(json.loads, (original_raw, configured_raw, other_raw))
        assert native['requester_original_sha256'] == sha(original_raw)
        assert native['requester_configured_sha256'] == sha(configured_raw)
        assert native['other_entity_readback_sha256'] == sha(other_raw)
        assert configured['id'] == native['requester_client_id'] == original['id']
        assert configured['clientId'] == original['clientId'] == entity
        assert set(configured['redirectUris']) == set(original['redirectUris']) | {secondary}
        assert configured['attributes']['saml.client.signature'] == 'false'
        allowed = {'redirectUris', 'attributes'}
        assert {key: value for key, value in configured.items() if key not in allowed} == {
            key: value for key, value in original.items() if key not in allowed}
        expected_attributes = dict(original.get('attributes') or {})
        expected_attributes['saml.client.signature'] = 'false'
        assert configured['attributes'] == expected_attributes
        assert other['id'] == native['other_client_id'] and other['clientId'] == other_entity
        assert other['protocol'] == 'saml' and other['redirectUris'] == [hostile]
        restored = json.loads((folder / 'main-client-restored-readback.json').read_bytes())
        assert canonical(restored) == canonical(original)
        restoration = read(folder, 'restoration.json')
        cleanup = restoration['cleanup']
        assert restoration['restored'] and restoration['import_ok']
        assert cleanup['requester_restore_attempted'] and cleanup['requester_restore_read_back']
        assert cleanup['requester_delete_attempted'] and cleanup['other_delete_attempted']
        assert cleanup['requester_read_back_absent'] and cleanup['other_read_back_absent']
        assert read(folder, 'final-client-absence-readback.json') == {
            'requester_query': [], 'other_entity_query': []}
    else:
        assert (folder / 'fixture.xml').read_bytes() == (folder / 'fixture-readback.xml').read_bytes()
        assert native['aggregate_sha256'] == sha((folder / 'fixture-readback.xml').read_bytes())
        fixture = ET.fromstring((folder / 'fixture-readback.xml').read_bytes())
        entities = fixture.findall('{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor')
        assert {item.get('entityID') for item in entities} == {entity, other_entity}
        other = one([item for item in entities if item.get('entityID') == other_entity])
        acs = one(other.findall('.//{urn:oasis:names:tc:SAML:2.0:metadata}AssertionConsumerService'))
        assert acs.get('Location') == hostile and acs.get('index') == '0'
        restoration = read(folder, 'restoration.json')
        assert restoration['restored'] and restoration['temporary_file_removed']
        assert restoration['original_sha256'] == restoration['final_sha256']
        assert (folder / 'original-providers.xml').read_bytes() == (folder / 'final-providers.xml').read_bytes()

    entries = read(folder, 'transcript.json')
    by_id = {entry['id']: entry for entry in entries}
    assert len(by_id) == len(entries) and all(entry['runId'] == run for entry in entries)
    decoded_rows = read(folder, 'decoded-manifest.json')
    decoded = {row['id']: row for row in decoded_rows}
    assert len(decoded) == len(decoded_rows)
    browser_rows = read(folder, 'browser-originals-manifest.json')
    browser = {row['id']: row for row in browser_rows}
    assert len(browser) == len(browser_rows)

    def xml_original(entry):
        row = decoded[entry['id']]
        assert row['file'] == 'decoded/' + entry['id'] + '.xml'
        raw = (folder / row['file']).read_bytes()
        assert sha(raw) == row['sha256'] and len(raw) == entry['decodedSamlBytes']
        return ET.fromstring(raw)

    def browser_original(entry):
        row = browser[entry['id']]
        assert row['file'] == 'browser-originals/' + entry['id'] + '.body'
        raw = (folder / row['file']).read_bytes()
        assert sha(raw) == row['sha256'] and len(raw) == row['bytes'] == entry['bodyBytes']
        assert len(raw) <= 64 * 1024
        return raw

    requests = {}
    request_files = []
    for entry in entries:
        summary = entry.get('samlSummary') or {}
        if summary.get('scenario_case_id') != CASE:
            continue
        fixture = summary.get('fixture_id')
        assert fixture in FIXTURES and fixture not in requests
        assert entry['direction'] == 'OUTBOUND' and entry['method'] == 'POST'
        assert summary['action_id'] == entry['correlationId']
        request = xml_original(entry)
        request_files.append((folder / decoded[entry['id']]['file'],
                              fixture.endswith('-signed') or fixture == 'registered-url-signed-control'))
        assert request.tag == P + 'AuthnRequest'
        assert request.get('ID') == '_' + summary['action_id']
        assert request.get('Destination') == expected_sso
        issuer = one(request.findall(A + 'Issuer'))
        assert issuer.text == entity
        signed = bool(request.findall('.//' + DS + 'Signature'))
        expected_signed = fixture.endswith('-signed') or fixture == 'registered-url-signed-control'
        assert signed == expected_signed
        if fixture.startswith('registered-url-'):
            assert request.get('AssertionConsumerServiceURL') == secondary
            assert request.get('AssertionConsumerServiceIndex') is None
        elif fixture.startswith('unregistered-url-'):
            assert request.get('AssertionConsumerServiceURL') == entity + '/sp/acs/999999'
        elif fixture.startswith('other-entity-url-'):
            assert request.get('AssertionConsumerServiceURL') == hostile
        else:
            assert fixture.startswith('unknown-index-')
            assert request.get('AssertionConsumerServiceIndex') == '999999'
            assert request.get('AssertionConsumerServiceURL') is None
        requests[fixture] = (entry, request)
    assert tuple(requests) == FIXTURES
    assert len({entry['samlSummary']['action_id'] for entry, _ in requests.values()}) == 8
    assert len({request.get('ID') for _, request in requests.values()}) == 8
    crypto = verify_wire_signatures(folder, metadata_path, request_files)
    metadata_certificate = bytes.fromhex(crypto['metadataCertificateSha256'])
    assert len(metadata_certificate) == 32
    metadata_document = ET.fromstring(metadata_path.read_bytes())
    published_certificates = {
        ''.join(certificate.text.split())
        for descriptor in metadata_document.findall(
            './/{urn:oasis:names:tc:SAML:2.0:metadata}SPSSODescriptor')
        for key in descriptor.findall(
            '{urn:oasis:names:tc:SAML:2.0:metadata}KeyDescriptor')
        if key.get('use') == 'signing'
        for certificate in key.findall('.//' + DS + 'X509Certificate')
    }
    published_cert = one(list(published_certificates))
    assert sha(__import__('base64').b64decode(published_cert)) == crypto['metadataCertificateSha256']
    if product == 'keycloak':
        assert configured['attributes']['saml.signing.certificate'] == published_cert
    else:
        native_main = one([item for item in entities if item.get('entityID') == entity])
        native_certs = {''.join(item.text.split()) for item in native_main.findall('.//' + DS + 'X509Certificate')}
        assert published_cert in native_certs

    used = set()
    for fixture, (request_entry, request) in requests.items():
        action = request_entry['samlSummary']['action_id']
        request_id = request.get('ID')
        candidates = [by_id[evidence] for evidence in evidence_ids
                      if by_id[evidence]['correlationId'] in {action, request_id}]
        observed = one(candidates)
        assert observed['id'] not in used and observed['timestamp'] >= request_entry['timestamp']
        used.add(observed['id'])
        if observed['method'] == 'BROWSER':
            assert not fixture.startswith('registered-url-')
            assert observed['correlationId'] == action
            assert observed['direction'] == 'INBOUND' and 400 <= observed['status'] <= 599
            assert origin(observed['url']) == origin(expected_target)
            assert observed['url'] != hostile and observed['decodedSamlBytes'] == 0
            assert observed['samlSummary'] == {
                'failure_indicated': True, 'type': 'BrowserResponseObservation',
                'http_status': observed['status'], 'url': observed['url']}
            raw = browser_original(observed)
            assert b'<samlp:Response' not in raw and b'name="SAMLResponse"' not in raw
        else:
            assert observed['direction'] == 'INBOUND' and observed['method'] == 'POST'
            assert observed['correlationId'] == request_id
            response = xml_original(observed)
            assert response.tag == P + 'Response' and response.get('InResponseTo') == request_id
            destination = response.get('Destination')
            assert destination in {primary, secondary} and observed['url'] == destination
            code = one(response.findall(P + 'Status/' + P + 'StatusCode')).get('Value')
            assert observed['samlSummary']['inResponseTo'] == request_id
            assert observed['samlSummary']['destination'] == destination
            assert observed['samlSummary']['statusCode'] == code
            assert observed['samlSummary']['activeProbeAccepted'] is True
            if fixture.startswith('registered-url-'):
                assert destination == secondary and code == SUCCESS
            elif fixture.startswith('unregistered-url-'):
                assert code != SUCCESS or destination == primary
            elif fixture.startswith('unknown-index-'):
                assert destination == primary
        # No event for this action/request may reach the URL owned by the other entity.
        correlated = [entry for entry in entries if entry['correlationId'] in {action, request_id}]
        assert all(entry.get('url') != hostile for entry in correlated)
        for entry in correlated:
            if entry.get('decodedSamlBytes', 0) and entry['id'] in decoded:
                message = xml_original(entry)
                if message.tag == P + 'Response':
                    assert message.get('Destination') != hostile
    assert used == set(evidence_ids)
    assert all(entry.get('url') != hostile for entry in entries)
    if product == 'shibboleth':
        d_case = one([candidate for requirement in result['requirements']
                      for candidate in requirement['cases'] if candidate['id'] == D_CASE])
        assert (d_case['outcome'], d_case['verdict'], d_case['reason_code']) == (
            'NOT_VERIFIED', 'NOT_VERIFIED', 'idp.acs-probe.inconclusive')
        assert d_case['evidence'] == []
    return result_path, {CASE: case}


def verify(root, product):
    root = Path(root)
    folder = root / ({'keycloak': 'idp12b-keycloak-v150',
                      'shibboleth': 'idp12bd-shibboleth-v150'}[product])
    return verify_folder(folder, product)


def tamper_self_test(folder, product):
    folder = Path(folder)

    def rejected(label, mutate):
        with tempfile.TemporaryDirectory(prefix='idp12b-tamper-') as temporary:
            trial = Path(temporary) / 'evidence'
            shutil.copytree(folder, trial)
            shutil.copytree(folder.parent / 'idp12b-suite-v150',
                            trial.parent / 'idp12b-suite-v150')
            mutate(trial)
            try:
                verify_folder(trial, product)
            except (AssertionError, KeyError, ValueError, ET.ParseError):
                return label
            raise AssertionError('Tamper was accepted: ' + label)

    def first_response(trial):
        entries = read(trial, 'transcript.json')
        matches = [entry for entry in entries if entry['id'] in {
            item['reference'] for requirement in read(trial, 'result.json')['requirements']
            for case in requirement['cases'] if case['id'] == CASE for item in case['evidence']}
                   and entry['method'] == 'POST']
        assert matches
        return matches[0]

    def tamper_response(trial):
        entry = first_response(trial)
        row = next(row for row in read(trial, 'decoded-manifest.json') if row['id'] == entry['id'])
        path = trial / row['file']
        path.write_bytes(path.read_bytes().replace(b'/sp/acs/1', b'/samlscope-other-sp/acs', 1))

    def tamper_browser(trial):
        row = read(trial, 'browser-originals-manifest.json')[0]
        path = trial / row['file']
        path.write_bytes(path.read_bytes() + b'tamper')

    def tamper_other(trial):
        if product == 'keycloak':
            value = read(trial, 'other-client-configured-readback.json')
            value['redirectUris'] = ['http://invalid.example/acs']
            (trial / 'other-client-configured-readback.json').write_text(json.dumps(value))
        else:
            path = trial / 'fixture-readback.xml'
            path.write_bytes(path.read_bytes().replace(b'/samlscope-other-sp/acs', b'/wrong/acs', 1))

    def tamper_signature_state(trial):
        entries = read(trial, 'transcript.json')
        entry = one([item for item in entries
                     if (item.get('samlSummary') or {}).get('fixture_id') == 'registered-url-signed-control'])
        manifest = read(trial, 'decoded-manifest.json')
        row = next(item for item in manifest if item['id'] == entry['id'])
        path = trial / row['file']
        root = ET.fromstring(path.read_bytes())
        signature = one(root.findall('.//' + DS + 'Signature'))
        for parent in root.iter():
            if signature in list(parent):
                parent.remove(signature)
                break
        raw = ET.tostring(root)
        path.write_bytes(raw)
        row['sha256'] = sha(raw)
        (trial / 'decoded-manifest.json').write_text(json.dumps(manifest))

    def tamper_restoration(trial):
        value = read(trial, 'restoration.json')
        value['restored'] = False
        (trial / 'restoration.json').write_text(json.dumps(value))

    labels = [
        rejected('response-original', tamper_response),
        rejected('browser-original', tamper_browser),
        rejected('other-entity-readback', tamper_other),
        rejected('signature-state', tamper_signature_state),
        rejected('restoration', tamper_restoration),
    ]
    return labels


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--product', choices=['keycloak', 'shibboleth'], required=True)
    parser.add_argument('--tamper-self-test', action='store_true')
    args = parser.parse_args()
    path, cases = verify(args.root, args.product)
    print(path, cases[CASE]['verdict'])
    if args.tamper_self_test:
        print('tamper rejected:', ', '.join(tamper_self_test(path.parent, args.product)))
