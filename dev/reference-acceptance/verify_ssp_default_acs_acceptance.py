"""Adopt the SimpleSAMLphp default-ACS result only after replaying its native inputs."""
import hashlib
import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import xml.etree.ElementTree as ET


# This verifier protects an adoption decision.  Python removes ``assert`` statements
# under -O, so refuse that execution mode instead of silently accepting incomplete
# evidence.  The existing assertions remain useful concise checks in the supported
# interpreter mode.
if not __debug__:
    raise RuntimeError('default-ACS acceptance verification must not run with Python optimization')


CASE = 'IIP-MD05-av-idp-01'
VARIANTS = {
    'control': 0,
    'default-acs-first': 0,
    'default-acs-first-omitted': 1,
    'default-acs-all-false': 0,
    'default-acs-duplicate-index': 0,
}
REQUIRED = tuple(VARIANTS)
SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
TARGET_CONTAINER = 'samlscope-reference-ssp'
TARGET_VERSION = '2.5.0'
TARGET_VERSION_SOURCE = '/var/simplesamlphp/src/SimpleSAML/Configuration.php'


def read(folder, name):
    return json.loads((folder / name).read_text())


def case(result):
    return next(item for requirement in result['requirements'] for item in requirement['cases']
                if item['id'] == CASE)


def local_name(tag):
    return tag.rsplit('}', 1)[-1]


def xml(raw):
    if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise AssertionError('XML originals must not contain a DTD or entity declaration')
    return ET.fromstring(raw)


def saml_assertion_consumer_services(raw):
    root = xml(raw)
    assert local_name(root.tag) == 'EntityDescriptor'
    descriptors = [item for item in root.iter() if local_name(item.tag) == 'SPSSODescriptor']
    assert len(descriptors) == 1
    services = [item.attrib.copy() for item in descriptors[0]
                if local_name(item.tag) == 'AssertionConsumerService']
    assert len(services) == 4
    return root.attrib['entityID'], services


def expected_services(entity, run, variant):
    values = [
        {'Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
         'Location': f'{entity}/sp/acs/0?mdv={variant}&run={run}', 'index': '0'},
        {'Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
         'Location': f'{entity}/sp/acs/1?mdv={variant}&run={run}', 'index': '1'},
        {'Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:PAOS',
         'Location': f'{entity}/sp/paos?mdv={variant}&run={run}', 'index': '2'},
        {'Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
         'Location': f'{entity}/sp/acs/3?mdv={variant}&run={run}', 'index': '3'},
    ]
    if variant in {'control', 'default-acs-first'}:
        values[0]['isDefault'] = 'true'
    elif variant == 'default-acs-first-omitted':
        values[0]['isDefault'] = 'false'
    elif variant in {'default-acs-all-false', 'default-acs-duplicate-index'}:
        for value in values:
            value['isDefault'] = 'false'
    if variant == 'default-acs-duplicate-index':
        values[1]['index'] = '0'
    return values


def response_path_is(entry, run, variant, index):
    parsed = urlparse(entry['url'])
    return (parsed.path.endswith(f'/sp/acs/{index}')
            and parse_qs(parsed.query) == {'mdv': [variant], 'run': [run]})


def parsed_time(value):
    return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()


def require(condition, detail):
    if not condition:
        raise ValueError(detail)


def target_binding(inspect):
    require(isinstance(inspect, list) and len(inspect) == 1,
            'target container inspection must contain exactly one object')
    value = inspect[0]
    state = value.get('State', {})
    require(state.get('Running') is True, 'target container was not running')
    container_id = value.get('Id', '')
    image_id = value.get('Image', '')
    started_at = state.get('StartedAt', '')
    require(len(container_id) == 64 and image_id.startswith('sha256:') and started_at,
            'target container identity is incomplete')
    protected_roots = (
        '/var/simplesamlphp/src', '/var/simplesamlphp/vendor',
        '/var/simplesamlphp/public/module.php',
    )
    for mount in value.get('Mounts', []):
        destination = mount.get('Destination', '')
        require(not any(destination == root or destination.startswith(root + '/')
                        for root in protected_roots),
                'target executable source is covered by a mount')
    ports = value.get('NetworkSettings', {}).get('Ports', {}).get('80/tcp') or []
    require(any(item.get('HostIp') == '127.0.0.1' and item.get('HostPort') == '18380'
                for item in ports), 'target localhost port binding is absent')
    return {
        'container_name': TARGET_CONTAINER,
        'container_id': container_id,
        'image_id': image_id,
        'container_started_at': started_at,
        'running_at_capture': True,
        'host_port': 18380,
        'version_source_tree_mounted': False,
    }


def verify_target_runtime(folder, run_created_at):
    observations = []
    for label in ('start', 'end'):
        runtime = read(folder, f'target-runtime-{label}.json')
        inspect_raw = (folder / f'target-container-inspect-{label}.json').read_bytes()
        source_raw = (folder / f'target-version-source-{label}.php').read_bytes()
        runtime_value = (folder / f'target-version-runtime-{label}.txt').read_text().strip()
        binding = target_binding(json.loads(inspect_raw))
        source_match = re.search(rb"public const string VERSION = '([^']+)';", source_raw)
        require(source_match is not None, 'target version source is not recognizable')
        source_value = source_match.group(1).decode()
        require(runtime == {
            'binding': binding,
            'docker_inspect_sha256': SHA(inspect_raw),
            'version_source': {
                'path': TARGET_VERSION_SOURCE,
                'file': f'target-version-source-{label}.php',
                'sha256': SHA(source_raw),
                'value': source_value,
            },
            'runtime_version': {
                'file': f'target-version-runtime-{label}.txt',
                'value': runtime_value,
            },
        }, 'target runtime summary does not bind its originals')
        require(source_value == runtime_value == TARGET_VERSION,
                'target is not the claimed SimpleSAMLphp version')
        observations.append((binding, source_raw, runtime_value))
    require(observations[0] == observations[1],
            'target identity or executable version changed during campaign')
    require(parsed_time(observations[0][0]['container_started_at']) < run_created_at,
            'target was started after the measured Run began')
    return observations[0][0]


def verify(root):
    folder = Path(root) / 'ssp-default-acs-v136'
    run = read(folder, 'created.json')['run']['id']
    run_created_at = read(folder, 'created.json')['run']['createdAt']
    plan = read(folder, 'plan.json')['plan']['plan']
    assert plan['profile'] == 'metadata_idp'
    assert plan['target']['kind'] == 'IDP'
    assert plan['target']['entityId'] == 'http://localhost:18380/idp'
    entity = read(folder, 'plan.json')['plan']['entityId']
    campaign = read(folder, 'campaign.json')
    assert campaign['runId'] == run and campaign['planId'] == plan['id']
    assert campaign['ingestionMode'] == 'AUTOMATIC_POLLING'
    assert tuple(campaign['campaignVariants']) == REQUIRED
    assert campaign['operatorContinuationActions'] == 0
    verify_target_runtime(folder, run_created_at)

    capture = read(folder, 'original-capture.json')
    target = (folder / 'target-metadata.xml').read_bytes()
    assert capture == {'run': run, 'originals': 20, 'target_metadata_sha256': SHA(target)}

    original = (folder / 'original-config.php').read_bytes()
    configured = (folder / 'configured-config.php').read_bytes()
    final = (folder / 'final-config.php').read_bytes()
    restoration = read(folder, 'restoration.json')
    assert original != configured and original == final
    assert restoration == {'restored': True, 'original_sha256': SHA(original), 'final_sha256': SHA(final)}
    sources = read(folder, 'effective-source.json')
    assert any(value.get('type') == 'mdq' and value.get('server') == 'http://127.0.0.1:8081'
               for value in sources)
    operation_counts = read(folder, 'operation-counts.json')
    assert operation_counts['restored'] is True
    assert operation_counts['product_configuration_writes'] == 2
    assert operation_counts['restoration_writes'] == 1
    assert operation_counts['product_restarts'] == operation_counts['human_operations'] == 0
    operations = operation_counts['operations']
    assert operations[0] == {'operation': 'product-config-write', 'sha256': SHA(configured), 'read_back': True}
    assert operations[-2] == {'operation': 'product-config-restore', 'sha256': SHA(original), 'read_back': True}
    assert operations[-1] == {'operation': 'temporary-relay-stop', 'completed': True}

    transcript = read(folder, 'transcript.json')
    entries = {entry['id']: entry for entry in transcript}
    assert len(entries) == len(transcript) == 30
    assert all(entry['runId'] == run for entry in transcript)
    manifest = read(folder, 'decoded-manifest.json')
    assert len(manifest) == capture['originals']
    assert {row['id'] for row in manifest} == {
        entry['id'] for entry in transcript if entry['decodedSamlBytes'] > 0}
    decoded = {}
    decoded_root = (folder / 'decoded').resolve()
    for row in manifest:
        assert set(row) == {'id', 'file', 'sha256'} and row['id'] in entries
        path = (folder / row['file']).resolve()
        assert path.parent == decoded_root and path.is_file()
        raw = path.read_bytes()
        assert SHA(raw) == row['sha256']
        assert entries[row['id']]['decodedSamlBytes'] == len(raw)
        decoded[row['id']] = raw

    runtime = read(folder, 'suite-runtime.json')
    inspect_raw = (folder / 'suite-container-inspect.json').read_bytes()
    inspected = json.loads(inspect_raw)[0]
    jar = (folder / 'suite-runner-0.1.0.jar').read_bytes()
    assert runtime['run'] == run and runtime['docker_inspect_sha256'] == SHA(inspect_raw)
    assert runtime['container'] == {
        'name': inspected['Name'].removeprefix('/'), 'id': inspected['Id'],
        'image': inspected['Image'], 'started_at': inspected['State']['StartedAt'],
    }
    assert runtime['runner_jar'] == {
        'path': '/opt/samlscope/lib/runner-0.1.0.jar', 'sha256': SHA(jar)}
    with zipfile.ZipFile(folder / 'suite-runner-0.1.0.jar') as archive:
        factory = archive.read('com/samlscope/runner/cases/MetadataConfigCaseFactory.class')
    assert all(value.encode() in factory for value in (
        'IIP-MD05.av', 'default-acs-first', 'default-acs-first-omitted',
        'default-acs-all-false', 'default-acs-duplicate-index'))

    expected_refs = set()
    seen_proxy_hashes = set()
    for ordinal, variant in enumerate(REQUIRED):
        fixture = (folder / variant / 'fixture.xml').read_bytes()
        proxy = (folder / variant / 'proxy-response.xml').read_bytes()
        fixture_entity, fixture_services = saml_assertion_consumer_services(fixture)
        proxy_entity, proxy_services = saml_assertion_consumer_services(proxy)
        expected = expected_services(entity, run, variant)
        assert fixture_entity == proxy_entity == entity
        assert fixture_services == proxy_services == expected
        if variant == 'default-acs-duplicate-index':
            assert [service['index'] for service in proxy_services] == ['0', '0', '2', '3']
        else:
            assert [service['index'] for service in proxy_services] == ['0', '1', '2', '3']

        operation = read(folder / variant, 'operation.json')
        assert operation == {
            'variant': variant, 'status': 'success', 'source': 'simplesamlphp-native-mdq',
            'fixture_sha256': SHA(fixture), 'native_fetch_count_before': ordinal,
            'native_fetch_count_after': ordinal + 1,
        }
        fetches = [json.loads(line) for line in (folder / variant / 'proxy-requests.jsonl').read_text().splitlines()
                   if line]
        matching_fetches = [row for row in fetches if row.get('responseSha256') == SHA(proxy)]
        assert len(matching_fetches) == 1
        proxy_fetch = matching_fetches[0]
        assert proxy_fetch['entityId'] == entity and proxy_fetch['httpStatus'] == 200
        assert proxy_fetch['sourceUrl'].endswith(f'/p/{plan["id"]}/metadata/live?run={run}')
        seen_proxy_hashes.add(proxy_fetch['responseSha256'])

        related = [entry for entry in transcript if entry['samlSummary'].get('variant') == variant]
        fetch_entries = [entry for entry in related if entry['samlSummary'].get('type') == 'MetadataFetch']
        prepared = [entry for entry in related if entry['samlSummary'].get('type') == 'MetadataPrepared']
        requests = [entry for entry in related if entry['samlSummary'].get('type') == 'AuthnRequest']
        assert len(fetch_entries) == len(prepared) == 2 and len(requests) == 1
        direct_fetch = next(entry for entry in fetch_entries if entry['url'].startswith('http://localhost:18080/'))
        target_fetch = next(entry for entry in fetch_entries if entry['url'].startswith('http://samlscope-reference-suite:8080/'))
        direct_prepared = next(entry for entry in prepared
                               if entry['samlSummary']['fetchTranscriptId'] == direct_fetch['id'])
        target_prepared = next(entry for entry in prepared
                               if entry['samlSummary']['fetchTranscriptId'] == target_fetch['id'])
        assert decoded[direct_prepared['id']] == fixture
        assert decoded[target_prepared['id']] == proxy
        assert direct_prepared['samlSummary']['metadataSha256'] == SHA(fixture)
        assert target_prepared['samlSummary']['metadataSha256'] == SHA(proxy)
        request = requests[0]
        request_xml = xml(decoded[request['id']])
        assert local_name(request_xml.tag) == 'AuthnRequest'
        assert 'AssertionConsumerServiceIndex' not in request_xml.attrib
        if variant == 'control':
            assert request_xml.attrib['AssertionConsumerServiceURL'] == expected[0]['Location']
        else:
            assert 'AssertionConsumerServiceURL' not in request_xml.attrib
        request_id = request['samlSummary']['id']
        assert request_xml.attrib['ID'] == request_id
        assert request['samlSummary']['metadataSignatureControl'] == 'valid'
        responses = [entry for entry in transcript
                     if entry['samlSummary'].get('type') == 'Response'
                     and entry['samlSummary'].get('inResponseTo') == request_id]
        assert len(responses) == 1
        response = responses[0]
        assert response['samlSummary'].get('metadataProbeAccepted') is True
        assert response['samlSummary'].get('statusCode') == SUCCESS
        assert response_path_is(response, run, variant, VARIANTS[variant])
        response_xml = xml(decoded[response['id']])
        assert local_name(response_xml.tag) == 'Response'
        assert response_xml.attrib['InResponseTo'] == request_id
        assert response_xml.attrib['Destination'] == response['url']
        status = next(value for value in response_xml.iter() if local_name(value.tag) == 'StatusCode')
        assert status.attrib['Value'] == SUCCESS
        assert (direct_fetch['timestamp'] < direct_prepared['timestamp'] < request['timestamp']
                < target_fetch['timestamp'] < target_prepared['timestamp'] < response['timestamp'])
        assert request['timestamp'] < parsed_time(proxy_fetch['observedAt']) < response['timestamp']
        expected_refs.update({direct_fetch['id'], target_fetch['id'], request['id'], response['id']})
    assert len(seen_proxy_hashes) == len(REQUIRED)

    original_result = read(folder, 'result.json')
    final_result = read(folder, 'evaluation-v136/result.json')
    observed = case(original_result)
    assert observed == case(final_result)
    assert (observed['outcome'], observed['verdict'], observed['reason_code'], observed['attested']) == (
        'VIOLATED', 'FAIL', 'metadata.fixture-probe.violated', False)
    assert {(item['kind'], item['reference']) for item in observed['evidence']} == {
        ('transcript', 'transcript:' + entry) for entry in expected_refs}
    assert set(observed['diagnostics']) == {'fetched_variants', 'fixtures', 'used_variants'}
    assert set(observed['diagnostics']['fetched_variants']) == set(REQUIRED)
    assert set(observed['diagnostics']['used_variants']) == set(REQUIRED)
    assert set(observed['diagnostics']['fixtures']) == set(REQUIRED) - {'control'}
    assert original_result['target']['metadata_digest'] == 'sha256:' + SHA(target)
    before = {entry['id']: entry for entry in read(folder, 'evaluation-v136/transcript-before.json')}
    after = {entry['id']: entry for entry in read(folder, 'evaluation-v136/transcript.json')}
    assert before == after == entries
    assert read(folder, 'evaluation-v136/evaluation.json')['completed'] == []
    return folder / 'evaluation-v136/result.json', {CASE: observed}


if __name__ == '__main__':
    import sys
    result, cases = verify(sys.argv[1])
    print(result, {name: value['verdict'] for name, value in cases.items()})
