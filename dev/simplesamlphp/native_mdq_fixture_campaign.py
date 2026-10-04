#!/usr/bin/env python3
"""Run Suite metadata fixtures through SimpleSAMLphp's native MDQ source."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, flow, save, BASE
sys.path.insert(0, str(Path(__file__).resolve().parent))
from native_mdq_campaign import CONFIG, CONTAINER, RELAY, OVERLAY, docker, relay_script, write_in_place

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
VERSION_SOURCE = '/var/simplesamlphp/src/SimpleSAML/Configuration.php'
VERSION_COMMAND = ("require '/var/simplesamlphp/lib/_autoload.php'; "
                   "echo \\SimpleSAML\\Configuration::VERSION;")
DEFAULT_VARIANTS = ('control', 'no-valid-until', 'expired', 'valid-until-near',
                    'valid-until-far', 'distinct-entity-ids', 'duplicate-entity-ids',
                    'conflicting-duplicate-entity-ids')


def product_binding(inspect):
    """Return the immutable parts of the product identity used for one campaign."""
    state = inspect.get('State', {})
    if state.get('Running') is not True:
        raise RuntimeError('SimpleSAMLphp container is not running')
    container_id = inspect.get('Id', '')
    image_id = inspect.get('Image', '')
    started_at = state.get('StartedAt', '')
    if len(container_id) != 64 or not image_id.startswith('sha256:') or not started_at:
        raise RuntimeError('Incomplete SimpleSAMLphp container identity')
    protected_roots = (
        '/var/simplesamlphp/src', '/var/simplesamlphp/vendor',
        '/var/simplesamlphp/public/module.php',
    )
    for mount in inspect.get('Mounts', []):
        destination = mount.get('Destination', '')
        if any(destination == root or destination.startswith(root + '/') for root in protected_roots):
            raise RuntimeError('SimpleSAMLphp executable source is covered by a mount')
    ports = inspect.get('NetworkSettings', {}).get('Ports', {}).get('80/tcp') or []
    if not any(item.get('HostIp') == '127.0.0.1' and item.get('HostPort') == '18380' for item in ports):
        raise RuntimeError('Expected localhost SimpleSAMLphp port mapping is absent')
    return {
        'container_name': CONTAINER,
        'container_id': container_id,
        'image_id': image_id,
        'container_started_at': started_at,
        'running_at_capture': True,
        'host_port': 18380,
        'version_source_tree_mounted': False,
    }


def capture_product_runtime(out, label):
    """Capture the target identity and version both before and after the campaign."""
    raw_inspect = subprocess.check_output(['docker', 'inspect', CONTAINER], timeout=30)
    inspect = json.loads(raw_inspect)
    if not isinstance(inspect, list) or len(inspect) != 1:
        raise RuntimeError('Ambiguous SimpleSAMLphp container inspection')
    binding = product_binding(inspect[0])
    version_source = docker('cat', VERSION_SOURCE)
    match = re.search(rb"public const string VERSION = '([^']+)';", version_source)
    if match is None:
        raise RuntimeError('SimpleSAMLphp version source is not recognizable')
    runtime_version = docker('php', '-r', VERSION_COMMAND).decode().strip()
    source_version = match.group(1).decode()
    if runtime_version != source_version:
        raise RuntimeError('SimpleSAMLphp runtime and source versions differ')
    inspect_file = f'target-container-inspect-{label}.json'
    source_file = f'target-version-source-{label}.php'
    runtime_file = f'target-version-runtime-{label}.txt'
    (out / inspect_file).write_bytes(raw_inspect)
    (out / source_file).write_bytes(version_source)
    (out / runtime_file).write_text(runtime_version + '\n')
    record = {
        'binding': binding,
        'docker_inspect_sha256': SHA(raw_inspect),
        'version_source': {'path': VERSION_SOURCE, 'file': source_file, 'sha256': SHA(version_source),
                           'value': source_version},
        'runtime_version': {'file': runtime_file, 'value': runtime_version},
    }
    save(out / f'target-runtime-{label}.json', record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--variants', default=','.join(DEFAULT_VARIANTS))
    args = parser.parse_args()
    variants = args.variants.split(',')
    if not variants or variants[0] != 'control' or len(set(variants)) != len(variants):
        parser.error('Variants must be unique and start with control')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    original = CONFIG.read_bytes()
    configured = original + OVERLAY
    (out / 'original-config.php').write_bytes(original)
    (out / 'configured-config.php').write_bytes(configured)
    initial_product_runtime = capture_product_runtime(out, 'start')
    created = api('/api/plans', dict(name='SimpleSAMLphp native MDQ fixture campaign', profile='metadata_idp',
        targetKind='IDP', targetEntityId='http://localhost:18380/idp', metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300, testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', created)
    plan = created['plan']['plan']['id']
    created = api('/api/plans/' + plan + '/runs', {})
    save(out / 'created.json', created)
    run = created['run']['id']
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
    save(out / 'campaign.json', api('/api/runs/' + run + '/metadata-lab/automatic-polling',
                                    dict(variants=variants, pollingDelaySeconds=0)))
    entity = BASE + '/p/' + plan
    source = 'http://samlscope-reference-suite:8080/p/' + plan + '/metadata/live?run=' + run
    relay = relay_script(entity, source)
    (out / 'proxy-router.php').write_bytes(relay)
    changed = relay_started = False
    operations = []
    try:
        if docker('sh', '-c', 'test -e ' + RELAY + '/pid && echo present || true').strip():
            raise RuntimeError('Another native MDQ relay is active')
        docker('mkdir', '-p', RELAY)
        docker('sh', '-c', 'cat > ' + RELAY + '/router.php', data=relay)
        if docker('cat', RELAY + '/router.php') != relay:
            raise RuntimeError('Relay read-back mismatch')
        subprocess.run(['docker', 'exec', '-d', CONTAINER, 'sh', '-c',
            'echo $$ > ' + RELAY + '/pid; exec php -S 127.0.0.1:8081 -t ' + RELAY + ' '
            + RELAY + '/router.php >' + RELAY + '/server.log 2>&1'], check=True, timeout=20)
        relay_started = True
        time.sleep(1)
        changed = True
        write_in_place(CONFIG, configured)
        operations.append(dict(operation='product-config-write', sha256=SHA(configured), read_back=True))
        time.sleep(3)
        php = ("require '/var/simplesamlphp/lib/_autoload.php'; "
               "echo json_encode(\\SimpleSAML\\Configuration::getInstance()->getArray('metadata.sources'));")
        effective = docker('php', '-r', php)
        (out / 'effective-source.json').write_bytes(effective)
        if not any(value.get('type') == 'mdq' and value.get('server') == 'http://127.0.0.1:8081'
                   for value in json.loads(effective)):
            raise RuntimeError('Native MDQ source not effective')
        for index, variant in enumerate(variants):
            state = api('/api/runs/' + run + '/metadata-lab')
            if state['selectedVariant'] != variant:
                raise RuntimeError('Unexpected campaign member')
            folder = out / variant
            folder.mkdir()
            record = dict(variant=variant, status='incomplete', source='simplesamlphp-native-mdq')
            try:
                with urllib.request.urlopen(state['automaticStartUrl'], timeout=30) as response:
                    if response.status != 202:
                        raise RuntimeError('Suite fetch gate did not open')
                with urllib.request.urlopen(state['metadataUrl'], timeout=30) as response:
                    raw = response.read()
                (folder / 'fixture.xml').write_bytes(raw)
                record['fixture_sha256'] = SHA(raw)
                before = docker('sh', '-c', 'test -f ' + RELAY + '/requests.jsonl && '
                                'wc -l < ' + RELAY + '/requests.jsonl || echo 0').strip()
                record['native_fetch_count_before'] = int(before)
                # The Suite's confirmation page is not a SAML result. The shared
                # driver checks the request/response originals and campaign index.
                flow(run, folder / 'flow.json', suite_signature_control=False)
                record['status'] = 'success'
            except Exception as error:
                record['reason'] = str(error)[:300]
            finally:
                try:
                    requests = docker('sh', '-c', 'test -f ' + RELAY + '/requests.jsonl && '
                                      'cat ' + RELAY + '/requests.jsonl || true')
                    (folder / 'proxy-requests.jsonl').write_bytes(requests)
                    record['native_fetch_count_after'] = len(requests.splitlines())
                    if record['native_fetch_count_after'] > record.get('native_fetch_count_before', 0):
                        (folder / 'proxy-response.xml').write_bytes(docker('cat', RELAY + '/response.xml'))
                except Exception as capture_error:
                    record['capture_error'] = type(capture_error).__name__
                save(folder / 'operation.json', record)
                operations.append(record)
                print(variant, record['status'], record.get('reason', ''), flush=True)
            if index == 0:
                if record['status'] != 'success':
                    raise RuntimeError('Baseline MDQ flow failed')
                save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
            pending = api('/api/runs/' + run + '/metadata-lab')
            if pending['campaignIndex'] == state['campaignIndex'] and pending.get('automaticContinueUrl'):
                with urllib.request.urlopen(urllib.request.Request(pending['automaticContinueUrl'], data=b''),
                                            timeout=30) as response:
                    response.read()
    finally:
        if changed:
            if CONFIG.read_bytes() != configured:
                raise RuntimeError('Concurrent product config change; refusing overwrite')
            write_in_place(CONFIG, original)
            operations.append(dict(operation='product-config-restore', sha256=SHA(original), read_back=True))
        (out / 'final-config.php').write_bytes(CONFIG.read_bytes())
        restored = CONFIG.read_bytes() == original
        save(out / 'restoration.json', dict(restored=restored, original_sha256=SHA(original),
                                           final_sha256=SHA(CONFIG.read_bytes())))
        if relay_started:
            docker('sh', '-c', 'kill "$(cat ' + RELAY + '/pid)"')
            docker('rm', '-rf', RELAY)
            operations.append(dict(operation='temporary-relay-stop', completed=True))
        final_product_runtime = capture_product_runtime(out, 'end')
        stable_start = (initial_product_runtime['binding'],
                        initial_product_runtime['version_source']['sha256'],
                        initial_product_runtime['version_source']['value'],
                        initial_product_runtime['runtime_version']['value'])
        stable_end = (final_product_runtime['binding'],
                      final_product_runtime['version_source']['sha256'],
                      final_product_runtime['version_source']['value'],
                      final_product_runtime['runtime_version']['value'])
        if stable_end != stable_start:
            raise RuntimeError('SimpleSAMLphp product identity or version changed during campaign')
        save(out / 'operation-counts.json', dict(operations=operations,
            product_configuration_writes=sum(item['operation'].startswith('product-config') for item in operations
                                             if 'operation' in item), restoration_writes=1 if changed else 0,
            product_restarts=0, human_operations=0, restored=restored))
        if not restored:
            raise RuntimeError('Product config restoration failed')
    try:
        save(out / 'evaluation.json', api('/api/runs/' + run + '/protocol-evidence/evaluate', {}))
    except Exception as error:
        save(out / 'evaluation-error.json', dict(reason=str(error)[:300]))
    for endpoint, filename in (('result.json', 'result.json'), ('transcript', 'transcript.json')):
        with urllib.request.urlopen(BASE + '/api/runs/' + run + '/' + endpoint, timeout=30) as response:
            (out / filename).write_bytes(response.read())
    print('Run', run, 'restored', restored)


if __name__ == '__main__':
    main()
