#!/usr/bin/env python3
"""Exercise SimpleSAMLphp's native MDQ source through a path-only local relay.

The relay only maps the product's /entities/{entityID} request to the Suite's
/mdq/{entityID}; it does not parse, rewrite, cache, or judge metadata. All
product configuration is restored before the evidence is offered to Runner.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, save, BASE
from reference_flow import Client

CONFIG = REPO / 'build/acceptance/reference-20260914/ssp-config/config-override.php'
CONTAINER = 'samlscope-reference-ssp'
RELAY = '/tmp/samlscope-native-mdq'
OVERLAY = b"\n$config['metadata.sources'] = [['type'=>'flatfile'], ['type'=>'mdq','server'=>'http://127.0.0.1:8081','cachelength'=>0]];\n"
SHA = lambda value: hashlib.sha256(value).hexdigest()


def docker(*args, data=None):
    return subprocess.run(['docker', 'exec', *(['-i'] if data is not None else []), CONTAINER, *args],
                          input=data, capture_output=True, check=True, timeout=40).stdout


def write_in_place(path, value):
    with open(path, 'r+b') as handle:
        handle.seek(0)
        handle.write(value)
        handle.truncate()
    if path.read_bytes() != value:
        raise RuntimeError('Host configuration read-back mismatch')
    # Docker Desktop may expose an in-place bind-mount write to the container a
    # moment after the host read-back. Wait for the product's own view.
    for _ in range(20):
        if docker('cat', '/var/simplesamlphp/config/config-override.php') == value:
            return
        time.sleep(0.25)
    raise RuntimeError('Product configuration read-back mismatch')


def relay_script(entity, source):
    return ("<?php\n"
            "$expected=" + json.dumps(entity) + ";\n"
            "$source=" + json.dumps(source) + ";\n"
            "$prefix='/entities/';\n"
            "$path=parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);\n"
            "if (!str_starts_with($path,$prefix) || rawurldecode(substr($path,strlen($prefix)))!==$expected) {http_response_code(404);exit;}\n"
            "$data=file_get_contents($source);\n"
            "if ($data===false) {http_response_code(502);exit;}\n"
            "file_put_contents('" + RELAY + "/response.xml',$data);\n"
            "$record=['entityId'=>$expected,'sourceUrl'=>$source,'responseSha256'=>hash('sha256',$data),"
            "'httpStatus'=>200,'observedAt'=>(new DateTimeImmutable('now',new DateTimeZone('UTC')))->format('Y-m-d\\TH:i:s.u\\Z')];\n"
            "file_put_contents('" + RELAY + "/requests.jsonl',json_encode($record).\"\\n\",FILE_APPEND|LOCK_EX);\n"
            "header('Content-Type: application/samlmetadata+xml');echo $data;\n").encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    original = CONFIG.read_bytes()
    configured = original + OVERLAY
    (out / 'original-config.php').write_bytes(original)
    (out / 'configured-config.php').write_bytes(configured)
    operations = []
    created = api('/api/plans', dict(name='SimpleSAMLphp native MDQ acquisition', profile='metadata_idp',
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
    entity = BASE + '/p/' + plan
    source = 'http://samlscope-reference-suite:8080/mdq/' + urllib.parse.quote(entity, safe='')
    public_source = BASE + '/mdq/' + urllib.parse.quote(entity, safe='')
    relay = relay_script(entity, source)
    (out / 'proxy-router.php').write_bytes(relay)
    changed = relay_started = False
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
               "echo json_encode(\\SimpleSAML\\Configuration::getInstance()->getArray('metadata.sources')); ")
        effective = docker('php', '-r', php)
        (out / 'effective-source.json').write_bytes(effective)
        sources = json.loads(effective)
        if not any(value.get('type') == 'mdq' and value.get('server') == 'http://127.0.0.1:8081'
                   for value in sources):
            raise RuntimeError('Native MDQ source is not effective')
        parser_code = ("require '/var/simplesamlphp/lib/_autoload.php'; "
            "$source=\\SimpleSAML\\Metadata\\MetaDataStorageSource::getSource("
            "['type'=>'mdq','server'=>'http://127.0.0.1:8081','cachelength'=>0]); "
            "$metadata=$source->getMetaData($argv[1],'saml20-sp-remote'); "
            "echo json_encode(['entityid'=>$metadata['entityid']??null,"
            "'expire'=>$metadata['expire']??null]);")
        parsed = subprocess.run(['docker', 'exec', CONTAINER, 'php', '-r', parser_code, entity],
                                capture_output=True, timeout=40)
        (out / 'native-mdq-parser.json').write_bytes(parsed.stdout)
        (out / 'native-mdq-parser.log').write_bytes(parsed.stderr)
        if parsed.returncode != 0 or json.loads(parsed.stdout).get('entityid') != entity:
            raise RuntimeError('Native MDQ parser did not return the Suite entity')
        username = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
        password = os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password')
        before = {entry['id'] for entry in api('/api/runs/' + run + '/transcript')}
        receipt = Client().flow(BASE + '/p/' + plan + '/start/m0-roundtrip?run=' + run,
                                None, username, password)
        save(out / 'flow.json', dict(run=run, receipt=receipt))
        if receipt != 'recorded':
            raise RuntimeError('Native MDQ SSO did not complete')
        transcript = api('/api/runs/' + run + '/transcript')
        save(out / 'transcript.json', transcript)
        new = [entry for entry in transcript if entry['id'] not in before]
        requests = [entry for entry in new if entry['direction'] == 'OUTBOUND'
                    and entry['samlSummary'].get('type') == 'AuthnRequest']
        if len(requests) != 1:
            raise RuntimeError('Ambiguous SSO request')
        responses = [entry for entry in new if entry['direction'] == 'INBOUND'
                     and entry['samlSummary'].get('type') == 'Response'
                     and entry['samlSummary'].get('inResponseTo') == requests[0]['samlSummary']['id']
                     and entry['samlSummary'].get('statusCode') == 'urn:oasis:names:tc:SAML:2.0:status:Success']
        if len(responses) != 1:
            raise RuntimeError('Correlated SSO response missing')
        save(out / 'sso-correlation.json', dict(requestTranscriptId=requests[0]['id'],
                                               responseTranscriptId=responses[0]['id']))
        (out / 'proxy-requests.jsonl').write_bytes(docker('cat', RELAY + '/requests.jsonl'))
        (out / 'mdq-response.xml').write_bytes(docker('cat', RELAY + '/response.xml'))
        product_log = (out / 'native-mdq-parser.log').read_bytes()
        product_log += docker('sh', '-c', 'cat ' + RELAY + '/server.log')
        (out / 'mdq-product-observation.log').write_bytes(product_log)
        response = (out / 'mdq-response.xml').read_bytes()
        save(out / 'mdq-request.json', dict(entity_id=entity, url=public_source,
                                           response_sha256=SHA(response)))
        save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
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
        save(out / 'operation-counts.json', dict(operations=operations, configuration_writes=sum(
            item['operation'].startswith('product-config') for item in operations),
            restoration_writes=sum(item['operation'] == 'product-config-restore' for item in operations),
            product_restarts=0, human_operations=0, restored=restored))
        if not restored:
            raise RuntimeError('Product configuration restoration failed')
    for endpoint, filename in (('result.json', 'result.json'), ('transcript', 'transcript.json')):
        with urllib.request.urlopen(BASE + '/api/runs/' + run + '/' + endpoint, timeout=30) as response:
            (out / filename).write_bytes(response.read())
    print(run, 'native MDQ fetch and SSO recorded; configuration restored')


if __name__ == '__main__':
    main()
