#!/usr/bin/env python3
"""Measure retained native metadata expiry with one authenticated client.

The installed product parses the original XML and retains its own calculated expire
value. No product code is replaced. Originals and exact restoration are recorded;
this collector never assigns a verdict or submits an operator attestation.
"""
import argparse
import base64
import datetime
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, save, BASE
from reference_flow import Client
sys.path.insert(0, str(Path(__file__).resolve().parent))
from configuration_batch import ConfigurationBatch
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
from public_runtime_capture import capture_target, capture_suite
from capture_run_originals import capture

CONTAINER = 'samlscope-reference-ssp'
REMOTE = '/var/simplesamlphp/metadata/saml20-sp-remote.php'
CONFIG = REPO / 'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php'
VARIANTS = ('live-validity-root', 'live-validity-parent', 'live-validity-child')
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NOW = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()

PARSER = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$xml=stream_get_contents(STDIN);
(new \SimpleSAML\Utils\XML())->checkSAMLMessage($xml,'saml-meta');
$entities=\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($xml);
$entity=$argv[1];
if (!isset($entities[$entity])) { throw new \RuntimeException('Expected entity missing'); }
$metadata=$entities[$entity]->getMetadata20SP();
if ($metadata===null || !is_int($metadata['expire']??null)) {
    throw new \RuntimeException('Native SP expiry missing');
}
// Retain the native parser's expiry. The static admin converter intentionally
// discards it; this CONFIG campaign measures the supported native expiry handler.
unset($metadata['entityDescriptor']);
echo json_encode(['entityId'=>$entity,'expire'=>$metadata['expire'],
 'validateAuthnRequest'=>$metadata['validate.authnrequest']??null,
 'php'=>'$metadata['.var_export($entity,true).'] = '.var_export($metadata,true).';'],JSON_THROW_ON_ERROR);
'''
READBACK = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$metadata=[];require '/var/simplesamlphp/metadata/saml20-sp-remote.php';
$entity=$argv[1];$before=time();$result=null;$error=null;
try {$result=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler()->getMetaData($entity,'saml20-sp-remote');}
catch (\Throwable $e) {$error=['class'=>get_class($e),'message'=>$e->getMessage()];}
echo json_encode(['entityId'=>$entity,'nativeTimeBefore'=>$before,'nativeTimeAfter'=>time(),
 'configurationSha256'=>hash_file('sha256','/var/simplesamlphp/metadata/saml20-sp-remote.php'),
 'flatfileMetadata'=>$metadata[$entity]??null,'resolvedMetadata'=>$result,'resolutionError'=>$error,
 'metadataSources'=>\SimpleSAML\Configuration::getInstance()->getArray('metadata.sources')],JSON_THROW_ON_ERROR);
'''
SOURCE_PATHS = {
    'native-parser.php': '/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php',
    'native-handler.php': '/var/simplesamlphp/src/SimpleSAML/Metadata/MetaDataStorageHandler.php',
    'native-source.php': '/var/simplesamlphp/src/SimpleSAML/Metadata/MetaDataStorageSource.php',
    'native-idp.php': '/var/simplesamlphp/modules/saml/src/IdP/SAML2.php',
}


def docker(*args, data=None):
    return subprocess.run(['docker', 'exec', '-i', CONTAINER, *args], input=data,
                          capture_output=True, check=True, timeout=40).stdout


def visible_error(page):
    """Persist only a public terminal error, never a login or SAML form."""
    if re.search(r'<\s*input\b|SAMLResponse|SAMLRequest|Authorization\s*:|Cookie\s*:', page, re.I):
        return False
    return len(page.encode()) <= 1048576


def reject_sensitive(value):
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r'[-_.]', '', key.lower())
            if normalized in {'cookie', 'setcookie', 'authorization', 'proxyauthorization',
                              'password', 'passwd', 'secret', 'credentials', 'token',
                              'accesstoken', 'refreshtoken', 'registrationaccesstoken',
                              'privatekey', 'metadatasignprivatekey'}:
                raise ValueError('Sensitive native readback field')
            reject_sensitive(child)
    elif isinstance(value, list):
        for child in value:
            reject_sensitive(child)


def expired_error(page, entity):
    class Text(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.parts = []
            self.hidden = 0
        def handle_starttag(self, tag, attrs):
            if tag in {'script', 'style'}:
                self.hidden += 1
        def handle_endtag(self, tag):
            if tag in {'script', 'style'}:
                self.hidden = max(0, self.hidden - 1)
        def handle_data(self, data):
            if not self.hidden:
                self.parts.append(data)
    parsed = Text()
    parsed.feed(page)
    return re.search(r'Metadata for the entity \[' + re.escape(entity) +
                     r'\] expired [0-9]+ seconds ago\.', '\n'.join(parsed.parts)) is not None


class ObservedClient(Client):
    def __init__(self, records, originals):
        super().__init__()
        self.records = records
        self.originals = originals
        self.login_count = 0
    def request(self, url, fields=None):
        if fields and any(key in fields for key in ('password', 'j_password')):
            self.login_count += 1
        record = None
        if urllib.parse.urlparse(url).port == 18380 and fields and 'SAMLRequest' in fields:
            raw = base64.b64decode(fields['SAMLRequest'], validate=True)
            root = ET.fromstring(raw)
            if root.get('ForceAuthn') in {'true', '1'} or root.get('IsPassive') in {'true', '1'}:
                raise ValueError('Shared-session metadata campaign requires an ordinary request')
            record = dict(requestId=root.get('ID'), requestSha256=SHA(raw), method='POST',
                          requestUrl=url, startedAt=NOW())
        final, page, status = super().request(url, fields)
        if record:
            record.update(finishedAt=NOW(), responseStatus=status, responseSha256=SHA(page.encode()),
                          responseUrl=urllib.parse.urlunsplit(urllib.parse.urlsplit(final)._replace(query='', fragment='')),
                          exactResponseUrl=final == url, samlResponseFormPresent='name="SAMLResponse"' in page,
                          publicTerminalError=visible_error(page))
            self.records.append(record)
            if record['publicTerminalError'] and status >= 400:
                self.originals[record['requestId']] = page.encode()
        return final, page, status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--lifetime', type=int, default=30,
                        help='Fixture preparation lifetime, not a conformance threshold')
    args = parser.parse_args()
    if not 15 <= args.lifetime <= 60:
        parser.error('Preparation lifetime must be between 15 and 60 seconds')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    (out / 'collector-source.py').write_bytes(Path(__file__).read_bytes())
    receipt = out / 'receipt'
    receipt.mkdir()
    remote = ConfigurationBatch(CONFIG)
    remote.container = CONTAINER
    remote.container_path = REMOTE
    if b'?>' in remote.original or docker('cat', REMOTE) != remote.original:
        raise ValueError('Unexpected native metadata baseline')
    (receipt / 'original-configuration.php').write_bytes(remote.original)
    (receipt / 'native-parser-command.php').write_text(PARSER)
    (receipt / 'native-readback-command.php').write_text(READBACK)
    sources = {name: docker('cat', path) for name, path in SOURCE_PATHS.items()}
    for name, raw in sources.items():
        (receipt / name).write_bytes(raw)
    capture_target(receipt, 'simplesamlphp', 'start')
    http, errors, observations = [], {}, []
    client = ObservedClient(http, errors)
    user = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
    password = os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password')
    run = None
    baseline_attempts = 0
    baseline_completed = False
    operations = []
    save(out / 'operations.json', operations)

    def readback(label):
        before = NOW()
        raw = docker('php', '-r', READBACK, entity)
        after = NOW()
        value = json.loads(raw)
        reject_sensitive(value)
        current = docker('cat', REMOTE)
        if current != remote.expected or value['configurationSha256'] != SHA(current):
            raise ValueError('Native configuration readback differs')
        (receipt / (label + '-configuration.php')).write_bytes(current)
        (receipt / (label + '-native.json')).write_bytes(raw)
        save(receipt / (label + '-clock.json'), dict(startedAt=before, finishedAt=after))
        return value

    def arm(variant, label):
        save(out / (label + '-campaign.json'), api('/api/runs/' + run + '/metadata-lab/automatic-polling',
             dict(variants=[variant], pollingDelaySeconds=0)))
        state = api('/api/runs/' + run + '/metadata-lab')
        with urllib.request.urlopen(state['automaticStartUrl'], timeout=30) as response:
            if response.status != 202:
                raise ValueError('Expected fixture retrieval gate')
        with urllib.request.urlopen(state['metadataUrl'], timeout=30) as response:
            raw = response.read()
        (receipt / (label + '-suite-prepared.xml')).write_bytes(raw)
        return state, raw

    def send(state, variant, label, invalid=False):
        old = {entry['id'] for entry in api('/api/runs/' + run + '/transcript')}
        first = len(http)
        url = state['automaticStartUrl'] + ('&signatureControl=invalid' if invalid else '')
        result = client.flow(url, None, user, password)
        entries = api('/api/runs/' + run + '/transcript')
        requests = [entry for entry in entries if entry['id'] not in old and entry['direction'] == 'OUTBOUND'
                    and entry.get('samlSummary', {}).get('type') == 'AuthnRequest'
                    and entry['samlSummary'].get('variant') == variant]
        if len(requests) != 1:
            raise ValueError('Issued request is ambiguous')
        request = requests[0]
        responses = [entry for entry in entries if entry['direction'] == 'INBOUND'
                     and entry.get('samlSummary', {}).get('inResponseTo') == request['samlSummary']['id']]
        record = dict(label=label, variant=variant, requestReference=request['id'],
                      responseReference=responses[0]['id'] if len(responses) == 1 else None,
                      receipt=result, nativeHttp=http[first:], invalidSignature=invalid)
        save(receipt / (label + '-exchange.json'), record)
        return record

    try:
        created = api('/api/plans', dict(name='SimpleSAMLphp retained native metadata expiry shared-session campaign',
            profile='metadata_idp', targetKind='IDP', targetEntityId='http://localhost:18380/idp',
            metadataSourceKind='URL', metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
            suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
            metadataRefreshWaitSeconds=args.lifetime, testUserHint=user, requestSigningMode='REQUIRED'),
            interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
        save(out / 'plan.json', created)
        plan = created['plan']['plan']['id']
        entity = BASE + '/p/' + plan
        if entity.encode() in remote.original:
            raise ValueError('Fresh peer already configured')
        created = api('/api/plans/' + plan + '/runs', {})
        save(out / 'created.json', created)
        run = created['run']['id']
        save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
        # Complete the Suite's initial round trip using this same in-memory
        # client. This prevents an additional login at formal export time.
        with urllib.request.urlopen(entity + '/metadata', timeout=30) as response:
            initial_fixture = response.read()
        (out / 'baseline-fixture.xml').write_bytes(initial_fixture)
        initial_parsed = docker('php', '-r', PARSER, entity, data=initial_fixture)
        (out / 'baseline-parser-output.json').write_bytes(initial_parsed)
        initial_data = json.loads(initial_parsed)
        if initial_data['entityId'] != entity or initial_data['validateAuthnRequest'] is not True:
            raise ValueError('Initial native metadata policy differs')
        remote.apply(initial_data['php'].encode())
        time.sleep(3)
        readback('baseline')
        baseline_attempts += 1
        initial_flow = client.flow(entity + '/start/m0-roundtrip?run=' + run, None, user, password)
        save(out / 'baseline-flow.json', dict(receipt=initial_flow))
        if api('/api/runs/' + run)['status'] != 'COMPLETED':
            raise ValueError('Initial round trip incomplete; no repeated login attempted')
        baseline_completed = True
        control = None
        for index, variant in enumerate(VARIANTS):
            row = dict(variant=variant, status='incomplete')
            operations.append(row)
            save(out / 'operations.json', operations)
            state, fixture = arm(variant, variant + '-before')
            (receipt / (variant + '-fixture.xml')).write_bytes(fixture)
            parsed = docker('php', '-r', PARSER, entity, data=fixture)
            (receipt / (variant + '-parser-output.json')).write_bytes(parsed)
            data = json.loads(parsed)
            if data['entityId'] != entity or data['validateAuthnRequest'] is not True:
                raise ValueError('Native parsed request policy differs')
            remote.apply(data['php'].encode())
            time.sleep(3)
            before = readback(variant + '-before')
            expire = data['expire']
            if before['nativeTimeAfter'] >= expire or before['flatfileMetadata']['expire'] != expire:
                raise ValueError('Fixture expired during setup')
            if index == 0:
                control = send(state, variant, 'invalid-signature-control', True)
            positive = send(state, variant, variant + '-before')
            positive_after = readback(variant + '-before-after-send')
            if positive['responseReference'] is None or positive_after['nativeTimeAfter'] >= expire:
                raise ValueError('Normal before-expiry control unavailable; no extra login attempted')
            limit = time.monotonic() + args.lifetime + 10
            while True:
                native_time = int(docker('php', '-r', 'echo time();').decode())
                if native_time > expire:
                    break
                if time.monotonic() > limit:
                    raise ValueError('Native clock did not cross fixture expiry')
                time.sleep(1)
            state, _ = arm(variant, variant + '-after-unconsumed')
            readback(variant + '-after-before-send')
            negative = send(state, variant, variant + '-after')
            readback(variant + '-after')
            native_errors = []
            for record in negative['nativeHttp']:
                raw = errors.get(record['requestId'])
                if raw is not None and expired_error(raw.decode(), entity):
                    native_errors.append(record['requestId'])
                    (receipt / (record['requestId'] + '-native-error.html')).write_bytes(raw)
            row.update(status='recorded', nativeExpiryErrors=native_errors)
            observations.append(dict(variant=variant, before=positive, after=negative))
            save(out / 'observations.json', observations)
            save(out / 'operations.json', operations)
        for record in http:
            if record['requestId'] in errors:
                (receipt / (record['requestId'] + '-native-error.html')).write_bytes(errors[record['requestId']])
        save(receipt / 'observations.json', observations)
        save(receipt / 'signature-control.json', control)
        capture_target(receipt, 'simplesamlphp', 'end')
        for name, path in SOURCE_PATHS.items():
            final = docker('cat', path)
            if final != sources[name]:
                raise ValueError('Native expiry implementation changed during campaign')
            (receipt / ('final-' + name)).write_bytes(final)
    finally:
        restoration = remote.restore()
        final = docker('cat', REMOTE)
        (receipt / 'final-configuration.php').write_bytes(final)
        restoration['restored'] = restoration['restored'] and final == remote.original
        save(out / 'restoration.json', restoration)
        save(receipt / 'restoration.json', restoration)
        save(receipt / 'native-http-observations.json', http)
        save(out / 'operation-counts.json', dict(productConfigurationWrites=remote.write_count,
            configurationApplyWrites=remote.applied_count, restorationWrites=remote.restoration_writes,
            protocolSubmissions=len(http) + int(baseline_completed),
            nativePostSubmissions=len(http), correlatedInitialRoundTrips=int(baseline_completed),
            initialBaselineFlowAttempts=baseline_attempts,
            protocolOperationsAttempted=len(http) + baseline_attempts,
            credentialPosts=client.login_count, sharedAuthenticatedClients=1,
            productRestarts=0, personOperations=0, runCreations=int(run is not None),
            unconsumedSuiteRearms=len(observations), restored=restoration['restored']))
        if run:
            save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
            entries = api('/api/runs/' + run + '/transcript')
            save(out / 'transcript.json', entries)
            save(out / 'result.json', api('/api/runs/' + run + '/result.json'))
            save(out / 'protocol-evidence.json', api('/api/runs/' + run + '/protocol-evidence'))
            capture(out, run, entries)
            capture_suite(out)
            save(receipt / 'identity.json', dict(runId=run, entityId=entity,
                 targetMetadataSha256=SHA((out / 'target-metadata.xml').read_bytes()),
                 adapter='simplesamlphp-native-filesystem-validity-v1',
                 adopted=False))
        if not restoration['restored']:
            raise ValueError('Native settings restoration incomplete')
    print(run, 'retained native expiry recorded; settings restored; no verdict inferred', flush=True)


if __name__ == '__main__':
    main()
