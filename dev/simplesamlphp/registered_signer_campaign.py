#!/usr/bin/env python3
"""Collect two native peers and six Suite outbox signer controls with one login.

The installed SimpleSAMLphp parser imports both original metadata documents in one
temporary overlay. The collector records originals and exact restoration; Runner
alone determines an outcome. Cookies, credentials and login forms remain in memory.
"""
import argparse
import base64
import datetime
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
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, save, BASE
from reference_flow import Client
sys.path.insert(0, str(Path(__file__).resolve().parent))
from configuration_batch import ConfigurationBatch
from metadata_validity_epoch_campaign import reject_sensitive
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
from browser_probe_selection import prepare_and_skip
from capture_run_originals import capture
from algorithm_preference_campaign import recorded

CASE = 'IIP-SSO01-al-idp-01'
CAMPAIGN = 'native-registered-signer'
TARGET = 'http://localhost:18380/idp'
CONTAINER = 'samlscope-reference-ssp'
SUITE = 'samlscope-reference-suite'
REMOTE = '/var/simplesamlphp/metadata/saml20-sp-remote.php'
CONFIG = REPO / 'build/acceptance/reference-20260914/ssp-config/saml20-sp-remote.php'
INSTALL = '/data/registered-signer-evidence-simplesamlphp'
FIXTURES = ('local-normal', 'local-invalid-signature', 'local-other-signer')
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NOW = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
SOURCES = {
    'native-idp.php': '/var/simplesamlphp/modules/saml/src/IdP/SAML2.php',
    'native-message.php': '/var/simplesamlphp/modules/saml/src/Message.php',
    'native-configuration.php': '/var/simplesamlphp/src/SimpleSAML/Configuration.php',
    'native-parser.php': '/var/simplesamlphp/src/SimpleSAML/Metadata/SAMLParser.php',
    'native-handler.php': '/var/simplesamlphp/src/SimpleSAML/Metadata/MetaDataStorageHandler.php',
    'native-source.php': '/var/simplesamlphp/src/SimpleSAML/Metadata/MetaDataStorageSource.php',
    'native-signed-helper.php': '/var/simplesamlphp/vendor/simplesamlphp/saml2-legacy/src/SAML2/SignedElementHelper.php',
}
PARSER = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$xml=stream_get_contents(STDIN);
(new \SimpleSAML\Utils\XML())->checkSAMLMessage($xml,'saml-meta');
$entities=\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($xml);$entity=$argv[1];
if (!isset($entities[$entity])) {throw new \RuntimeException('Expected entity missing');}
$metadata=$entities[$entity]->getMetadata20SP();
if ($metadata===null) {throw new \RuntimeException('Native SP role missing');}
// Match the installed admin converter's native static import semantics.
unset($metadata['entityDescriptor'],$metadata['expire']);
echo json_encode(['entityId'=>$entity,'validateAuthnRequest'=>$metadata['validate.authnrequest']??null,
 'metadata'=>$metadata,'php'=>'$metadata['.var_export($entity,true).'] = '.var_export($metadata,true).';'],JSON_THROW_ON_ERROR);
'''
READBACK = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$input=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);
$metadata=[];require '/var/simplesamlphp/metadata/saml20-sp-remote.php';
$handler=\SimpleSAML\Metadata\MetaDataStorageHandler::getMetadataHandler();$rows=[];
foreach($input['entities'] as $entity) {
 $present=isset($metadata[$entity]);$resolved=null;$keys=[];
 if ($present) {$native=$handler->getMetaDataConfig($entity,'saml20-sp-remote');
  $resolved=$native->toArray();$keys=$native->getPublicKeys('signing');}
 $rows[]=['entityId'=>$entity,'present'=>$present,'resolvedMetadata'=>$resolved,'signingKeys'=>$keys];
}
$idp=$handler->getMetaDataConfig('http://localhost:18380/idp','saml20-idp-hosted');
$sourceHashes=[];foreach($input['sourcePaths'] as $name=>$path){$sourceHashes[$name]=hash_file('sha256',$path);}
echo json_encode(['peers'=>$rows,'configurationSha256'=>hash_file('sha256','/var/simplesamlphp/metadata/saml20-sp-remote.php'),
 'metadataSources'=>\SimpleSAML\Configuration::getInstance()->getArray('metadata.sources'),
 'hostedIdp'=>['entityId'=>$idp->getString('entityid'),'authSource'=>$idp->getString('auth'),
  'authproc'=>$idp->getOptionalArray('authproc',[])],'sourceHashes'=>$sourceHashes],JSON_THROW_ON_ERROR);
'''


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def public_terminal(page):
    return (len(page.encode()) <= 262144 and
            re.search(r'<\s*input\b|SAMLResponse|SAMLRequest|Authorization\s*:|Cookie\s*:', page, re.I) is None)


class SharedClient(Client):
    """Fail closed on additional authentication or a fresh-session confirmation."""
    def __init__(self):
        super().__init__()
        self.credential_posts = 0
        self.credential_attempts = 0
        self.protocol_posts = []
        self.terminal_pages = {}
        self.native_post_attempts = 0
        self.native_redirect_attempts = 0
        owner = self
        class Redirects(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                parsed = urllib.parse.urlsplit(newurl)
                if parsed.hostname not in {'localhost', '127.0.0.1'}:
                    raise ValueError('Nonlocal redirect refused')
                if parsed.port == 18380 and 'SAMLRequest' in urllib.parse.parse_qs(parsed.query):
                    owner.native_redirect_attempts += 1
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), Redirects())

    def request(self, url, fields=None):
        if fields and 'freshSessionConfirmed' in fields:
            raise ValueError('Shared-session signer campaign cannot confirm a fresh session')
        if fields and any(name in fields for name in ('password', 'j_password')):
            self.credential_attempts += 1
            if self.credential_posts >= 1:
                raise ValueError('Additional credential submission refused')
            self.credential_posts += 1
        record = None
        if urllib.parse.urlparse(url).port == 18380 and fields and 'SAMLRequest' in fields:
            raw = base64.b64decode(fields['SAMLRequest'], validate=True)
            root = ET.fromstring(raw)
            if root.get('ForceAuthn') not in (None, 'false', '0') or root.get('IsPassive') not in (None, 'false', '0'):
                raise ValueError('Signer observation requires an ordinary reused-session request')
            record = dict(method='POST', requestUrl=url, requestId=root.get('ID'),
                          requestSha256=SHA(raw), startedAt=NOW())
            self.native_post_attempts += 1
        final, page, status = super().request(url, fields)
        if record:
            record.update(finishedAt=NOW(), responseUrl=final, responseStatus=status,
                          responseBodyBytes=len(page.encode()), responseBodySha256=SHA(page.encode()))
            if final != url:
                raise ValueError('Native signer response changed endpoint')
            self.protocol_posts.append(record)
            if status >= 400 and public_terminal(page):
                self.terminal_pages[record['requestId']] = page
        return final, page, status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-suite-probes', type=int, default=350)
    parser.add_argument('--min-free-mib', type=int, default=96,
                        help='Operational host-space guard before any native setting or protocol operation')
    args = parser.parse_args()
    if not 1 <= args.max_suite_probes <= 500:
        parser.error('--max-suite-probes must be between 1 and 500')
    if args.min_free_mib < 32:
        parser.error('--min-free-mib must be at least 32')
    space = os.statvfs(REPO)
    if space.f_bavail * space.f_frsize < args.min_free_mib * 1024 * 1024:
        parser.error('Insufficient host space; no product setting, login or protocol operation was performed')
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    receipt = out / 'receipt'
    receipt.mkdir()
    (out / 'collector-source.py').write_bytes(Path(__file__).read_bytes())
    (receipt / 'native-parser-command.php').write_text(PARSER)
    (receipt / 'native-readback-command.php').write_text(READBACK)
    native_commands, suite_only_skips, peers, refs, probes = [], [], [], {}, []
    client = SharedClient()
    user = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
    password = os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password')
    batch = ConfigurationBatch(CONFIG)
    batch.container, batch.container_path = CONTAINER, REMOTE
    initial_baselines = 0
    selected_attempts = 0
    baseline_target_attempts = 0
    restoration = dict(restored=False)
    root_created = None
    baseline_safe = False

    def docker(*arguments, data=None, container=CONTAINER):
        started = NOW()
        result = subprocess.run(['docker', 'exec', '-i', container, *arguments], input=data,
                                capture_output=True, timeout=40)
        native_commands.append(dict(container=container, executable=arguments[0],
                                    startedAt=started, finishedAt=NOW(), exitCode=result.returncode))
        save(out / 'native-command-counts.json', native_commands)
        if result.returncode:
            raise ValueError('Native command failed; stderr is not persisted')
        return result.stdout

    def runtime():
        format_ = '{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},"startedAt":{{json .State.StartedAt}}}'
        raw = subprocess.run(['docker', 'inspect', '--format', format_, CONTAINER],
                             capture_output=True, check=True, timeout=20).stdout
        value = json.loads(raw)
        if value.get('running') is not True:
            raise ValueError('Native runtime is stopped')
        return value

    def record(label, kind, **value):
        original = dict(schema='samlscope-simplesamlphp-registered-signer-original-v1',
                        runId=root_created['run']['id'], campaignId=CAMPAIGN,
                        targetMetadataSha256=SHA((receipt / 'target-metadata.xml').read_bytes()),
                        recordedAt=NOW(), kind=kind, **value)
        reject_sensitive(original)
        refs[label] = recorded(receipt, root_created, original, label)
        return original

    def state(label, phase, **extra):
        started = NOW()
        native_raw = docker('php', '-r', READBACK,
                            data=canonical(dict(entities=[p['entity'] for p in peers], sourcePaths=SOURCES)))
        finished = NOW()
        native = json.loads(native_raw)
        reject_sensitive(native)
        actual = docker('cat', REMOTE)
        if actual != batch.expected or native['configurationSha256'] != SHA(actual):
            raise ValueError('Native/host configuration read-back mismatch')
        readbacks = receipt / 'native-readbacks'
        readbacks.mkdir(exist_ok=True)
        (readbacks / (label + '.json')).write_bytes(native_raw)
        return record(label, 'native-registered-peers', phase=phase, runtime=runtime(),
                      nativeReadbackSha256=SHA(native_raw), nativeStartedAt=started,
                      nativeFinishedAt=finished, **native, **extra)

    def install(folder, run, preparation_only=False):
        destination = INSTALL + '/' + run
        docker('mkdir', '-p', destination, container=SUITE)
        names = ['preparation.json', 'target-metadata.xml', 'primary', 'secondary'] if preparation_only else None
        if names is None:
            subprocess.run(['docker', 'cp', str(folder) + '/.', SUITE + ':' + destination],
                           capture_output=True, check=True, timeout=40)
        else:
            for name in names:
                subprocess.run(['docker', 'cp', str(folder / name), SUITE + ':' + destination + '/' + name],
                               capture_output=True, check=True, timeout=40)
        expected = (folder / 'preparation.json').read_bytes()
        if docker('cat', destination + '/preparation.json', container=SUITE) != expected:
            raise ValueError('Preparation receipt read-back mismatch')

    try:
        if b'?>' in batch.original or docker('cat', REMOTE) != batch.original:
            raise ValueError('Unexpected native metadata baseline')
        # This file contains public remote-SP metadata. Refuse credential-bearing operator settings.
        if re.search(rb'(?i)private[._-]?key|password|passwd|authorization|cookie|client[._-]?secret', batch.original):
            raise ValueError('Native metadata baseline may contain credentials; never persist it')
        baseline_safe = True
        (receipt / 'original-configuration.php').write_bytes(batch.original)
        source_dir = receipt / 'native-source'
        source_dir.mkdir()
        for name, path in SOURCES.items():
            (source_dir / name).write_bytes(docker('cat', path))
        for label in ('primary', 'secondary'):
            folder = receipt / label
            folder.mkdir()
            plan = api('/api/plans', dict(name='SimpleSAMLphp registered signer peer ' + label,
                profile='browser_sso_idp', targetKind='IDP', targetEntityId=TARGET, metadataSourceKind='URL',
                metadataSourceLocation='http://samlscope-reference-ssp/simplesaml/module.php/saml/idp/metadata',
                suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
                metadataRefreshWaitSeconds=300, testUserHint=user, requestSigningMode='REQUIRED'),
                interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
            save(folder / 'plan.json', plan)
            plan_id = plan['plan']['plan']['id']
            created = api('/api/plans/' + plan_id + '/runs', {})
            save(folder / 'created.json', created)
            if root_created is None:
                root_created = created
                save(out / 'created.json', created)
            run = created['run']['id']
            save(folder / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
            entity = BASE + '/p/' + plan_id
            if entity.encode() in batch.original:
                raise ValueError('Fresh peer already exists in native configuration')
            with urllib.request.urlopen(entity + '/metadata', timeout=30) as response:
                (folder / 'fixture.xml').write_bytes(response.read())
            subprocess.run(['docker', 'cp', SUITE + ':/data/target-metadata/' + run + '.xml', str(folder / 'target-metadata.xml')],
                           capture_output=True, check=True, timeout=40)
            target_raw = (folder / 'target-metadata.xml').read_bytes()
            if label == 'primary':
                (receipt / 'target-metadata.xml').write_bytes(target_raw)
                (out / 'target-metadata.xml').write_bytes(target_raw)
            elif target_raw != (receipt / 'target-metadata.xml').read_bytes():
                raise ValueError('Peers have different fixed target metadata')
            peers.append(dict(label=label, runId=run, planId=plan_id, entity=entity))
        initial = state('initial', 'initial')
        if any(p.get('present') is not False for p in initial['peers']):
            raise ValueError('Fresh peer is already natively registered')
        overlays = []
        for peer in peers:
            fixture = (receipt / peer['label'] / 'fixture.xml').read_bytes()
            started = NOW()
            parsed_raw = docker('php', '-r', PARSER, peer['entity'], data=fixture)
            finished = NOW()
            parsed = json.loads(parsed_raw)
            reject_sensitive(parsed)
            if parsed.get('entityId') != peer['entity'] or parsed.get('validateAuthnRequest') is not True:
                raise ValueError('Native parser did not require signed AuthnRequest')
            (receipt / peer['label'] / 'parser-output.json').write_bytes(parsed_raw)
            record(peer['label'] + '-conversion', 'native-metadata-conversion', entityId=peer['entity'],
                   fixtureSha256=SHA(fixture), parserOutput=parsed, parserOutputSha256=SHA(parsed_raw),
                   nativeStartedAt=started, nativeFinishedAt=finished)
            overlays.append(parsed['php'].encode())
        batch.apply(b'\n'.join(overlays))
        if docker('cat', REMOTE) != batch.expected:
            raise ValueError('Native overlay not applied')
        (receipt / 'configured-configuration.php').write_bytes(batch.expected)
        time.sleep(3)  # Installed OPcache reload interval; this is not a conformance threshold.
        for peer in peers:
            run = peer['runId']
            before_ids = {e['id'] for e in api('/api/runs/' + run + '/transcript')}
            native_before = client.native_post_attempts + client.native_redirect_attempts
            result = client.flow(BASE + '/p/' + peer['planId'] + '/start/m0-roundtrip?run=' + run, None, user, password)
            entries = api('/api/runs/' + run + '/transcript')
            wire = [e for e in entries if e['id'] not in before_ids and e['direction'] == 'OUTBOUND'
                    and e.get('samlSummary', {}).get('type') == 'AuthnRequest']
            actual_attempts = client.native_post_attempts + client.native_redirect_attempts - native_before
            initial_baselines += actual_attempts
            baseline_target_attempts += actual_attempts
            save(receipt / peer['label'] / 'baseline.json', dict(receipt=result,
                 outboundReferences=[e['id'] for e in wire], nativePostHookCount=len(client.protocol_posts),
                 credentialPosts=client.credential_posts, credentialValuesPersisted=False))
            if result != 'recorded' or len(wire) != 1 or actual_attempts != 1:
                raise ValueError('Native baseline did not complete exactly once')
        before = state('probes-before', 'configured')
        configured_at = before['recordedAt']
        for peer in peers:
            stage = out / ('preparation-' + peer['label'])
            stage.mkdir()
            files = {}
            for name in ('target-metadata.xml', 'primary/created.json', 'primary/fixture.xml', 'secondary/created.json', 'secondary/fixture.xml'):
                path = stage / name
                path.parent.mkdir(exist_ok=True)
                path.write_bytes((receipt / name).read_bytes())
                files[name] = SHA(path.read_bytes())
            preparation = dict(schema='samlscope-simplesamlphp-registered-signer-preparation-v1',
                campaignId=CAMPAIGN, localRunId=peer['runId'], targetMetadataSha256=SHA((receipt / 'target-metadata.xml').read_bytes()),
                peers=peers, files=files)
            save(stage / 'preparation.json', preparation)
            install(stage, peer['runId'], preparation_only=True)
            if peer['label'] == 'primary':
                (receipt / 'preparation.json').write_bytes((stage / 'preparation.json').read_bytes())
        for peer in peers:
            run = peer['runId']
            save(receipt / peer['label'] / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
            selected = 0
            for _ in range(args.max_suite_probes):
                status = api('/api/runs/' + run + '/active-probe')
                if selected == 3:
                    break
                if status.get('state') != 'READY':
                    raise ValueError('Selected signer probe was not ready')
                if status.get('caseId') != CASE:
                    suite_only_skips.append(prepare_and_skip(BASE, run, status, api))
                    save(out / 'suite-only-skips.json', suite_only_skips)
                    continue
                if status.get('requiresFreshSession') is not False:
                    raise ValueError('Selected probe does not explicitly allow session reuse')
                action, fixture = status['actionId'], FIXTURES[selected]
                selected_attempts += 1
                previous = {e['id'] for e in api('/api/runs/' + run + '/transcript')}
                first = len(client.protocol_posts)
                def terminal(url, page, code, reason):
                    if not public_terminal(page):
                        raise ValueError('Native error page is not safe for the Recorder')
                    api('/api/runs/' + run + '/active-probe/browser-response',
                        dict(actionId=action, status=code, url=url, body=page))
                result = client.flow(status['startUrl'], None, user, password, terminal_observer=terminal)
                entries = api('/api/runs/' + run + '/transcript')
                requests = [e for e in entries if e['id'] not in previous and e['direction'] == 'OUTBOUND'
                            and e.get('correlationId') == action and e.get('samlSummary', {}).get('type') == 'AuthnRequest']
                if len(requests) != 1 or len(client.protocol_posts[first:]) != 1:
                    raise ValueError('Actual selected request is ambiguous')
                request = requests[0]
                request_id = client.protocol_posts[first]['requestId']
                if request_id != '_' + action:
                    raise ValueError('Native request ID differs from the deterministic Suite action')
                responses = [e for e in entries if e['direction'] == 'INBOUND' and
                    (e.get('samlSummary', {}).get('inResponseTo') == request_id or
                     e.get('correlationId') == action and e.get('samlSummary', {}).get('type') == 'BrowserResponseObservation')]
                if len(responses) != 1:
                    raise ValueError('Selected response original is ambiguous')
                response = responses[0]
                row = dict(runId=run, fixture=fixture, actionId=action,
                           requestReference=request['id'], responseReference=response['id'], receipt=result)
                if response.get('method') == 'BROWSER':
                    label = peer['label'] + '-' + fixture + '-http'
                    record(label, 'native-http-response', observedRunId=run, requestReference=request['id'],
                           responseReference=response['id'], actionId=action, native=client.protocol_posts[first])
                    row['nativeHttpOriginal'] = label
                probes.append(row)
                save(out / 'probes.json', probes)
                selected += 1
            if selected != 3:
                raise ValueError('Suite-only selection limit reached before all controls')
        after = state('probes-after', 'configured')
        completed_at = after['recordedAt']
    finally:
        try:
            restoration = batch.restore()
            final = docker('cat', REMOTE)
            if baseline_safe and final == batch.original:
                (receipt / 'final-configuration.php').write_bytes(final)
            restoration['restored'] = restoration.get('restored') is True and final == batch.original
            if root_created and len(peers) == 2:
                state('restoration', 'restored', restored=restoration['restored'])
        except Exception as error:
            restoration = dict(restored=False, failureType=type(error).__name__,
                               configuration_write_attempts=batch.write_count)
        actual_target_attempts = client.native_post_attempts + client.native_redirect_attempts
        counts = dict(restored=restoration.get('restored') is True,
                      nativeConfigurationWrites=batch.write_count, restorationWrites=batch.restoration_writes,
                      initialBaselineSubmissions=initial_baselines, outboxProtocolSubmissions=len(probes),
                      selectedProbeAttempts=selected_attempts,
                      actualOutboxTargetAttempts=actual_target_attempts - baseline_target_attempts,
                      protocolSubmissions=actual_target_attempts, credentialPosts=client.credential_posts,
                      nativePostAttempts=client.native_post_attempts,
                      nativeRedirectAttempts=client.native_redirect_attempts,
                      credentialPostAttempts=client.credential_attempts,
                      personOperations=0, productRestarts=0,
                      nativeCliExecutions=sum(row['container'] == CONTAINER and row['executable'] == 'php'
                                              for row in native_commands),
                      dockerExecCommandsThroughRestoration=len(native_commands),
                      suiteOnlySkippedActions=len(suite_only_skips), credentialValuesPersisted=False)
        save(receipt / 'operation-counts.json', counts)
        save(out / 'restoration.json', restoration)
        # Preserve actual attempts on failure, including requests with no terminal proof.
        save(out / 'native-protocol-posts.json', client.protocol_posts)
    if not restoration.get('restored') or len(probes) != 6:
        raise ValueError('Incomplete/restoration-unproven campaign is not adoptable')
    for peer in peers:
        folder = receipt / peer['label']
        run = peer['runId']
        entries = api('/api/runs/' + run + '/transcript')
        save(folder / 'transcript.json', entries)
        capture(folder, run, entries)
        browser_manifest = []
        for entry in entries:
            if entry.get('method') != 'BROWSER':
                continue
            ref = entry.get('bodyRef', '')
            if ref != 'transcripts/' + run + '/' + entry['id'] + '.body':
                raise ValueError('Foreign browser original reference')
            destination = folder / 'browser-originals' / (entry['id'] + '.body')
            destination.parent.mkdir(exist_ok=True)
            raw = docker('cat', '/data/' + ref, container=SUITE)
            if len(raw) != entry['bodyBytes'] or not public_terminal(raw.decode()):
                raise ValueError('Browser original privacy/byte mismatch')
            destination.write_bytes(raw)
            browser_manifest.append(dict(id=entry['id'], reference=ref, bytes=len(raw),
                                         file='browser-originals/' + destination.name, sha256=SHA(raw)))
        save(folder / 'browser-originals-manifest.json', browser_manifest)
    manifest = dict(schema='samlscope-simplesamlphp-registered-signer-v1',
        adapter='simplesamlphp-native-issuer-key-locator-v1', campaignId=CAMPAIGN,
        runId=peers[0]['runId'], planId=peers[0]['planId'], targetEntityId=TARGET,
        targetMetadataSha256=SHA((receipt / 'target-metadata.xml').read_bytes()),
        peers=peers, configuredAt=configured_at, completedAt=completed_at,
        probes=probes, originals=refs,
        files={str(p.relative_to(receipt)): SHA(p.read_bytes()) for p in sorted(receipt.rglob('*')) if p.is_file()})
    save(receipt / 'manifest.json', manifest)
    # Adoption must first capture the old stored outcome and transcript. Installing
    # a final manifest here could trigger GET reevaluation before that audit exists.
    save(out / 'collector-operation-audit.json', dict(nativeCliExecutions=counts['nativeCliExecutions'],
        dockerExecCommands=len(native_commands), targetConfigurationWrites=batch.write_count,
        restorationWrites=batch.restoration_writes, targetProtocolSubmissions=counts['protocolSubmissions'],
        credentialPosts=client.credential_posts, personOperations=0, finalReceiptInstalled=False,
        oldStoredOutcomeRequiredBeforeFinalInstallation=True))
    print(json.dumps(dict(status='collected-not-adopted', runId=peers[0]['runId'], counts=counts)))


if __name__ == '__main__':
    main()
