#!/usr/bin/env python3
"""Two native SPs and six Suite outbox signer controls, with one memory login.

Runner alone emits signed requests. Product originals and exact restoration are
captured without credentials, cookies or authentication form values. Final evidence
is left uninstalled until the adopter captures the previous stored conclusion.
"""
import argparse
import base64
import datetime
import hashlib
import importlib.util
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
sys.path[:0] = [str(REPO / 'dev/shibboleth'), str(REPO / 'dev/keycloak'), str(REPO / 'dev/reference-acceptance')]
_spec = importlib.util.spec_from_file_location('shib_signer_suite_api', REPO / 'dev/keycloak/import_metadata_batch.py')
_suite = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_suite)
api, save, BASE = _suite.api, _suite.save, _suite.BASE
from reference_flow import Client
from metadata_native_observation import MetadataNativeClient
import metadata_certificate_trust_scope as trust_scope
from signature_audit_format import signature_audit, FORMAT
from browser_probe_selection import prepare_and_skip
from capture_run_originals import capture

CASE = 'IIP-SSO01-al-idp-01'
CAMPAIGN = 'native-registered-signer'
SCHEMA = 'samlscope-shibboleth-registered-signer-v1'
ADAPTER = 'shibboleth-native-issuer-key-locator-v1'
PREPARATION = 'samlscope-shibboleth-registered-signer-preparation-v1'
ORIGINAL = 'samlscope-shibboleth-registered-signer-original-v1'
TARGET = 'http://localhost:18280/idp/shibboleth'
CONTAINER = 'samlscope-reference-shibboleth'
SUITE = 'samlscope-reference-suite'
PROVIDERS = '/opt/reference-idp/conf/metadata-providers.xml'
AUDIT = '/opt/reference-idp/conf/audit.xml'
AUDIT_LOG = '/opt/reference-idp/logs/idp-audit.log'
INSTALL = '/data/registered-signer-evidence-shibboleth'
FIXTURES = ('local-normal', 'local-invalid-signature', 'local-other-signer')
MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
N = 'urn:mace:shibboleth:2.0:metadata'
XSI = 'http://www.w3.org/2001/XMLSchema-instance'
DS = 'http://www.w3.org/2000/09/xmldsig#'
API_JAR = REPO / 'build/acceptance/reference-20261001/shibboleth-subject-confirmation-v183-r2/native-jars/opensaml-saml-api.jar'
API_JAR_SHA = 'cce72578ec8df5dd18cb71c88bba89bd196c640281c199ce875e2aa44154f93f'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NOW = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


def recorded(folder, created, value, label):
    """Submit already public original bytes to this Run's Recorder, never to the product."""
    run, plan = created['run']['id'], created['run']['planId']
    raw = (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()
    before = {entry['id'] for entry in api('/api/runs/' + run + '/transcript')}
    request = urllib.request.Request(BASE + '/p/' + plan + '/sp/paos?run=' + run,
        data=raw, method='POST', headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=40) as response:
        if response.status != 204: raise ValueError('Original Recorder did not acknowledge the public bytes')
    added = [entry for entry in api('/api/runs/' + run + '/transcript')
        if entry['id'] not in before and entry.get('decodedSamlRef')]
    if len(added) != 1 or added[0].get('runId') != run or added[0].get('decodedSamlBytes') != len(raw):
        raise ValueError('Original Recorder reference is ambiguous or has different bytes')
    original_folder = folder / 'native-originals'; original_folder.mkdir(exist_ok=True)
    (original_folder / (label + '.json')).write_bytes(raw)
    return dict(reference=added[0]['id'], sha256=SHA(raw))


def reject_sensitive(value):
    if isinstance(value, dict):
        for key, member in value.items():
            if re.search(r'(?i)password|passwd|private.?key|secret|credential|authorization|cookie|(?:^|[-_.])token(?:$|[-_.])', key):
                if key not in {'credentialValuesPersisted', 'credentialPosts', 'credentialPostAttempts', 'privateFieldsExported'}:
                    raise ValueError('Credential-bearing native field refused before recording')
            reject_sensitive(member)
    elif isinstance(value, list):
        for member in value:
            reject_sensitive(member)


def public_terminal(page):
    return len(page.encode()) <= 262144 and re.search(r'<\s*input\b|SAMLResponse|SAMLRequest|Authorization\s*:|Cookie\s*:', page, re.I) is None


def audit_configuration(original):
    root = ET.fromstring(original)
    B, U = 'http://www.springframework.org/schema/beans', 'http://www.springframework.org/schema/util'
    maps = [n for n in root if n.tag == '{' + U + '}map' and n.get('id') == 'shibboleth.AuditFormattingMap']
    if len(maps) != 1:
        raise ValueError('Ambiguous native audit formatting map')
    entries = [n for n in maps[0] if n.tag == '{' + B + '}entry' and n.get('key') == 'Shibboleth-Audit']
    if len(entries) != 1:
        raise ValueError('Ambiguous native audit formatting entry')
    return original if entries[0].get('value') == FORMAT else signature_audit(original)


def public_fixture(raw, entity):
    root = ET.fromstring(raw)
    if root.tag != '{' + MD + '}EntityDescriptor' or root.get('entityID') != entity:
        raise ValueError('Fresh Suite metadata identity mismatch')
    roles, signatures = root.findall('./{' + MD + '}SPSSODescriptor'), root.findall('./{' + DS + '}Signature')
    if len(roles) != 1 or len(signatures) != 1 or roles[0].get('AuthnRequestsSigned') != 'true':
        raise ValueError('Whole signer campaign requires signed metadata and requests')
    certificates = roles[0].findall('./{' + MD + '}KeyDescriptor[@use="signing"]/{' + DS + '}KeyInfo/{' + DS + '}X509Data/{' + DS + '}X509Certificate')
    if len(certificates) != 1 or not certificates[0].text:
        raise ValueError('Ambiguous native signing certificate')
    der = base64.b64decode(''.join(certificates[0].text.split()), validate=True)
    acs = roles[0].findall('./{' + MD + '}AssertionConsumerService[@index="0"]')
    if not der or len(acs) != 1 or acs[0].get('Binding') != 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST':
        raise ValueError('Signer metadata lacks the normal POST ACS')
    if urllib.parse.urlsplit(acs[0].get('Location', '')).hostname not in {'localhost', '127.0.0.1'}:
        raise ValueError('Nonlocal Suite ACS refused')
    return SHA(der)


def provider_configuration(original, peers):
    root = ET.fromstring(original)
    if root.tag != '{' + N + '}MetadataProvider' or root.get('{' + XSI + '}type') != 'ChainingMetadataProvider':
        raise ValueError('Expected the native reference metadata chain')
    ids = {n.get('id') for n in root.iter('{' + N + '}MetadataProvider')}
    ET.register_namespace('', N)
    ET.register_namespace('xsi', XSI)
    for peer in reversed(peers):
        identity = 'RegisteredSigner' + peer['runId']
        if identity in ids or not re.fullmatch(r'/opt/reference-idp/metadata/registered-signer-run_[0-9A-HJKMNP-TV-Z]{26}\.xml', peer['sourcePath']):
            raise ValueError('Fresh native provider identity/path is unsafe')
        root.insert(0, ET.Element('{' + N + '}MetadataProvider', {'id': identity,
            '{' + XSI + '}type': 'FilesystemMetadataProvider', 'metadataFile': peer['sourcePath']}))
    return ET.tostring(root, encoding='utf-8', xml_declaration=True)


class SharedClient(MetadataNativeClient):
    def __init__(self, records, directory=None):
        super().__init__(records, directory)
        self.credential_posts = self.credential_attempts = self.native_post_attempts = self.native_redirect_attempts = 0
        owner = self
        class Redirects(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                parsed = urllib.parse.urlsplit(newurl)
                if parsed.hostname not in {'localhost', '127.0.0.1'}:
                    raise ValueError('Nonlocal redirect refused')
                if parsed.port == 18280 and 'SAMLRequest' in urllib.parse.parse_qs(parsed.query):
                    owner.native_redirect_attempts += 1
                return super().redirect_request(req, fp, code, msg, headers, newurl)
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), Redirects())

    def request(self, url, fields=None):
        if fields and 'freshSessionConfirmed' in fields:
            raise ValueError('Shared signer campaign cannot confirm a fresh session')
        if fields and any(key in fields for key in ('password', 'j_password')):
            self.credential_attempts += 1
            if self.credential_posts >= 1:
                raise ValueError('Additional credential submission refused before transport')
            self.credential_posts += 1
        if urllib.parse.urlsplit(url).port == 18280 and fields and 'SAMLRequest' in fields:
            root = ET.fromstring(base64.b64decode(fields['SAMLRequest'], validate=True))
            if root.get('ForceAuthn') not in (None, 'false', '0') or root.get('IsPassive') not in (None, 'false', '0'):
                raise ValueError('Signer controls require ordinary shared authentication')
            self.native_post_attempts += 1
        index = len(self.records)
        result = super().request(url, fields)
        if len(self.records) > index:
            native = self.records[-1]
            native['method'] = native['requestMethod']
            native['finishedAt'] = native['completedAt']
            native['responseBodyBytes'] = len(result[1].encode())
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--max-suite-probes', type=int, default=400)
    parser.add_argument('--min-free-mib', type=int, default=96)
    args = parser.parse_args()
    if not 1 <= args.max_suite_probes <= 500 or args.min_free_mib < 32:
        parser.error('Invalid operational guard bounds')
    space = os.statvfs(REPO)
    if space.f_bavail * space.f_frsize < args.min_free_mib * 1024 * 1024:
        parser.error('Insufficient host space; no product settings or login attempted')
    out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    receipt = out / 'receipt'; receipt.mkdir()
    (out / 'collector-source.py').write_bytes(Path(__file__).read_bytes())
    peers, refs, probes, operations, commands, skipped, http = [], {}, [], [], [], [], []
    client = SharedClient(http, receipt)
    user = os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user')
    password = os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password')
    original, configured, changed, source_writes = {}, {}, [], []
    primary = None; restoration = dict(restored=False)
    baselines = selected_attempts = baseline_attempts = inspect_calls = trust_captures = 0

    def docker_result(*arguments, data=None, container=CONTAINER):
        row = dict(container=container, executable=arguments[0], startedAt=NOW(), completed=False)
        commands.append(row); save(out / 'native-command-counts.json', commands)
        result = subprocess.run(['docker', 'exec', '-i', container, *arguments], input=data, capture_output=True, timeout=60)
        row.update(finishedAt=NOW(), exitCode=result.returncode, completed=True)
        save(out / 'native-command-counts.json', commands)
        return result

    def docker(*arguments, data=None, container=CONTAINER):
        result = docker_result(*arguments, data=data, container=container)
        if result.returncode: raise ValueError('Native command failed; private stderr is not persisted')
        return result.stdout

    def runtime():
        nonlocal inspect_calls
        inspect_calls += 1
        format_ = ('{"id":{{json .Id}},"image":{{json .Image}},"running":{{json .State.Running}},'
                   '"startedAt":{{json .State.StartedAt}},"mounts":{{json .Mounts}}}')
        value = json.loads(subprocess.run(['docker', 'inspect', '--format', format_, CONTAINER], capture_output=True, check=True, timeout=20).stdout)
        if value['running'] is not True: raise ValueError('Native runtime is stopped')
        return value

    def write(path, raw, label):
        row = dict(operation='write', label=label, path=path, startedAt=NOW(), sha256=SHA(raw), readBack=False)
        operations.append(row); save(out / 'operations.json', operations)
        docker('sh', '-c', 'cat > ' + path, data=raw)
        if docker('cat', path) != raw: raise ValueError('Native configuration write/read-back mismatch')
        row.update(finishedAt=NOW(), readBack=True); save(out / 'operations.json', operations)

    def activate(label, restart):
        row = dict(operation='restart' if restart else 'reload', label=label, startedAt=NOW(), completed=False)
        operations.append(row); save(out / 'operations.json', operations)
        if restart:
            subprocess.run(['docker', 'restart', CONTAINER], capture_output=True, check=True, timeout=60)
            docker('/usr/local/tomcat/bin/catalina.sh', 'start')
            limit = time.monotonic() + 90
            while True:
                try:
                    with urllib.request.urlopen(TARGET, timeout=3) as response:
                        if response.status == 200: break
                except Exception: pass
                if time.monotonic() >= limit: raise ValueError('Native restart readiness not observed')
                time.sleep(1)
        else:
            raw = docker('/opt/reference-idp/bin/reload-service.sh', '-id', 'shibboleth.MetadataResolverService', '-u', 'http://localhost:8080/idp')
            (receipt / (label + '-reload.txt')).write_bytes(raw)
        row.update(finishedAt=NOW(), completed=True); save(out / 'operations.json', operations)

    def record(label, kind, **payload):
        value = dict(schema=ORIGINAL, runId=primary['run']['id'], campaignId=CAMPAIGN,
            targetMetadataSha256=SHA((receipt / 'target-metadata.xml').read_bytes()), recordedAt=NOW(), kind=kind, **payload)
        reject_sensitive(value); refs[label] = recorded(receipt, primary, value, label)
        return value

    def state(label, phase, queried=False, recorder_original=True):
        start = NOW(); native_peers = []
        if label in {'probes-before', 'probes-after'}:
            scope(label)
        providers, audit = docker('cat', PROVIDERS), docker('cat', AUDIT)
        expected = configured if phase == 'configured' else original
        if providers != expected[PROVIDERS] or audit != expected[AUDIT]: raise ValueError('Native configuration changed during measurement')
        for peer in peers:
            row = dict(label=peer['label'], entityId=peer['entity'], sourcePath=peer['sourcePath'], sourceSha256=SHA((receipt / peer['label'] / 'fixture.xml').read_bytes()))
            if queried:
                source = docker('cat', peer['sourcePath'])
                if source != (receipt / peer['label'] / 'fixture.xml').read_bytes(): raise ValueError('Native source differs from the Suite original')
                (receipt / (peer['label'] + '-source.xml')).write_bytes(source)
                command = ['/opt/reference-idp/bin/mdquery.sh', '-u', 'http://localhost:8080/idp', '-e', peer['entity']]
                query_start = NOW(); result = docker_result(*command); query_end = NOW()
                prefix = label + '-' + peer['label']
                stdout_file, stderr_file, query_file = prefix + '-metadata-stdout.xml', prefix + '-metadata-stderr.txt', prefix + '-metadata-query.json'
                (receipt / stdout_file).write_bytes(result.stdout); (receipt / stderr_file).write_bytes(result.stderr)
                save(receipt / query_file, dict(command=command, entityId=peer['entity'], exitCode=result.returncode, startedAt=query_start,
                    recordedAt=query_end, stdoutSha256=SHA(result.stdout), stderrSha256=SHA(result.stderr)))
                if result.returncode != 0 or ET.fromstring(result.stdout).get('entityID') != peer['entity']: raise ValueError('Native metadata acceptance unproven; no repeated login')
                row.update(queryFile=query_file, queryStdoutFile=stdout_file, queryStderrFile=stderr_file)
            native_peers.append(row)
        payload = dict(phase=phase, runtime=runtime(), providersSha256=SHA(providers),
            auditSha256=SHA(audit), peers=native_peers, nativeStartedAt=start, nativeFinishedAt=NOW())
        if phase == 'restored': payload['restored'] = True
        if recorder_original: return record(label, 'native-registered-peers', **payload)
        value = dict(schema=ORIGINAL, runId=primary['run']['id'], campaignId=CAMPAIGN,
            targetMetadataSha256=SHA((receipt / 'target-metadata.xml').read_bytes()),
            recordedAt=NOW(), kind='native-registered-peers', **payload)
        reject_sensitive(value); save(receipt / (label + '.json'), value)
        return value

    def clock(label):
        start = NOW(); raw = docker('date', '-u', '+%Y-%m-%dT%H:%M:%S.%NZ'); end = NOW()
        raw_file, file = label + '-clock.txt', label + '-clock.json'
        (receipt / raw_file).write_bytes(raw)
        save(receipt / file, dict(command=['date', '-u', '+%Y-%m-%dT%H:%M:%S.%NZ'], clockDomain='native-product-os-UTC',
            nativeClockFile=raw_file, nativeClockSha256=SHA(raw), nativeInstant=raw.decode().strip(), hostStartedAt=start, hostCompletedAt=end))
        return file

    def native_audit(request_id, label):
        for _ in range(5):
            matches = []
            for line in docker('cat', AUDIT_LOG).decode().splitlines():
                if 'SAMLscope-signature-v1|' not in line: continue
                fields = line.split('SAMLscope-signature-v1|', 1)[1].split('|')
                if len(fields) == 8 and fields[0] == request_id: matches.append('SAMLscope-signature-v1|' + '|'.join(fields))
            if len(matches) == 1:
                file = label + '-native-audit.log'; (receipt / file).write_text(matches[0] + '\n'); return file
            if len(matches) > 1: raise ValueError('Native request-bound audit is ambiguous')
            time.sleep(.2)
        raise ValueError('No request-bound native signature decision; no repeated browser action')

    def scope(phase):
        nonlocal trust_captures
        folder = receipt / 'native'; folder.mkdir(exist_ok=True)
        previous = trust_scope.docker; trust_scope.docker = docker
        try:
            for peer in peers:
                trust_scope.capture(folder, phase + '-' + peer['label'], peer['entity']); trust_captures += 1
            native_path = '/usr/local/tomcat/webapps/idp/WEB-INF/lib/opensaml-saml-api-5.2.3.jar'
            if docker('sha256sum', native_path).decode().split()[0] != API_JAR_SHA or SHA(API_JAR.read_bytes()) != API_JAR_SHA:
                raise ValueError('Native Issuer entity-context implementation differs from the pinned original')
            destination = folder / 'native-opensaml-saml-api.jar'
            if not destination.exists(): os.link(API_JAR, destination)
        finally: trust_scope.docker = previous

    def install_preparation(peer):
        stage = out / ('preparation-' + peer['label']); stage.mkdir()
        for name in ('target-metadata.xml', 'primary/created.json', 'primary/fixture.xml', 'secondary/created.json', 'secondary/fixture.xml'):
            dest = stage / name; dest.parent.mkdir(exist_ok=True); dest.write_bytes((receipt / name).read_bytes())
        save(stage / 'preparation.json', dict(schema=PREPARATION, campaignId=CAMPAIGN, localRunId=peer['runId'],
            targetMetadataSha256=SHA((receipt / 'target-metadata.xml').read_bytes()), peers=peers,
            files={str(p.relative_to(stage)): SHA(p.read_bytes()) for p in stage.rglob('*') if p.is_file()}))
        remote = INSTALL + '/' + peer['runId']; docker('mkdir', '-p', remote, container=SUITE)
        subprocess.run(['docker', 'cp', str(stage) + '/.', SUITE + ':' + remote], capture_output=True, check=True, timeout=40)
        if docker('cat', remote + '/preparation.json', container=SUITE) != (stage / 'preparation.json').read_bytes(): raise ValueError('Preparation read-back mismatch')
        if peer['label'] == 'primary': (receipt / 'preparation.json').write_bytes((stage / 'preparation.json').read_bytes())

    try:
        # All public inputs and paths are prepared before the first native write/login.
        for path, kind in ((PROVIDERS, 'providers'), (AUDIT, 'audit')):
            original[path] = docker('cat', path); (receipt / ('original-' + kind + '.xml')).write_bytes(original[path])
        configured[AUDIT] = audit_configuration(original[AUDIT])
        for label in ('primary', 'secondary'):
            folder = receipt / label; folder.mkdir()
            plan = api('/api/plans', dict(name='Shibboleth registered signer peer ' + label, profile='browser_sso_idp', targetKind='IDP',
                targetEntityId=TARGET, metadataSourceKind='URL', metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',
                suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180, metadataRefreshWaitSeconds=300,
                testUserHint=user, requestSigningMode='REQUIRED'), interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
            save(folder / 'plan.json', plan); plan_id = plan['plan']['plan']['id']
            created = api('/api/plans/' + plan_id + '/runs', {}); save(folder / 'created.json', created)
            if primary is None: primary = created; save(out / 'created.json', created)
            run = created['run']['id']; save(folder / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
            entity = BASE + '/p/' + plan_id
            with urllib.request.urlopen(entity + '/metadata', timeout=30) as response: raw = response.read()
            (folder / 'fixture.xml').write_bytes(raw); fingerprint = public_fixture(raw, entity)
            subprocess.run(['docker', 'cp', SUITE + ':/data/target-metadata/' + run + '.xml', str(folder / 'target-metadata.xml')], capture_output=True, check=True, timeout=40)
            target_raw = (folder / 'target-metadata.xml').read_bytes()
            if label == 'primary': (receipt / 'target-metadata.xml').write_bytes(target_raw); (out / 'target-metadata.xml').write_bytes(target_raw)
            elif target_raw != (receipt / 'target-metadata.xml').read_bytes(): raise ValueError('Peers have different fixed target metadata')
            peers.append(dict(label=label, runId=run, planId=plan_id, entity=entity, sourcePath='/opt/reference-idp/metadata/registered-signer-' + run + '.xml', signingCertificateSha256=fingerprint))
        if peers[0]['signingCertificateSha256'] == peers[1]['signingCertificateSha256']: raise ValueError('Other peer lacks an independent signing key')
        configured[PROVIDERS] = provider_configuration(original[PROVIDERS], peers)
        for path, kind in ((PROVIDERS, 'providers'), (AUDIT, 'audit')): (receipt / ('configured-' + kind + '.xml')).write_bytes(configured[path])
        inventory = []
        for index, provider in enumerate(ET.fromstring(original[PROVIDERS]).iter('{' + N + '}MetadataProvider')):
            if provider.get('{' + XSI + '}type') == 'ChainingMetadataProvider': continue
            if provider.get('{' + XSI + '}type') != 'FilesystemMetadataProvider' or provider.get('metadataFile') is None: raise ValueError('Unclosed native metadata source; no writes/login attempted')
            path = provider.get('metadataFile').replace('%{idp.home}', '/opt/reference-idp')
            raw = docker('cat', path); file = 'other-provider-' + str(index) + '.xml'; (receipt / file).write_bytes(raw)
            entities = {n.get('entityID') for n in ET.fromstring(raw).iter('{' + MD + '}EntityDescriptor')}
            if any(peer['entity'] in entities for peer in peers): raise ValueError('Fresh peer already registered')
            inventory.append(dict(path=path, file=file, sha256=SHA(raw)))
        save(receipt / 'other-provider-inventory.json', inventory)
        for peer in peers:
            if docker('sh', '-c', 'test -e ' + peer['sourcePath'] + ' && echo exists || true').strip(): raise ValueError('Temporary metadata source already exists')
        state('initial', 'initial'); audit_changed = configured[AUDIT] != original[AUDIT]
        if audit_changed: changed.append(AUDIT); write(AUDIT, configured[AUDIT], 'prepare-audit')
        for peer in peers:
            source_writes.append(peer['sourcePath']); write(peer['sourcePath'], (receipt / peer['label'] / 'fixture.xml').read_bytes(), 'prepare-' + peer['label'] + '-metadata')
        changed.append(PROVIDERS); write(PROVIDERS, configured[PROVIDERS], 'prepare-native-providers'); activate('prepare-native-settings', audit_changed)
        state('prerequisites-before', 'configured', queried=True, recorder_original=False)
        for peer in peers:
            prior = {e['id'] for e in api('/api/runs/' + peer['runId'] + '/transcript')}; first = client.native_post_attempts + client.native_redirect_attempts
            result = client.flow(peer['entity'] + '/start/m0-roundtrip?run=' + peer['runId'], None, user, password)
            entries = api('/api/runs/' + peer['runId'] + '/transcript')
            requests = [e for e in entries if e['id'] not in prior and e['direction'] == 'OUTBOUND' and e.get('samlSummary', {}).get('type') == 'AuthnRequest']
            responses = [e for e in entries if e['direction'] == 'INBOUND' and e.get('samlSummary', {}).get('inResponseTo') == requests[0].get('samlSummary', {}).get('id')] if len(requests) == 1 else []
            actual = client.native_post_attempts + client.native_redirect_attempts - first; baselines += actual; baseline_attempts += actual
            save(receipt / peer['label'] / 'baseline.json', dict(receipt=result, requestReferences=[e['id'] for e in requests], responseReferences=[e['id'] for e in responses], actualTargetAttempts=actual, credentialPosts=client.credential_posts, credentialValuesPersisted=False))
            if result != 'recorded' or len(requests) != 1 or len(responses) != 1 or actual != 1: raise ValueError('Normal prerequisite failed; additional login blocked')
        before = state('probes-before', 'configured', queried=True); configured_at = before['recordedAt']
        for peer in peers: install_preparation(peer)
        for peer in peers:
            run = peer['runId']; save(receipt / peer['label'] / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {})); selected = 0
            for _ in range(args.max_suite_probes):
                if selected == 3: break
                status = api('/api/runs/' + run + '/active-probe')
                if status.get('state') != 'READY': raise ValueError('Signer probe not ready; no repeated operation')
                if status.get('caseId') != CASE: skipped.append(prepare_and_skip(BASE, run, status, api)); save(out / 'suite-only-skips.json', skipped); continue
                if status.get('requiresFreshSession') is not False: raise ValueError('Shared session is not explicitly allowed')
                action, fixture = status['actionId'], FIXTURES[selected]; selected_attempts += 1
                prior = {e['id'] for e in api('/api/runs/' + run + '/transcript')}; index = len(http)
                clock_before = clock(peer['label'] + '-' + fixture + '-before')
                def terminal(url, page, code, reason):
                    if not public_terminal(page): raise ValueError('Native error page cannot be safely recorded')
                    api('/api/runs/' + run + '/active-probe/browser-response', dict(actionId=action, status=code, url=url, body=page))
                result = client.flow(status['startUrl'], None, user, password, terminal_observer=terminal)
                clock_after = clock(peer['label'] + '-' + fixture + '-after'); entries = api('/api/runs/' + run + '/transcript')
                requests = [e for e in entries if e['id'] not in prior and e['direction'] == 'OUTBOUND' and e.get('correlationId') == action and e.get('samlSummary', {}).get('type') == 'AuthnRequest']
                if len(requests) != 1 or len(http) - index != 1: raise ValueError('Signer action has ambiguous request originals')
                native, request = http[index], requests[0]
                if native['requestId'] != '_' + action: raise ValueError('Native request differs from the deterministic action')
                responses = [e for e in entries if e['id'] not in prior and e['direction'] == 'INBOUND' and (e.get('samlSummary', {}).get('inResponseTo') == native['requestId'] or e.get('correlationId') == action and e.get('samlSummary', {}).get('type') == 'BrowserResponseObservation')]
                if len(responses) != 1: raise ValueError('Signer response is not uniquely request-bound')
                response = responses[0]; label = peer['label'] + '-' + fixture + '-http'
                audit_file = native_audit(native['requestId'], peer['label'] + '-' + fixture)
                record(label, 'native-http-response', observedRunId=run, requestReference=request['id'], responseReference=response['id'], actionId=action, clockBeforeFile=clock_before, clockAfterFile=clock_after, auditFile=audit_file, native=native)
                probes.append(dict(runId=run, fixture=fixture, actionId=action, requestReference=request['id'], responseReference=response['id'], nativeHttpOriginal=label, receipt=result, reusedAuthenticatedClient=True, requiresFreshSession=False))
                save(out / 'probes.json', probes); selected += 1
            if selected != 3: raise ValueError('Suite selection bound reached before all controls')
        after = state('probes-after', 'configured', queried=True); completed_at = after['recordedAt']
        for item in inventory:
            if SHA(docker('cat', item['path'])) != item['sha256']: raise ValueError('Existing native metadata source changed')
        save(receipt / 'other-provider-final-readback.json', inventory)
    finally:
        errors = []
        for path in reversed(changed):
            try: write(path, original[path], 'restore-' + path.rsplit('/', 1)[-1])
            except Exception as error: errors.append(dict(path=path, failureType=type(error).__name__))
        if changed and not errors:
            try: activate('restore-native-settings', AUDIT in changed)
            except Exception as error: errors.append(dict(operation='activate-restoration', failureType=type(error).__name__))
        removed = []
        if not errors:
            for path in reversed(source_writes):
                try:
                    docker('rm', '-f', '--', path); removed.append(dict(path=path, absent=not docker('sh', '-c', 'test -e ' + path + ' && echo exists || true').strip()))
                except Exception as error: errors.append(dict(path=path, failureType=type(error).__name__))
        finals = {}
        for path, kind in ((PROVIDERS, 'providers'), (AUDIT, 'audit')):
            try: finals[path] = docker('cat', path); (receipt / ('final-' + kind + '.xml')).write_bytes(finals[path])
            except Exception as error: errors.append(dict(path=path, failureType=type(error).__name__))
        restored = not errors and len(original) == 2 and all(finals.get(path) == raw for path, raw in original.items()) and all(row['absent'] for row in removed)
        restoration = dict(restored=restored, errors=errors, original={path: SHA(raw) for path, raw in original.items()}, final={path: SHA(raw) for path, raw in finals.items()}, temporarySourcesRemoved=removed)
        if primary and len(peers) == 2 and restored:
            try: state('restoration', 'restored')
            except Exception as error: restoration['restored'] = False; restoration['originalRecordingFailure'] = type(error).__name__
        save(out / 'restoration.json', restoration); save(receipt / 'restoration.json', restoration)
        counts = dict(restored=restoration['restored'], nativeConfigurationWrites=sum(row['operation'] == 'write' for row in operations), restorationWrites=sum(row['operation'] == 'write' and row['label'].startswith('restore-') for row in operations),
            productRestarts=sum(row['operation'] == 'restart' for row in operations), metadataReloads=sum(row['operation'] == 'reload' for row in operations), initialBaselineSubmissions=baselines, outboxProtocolSubmissions=len(probes), selectedProbeAttempts=selected_attempts,
            protocolSubmissions=client.native_post_attempts + client.native_redirect_attempts, actualOutboxTargetAttempts=client.native_post_attempts + client.native_redirect_attempts - baseline_attempts,
            nativePostAttempts=client.native_post_attempts, nativeRedirectAttempts=client.native_redirect_attempts, credentialPosts=client.credential_posts, credentialPostAttempts=client.credential_attempts,
            personOperations=0, sameAuthenticatedClient=True, additionalLoginBlocked=True, credentialValuesPersisted=False, suiteOnlySkippedActions=len(skipped),
            collectorDockerExecCommandsThroughRestoration=len(commands), nativeCliExecutions=sum(row['container'] == CONTAINER for row in commands), nativeRuntimeInspections=inspect_calls, readOnlyTrustScopeCaptures=trust_captures)
        save(out / 'operation-counts.json', counts); save(receipt / 'operation-counts.json', counts)
        save(receipt / 'operations.json', operations); save(out / 'native-protocol-posts.json', http)
    if restoration['restored'] is not True or len(probes) != 6: raise ValueError('Incomplete/restoration-unproven campaign is not adoptable')
    for peer in peers:
        folder = receipt / peer['label']; entries = api('/api/runs/' + peer['runId'] + '/transcript')
        save(folder / 'transcript.json', entries); capture(folder, peer['runId'], entries); browser = []
        for entry in entries:
            if entry.get('method') != 'BROWSER': continue
            ref = 'transcripts/' + peer['runId'] + '/' + entry['id'] + '.body'
            if entry.get('bodyRef') != ref: raise ValueError('Foreign browser original reference')
            raw = docker('cat', '/data/' + ref, container=SUITE)
            if len(raw) != entry['bodyBytes'] or not public_terminal(raw.decode()): raise ValueError('Browser original byte/privacy mismatch')
            dest = folder / 'browser-originals' / (entry['id'] + '.body'); dest.parent.mkdir(exist_ok=True); dest.write_bytes(raw)
            browser.append(dict(id=entry['id'], reference=ref, bytes=len(raw), file='browser-originals/' + dest.name, sha256=SHA(raw)))
        save(folder / 'browser-originals-manifest.json', browser)
    baselines_proof = []
    for peer in peers:
        baseline = json.loads((receipt / peer['label'] / 'baseline.json').read_bytes())
        baselines_proof.append(dict(runId=peer['runId'], label=peer['label'], requestReference=baseline['requestReferences'][0], responseReference=baseline['responseReferences'][0]))
    manifest = dict(schema=SCHEMA, adapter=ADAPTER, campaignId=CAMPAIGN, runId=peers[0]['runId'], planId=peers[0]['planId'], targetEntityId=TARGET,
        targetMetadataSha256=SHA((receipt / 'target-metadata.xml').read_bytes()), peers=peers, probes=probes, originals=refs, configuredAt=configured_at, completedAt=completed_at,
        baselines=baselines_proof,
        files={str(p.relative_to(receipt)): SHA(p.read_bytes()) for p in sorted(receipt.rglob('*')) if p.is_file()})
    save(receipt / 'manifest.json', manifest)
    save(out / 'collector-operation-audit.json', dict(finalReceiptInstalled=False, oldStoredOutcomeRequiredBeforeFinalInstallation=True,
        targetProtocolSubmissions=counts['protocolSubmissions'], credentialPosts=client.credential_posts, personOperations=0,
        collectorDockerExecCommandsIncludingExports=len(commands)))
    print(json.dumps(dict(status='collected-not-adopted', runId=peers[0]['runId'], counts=counts)))


if __name__ == '__main__':
    main()
