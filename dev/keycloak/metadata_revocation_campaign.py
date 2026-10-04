#!/usr/bin/env python3
"""Native metadata certificate matrix with one client/session and request-bound controls.

Temporary administrative setup is automated and restored; credentials/cookies never enter
evidence. Native parser acceptance, HTTP errors and missing responses do not assign verdicts.
"""
import argparse
import base64
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from attribute_policy_capability_absence import product_token
from browser_chain_campaign import public_client_readback, SessionDriver, USER, PASSWORD
from import_metadata_batch import BASE, api, save, flow
from mdiop_representation_campaign import runtime
from schema_admission_campaign import reject_sensitive
from signed_request_observation import LISTENER, event_configuration, signature_events

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
from capture_run_originals import capture

CONTAINER = 'samlscope-reference-keycloak'
ADMIN = 'http://localhost:18180/admin/realms/samlscope'
TARGET = 'http://localhost:18180/realms/samlscope'
PROVIDER = '/opt/keycloak/providers/samlscope-signature-observation.jar'
VARIANTS = ['control', 'certificate-critical-extension', 'certificate-unknown-ca',
            'certificate-revoked', 'certificate-revocation-unreachable']
JARS = ['org.keycloak.keycloak-services-26.7.2.jar', 'org.keycloak.keycloak-saml-core-26.7.2.jar',
        'org.keycloak.keycloak-saml-core-public-26.7.2.jar', 'org.keycloak.keycloak-common-26.7.2.jar',
        'org.keycloak.keycloak-core-26.7.2.jar', 'org.apache.santuario.xmlsec-3.0.6.jar']


def sha(raw): return hashlib.sha256(raw).hexdigest()
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class NativeMatrixClient:
    """Retain one cookie jar only for this matrix's plain normal AuthnRequests."""
    def __init__(self, sessions, observations):
        self.client = sessions.initial_client
        self.sessions = sessions
        self.observations = observations
        request = self.client.request

        def observed(url, fields=None):
            row = None
            if url == TARGET + '/protocol/saml' and fields and 'SAMLRequest' in fields:
                raw = base64.b64decode(fields['SAMLRequest'], validate=True)
                root = ET.fromstring(raw)
                if root.tag != '{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest' or root.get('ForceAuthn', 'false') not in {'false', '0'} or root.get('IsPassive', 'false') not in {'false', '0'}:
                    raise ValueError('This matrix cannot reuse a fresh/passive authentication boundary')
                row = dict(method='POST', requestId=root.get('ID'), requestSha256=sha(raw),
                    requestUrl=url, startedAt=now(), credentialPostsBefore=sessions.login_submissions,
                    sameInMemoryClient=True, forceAuthn=False, isPassive=False)
            final, page, code = request(url, fields)
            if row is not None:
                # Error bodies may contain authentication state; retain no HTML or form values.
                row.update(finishedAt=now(), responseStatus=code,
                    publicResponsePath=urllib.parse.urlsplit(final).path,
                    responseUrlExactMatch=final == url, responseBodySha256=sha(page.encode()),
                    invalidRequesterTextPresent='Invalid requester' in page,
                    credentialPostsAfter=sessions.login_submissions, responseStateValuesPersisted=False)
                observations.append(row)
            return final, page, code

        self.client.request = observed

    def factory(self):
        return self.client


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    originals = out / 'originals'; originals.mkdir()
    operations, observations, members = [], [], {}
    token, token_reads = product_token(), 1
    provider_installed = provider_attempted = events_changed = False
    client_id = None
    restarted = 0
    sessions = SessionDriver(True)
    matrix_client = NativeMatrixClient(sessions, observations)
    started = now()

    def operation(kind, **data):
        row = dict(kind=kind, attemptedAt=now(), **data); operations.append(row)
        save(out / 'operations.json', operations)
        return row

    def native(label, path, method='GET', body=None, xml=False, retry=False):
        nonlocal token, token_reads
        raw = body if isinstance(body, bytes) else None if body is None else canonical(body)
        if isinstance(body, dict): reject_sensitive(body)
        row = operation('native-http', path=path, method=method,
            productSettingWrite=method in {'PUT', 'DELETE'} or method == 'POST' and path != '/client-description-converter')
        req = urllib.request.Request(ADMIN + path, data=raw, method=method,
            headers={'Authorization': 'Bearer ' + token,
                     'Content-Type': 'application/xml' if xml else 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=40) as response:
                status, reply = response.status, response.read()
        except urllib.error.HTTPError as response:
            status, reply = response.code, response.read()
        row.update(status=status, finishedAt=now()); save(out / 'operations.json', operations)
        if status == 401 and not retry:
            token, token_reads = product_token(), token_reads + 1
            return native(label, path, method, body, xml, True)
        value = json.loads(reply) if reply else None
        projection = {}
        if method == 'GET' and re.fullmatch(r'/clients/[0-9a-f-]{36}', path) and isinstance(value, dict):
            value, projection = public_client_readback(value); reply = canonical(value)
        elif method == 'GET' and path.startswith('/clients?clientId=') and isinstance(value, list):
            public, rows = [], []
            for item in value:
                if not isinstance(item, dict): raise ValueError('Unexpected native client inventory')
                projected, annotation = public_client_readback(item)
                public.append(projected); rows.append(annotation)
            value, reply = public, canonical(public)
            projection = dict(response_projection='native-client-inventory-public-readback-v1',
                member_projections=rows, response_sha256=sha(reply))
        if value is not None: reject_sensitive(value)
        record = dict(method=method, url=ADMIN + path, status=status, recordedAt=now(),
            response_base64=base64.b64encode(reply).decode(), **projection)
        record['response_sha256'] = sha(reply)
        if raw is not None:
            record.update(request_base64=base64.b64encode(raw).decode(), request_sha256=sha(raw))
        save(originals / (label + '.json'), record)
        return value, record

    def get(label, path):
        value, record = native(label, path)
        if record['status'] != 200: raise ValueError('Native readback unavailable')
        return value

    def classpath(label):
        raw = subprocess.check_output(['docker', 'exec', CONTAINER, 'sh', '-c',
            'find /opt/keycloak/lib /opt/keycloak/providers -type f -name "*.jar" | sort | while IFS= read -r p; do sha256sum "$p"; done'])
        (originals / (label + '.native-classpath.txt')).write_bytes(raw)
        return sha(raw)

    def restart(label):
        nonlocal restarted
        row = operation('product-restart', label=label)
        subprocess.run(['docker', 'restart', CONTAINER], check=True, capture_output=True, timeout=30)
        restarted += 1
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(TARGET + '/protocol/saml/descriptor', timeout=3) as r:
                    if r.status == 200:
                        row.update(complete=True, finishedAt=now()); save(out / 'operations.json', operations); return
            except Exception: pass
            time.sleep(1)
        raise ValueError('Native product restart did not become healthy')

    def reachable(label):
        row = operation('target-revocation-endpoint-check', label=label)
        result = subprocess.run(['docker', 'exec', CONTAINER, 'bash', '-c',
            'exec 3<>/dev/tcp/samlscope-reference-suite/18481'], capture_output=True, timeout=10)
        record = dict(targetContainer=CONTAINER, host='samlscope-reference-suite', port=18481,
            exitCode=result.returncode, stdout=result.stdout.decode(), stderr=result.stderr.decode(),
            checkedAt=now())
        save(originals / (label + '.endpoint-check.json'), record)
        row.update(finishedAt=now(), status=result.returncode); save(out / 'operations.json', operations)
        if result.returncode == 0: raise ValueError('Fixture revocation endpoint is unexpectedly reachable')

    before_runtime = runtime(); save(originals / 'runtime-before.json', before_runtime)
    original_classpath = classpath('before')
    original_events = get('events-before', '/events/config')
    policy_before = {kind: get('policy-' + kind + '-before', '/client-policies/' + kind) for kind in ['policies', 'profiles']}
    if subprocess.run(['docker', 'exec', CONTAINER, 'test', '!', '-e', PROVIDER], capture_output=True).returncode:
        raise ValueError('Refuse existing observer provider replacement')
    observer = out / 'observer'; observer.mkdir(); lib = observer / 'lib'; lib.mkdir(); classes = observer / 'classes'; classes.mkdir()
    source = REPO / 'dev/keycloak/signature-listener'
    java = source / 'src/com/samlscope/reference/SignatureEventListenerFactory.java'
    shutil.copyfile(java, observer / java.name)
    for name in ['org.keycloak.keycloak-core-26.7.2.jar', 'org.keycloak.keycloak-server-spi-26.7.2.jar',
                 'org.keycloak.keycloak-server-spi-private-26.7.2.jar', 'jakarta.ws.rs.jakarta.ws.rs-api-3.1.0.jar']:
        subprocess.run(['docker', 'cp', CONTAINER + ':/opt/keycloak/lib/lib/main/' + name, str(lib / name)], check=True, capture_output=True)
    subprocess.run(['javac', '--release', '21', '-cp', str(lib / '*'), '-d', str(classes), str(java)], check=True, capture_output=True)
    observer_jar = observer / 'samlscope-signature-observation.jar'
    subprocess.run(['jar', '--create', '--file', str(observer_jar), '-C', str(classes), '.', '-C', str(source / 'resources'), '.'], check=True, capture_output=True)
    save(observer / 'installation.json', dict(sourceSha256=sha(java.read_bytes()), jarSha256=sha(observer_jar.read_bytes()), destination=PROVIDER, previouslyAbsent=True))
    (originals / 'collector.py').write_bytes(pathlib.Path(__file__).read_bytes())
    plan = api('/api/plans', dict(name='Keycloak native certificate runtime matrix', profile='metadata_idp',
        targetKind='IDP', targetEntityId=TARGET, metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
            metadataRefreshWaitSeconds=300, testUserHint=USER, requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', plan); pid = plan['plan']['plan']['id']
    created = api('/api/plans/' + pid + '/runs', {}); save(out / 'created.json', created); run = created['run']['id']
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
    subprocess.run(['docker', 'cp', 'samlscope-reference-suite:/data/target-metadata/' + run + '.xml', str(out / 'target-metadata.xml')], check=True, capture_output=True)
    entity = BASE + '/p/' + pid; lookup = '/clients?clientId=' + urllib.parse.quote(entity, safe='')
    if get('clients-before', lookup) != []: raise ValueError('Refuse existing native client mutation')
    try:
        provider_attempted = True; row = operation('observer-provider-install')
        subprocess.run(['docker', 'cp', str(observer_jar), CONTAINER + ':' + PROVIDER], check=True, capture_output=True)
        actual = subprocess.check_output(['docker', 'exec', CONTAINER, 'sha256sum', PROVIDER]).decode().split()[0]
        if actual != sha(observer_jar.read_bytes()): raise ValueError('Observer native readback differs')
        provider_installed = True; row.update(complete=True, finishedAt=now()); save(out / 'operations.json', operations)
        restart('observer-installed')
        configured_events = {**original_events, 'eventsEnabled': True,
            'eventsListeners': sorted(set(original_events.get('eventsListeners', [])) | {LISTENER}),
            'enabledEventTypes': sorted(set(original_events.get('enabledEventTypes', [])) | {'LOGIN_ERROR'}) if original_events.get('eventsEnabled') else ['LOGIN_ERROR']}
        events_changed = True; _, reply = native('events-apply', '/events/config', 'PUT', configured_events)
        if reply['status'] != 204 or event_configuration(get('events-active', '/events/config')) != event_configuration(configured_events):
            raise ValueError('Native observer setting differs')
        classpath('active')
        jars = originals / 'native-runtime'; jars.mkdir()
        for name in JARS:
            subprocess.run(['docker', 'cp', CONTAINER + ':/opt/keycloak/lib/lib/main/' + name, str(jars / name)], check=True, capture_output=True)
        save(out / 'campaign.json', api('/api/runs/' + run + '/metadata-lab/automatic-polling', dict(variants=VARIANTS, pollingDelaySeconds=0)))
        for variant in VARIANTS:
            folder = out / variant; folder.mkdir()
            state = api('/api/runs/' + run + '/metadata-lab')
            if state['selectedVariant'] != variant: raise ValueError('Unexpected fixture selection')
            with urllib.request.urlopen(state['automaticStartUrl'], timeout=30) as response:
                if response.status != 202: raise ValueError('Fixture preparation gate differs')
            with urllib.request.urlopen(state['metadataUrl'], timeout=30) as response: fixture = response.read()
            (folder / 'fixture.xml').write_bytes(fixture)
            recipe, conversion = native(variant + '-conversion', '/client-description-converter', 'POST', fixture, True)
            if conversion['status'] != 200 or recipe.get('clientId') != entity or recipe.get('protocol') != 'saml' or recipe.get('attributes', {}).get('saml.client.signature') != 'true':
                raise ValueError('Native metadata signature-validation prerequisite unavailable; no repeated login')
            before = get(variant + '-inventory-before', lookup)
            if client_id is None:
                if before != []: raise ValueError('Unexpected temporary client')
                _, mutation = native(variant + '-apply', '/clients', 'POST', recipe)
                if mutation['status'] != 201: raise ValueError('Native client create failed')
                inventory = get(variant + '-inventory-after', lookup)
                if len(inventory) != 1: raise ValueError('Created native client ambiguous')
                client_id = inventory[0]['id']
            else:
                if len(before) != 1 or before[0]['id'] != client_id: raise ValueError('Concurrent native client replacement')
                _, mutation = native(variant + '-apply', '/clients/' + client_id, 'PUT', recipe)
                if mutation['status'] != 204: raise ValueError('Same-client native replacement failed')
            saved = get(variant + '-client-before', '/clients/' + client_id)
            if saved.get('id') != client_id or saved.get('clientId') != entity or saved.get('attributes', {}).get('saml.client.signature') != 'true':
                raise ValueError('Native key-validation setup not persisted')
            if variant == 'certificate-revocation-unreachable': reachable('unreachable-before')
            before_ids = {entry['id'] for entry in api('/api/runs/' + run + '/transcript')}
            credentials_before = sessions.login_submissions
            try:
                flow(run, folder / 'flow.json', suite_signature_control=True, client_factory=matrix_client.factory)
            finally:
                entries = api('/api/runs/' + run + '/transcript')
                issued = [e for e in entries if e['id'] not in before_ids and e['direction'] == 'OUTBOUND' and e.get('samlSummary', {}).get('type') == 'AuthnRequest']
                request_ids = {e['samlSummary']['id'] for e in issued}
                audit = signature_events(started, request_ids)
                save(folder / 'signature-audit.json', dict(runId=run, rows=audit))
                save(folder / 'session-observations.json', dict(runId=run,
                    observations=[o for o in observations if o['requestId'] in request_ids],
                    credentialPosts=sessions.login_submissions-credentials_before, cookiesAndCredentialsPersisted=False))
            if variant == 'certificate-revocation-unreachable': reachable('unreachable-after')
            after = get(variant + '-client-after', '/clients/' + client_id)
            if saved != after: raise ValueError('Configuration changed during native key test')
            members[variant] = dict(fixtureSha256=sha(fixture), clientId=client_id,
                requestReferences=[e['id'] for e in issued], nativeAuditRows=len(audit))
            save(out / 'members.json', members)
            print(variant + ' native normal/control recorded; credentials=' + str(sessions.login_submissions), flush=True)
            if variant == 'control': save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
    finally:
        # Restoration precedes Suite export; a failed API/export cannot leave target mutations.
        errors = []
        try:
            found = get('clients-cleanup-before', lookup)
            if found:
                if len(found) != 1 or found[0].get('clientId') != entity or client_id is not None and found[0].get('id') != client_id:
                    raise ValueError('Temporary-client cleanup ownership differs')
                _, reply = native('client-delete', '/clients/' + found[0]['id'], 'DELETE')
                if reply['status'] != 204: raise ValueError('Native client delete failed')
            if get('clients-after', lookup) != []: raise ValueError('Native client remains')
        except Exception as error: errors.append('client-' + type(error).__name__)
        try:
            if events_changed:
                current = get('events-cleanup-before', '/events/config')
                if event_configuration(current) not in [event_configuration(configured_events), event_configuration(original_events)]:
                    raise ValueError('Concurrent native event policy edit')
                _, reply = native('events-restore', '/events/config', 'PUT', original_events)
                if reply['status'] != 204: raise ValueError('Native events restore failed')
            if event_configuration(get('events-after', '/events/config')) != event_configuration(original_events):
                raise ValueError('Native event policy not restored')
        except Exception as error: errors.append('events-' + type(error).__name__)
        try:
            if provider_attempted and subprocess.run(['docker', 'exec', CONTAINER, 'test', '-e', PROVIDER], capture_output=True).returncode == 0:
                actual = subprocess.check_output(['docker', 'exec', CONTAINER, 'sha256sum', PROVIDER]).decode().split()[0]
                if actual != sha(observer_jar.read_bytes()): raise ValueError('Concurrent provider replacement')
                row = operation('observer-provider-remove')
                subprocess.run(['docker', 'exec', CONTAINER, 'rm', PROVIDER], check=True, capture_output=True)
                row.update(complete=True, finishedAt=now()); save(out / 'operations.json', operations)
                restart('observer-removed')
            if subprocess.run(['docker', 'exec', CONTAINER, 'test', '!', '-e', PROVIDER], capture_output=True).returncode:
                raise ValueError('Observer provider remains')
        except Exception as error: errors.append('provider-' + type(error).__name__)
        after_policy, after_runtime, final_classpath, stable_runtime = None, None, None, False
        try:
            after_policy = {kind: get('policy-' + kind + '-after', '/client-policies/' + kind) for kind in ['policies', 'profiles']}
            after_runtime = runtime(); save(originals / 'runtime-after.json', after_runtime)
            final_classpath = classpath('after')
            stable_runtime = all(before_runtime[k] == after_runtime[k] for k in ['containerId', 'image', 'running', 'ports', 'version'])
        except Exception as error: errors.append('restoration-readback-' + type(error).__name__)
        restored = not errors and original_classpath == final_classpath and policy_before == after_policy and stable_runtime
        save(out / 'restoration.json', dict(restored=restored, failures=errors,
            originalClasspathSha256=original_classpath, finalClasspathSha256=final_classpath,
            stableRuntime=stable_runtime, plannedRestarts=restarted, restoredAt=now()))
        save(out / 'operation-counts.json', dict(restored=restored, human_operations=0, test_user_operations=0,
            administrator_setting_write_attempts=sum(o.get('productSettingWrite') is True for o in operations),
            successful_setting_writes=sum(o.get('productSettingWrite') is True and o.get('status') in {201, 204} for o in operations),
            observer_filesystem_write_attempts=sum(o['kind'] in {'observer-provider-install', 'observer-provider-remove'} for o in operations),
            product_restarts=restarted, admin_token_reads=token_reads, automated_credential_posts=sessions.login_submissions,
            same_in_memory_client_protocol_submissions=len(observations), fresh_session_requirements=0,
            protocol_operations_attempted=len(observations), fixture_count=len(members), verdict_adopted=False))
        save(out / 'native-http-observations.json', observations)
        entries = api('/api/runs/' + run + '/transcript'); save(out / 'transcript.json', entries); capture(out, run, entries)
        save(out / 'result.json', api('/api/runs/' + run + '/result.json'))
        files = {str(p.relative_to(out)): sha(p.read_bytes()) for p in out.rglob('*') if p.is_file() and not p.is_symlink()}
        save(out / 'manifest.json', dict(schema='samlscope-keycloak-metadata-revocation-v1', adapter='keycloak-native-metadata-revocation-v1',
            runId=run, campaignId='metadata-native-revocation', caseId='IIP-MD06-a6-idp-01',
            targetEntityId=TARGET, targetMetadataSha256=sha((out / 'target-metadata.xml').read_bytes()), peerEntityId=entity,
            members=members, files=files))
        if not restored: raise ValueError('Native restoration incomplete; stop subsequent mutation')
    print('Native certificate matrix restored; no verdict adopted: ' + run, flush=True)


if __name__ == '__main__': main()
