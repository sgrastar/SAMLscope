#!/usr/bin/env python3
"""One password-only client: fresh challenge, signed normal control, fresh passive error.

The authentication flow is a target-administrator prerequisite. Test-user credentials and
cookies stay in memory, and only one automated credential submission is planned.
No verdict is assigned; unsupported prerequisites stop instead of repeating logins.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import zlib

from attribute_policy_capability_absence import product_token
from import_metadata_batch import BASE, api, save
from mdiop_representation_campaign import runtime
from reference_flow import Client, parse_forms
from schema_admission_campaign import JARS, reject_sensitive

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
from browser_probe_selection import prepare_and_skip
from capture_run_originals import capture

ADMIN = 'http://localhost:18180/admin/realms/samlscope'
TARGET = 'http://localhost:18180/realms/samlscope'
CONTAINER = 'samlscope-reference-keycloak'
CASE = 'IIP-SSO01-ae-idp-01'
PASSIVE_CASE = 'IIP-IDP06-c-idp-01'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')


class IdentityRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, owner):
        self.owner = owner

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parts = urllib.parse.urlsplit(newurl)
        if parts.hostname not in {'localhost', '127.0.0.1'}:
            raise RuntimeError('Nonlocal redirect')
        if urllib.parse.urlunsplit(parts._replace(query='', fragment='')) == TARGET + '/protocol/saml':
            values = urllib.parse.parse_qs(parts.query, strict_parsing=True)
            if 'SAMLRequest' in values:
                if len(values['SAMLRequest']) != 1:
                    raise ValueError('Ambiguous Redirect request')
                raw = zlib.decompress(base64.b64decode(values['SAMLRequest'][0], validate=True), -15)
                self.owner.arrival(raw, 'GET', sha(parts.query.encode('ascii')))
        # Retain the original URL and original signature query bytes without reserialization.
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class IdentityClient(Client):
    def __init__(self, observations, credential_actions, label):
        super().__init__()
        self.observations, self.credential_actions, self.label = observations, credential_actions, label
        self.request_id = None
        self.credential_posts = 0
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), IdentityRedirectHandler(self))

    def arrival(self, raw, method, query_hash=None):
        import xml.etree.ElementTree as ET
        self.request_id = ET.fromstring(raw).get('ID')
        row = dict(kind='native-saml-arrival', label=self.label,
            requestId=self.request_id, requestSha256=sha(raw), recordedAt=now(), method=method,
            cookieCountBefore=len(self.jar), credentialPostsBefore=self.credential_posts,
            requestUrl=TARGET + '/protocol/saml')
        if query_hash:
            row['rawQuerySha256'] = query_hash
        self.observations.append(row)

    def request(self, url, fields=None):
        if url == TARGET + '/protocol/saml' and fields and 'SAMLRequest' in fields:
            raw = base64.b64decode(fields['SAMLRequest'], validate=True)
            self.arrival(raw, 'POST')
        if fields and ('password' in fields or 'j_password' in fields):
            self.credential_posts += 1
            self.credential_actions.append(dict(kind='credential-post', label=self.label,
                requestId=self.request_id, recordedAt=now(), valuesPersisted=False))
        final, page, status = super().request(url, fields)
        # Do not retain HTML, form actions, hidden values, cookies or session handles.
        forms = parse_forms(page)
        if self.request_id and any('password' in form.fields for form in forms):
            self.observations.append(dict(kind='native-password-challenge', label=self.label,
                requestId=self.request_id, recordedAt=now(), status=status,
                publicResponsePath=urllib.parse.urlsplit(final).path,
                originalResponseSha256=sha(page.encode()),
                inputNames=sorted({key for form in forms for key in form.fields}),
                credentialPostsBefore=self.credential_posts,
                credentialsAndStateValuesPersisted=False))
        return final, page, status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    originals = out / 'originals'
    originals.mkdir()
    operations, steps, observations, credentials_log = [], [], [], []
    token, token_reads = product_token(), 1
    writes = 0

    def native(path, method='GET', body=None, xml=False, refresh=False):
        nonlocal token, token_reads, writes
        raw = body if isinstance(body, bytes) else None if body is None else json.dumps(body, separators=(',', ':')).encode()
        if body is not None and not isinstance(body, bytes):
            reject_sensitive(body)
        row = dict(path=path, method=method, attemptedAt=now(),
            productSettingWrite=method in {'PUT', 'DELETE'} or method == 'POST' and path != '/client-description-converter')
        operations.append(row)
        save(out / 'operations.json', operations)
        request = urllib.request.Request(ADMIN + path, data=raw, method=method,
            headers={'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/xml' if xml else 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=40) as response:
                code, reply, location = response.status, response.read(), response.headers.get('Location')
        except urllib.error.HTTPError as response:
            code, reply, location = response.code, response.read(), response.headers.get('Location')
        row.update(status=code, finishedAt=now())
        save(out / 'operations.json', operations)
        if code == 401 and not refresh:
            token, token_reads = product_token(), token_reads + 1
            return native(path, method, body, xml, True)
        value = json.loads(reply) if reply else None
        redactions = []
        if method == 'GET' and re.fullmatch(r'/clients/[0-9a-f-]{36}', path) and isinstance(value, dict):
            for field in ['secret', 'registrationAccessToken']:
                if field in value:
                    del value[field]
                    redactions.append('$.' + field)
            reply = json.dumps(value, separators=(',', ':')).encode()
        if value is not None:
            reject_sensitive(value)
        record = dict(method=method, url=ADMIN + path, status=code,
            response_base64=base64.b64encode(reply).decode(), response_sha256=sha(reply), recordedAt=now())
        if redactions:
            record.update(response_projection='native-client-public-readback-v1', redactions=redactions)
        if raw is not None:
            record.update(request_base64=base64.b64encode(raw).decode(), request_sha256=sha(raw))
        if row['productSettingWrite'] and code in {201, 204}:
            writes += 1
        return value, record, location

    def get(label, path):
        value, record, _ = native(path)
        save(originals / (label + '.json'), record)
        if record['status'] != 200:
            raise ValueError('Native readback unavailable: ' + path)
        return value

    def environment(label):
        value = dict(runtime=runtime(), recordedAt=now())
        inventory = subprocess.check_output(['docker', 'exec', CONTAINER, 'sh', '-c',
            'find /opt/keycloak/lib /opt/keycloak/providers -type f -name "*.jar" | sort | while IFS= read -r p; do sha256sum "$p"; done'])
        (originals / (label + '.native-classpath.txt')).write_bytes(inventory)
        value['nativeClasspathSha256'] = sha(inventory)
        save(originals / (label + '.environment.json'), value)
        return value

    before = environment('before')
    jars = originals / 'native-runtime'
    jars.mkdir()
    for name in JARS:
        jar_dir = 'boot' if name.startswith('org.jboss.logging.jboss-logging-') else 'main'
        subprocess.run(['docker', 'cp', CONTAINER + ':/opt/keycloak/lib/lib/' + jar_dir + '/' + name,
            str(jars / name)], check=True, capture_output=True)
    (originals / 'collector.py').write_bytes(pathlib.Path(__file__).read_bytes())
    flow_inventory = get('flow-inventory-before', '/authentication/flows')
    policy_before = {kind: get('policy-' + kind + '-before', '/client-policies/' + kind) for kind in ['policies', 'profiles']}
    plan = api('/api/plans', dict(name='Keycloak password-only authentication identity', profile='browser_sso_idp',
        targetKind='IDP', targetEntityId=TARGET, metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
            metadataRefreshWaitSeconds=300, testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', plan)
    pid = plan['plan']['plan']['id']
    created = api('/api/plans/' + pid + '/runs', {})
    save(out / 'created.json', created)
    run = created['run']['id']
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
    subprocess.run(['docker', 'cp', 'samlscope-reference-suite:/data/target-metadata/' + run + '.xml',
        str(out / 'target-metadata.xml')], check=True, capture_output=True)
    peer = BASE + '/p/' + pid
    lookup = '/clients?clientId=' + urllib.parse.quote(peer, safe='')
    if get('client-inventory-before', lookup) != []:
        raise ValueError('Refuse existing client mutation')
    alias = 'samlscope-password-only-' + run[4:]
    if any(row['alias'] == alias for row in flow_inventory):
        raise ValueError('Refuse existing authentication flow mutation')
    client_id = flow_id = None
    normal = passive = False
    try:
        _, record, location = native('/authentication/flows', 'POST', dict(alias=alias,
            description='Isolated conformance prerequisite; removed after the observation',
            providerId='basic-flow', topLevel=True, builtIn=False))
        save(originals / 'flow-creation.json', record)
        if record['status'] != 201 or not location:
            raise ValueError('Password-only flow prerequisite unavailable')
        flow_id = location.rsplit('/', 1)[-1]
        _, record, _ = native('/authentication/flows/' + alias + '/executions/execution', 'POST',
            dict(provider='auth-username-password-form'))
        save(originals / 'flow-execution-creation.json', record)
        rows = get('flow-executions-created', '/authentication/flows/' + alias + '/executions')
        if len(rows) != 1 or rows[0]['providerId'] != 'auth-username-password-form':
            raise ValueError('Opaque or additional authentication path')
        _, record, _ = native('/authentication/flows/' + alias + '/executions', 'PUT',
            dict(id=rows[0]['id'], requirement='REQUIRED'))
        save(originals / 'flow-requirement-application.json', record)
        executions = get('flow-executions-before', '/authentication/flows/' + alias + '/executions')
        if len(executions) != 1 or executions[0]['requirement'] != 'REQUIRED':
            raise ValueError('Required interactive password prerequisite unavailable')
        with urllib.request.urlopen(peer + '/metadata', timeout=30) as response:
            fixture = response.read()
        (out / 'fixture.xml').write_bytes(fixture)
        converted, record, _ = native('/client-description-converter', 'POST', fixture, xml=True)
        save(originals / 'native-converter.json', record)
        if record['status'] != 200 or converted['clientId'] != peer:
            raise ValueError('Native metadata client conversion unavailable')
        configured = json.loads(json.dumps(converted))
        configured['attributes']['saml.encrypt'] = 'false'
        configured['authenticationFlowBindingOverrides'] = {'browser': flow_id}
        _, record, location = native('/clients', 'POST', configured)
        save(originals / 'client-creation.json', record)
        if record['status'] != 201 or not location:
            raise ValueError('Native client binding prerequisite unavailable')
        client_id = location.rsplit('/', 1)[-1]
        client_before = get('native-client-before', '/clients/' + client_id)
        if client_before.get('authenticationFlowBindingOverrides') != {'browser': flow_id}:
            raise ValueError('Native password-only binding not applied')
        credentials = (os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user'),
            os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password'))
        normal_client = IdentityClient(observations, credentials_log, 'normal')
        normal_result = normal_client.flow(peer + '/start/m0-roundtrip?run=' + run, None, *credentials)
        save(out / 'normal-flow.json', dict(receipt=normal_result, cookieCountInitially=0,
            credentialPosts=normal_client.credential_posts, credentialsPersisted=False))
        if normal_result != 'recorded' or normal_client.credential_posts != 1:
            raise ValueError('Normal authentication control failed; do not repeat login')
        normal = True
        save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
        for _ in range(400):
            state = api('/api/runs/' + run + '/active-probe')
            if state['state'] != 'READY':
                raise ValueError('Required passive control unavailable; no repeated login')
            if state['caseId'] != PASSIVE_CASE:
                steps.append(prepare_and_skip(BASE, run, state, api))
                save(out / 'steps.json', steps)
                continue
            driver = IdentityClient(observations, credentials_log, 'passive')
            result = driver.flow(state['startUrl'], None, *credentials)
            steps.append(dict(caseId=PASSIVE_CASE, actionId=state['actionId'], sentToTarget=True,
                receipt=result, cookieCountInitially=0, credentialPosts=driver.credential_posts,
                credentialsPersisted=False, recordedAt=now()))
            save(out / 'steps.json', steps)
            if driver.credential_posts != 0 or result != 'recorded':
                raise ValueError('Fresh passive signed-error control unavailable; do not repeat')
            passive = True
            break
        if not passive:
            raise ValueError('Passive control not reached')
        if get('native-client-after', '/clients/' + client_id) != client_before:
            raise ValueError('Native client changed during observation')
        if get('flow-executions-after', '/authentication/flows/' + alias + '/executions') != executions:
            raise ValueError('Authentication prerequisites changed during observation')
    finally:
        recovery = []
        if client_id:
            _, record, _ = native('/clients/' + client_id, 'DELETE')
            save(originals / 'client-removal.json', record)
            if record['status'] != 204:
                recovery.append('client-removal')
        if flow_id:
            _, record, _ = native('/authentication/flows/' + flow_id, 'DELETE')
            save(originals / 'flow-removal.json', record)
            if record['status'] != 204:
                recovery.append('flow-removal')
        clients = get('client-inventory-after', lookup)
        flows = get('flow-inventory-after', '/authentication/flows')
        policy_after = {kind: get('policy-' + kind + '-after', '/client-policies/' + kind) for kind in policy_before}
        after = environment('after')
        restored = clients == [] and flows == flow_inventory and policy_after == policy_before and not recovery \
            and before['runtime'] == after['runtime'] and before['nativeClasspathSha256'] == after['nativeClasspathSha256']
        save(out / 'restoration.json', dict(restored=restored, originalClientAbsent=True,
            remainingClients=clients, flowInventoryRestored=flows == flow_inventory, recoveryFailures=recovery))
        save(out / 'native-observations.json', observations)
        save(out / 'credential-actions.json', credentials_log)
        save(out / 'operation-counts.json', dict(product_setting_write_attempts=sum(row['productSettingWrite'] for row in operations),
            product_setting_writes=writes, native_http_attempts=len(operations),
            administrator_preparation_writes=sum(row['productSettingWrite'] and row['method'] != 'DELETE' for row in operations),
            administrator_restoration_writes=sum(row['productSettingWrite'] and row['method'] == 'DELETE' for row in operations),
            normal_control_completed=normal, passive_control_completed=passive,
            protocol_operations_attempted=len([row for row in observations if row['kind'] == 'native-saml-arrival']),
            automated_credential_submissions=len(credentials_log), test_user_operations=0,
            human_operations=0, product_restarts=0, management_token_acquisitions=token_reads,
            suite_only_prepared_aborts=len([row for row in steps if row.get('sentToTarget') is False]), restored=restored))
        entries = api('/api/runs/' + run + '/transcript')
        save(out / 'transcript.json', entries)
        capture(out, run, entries)
        try:
            save(out / 'result-before.json', api('/api/runs/' + run + '/result.json'))
        except RuntimeError as error:
            save(out / 'result-before-unavailable.json', dict(reason=str(error)))
        if not restored:
            raise ValueError('Native prerequisite restoration failed')
    print('Password-only identity campaign restored', run, 'normal+passive', normal, passive, flush=True)


if __name__ == '__main__':
    main()
