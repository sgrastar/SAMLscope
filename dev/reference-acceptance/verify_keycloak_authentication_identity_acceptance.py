#!/usr/bin/env python3
"""Replay the actual archived reader and adopt one scoped password-only identity observation.

Public challenge form structure is combined with native effective configuration and
signed protocol controls; its HTML hash is not a claim that secret-bearing HTML was retained.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

REPO = pathlib.Path(__file__).resolve().parents[2]
FOLDER = 'keycloak-authentication-identity-r2'
CASE = 'IIP-SSO01-ae-idp-01'
SUITE = 'samlscope-reference-suite'
HELPER = 'VerifyKeycloakAuthenticationIdentity'
JARS = ('runner', 'core', 'saml', 'store')
CLASSES = ('KeycloakAuthenticationIdentityEvidence', 'AuthenticationIdentityConfigurationTestCase',
    'KeycloakSubjectConfirmationEvidence', 'KeycloakNativeSchemaAdmissionEvidence', 'MetadataAlgorithmEvidence')
CONTROLS = {'wrong-run', 'wrong-case', 'wrong-target', 'wrong-adapter', 'wrong-campaign', 'wrong-profile',
    'collector-changed', 'native-jar-changed', 'native-classpath-subset', 'missing-original', 'symlink-original',
    'binding-changed', 'ambient-cookie-authenticator', 'required-password-disabled', 'execution-config-changed',
    'policy-selector-added', 'client-config-changed', 'normal-cookie-present', 'passive-cookie-present',
    'credential-before-challenge', 'credentials-recorded', 'missing-password-challenge', 'challenge-after-response',
    'missing-password-projection', 'forged-challenge-path', 'normal-arrival-wrong-query', 'normal-arrival-wrong-request',
    'passive-credential-present', 'wrong-positive-response', 'wrong-passive-response', 'not-restored',
    'flow-inventory-differs', 'invalid-readback-redaction', 'cost-underreported', 'duplicate-transcript', 'foreign-transcript'}
sha = lambda raw: hashlib.sha256(raw).hexdigest()
load = lambda path: json.loads(path.read_bytes())


def require(value, message):
    if not value:
        raise ValueError(message)


def api(path, body=None):
    request = urllib.request.Request('http://localhost:18080' + path,
        data=None if body is None else json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.load(response)


def locate(root):
    root = pathlib.Path(root).resolve()
    return root if root.name == FOLDER else root / FOLDER


def capture_runtime(folder):
    folder = pathlib.Path(folder)
    runtime = folder / 'runtime'
    runtime.mkdir(exist_ok=False)
    pins = {'jars': {}, 'classes': {}}
    for name in JARS:
        path = runtime / (name + '.jar')
        subprocess.run(['docker', 'cp', SUITE + ':/opt/samlscope/lib/' + name + '-0.1.0.jar', str(path)],
            check=True, capture_output=True)
        pins['jars'][name] = sha(path.read_bytes())
    helper = (REPO / 'dev/reference-acceptance' / (HELPER + '.java')).read_bytes()
    (runtime / (HELPER + '.java')).write_bytes(helper)
    pins['helperSha256'] = sha(helper)
    with zipfile.ZipFile(runtime / 'runner.jar') as jar:
        pins['classes'] = {name: sha(jar.read('com/samlscope/runner/cases/' + name + '.class')) for name in CLASSES}
    (runtime / 'pins.json').write_text(json.dumps(pins, indent=2) + '\n')


def replay(folder):
    folder = pathlib.Path(folder).resolve()
    runtime = folder / 'runtime'
    pins = load(runtime / 'pins.json')
    require(set(pins['jars']) == set(JARS), 'Runtime JAR inventory differs')
    for name in JARS:
        require(sha((runtime / (name + '.jar')).read_bytes()) == pins['jars'][name], 'Archived actual runtime JAR changed')
    require(sha((runtime / (HELPER + '.java')).read_bytes()) == pins['helperSha256'], 'Archived verifier helper changed')
    with zipfile.ZipFile(runtime / 'runner.jar') as jar:
        require(pins['classes'] == {name: sha(jar.read('com/samlscope/runner/cases/' + name + '.class')) for name in CLASSES},
            'Archived production reader/wrapper changed')
    dependencies = pathlib.Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip()
    classpath = ':'.join(str(runtime / (name + '.jar')) for name in JARS) + ':' + dependencies
    with tempfile.TemporaryDirectory(prefix='kc-identity-production-replay-') as name:
        temporary = pathlib.Path(name)
        subprocess.run(['javac', '-sourcepath', '', '-cp', classpath, '-d', str(temporary / 'classes'),
            str(runtime / (HELPER + '.java'))], check=True, capture_output=True)
        require(all(path.name.startswith(HELPER) for path in (temporary / 'classes').rglob('*.class')),
            'Helper shadows production classes')
        result = subprocess.run(['java', '-cp', classpath + ':' + str(temporary / 'classes'),
            'com.samlscope.runner.cases.' + HELPER, str(folder), str(temporary / 'replay.json')],
            capture_output=True, text=True, timeout=120)
        require(result.returncode == 0, 'Actual production reader replay failed: ' + result.stderr[-1800:])
        return load(temporary / 'replay.json')


def verify_adoption(root, live=False, formal=True):
    folder = locate(root)
    manifest = load(folder / 'manifest.json')
    run = load(folder / 'created.json')['run']['id']
    require(manifest['runId'] == run and manifest['caseId'] == CASE and
        manifest['adapter'] == 'keycloak-native-password-only-v1' and
        manifest['targetMetadataSha256'] == sha((folder / 'target-metadata.xml').read_bytes()), 'Native manifest identity differs')
    for name, digest in manifest['files'].items():
        path = folder / name
        require(path.resolve().is_relative_to(folder) and not any(p.is_symlink() for p in [path, *path.parents])
            and path.is_file() and sha(path.read_bytes()) == digest, 'Native original path/hash differs')
    entries = load(folder / 'transcript.json')
    by_id = {row['id']: row for row in entries}
    require(len(by_id) == len(entries) and all(row['runId'] == run for row in entries), 'Foreign/duplicated Run history')
    decoded = {}
    for row in load(folder / 'decoded-manifest.json'):
        path = folder / row['file']
        require(path.parent == folder / 'decoded' and path.name == row['id'] + '.xml' and row['id'] in by_id and
            row['id'] not in decoded and by_id[row['id']]['decodedSamlRef'] == 'transcripts/' + run + '/' + row['id'] + '.saml.xml',
            'Decoded original Run/path differs')
        raw = path.read_bytes()
        require(sha(raw) == row['sha256'] and len(raw) == by_id[row['id']]['decodedSamlBytes'], 'Decoded original bytes changed')
        decoded[row['id']] = raw
    require(set(decoded) == {row['id'] for row in entries if row['decodedSamlRef']}, 'Decoded original inventory incomplete')
    observed = load(folder / 'native-reader-replay.json')
    require(replay(folder) == observed, 'Archived actual production replay differs')
    outcome = observed['production_outcome']
    require(observed['runId'] == run and observed['shared_native_lifecycle'] and observed['privateMaterialExported'] is False and
        observed['manifestSha256'] == sha((folder / 'manifest.json').read_bytes()) and
        observed['transcriptSha256'] == sha((folder / 'transcript.json').read_bytes()) and
        set(observed['negative_controls']) == CONTROLS and set(observed['negative_controls'].values()) == {'NOT_VERIFIED'} and
        outcome['outcome'] == 'SATISFIED' and outcome['reasonCode'] == 'browser.authentication-identity.native-observed',
        'Native identity conclusion/control scope differs')
    operations = load(folder / 'operations.json')
    counts = load(folder / 'operation-counts.json')
    require(len(operations) == counts['native_http_attempts'] == 20 and
        [(row['method'], row['status']) for row in operations if row['productSettingWrite']] ==
        [('POST', 201), ('POST', 201), ('PUT', 204), ('POST', 201), ('DELETE', 204), ('DELETE', 204)] and
        counts['product_setting_writes'] == counts['product_setting_write_attempts'] == 6 and
        counts['administrator_preparation_writes'] == 4 and counts['administrator_restoration_writes'] == 2 and
        counts['protocol_operations_attempted'] == 2 and counts['automated_credential_submissions'] == 1 and
        counts['test_user_operations'] == counts['human_operations'] == counts['product_restarts'] == 0 and
        counts['restored'] is True, 'Administrator/test-user operation costs differ')
    prior = folder.parent / 'keycloak-authentication-identity-r1'
    audit = load(prior / 'qualification-audit.json')
    require(audit['original_counts_sha256'] == sha((prior / 'operation-counts.json').read_bytes()) and
        audit['qualification'] == 'NOT_VERIFIED' and audit['original_counts_preserved'] is True and
        audit['count_correction'] == dict(protocol_operations_attempted=2, original_reported=1,
            basis='normal successful Redirect exchange plus passive signed error in immutable transcript'), 'Failed initial qualification hidden')
    prior_entries = load(prior / 'transcript.json')
    prior_run = load(prior / 'created.json')['run']['id']
    require(len({e['id'] for e in prior_entries}) == len(prior_entries) and all(e['runId'] == prior_run for e in prior_entries),
        'Prior attempt original Run history changed')
    prior_xml = {}
    for row in load(prior / 'decoded-manifest.json'):
        raw = (prior / row['file']).read_bytes()
        require(sha(raw) == row['sha256'], 'Prior protocol original changed')
        prior_xml[row['id']] = ET.fromstring(raw)
    received = [e for e in prior_entries if e['direction'] == 'INBOUND' and e.get('decodedSamlRef')]
    require(len(received) == 2, 'Prior actual protocol operation count differs')
    status = '{urn:oasis:names:tc:SAML:2.0:protocol}'
    signatures = '{http://www.w3.org/2000/09/xmldsig#}'
    for index, entry in enumerate(received):
        response = prior_xml[entry['id']]
        requests = [e for e in prior_entries if e['direction'] == 'OUTBOUND' and
            e['id'] in prior_xml and prior_xml[e['id']].get('ID') == response.get('InResponseTo')]
        require(len(requests) == 1 and requests[0]['timestamp'] < entry['timestamp'] and response.find(signatures + 'Signature') is not None and
            response.find(status + 'Status/' + status + 'StatusCode').get('Value') ==
            'urn:oasis:names:tc:SAML:2.0:status:' + ('Success' if index == 0 else 'Responder') and
            requests[0]['method'] == ('GET' if index == 0 else 'POST'), 'Prior two actual exchange original correlation differs')
    prior_restoration = load(prior / 'restoration.json')
    require(prior_restoration['restored'] is True and prior_restoration['remainingClients'] == [] and
        prior_restoration['flowInventoryRestored'] is True and prior_restoration['recoveryFailures'] == [], 'Failed qualification left product configuration')
    scope = load(folder / 'measurement-scope.json')
    require(scope['aggregate_product_setting_writes'] == 12 and scope['aggregate_protocol_operations_attempted'] == 4 and
        scope['aggregate_automated_credential_submissions'] == 2 and scope['test_user_operations'] == scope['human_operations'] == 0 and
        scope['normal_public_projection_is_not_raw_html'] is True and scope['all_attempts_restored'] is True,
        'Aggregate attempts/user-effort scope differs')
    if live:
        sys.path.insert(0, str(REPO / 'dev/keycloak'))
        from attribute_policy_capability_absence import product_token
        from mdiop_representation_campaign import runtime as product_runtime
        token = product_token()
        def admin(path):
            request = urllib.request.Request('http://localhost:18180/admin/realms/samlscope' + path,
                headers={'Authorization': 'Bearer ' + token})
            with urllib.request.urlopen(request, timeout=40) as response:
                return json.load(response)
        peer = 'http://localhost:18080/p/' + load(folder / 'created.json')['run']['planId']
        require(admin('/clients?clientId=' + urllib.parse.quote(peer, safe='')) == [], 'Live temporary client remains')
        original = json.loads(base64.b64decode(load(folder / 'originals/flow-inventory-before.json')['response_base64']))
        require(admin('/authentication/flows') == original, 'Live authentication flows not restored')
        require(all(admin('/client-policies/' + kind) == {kind: []} for kind in ['policies', 'profiles']), 'Live client policy changed')
        require(product_runtime() == load(folder / 'originals/before.environment.json')['runtime'], 'Live native runtime changed')
        require(api('/api/runs/' + run + '/transcript') == entries, 'Live protocol history changed')
    if not formal:
        return observed
    from ssp_ui_stored_outcome import compare_stored
    evaluation = folder / 'evaluation'
    installation = load(folder / 'receipt-installation.json')
    require(installation['path'] == '/data/keycloak-authentication-identity-evidence/' + run and
        installation['readBackVerified'] is True and {row['file']: row['sha256'] for row in installation['records']} ==
        manifest['files'] | {'manifest.json': sha((folder / 'manifest.json').read_bytes())}, 'Installed receipt/readback differs')
    require(load(evaluation / 'transcript-before.json') == load(evaluation / 'transcript.json') == entries, 'Formal evaluation altered wire history')
    stored = compare_stored(folder, 'runtime', CASE, outcome)
    result = load(evaluation / 'result.json')
    cases = {case['id']: case for requirement in result['requirements'] for case in requirement['cases']}
    case = cases[CASE]
    require(result['run']['id'] == run and result['target']['metadata_digest'] == 'sha256:' + manifest['targetMetadataSha256'] and
        (case['outcome'], case['verdict'], case['reason_code'], case['attested'], case['evidence_class']) ==
        ('SATISFIED', 'PASS', 'browser.authentication-identity.native-observed', False, 'OPERATOR_ASSISTED') and
        case['evidence'] == outcome['evidence'] and stored['verdict'] == 'PASS', 'Formal native verdict/provenance differs')
    if live:
        current = api('/api/runs/' + run + '/result.json')
        current_cases = {c['id']: c for r in current['requirements'] for c in r['cases']}
        require(current_cases[CASE] == case, 'Live central result differs')
    return evaluation / 'result.json', {CASE: case}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=pathlib.Path)
    parser.add_argument('--capture-runtime', action='store_true')
    parser.add_argument('--record-replay', action='store_true')
    parser.add_argument('--diagnostic-only', action='store_true')
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    folder = locate(args.root)
    if args.capture_runtime:
        capture_runtime(folder)
    if args.record_replay:
        path = folder / 'native-reader-replay.json'
        require(not path.exists(), 'Actual runtime replay is immutable')
        path.write_text(json.dumps(replay(folder), indent=2) + '\n')
    if not args.capture_runtime and not args.record_replay:
        result = verify_adoption(folder, live=args.live, formal=not args.diagnostic_only)
        print('Keycloak authentication identity adoption verified: one scoped observation')
