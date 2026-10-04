#!/usr/bin/env python3
"""Adopt a scoped stock-native ordinary-bearer observation, never fabricated attestation.

Signed oracle calibration is separate from the real product transcript and cannot
become product evidence. The archived production reader independently repeats all
signature, factory, mapper, configuration, restoration and altered-original checks.
"""
import argparse
import base64
import importlib.util
import json
import pathlib
import subprocess
import sys
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

REPO = pathlib.Path(__file__).resolve().parents[2]
FOLDER = 'keycloak-native-subject-confirmation-v184-r1'
CASES = ('IIP-SSO01-fr-idp-01', 'IIP-SSO01-gd-idp-01')
SCHEMA = 'samlscope-keycloak-subject-confirmation-v1'
REASON = 'browser.subject-confirmation.native-no-opportunity'
spec = importlib.util.spec_from_file_location('kc_subject_confirmation_runtime', REPO / 'dev/reference-acceptance/verify_ssp_intersection_capability_acceptance.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)
runtime.HELPER = 'VerifyKeycloakSubjectConfirmation'
runtime.CLASSES = (
    'com/samlscope/runner/cases/KeycloakSubjectConfirmationEvidence.class',
    'com/samlscope/runner/cases/SimpleSamlPhpSubjectConfirmationEvidence.class',
    'com/samlscope/runner/cases/KeycloakNativeSchemaAdmissionEvidence.class',
    'com/samlscope/runner/cases/MetadataAlgorithmEvidence.class',
    'com/samlscope/runner/cases/SubjectConfirmationConfigurationTestCase.class',
    'com/samlscope/runner/cases/ApprovedConfigCaseRegistry.class',
)
sha, load, require = runtime.sha, runtime.load, runtime.require
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from subject_confirmation_campaign import ADMIN, TARGET, JARS, reject_sensitive
from mdiop_representation_campaign import runtime as product_runtime
from algorithm_preference_campaign import admin

MD = '{urn:oasis:names:tc:SAML:2.0:metadata}'
S = '{urn:oasis:names:tc:SAML:2.0:assertion}'
P = '{urn:oasis:names:tc:SAML:2.0:protocol}'
DS = '{http://www.w3.org/2000/09/xmldsig#}'
BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer'
IMAGE = 'sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067'
INVENTORY = '6c395042caae9cd300d9c0d989a58c5aaca4510dec2e1c1c9daeedfe3da5261e'
PROCESS = '75df757278ed67ca753b388fd3b6212db0dd085eee3cf75e6cd26dc4dbfe110d'
CONTROLS = {
    'wrong-run', 'wrong-campaign', 'wrong-target', 'wrong-profile', 'wrong-peer',
    'missing-restoration', 'restore-client-remains', 'native-runtime-changed',
    'classpath-injected', 'process-injected', 'unknown-factory',
    'unknown-factory-property', 'unknown-effective-mapper',
    'client-signature-disabled', 'foreign-attester-setting', 'client-before-after-differ',
    'missing-source-jar', 'native-source-mutated', 'source-producer-mutated',
    'control-purpose-product', 'control-target-trust-change',
    'control-signer-in-product-evidence', 'semantic-positive-swapped',
    'signed-calibration-tampered', 'duplicate-transcript', 'foreign-transcript-run',
    'foreign-content-reference', 'directory-receipt', 'symlink-receipt',
}


def api(path, body=None):
    request = urllib.request.Request('http://localhost:18080' + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=40) as response:
        return json.load(response)


def http(record, method, url, status, sensitive=True):
    require((record['method'], record['url'], record['status']) == (method, url, status), 'Native original HTTP identity changed')
    raw = base64.b64decode(record['response_base64'], validate=True)
    require(sha(raw) == record['response_sha256'], 'Native original response bytes changed')
    parsed = json.loads(raw) if raw else None
    if sensitive and parsed is not None:
        reject_sensitive(parsed)
    return parsed


def scope_state(value):
    if isinstance(value, dict) and 'response_base64' in value:
        return json.loads(base64.b64decode(value['response_base64']))
    if isinstance(value, dict):
        return {key: scope_state(child) for key, child in value.items()}
    if isinstance(value, list):
        return [scope_state(child) for child in value]
    return value


def structural(element):
    """Namespace-aware assertion structure; signatures and SC are calibration changes."""
    if element.tag in {DS + 'Signature', S + 'SubjectConfirmation'}:
        return None
    return (element.tag, tuple(sorted(element.attrib.items())), (element.text or '').strip(),
        tuple(value for child in element if (value := structural(child)) is not None))


def verify_adoption(root, live=False, formal=True):
    folder = pathlib.Path(root).resolve()
    if folder.name != FOLDER:
        folder = folder / FOLDER
    created = load(folder / 'created.json')['run']
    run = created['id']
    peer = 'http://localhost:18080/p/' + created['planId']
    target = (folder / 'target-metadata.xml').read_bytes()
    target_hash = sha(target)
    receipt = load(folder / 'qualified-receipt.json')
    require((receipt['schema'], receipt['runId'], receipt['campaignId'], receipt['targetEntityId'],
        receipt['targetMetadataSha256'], receipt['peerEntityId']) ==
        (SCHEMA, run, 'native-subject-confirmation', TARGET, target_hash, peer), 'Receipt identity changed')
    entries = load(folder / 'transcript.json')
    by_id = {entry['id']: entry for entry in entries}
    require(len(entries) == len(by_id) == 5 and all(entry['runId'] == run for entry in entries), 'Run history is incomplete, foreign or duplicated')
    originals = {}
    for row in load(folder / 'decoded-manifest.json'):
        path = (folder / row['file']).resolve()
        require(path.parent == (folder / 'decoded').resolve() and row['id'] not in originals, 'Decoded original path/identity changed')
        raw = path.read_bytes()
        require(sha(raw) == row['sha256'] and len(raw) == by_id[row['id']]['decodedSamlBytes'], 'Decoded original hash/length changed')
        require(by_id[row['id']]['decodedSamlRef'] == 'transcripts/' + run + '/' + row['id'] + '.saml.xml', 'Decoded original Run reference changed')
        originals[row['id']] = raw
    require(set(originals) == {entry['id'] for entry in entries if entry['decodedSamlRef'] is not None}, 'Not every decoded real transcript has an original')
    sidecar = folder / 'originals'
    for name, digest in receipt['files'].items():
        path = sidecar / name
        require(path.resolve().is_relative_to(sidecar.resolve()) and not any(parent.is_symlink() for parent in [path, *path.parents]), 'Unsafe native original')
        require(path.is_file() and sha(path.read_bytes()) == digest, 'Native original hash changed')
    require(set(receipt['files']) == {str(path.relative_to(sidecar)) for path in sidecar.rglob('*') if path.is_file()}, 'Native original inventory changed')
    fixture = (sidecar / 'fixture.xml').read_bytes()
    require(fixture == (folder / 'fixture.xml').read_bytes() == originals[receipt['metadataReference']], 'Prepared fixture native input changed')
    require(by_id[receipt['metadataReference']]['samlSummary']['variant'] == 'control' and
        by_id[receipt['metadataReference']]['samlSummary']['fetchTranscriptId'] == receipt['fetchReference'], 'Prepared fixture/fetch relation changed')
    metadata = ET.fromstring(fixture)
    require(metadata.get('entityID') == peer and ET.fromstring(target).get('entityID') == TARGET, 'Actual metadata entity changed')
    before, after = (load(sidecar / ('environment-' + phase + '.json')) for phase in ['before', 'after'])
    require(before['runtime'] == after['runtime'] and before['runtime']['image'] == IMAGE and before['runtime']['running'] is True,
        'Native runtime restoration scope changed')
    for phase, environment in [('before', before), ('after', after)]:
        inventory = (sidecar / (phase + '.native-classpath.txt')).read_bytes()
        require(sha(inventory) == environment['nativeClasspathSha256'] == INVENTORY and len(inventory.splitlines()) == 471,
            'Full native installed classpath changed')
        process = json.dumps(environment['publicProcessArguments'], separators=(',', ':')).encode()
        require(sha(process) == PROCESS and environment['processRedactions'] == [] and environment['mounts'] ==
            [dict(destination='/opt/keycloak/data/import/realm-samlscope.json', type='bind', rw=False)], 'Native process/provider scope changed')
    pins = load(sidecar / 'native-runtime/pins.json')
    require(set(pins) == set(JARS), 'Native factory/source JAR set changed')
    for name, digest in pins.items():
        require(sha((sidecar / 'native-runtime' / name).read_bytes()) == digest and
            any(line.split()[0] == digest and line.split()[1].endswith('/' + name) for line in (sidecar / 'before.native-classpath.txt').read_text().splitlines()),
            'Operative native classpath/JAR binding changed')
    lookup = ADMIN + '/clients?clientId=' + urllib.parse.quote(peer, safe='')
    for phase in ['before', 'after']:
        require(http(load(sidecar / ('client-inventory-' + phase + '.json')), 'GET', lookup, 200) == [], 'Temporary client was not absent/restored')
        for kind, record in load(sidecar / ('global-policy-' + phase + '.json')).items():
            require(kind in ['policies', 'profiles'] and http(record, 'GET', ADMIN + '/client-policies/' + kind, 200) == {kind: []}, 'Native policy changed')
    require(load(folder / 'restoration.json') == load(sidecar / 'restoration.json') ==
        dict(restored=True, remaining_clients=[], originally_absent=True, client_removed=True, recovery_failures=0), 'Restoration incomplete')
    converter = load(sidecar / 'native-converter.json')
    converted = http(converter, 'POST', ADMIN + '/client-description-converter', 200)
    require(base64.b64decode(converter['request_base64'], validate=True) == fixture and converter['request_sha256'] == sha(fixture), 'Native metadata converter input changed')
    application = load(sidecar / 'native-client-application.json')
    require(application['only_native_override'] == 'saml.encrypt=false', 'Plaintext observation override expanded')
    app = application['native']
    http(app, 'POST', ADMIN + '/clients', 201)
    payload = json.loads(base64.b64decode(app['request_base64'], validate=True))
    expected = json.loads(json.dumps(converted))
    expected['attributes']['saml.encrypt'] = 'false'
    require(payload == expected and app['request_sha256'] == sha(base64.b64decode(app['request_base64'])), 'Suite added native configuration beyond declared plaintext observation')
    readback = {}
    for phase in ['before', 'after']:
        record = load(sidecar / ('native-client-' + phase + '.json'))
        require(record['response_projection'] == 'native-client-public-readback-v1' and set(record['redactions']) <= {'$.secret', '$.registrationAccessToken'}, 'Public native readback projection changed')
        readback[phase] = http(record, 'GET', record['url'], 200)
        require(readback[phase]['clientId'] == peer and readback[phase]['protocol'] == 'saml', 'Native client entity changed')
    require(readback['before'] == readback['after'], 'Effective native client changed during protocol controls')
    require(scope_state(load(sidecar / 'native-scopes-before.json')) == scope_state(load(sidecar / 'native-scopes-after.json')), 'Effective native mapper scopes changed')
    native_id = readback['before']['id']
    http(load(sidecar / 'native-client-removal.json'), 'DELETE', ADMIN + '/clients/' + native_id, 204)
    real = ET.fromstring(originals[receipt['responseReference']])
    require(real.get('InResponseTo') == ET.fromstring(originals[receipt['requestReference']]).get('ID') and real.find(P + 'Status/' + P + 'StatusCode').get('Value') == 'urn:oasis:names:tc:SAML:2.0:status:Success', 'Normal response correlation/status changed')
    assertion = real.find(S + 'Assertion')
    require(assertion is not None and real.find(DS + 'Signature') is not None and assertion.find(DS + 'Signature') is not None, 'Normal product signatures absent')
    confirmations = assertion.findall(S + 'Subject/' + S + 'SubjectConfirmation')
    require(len(confirmations) == 1 and confirmations[0].get('Method') == BEARER and all(confirmations[0].find(S + name) is None for name in ['BaseID', 'NameID', 'EncryptedID']), 'Actual ordinary bearer observation changed')
    calibration = load(sidecar / 'calibration/calibration.json')
    require(calibration['purpose'] == 'oracle-calibration-only' and calibration['productNetworkOperations'] == calibration['targetTrustChanges'] == 0 and
        calibration['nativePrivateKeyRead'] is False and calibration['ephemeralPrivateKeyPersisted'] is False and calibration['baseResponseSha256'] == sha(originals[receipt['responseReference']]), 'Calibration contaminated product evidence')
    expected_controls = {'foreign-positive', 'foreign-missing-identifier', 'multiple-positive', 'multiple-packed-identifiers'}
    require(set(calibration['expected']) == expected_controls, 'Calibration inventory changed')
    actual_structure = structural(real)
    for name in expected_controls:
        control = (sidecar / 'calibration' / (name + '.xml')).read_bytes()
        require(structural(ET.fromstring(control)) == actual_structure and control not in originals.values(), 'Calibration changed unrelated product structure or became real traffic')
    operations = load(folder / 'operations.json')
    writes = [row for row in operations if row['product_setting_write']]
    require(len(operations) == 31 and [(row['method'], row['status']) for row in writes] == [('POST', 201), ('DELETE', 204)], 'Native operation costs changed')
    require(load(folder / 'operation-counts.json') == dict(product_setting_write_attempts=2, product_setting_writes=2, native_http_attempts=31,
        protocol_operations_attempted=2, normal_protocol_success=True, product_restarts=0, human_operations=0, restored=True,
        calibration_network_operations=0, calibration_target_trust_changes=0), 'Native cost/restoration counters changed')
    require(load(folder / 'calibration-operation-history.json') == dict(calibration_producer_attempts=2, failed_attempts=1,
        failed_reason='native common JAR missing from initial isolated classpath', public_native_jar_captures=6,
        product_setting_writes=0, product_network_operations=0, target_trust_changes=0, human_operations=0,
        ephemeral_private_keys_persisted=False, failed_public_artifacts_preserved=True), 'Calibration failed-attempt costs missing')
    recorded = load(folder / 'native-reader-replay.json')
    require(runtime.replay(folder) == recorded, 'Archived actual production replay changed')
    require(recorded['runId'] == run and set(recorded['production_outcomes']) == set(CASES) and
        set(recorded['negative_controls']) == CONTROLS and set(recorded['negative_controls'].values()) == {'NOT_VERIFIED'} and
        recorded['oracle_calibration_controls'] == 4 and recorded['calibration_product_evidence'] is False and
        recorded['transcriptSha256'] == sha((folder / 'transcript.json').read_bytes()) and recorded['verdict_adopted'] is False,
        'Production original/altered-original calibration inventory changed')
    for case_id, outcome in recorded['production_outcomes'].items():
        require(outcome['outcome'] == 'SATISFIED_WITH_NOTE' and outcome['reasonCode'] == REASON and
            outcome['details']['scope'] == 'this-run-stock-native-bearer-factory-installed-mappers-and-effective-client' and
            outcome['details']['custom_provider_capability_asserted'] is False and outcome['details']['calibration_product_evidence'] is False and
            dict((row['kind'], row['reference']) for row in outcome['evidence']).get('native-keycloak-subject-confirmation') ==
            run + '.keycloak-subject-confirmation.json#' + sha((folder / 'qualified-receipt.json').read_bytes()), 'Scoped native note/provenance changed')
    if live:
        require(product_runtime() == before['runtime'] and admin('/clients?clientId=' + urllib.parse.quote(peer, safe='')) == [], 'Live product not restored')
        require({kind: admin('/client-policies/' + kind) for kind in ['policies', 'profiles']} == {'policies': {'policies': []}, 'profiles': {'profiles': []}}, 'Live native policy changed')
        require(api('/api/runs/' + run + '/transcript') == entries, 'Live product transcript changed')
    if not formal:
        return recorded
    evaluation = folder / 'evaluation'
    result = load(evaluation / 'result.json')
    rows = {case['id']: case for requirement in result['requirements'] for case in requirement['cases']}
    require(result['run']['id'] == run and result['target']['metadata_digest'] == 'sha256:' + target_hash, 'Formal target/Run changed')
    require(load(evaluation / 'transcript-before.json') == load(evaluation / 'transcript.json') == entries, 'Formal evaluation changed real protocol history')
    require(load(evaluation / 'receipt-readback.json')['sha256'] == sha((folder / 'qualified-receipt.json').read_bytes()), 'Installed native receipt changed')
    for case_id in CASES:
        case, expected_outcome = rows[case_id], recorded['production_outcomes'][case_id]
        require((case['outcome'], case['verdict'], case['reason_code'], case['attested'], case['evidence_class']) ==
            ('SATISFIED_WITH_NOTE', 'WARNING', REASON, False, 'PROTOCOL_OBSERVED'), 'Formal native note/attestation provenance changed')
        stored = load(evaluation / (case_id + '.case-execution.json'))
        execution = stored['cases'][case_id]
        observed = dict(execution['outcome'])
        details = dict(observed['details'])
        previous = details.pop('previous_recorded_evidence_result', None)
        observed['details'] = details
        require(stored['runId'] == run and execution['status'] == 'FINISHED' and execution['outboxCount'] == 0 and
            observed == expected_outcome and execution['outcome']['evidence'] == case['evidence'] and execution['verdict'] == case['verdict'], 'Formal full stored native outcome changed')
        if previous is not None:
            old_rows = {case['id']: case for requirement in load(evaluation / 'result-before.json')['requirements'] for case in requirement['cases']}
            require(previous['outcome'] == old_rows[case_id]['outcome'] == 'NOT_VERIFIED' and
                previous['reason_code'] == old_rows[case_id]['reason_code'], 'Previous native result audit changed')
    return evaluation / 'result.json', {case_id: rows[case_id] for case_id in CASES}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=pathlib.Path)
    parser.add_argument('--capture-runtime', action='store_true')
    parser.add_argument('--record-replay', action='store_true')
    parser.add_argument('--live', action='store_true')
    parser.add_argument('--diagnostic-only', action='store_true')
    args = parser.parse_args()
    folder = args.root.resolve()
    if folder.name != FOLDER:
        folder = folder / FOLDER
    if args.capture_runtime:
        runtime.capture_runtime(folder)
    if args.record_replay:
        require(not (folder / 'native-reader-replay.json').exists(), 'Immutable replay exists')
        (folder / 'native-reader-replay.json').write_text(json.dumps(runtime.replay(folder), indent=2) + '\n')
    verify_adoption(folder, live=args.live, formal=not args.diagnostic_only)
    print('Native ordinary bearer subject-confirmation adoption verified; two scoped observations')
