#!/usr/bin/env python3
"""Adopt MD06.a3 only from native XML signatures and a complete HTTP-only campaign scope."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

from verify_metadata_refresh_acceptance import verify_signatures
from verify_shibboleth_metadata_refresh_acceptance import decoded_originals, FILES, HASH_FIELDS
from verify_shibboleth_persistent_pairwise_acceptance import PINS, runtime_classpath
from verify_terminal_http_acceptance import _verify_target_runtime, _verify_suite_runtime, find_case, parsed_time

REPO = Path(__file__).resolve().parents[2]
FOLDER = 'shibboleth-role-signing-http-v165-r1'
CASE = 'IIP-MD06-a3-idp-01'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
READ = lambda path: json.loads(Path(path).read_text())


def require(value, detail):
    if not value:
        raise ValueError(detail)


def verify_preparation_lifecycle(child, manifest, transcript):
    """Prove the explicit setup restart ends before any measured protocol request.

    The Run is allocated before the campaign registers its native provider. This is a
    recorded preparation operation, not permission to replace a target during measurement.
    All provider writes must precede startup/native fetch; all restoration follows the
    final measured Response. The independently checked start/end runtime remains identical.
    """
    created = float(READ(child / 'created.json')['run']['createdAt'])
    operations = READ(child / 'operations.json')
    require([item['label'] for item in operations] == ['apply-metadata-providers.xml', 'apply-audit.xml',
        'campaign-prepare', 'restore-audit.xml', 'restore-metadata-providers.xml', 'campaign-restore'],
        'Native lifecycle operation inventory differs')
    prepare = operations[2]
    native_start = parsed_time(READ(child / 'target-runtime-start.json')['binding']['container_started_at'])
    first_fetch = min(float(entry['timestamp']) for entry in transcript if entry['id'] == manifest['phaseA']['fetchReference'])
    first_request = min(float(entry['timestamp']) for entry in transcript
                        if entry['direction'] == 'OUTBOUND' and entry['method'] == 'POST')
    last_response = max(float(entry['timestamp']) for entry in transcript
                        if entry['direction'] == 'INBOUND' and entry['method'] == 'POST')
    require(prepare['operation'] == 'product-restart' and prepare['completed'] is True
            and created <= operations[0]['recordedAt'] <= operations[1]['recordedAt'] <= prepare['recordedAt']
            <= native_start < first_fetch <= first_request
            and native_start <= prepare['completedAt'] < first_request,
            'Native preparation restart is not wholly before measured requests')
    for item, original in zip(operations[:2], ('configured-providers.xml', 'configured-audit.xml')):
        require(item['operation'] == 'product-config-write' and item['readBack'] is True
                and item['sha256'] == SHA((child / original).read_bytes()), 'Preparation write/read-back differs')
    require(last_response < operations[3]['recordedAt'] <= operations[4]['recordedAt'] <= operations[5]['recordedAt']
            and operations[5]['completed'] is True, 'Restoration overlapped measured protocol')
    _verify_target_runtime(child, 'shibboleth', first_fetch)


def replay(folder, retain=False):
    folder = Path(folder)
    child = folder / 'refresh'
    runtime = READ(child / 'suite-runtime-terminal-http.json')
    store = READ(child / 'store-runtime.json')
    helper = folder / 'replay-helper-original.java'
    original = READ(folder / 'replay-helper-original.json')
    require(original['sha256'] == SHA(helper.read_bytes()), 'Archived replay helper changed')
    jars = [child / runtime['jars'][name]['file'] for name in ('runner', 'core', 'saml')]
    require(all(SHA(jars[index].read_bytes()) == PINS['jars'][name] for index, name in enumerate(('runner', 'core', 'saml')))
            and store['sha256'] == SHA((child / store['file']).read_bytes()), 'Archived runtime JAR changed')
    classpath = ':'.join(map(str, jars + [child / store['file']])) + ':' + runtime_classpath()
    with tempfile.TemporaryDirectory(prefix='samlscope-shib-transport-verifier-') as temporary:
        temporary = Path(temporary)
        named = temporary / 'VerifyShibbolethRoleSigningTransportEvidence.java'
        named.write_bytes(helper.read_bytes())
        classes = temporary / 'classes'
        classes.mkdir()
        subprocess.run(['javac', '-cp', classpath, '-d', str(classes), str(named)], check=True, capture_output=True)
        require(all(path.name.startswith('VerifyShibbolethRoleSigningTransportEvidence') for path in classes.rglob('*.class')),
                'Helper would shadow production classes')
        report = temporary / 'report.json'
        executed = subprocess.run(['java', '-cp', ':'.join(map(str, jars + [child / store['file']])) + ':' + str(classes) + ':' + runtime_classpath(),
            'com.samlscope.runner.cases.VerifyShibbolethRoleSigningTransportEvidence', str(child), str(report)], capture_output=True)
        require(executed.returncode == 0, 'Production replay failed: ' + executed.stderr.decode(errors='replace')[-2000:])
        regenerated = report.read_bytes()
    retained = folder / 'production-replay-v166.json'
    if retain:
        require(not retained.exists(), 'Refusing to replace production replay')
        retained.write_bytes(regenerated)
    else:
        require(retained.read_bytes() == regenerated, 'Archived production replay differs')
    value = json.loads(regenerated)
    require(value['productionOutcome'] == 'SATISFIED_WITH_NOTE' and len(value['tamperControls']) == 34
            and set(value['tamperControls'].values()) == {'NOT_VERIFIED'}, 'Native transport controls incomplete')
    return value


def verify(root):
    folder = Path(root) / FOLDER
    child = folder / 'refresh'
    manifest = READ(child / 'metadata-refresh-manifest.json')
    scope = READ(folder / 'http-scope.json')
    run = READ(child / 'created.json')['run']['id']
    require(manifest['runId'] == scope['runId'] == run
            and scope['schema'] == 'samlscope-shibboleth-role-signing-transport-v1'
            and manifest['adapter'] == 'shibboleth-native-http-refresh-v1'
            and scope['targetMetadataSha256'] == SHA((child / 'target-metadata.xml').read_bytes()), 'Wrong native scope/Run')
    for name, field in HASH_FIELDS.items():
        require(manifest[field] == SHA((child / name).read_bytes()), 'Native refresh original changed: ' + name)
    transcript = READ(child / 'transcript.json')
    originals = decoded_originals(child, transcript)
    for phase, name in (('phaseA', 'metadata-a.xml'), ('phaseB', 'metadata-b.xml')):
        require(originals[manifest[phase]['preparedReference']] == (child / name).read_bytes(), 'Native metadata fixture differs')
    verify_signatures(child, manifest)
    verify_preparation_lifecycle(child, manifest, transcript)
    counts = READ(child / 'operation-counts.json')
    require((counts['product_configuration_writes'], counts['restoration_writes'], counts['product_restarts'],
            counts['product_reloads'], counts['human_operations'], counts['protocol_operations'], counts['restored'])
            == (4, 2, 2, 0, 0, 3, True) and counts['operations'] == READ(child / 'operations.json'), 'Native operation counts changed')
    for kind in ('providers', 'audit'):
        require((child / ('original-' + kind + '.xml')).read_bytes() == (child / ('final-' + kind + '.xml')).read_bytes(), 'Native restoration differs')
    installation = READ(child / 'metadata-refresh-receipt-install.json')
    require(installation['runId'] == run and installation['readBackSha256'] == [*[SHA((child / name).read_bytes()) for name in FILES],
            SHA((child / 'metadata-refresh-manifest.json').read_bytes())], 'Native refresh placement differs')
    extra = READ(folder / 'http-scope-receipt-install.json')
    names = sorted(path.name for path in folder.glob('http-*.xml')) + ['http-scope.json']
    require(extra['runId'] == run and extra['destination'] == '/data/metadata-rejection-evidence/' + run + '.refresh'
            and {row['file']: row['sha256'] for row in extra['files']} == {name: SHA((folder / name).read_bytes()) for name in names}
            and extra['native_scope_configuration_writes'] == extra['human_operations'] == 0
            and extra['native_scope_file_reads'] == 10, 'Native scope placement/operations differ')
    for name in names:
        require((folder / name).read_bytes() == (child / name).read_bytes(), 'Scope replay original differs')
    for phase in ('before', 'after'):
        record = scope[phase]
        for prefix in ('server', 'providers'):
            require(record[prefix + 'Sha256'] == SHA((folder / record[prefix + 'File']).read_bytes()), 'Native scope configuration changed')
        for row in record['files']:
            require(row['sha256'] == SHA((folder / row['file']).read_bytes()), 'Native source original changed')
    evaluation = child / 'evaluation-terminal-http-v1'
    require(READ(evaluation / 'transcript-before.json') == READ(evaluation / 'transcript.json') == transcript, 'Formal re-evaluation changed transcript')
    formal = READ(child / 'formal-evaluation.json')
    require(formal['runId'] == run and formal['transcriptUnchanged'] is True, 'Formal Run binding differs')
    _verify_suite_runtime(child, run, parsed_time(formal['startedAt']), PINS)
    with zipfile.ZipFile(child / READ(child / 'suite-runtime-terminal-http.json')['jars']['runner']['file']) as archive:
        require(b'samlscope-shibboleth-role-signing-transport-v1' in archive.read('com/samlscope/runner/cases/ShibbolethRoleSigningTransportEvidenceFile.class'),
                'Production native transport reader missing')
    result_path = evaluation / 'result.json'
    result = READ(result_path)
    case = find_case(result, CASE)
    require(result['run']['id'] == run and (case['outcome'], case['verdict'], case['reason_code'], case['attested'])
            == ('SATISFIED_WITH_NOTE', 'WARNING', 'metadata.role-signing.http-transport-observed', False), 'Formal XML/HTTP conclusion differs')
    references = {row['reference'] for row in case['evidence']}
    expected = {'transcript:' + manifest[phase][field] for phase in ('phaseA', 'phaseB')
                for field in ('fetchReference', 'preparedReference', 'requestReference', 'responseReference')}
    expected |= {'transcript:' + manifest['phaseB']['controlRequestReference'], run + '.refresh/manifest.json', run + '.refresh/http-scope.json'}
    require(references == expected, 'Formal transport evidence differs')
    require(replay(folder)['runId'] == run, 'Replay belongs to another Run')
    return result_path, {CASE: case}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('--retain-replay', action='store_true')
    args = parser.parse_args()
    if args.retain_replay:
        print(replay(args.root / FOLDER, retain=True))
    else:
        path, cases = verify(args.root)
        print(path, {name: case['verdict'] for name, case in cases.items()})
