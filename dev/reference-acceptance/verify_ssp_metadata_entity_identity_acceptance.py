#!/usr/bin/env python3
"""Fail-closed archived reader replay and central stored-result adoption verification.

The default operation is offline and read-only except for temporary javac output.
Runtime and receipt digests must come from the caller's trusted capture record.
Source precedence remains diagnostic and cannot be installed as a conclusive result.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile

HELPER = 'VerifySspMetadataEntityIdentityEvidence'
STORED = 'ReadSspMetadataEntityIdentityStoredConclusions'
PACKAGE = 'com.samlscope.runner.cases.'
ADAPTER = 'simplesamlphp-native-metadata-entity-identity-v1'
CASES = {'IIP-MD05-a1-idp-01', 'IIP-MD05-a2-idp-01'}
CONTROLS = {'wrong-run', 'wrong-adapter', 'wrong-target', 'wrong-campaign', 'unknown-secondary',
    'duplicate-history', 'foreign-history', 'foreign-decoded-ref', 'missing-normal', 'tampered-file',
    'missing-restoration', 'explicit-replacement-not-simultaneous', 'positive-control-failed',
    'mut-iip-md05-a1-idp', 'mut-iip-md05-a2-idp'}
CLASSES = ('SimpleSamlPhpMetadataEntityIdentityEvidence', 'SimpleSamlPhpMetadataEntityIdentityConfigurationTestCase')
SUITE = 'samlscope-reference-suite'
SHA = lambda b: hashlib.sha256(b).hexdigest()


def require(value, message):
    if not value:
        raise ValueError(message)


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON field')
        result[key] = value
    return result


def load(path):
    return json.loads(Path(path).read_bytes(), object_pairs_hook=strict_pairs)


def safe(root, name):
    root = Path(root).absolute()
    path = root/name
    require(not Path(name).is_absolute() and str(Path(name)) == name and '..' not in Path(name).parts,
            'Noncanonical original path')
    require(path != root and path.is_relative_to(root) and not any(p.is_symlink() for p in (path, *path.parents)),
            'Escaped or symbolic original')
    require(path.is_file(), 'Missing original')
    return path


def verify_receipt(folder, expected_sha256):
    receipt = Path(folder)/'receipt'
    manifest_path = safe(receipt, 'manifest.json')
    require(SHA(manifest_path.read_bytes()) == expected_sha256, 'Receipt trust anchor changed')
    m = load(manifest_path)
    require(re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', m['runId']) and m['adapter'] == ADAPTER,
            'Wrong receipt ownership')
    expected = set(m['files']) | {'manifest.json'}
    actual = {str(p.relative_to(receipt)) for p in receipt.rglob('*') if p.is_file() or p.is_symlink()}
    require(expected == actual, 'Receipt inventory changed')
    for name, digest in m['files'].items():
        require(re.fullmatch('[0-9a-f]{64}', digest) and SHA(safe(receipt, name).read_bytes()) == digest, 'Original changed')
    require(len(m['peers']) == 2 and {p['label'] for p in m['peers']} == {'primary', 'secondary'}
            and len({p['runId'] for p in m['peers']}) == 2, 'Secondary peer missing or duplicated')
    for peer in m['peers']:
        child = receipt/peer['label']
        entries = load(safe(child, 'transcript.json'))
        by = {}
        for row in entries:
            require(row['id'] not in by and row['runId'] == peer['runId'], 'Foreign or duplicate transcript')
            require(not any(k.lower() in {'authorization', 'cookie', 'set-cookie'} for k in row['headers']), 'Unredacted transcript headers')
            by[row['id']] = row
        decoded = {}
        for row in load(safe(child, 'decoded-manifest.json')):
            identity = row['id']
            require(identity in by and identity not in decoded and row['file'] == 'decoded/'+identity+'.xml', 'Duplicate or foreign decoded original')
            original = safe(child, row['file']).read_bytes()
            require(by[identity]['decodedSamlRef'] == 'transcripts/'+peer['runId']+'/'+identity+'.saml.xml'
                    and len(original) == by[identity]['decodedSamlBytes'] and SHA(original) == row['sha256'], 'Decoded original differs')
            decoded[identity] = original
        require(set(decoded) == {row['id'] for row in entries if row.get('decodedSamlRef')}, 'Decoded inventory incomplete')
    require(load(receipt/'restoration.json')['restored'] is True, 'Restoration missing')
    return m


def pin_runtime(source, output, helpers=None):
    """Archive copied bytes, not hardlinks to mutable Gradle build products."""
    source, output = Path(source), Path(output)
    jars = sorted(source.glob('*.jar'))
    require(jars and any(p.name.startswith('runner-') or p.name == 'runner.jar' for p in jars), 'Actual Runner jar missing')
    helpers = Path(helpers or Path(__file__).parent)
    output.mkdir(parents=True, exist_ok=False)
    (output/'lib').mkdir()
    for path in jars:
        require(path.is_file() and not path.is_symlink(), 'Unsafe deployed jar')
        shutil.copyfile(path, output/'lib'/path.name)
    for name in (HELPER, STORED):
        shutil.copyfile(helpers/(name+'.java'), output/(name+'.java'))
    pins = dict(files={str(p.relative_to(output)): SHA(p.read_bytes()) for p in output.rglob('*') if p.is_file()}, classes={})
    runner = next(p for p in jars if p.name.startswith('runner-') and not p.name.endswith('-sources.jar') or p.name == 'runner.jar')
    with zipfile.ZipFile(output/'lib'/runner.name) as archive:
        pins['classes'] = {name: SHA(archive.read('com/samlscope/runner/cases/'+name+'.class')) for name in CLASSES}
    (output/'pins.json').write_text(json.dumps(pins, indent=2)+'\n')
    return SHA((output/'pins.json').read_bytes())


def verify_runtime(runtime, expected_sha256):
    runtime = Path(runtime)
    require(SHA(safe(runtime, 'pins.json').read_bytes()) == expected_sha256, 'Runtime trust anchor changed')
    pins = load(runtime/'pins.json')
    require(set(pins['classes']) == set(CLASSES), 'Reader class inventory differs')
    require(set(pins['files']) | {'pins.json'} == {str(p.relative_to(runtime)) for p in runtime.rglob('*') if p.is_file() or p.is_symlink()}, 'Runtime inventory changed')
    for name, digest in pins['files'].items():
        require(SHA(safe(runtime, name).read_bytes()) == digest, 'Archived runtime changed')
    jars = sorted((runtime/'lib').glob('*.jar'))
    runners = [p for p in jars if p.name == 'runner.jar' or p.name.startswith('runner-') and not p.name.endswith('-sources.jar')]
    require(len(runners) == 1, 'Ambiguous Runner archive')
    # Dependencies may not shadow the production classes selected for replay.
    observed = {}
    for jar in jars:
        with zipfile.ZipFile(jar) as archive:
            for name in CLASSES:
                entry = 'com/samlscope/runner/cases/'+name+'.class'
                if entry in archive.namelist():
                    require(name not in observed and jar == runners[0], 'Shadow reader class')
                    observed[name] = SHA(archive.read(entry))
    require(observed == pins['classes'], 'Actual archived reader changed')
    return ':'.join(str(p.resolve()) for p in jars)


def java(runtime, pins_sha256, helper, arguments):
    cp = verify_runtime(runtime, pins_sha256)
    with tempfile.TemporaryDirectory(prefix='ssp-md05-verify-') as name:
        classes = Path(name)/'classes'
        source = Path(runtime)/(helper+'.java')
        subprocess.run(['javac', '-sourcepath', '', '-cp', cp, '-d', str(classes), str(source)],
                       check=True, capture_output=True, timeout=90)
        require(all(p.name.startswith(helper) for p in classes.rglob('*.class')), 'Helper shadows production')
        return subprocess.run(['java', '-cp', str(classes)+':'+cp, PACKAGE+helper, *map(str, arguments)],
                              check=True, capture_output=True, timeout=120).stdout


def replay(folder, runtime, data, pins_sha256):
    with tempfile.TemporaryDirectory(prefix='ssp-md05-output-') as name:
        output = Path(name)/'replay.json'
        java(runtime, pins_sha256, HELPER, [Path(folder)/'receipt', Path(data), output])
        return load(output)


def verify_replay(observed, manifest, conclusive):
    require(observed['runId'] == manifest['runId'] and observed['shared_native_lifecycle'] is True
            and observed['privateMaterialExported'] is False and observed['additionalProductOperations'] == 0
            and observed['calibrationOnly'] is True and set(observed['checks']) == CONTROLS, 'Replay scope differs')
    for name, results in observed['checks'].items():
        require(set(results) == CASES and all(row['outcome'] == ('VIOLATED' if name.startswith('mut-') else 'NOT_VERIFIED')
                                             for row in results.values()), 'Calibration detection power missing')
    require(set(observed['production_outcomes']) == CASES, 'Production cases differ')
    for identity, result in observed['production_outcomes'].items():
        require(result['details']['evidence_adapter'] == ADAPTER and result['details']['native_run_id'] == manifest['runId']
                and result['details']['case_id'] == identity, 'Production ownership differs')
        # No success diagnostic for stock 2.5.0 has been qualified. Do not accept
        # source priority as success, even if a future result file claims it.
        require(result['outcome'] == 'VIOLATED' or not conclusive and result['outcome'] == 'NOT_VERIFIED'
                and result['notVerifiedReason'] == 'duplicate-conflict-unqualified', 'Native conclusion unqualified')


def bind_stored_to_database(runtime, pins_sha256, data, run, identity, archived):
    """Require the archived stored outcome to equal the case row now held by the Suite database."""
    current = json.loads(java(runtime, pins_sha256, STORED, ['capture', data, run, identity]))
    require(current == archived, 'Archived stored outcome differs from the Suite database')


def verify_formal(folder, runtime, pins_sha256, observed, manifest, data=None):
    folder = Path(folder)
    evaluation = folder/'evaluation'
    require(load(safe(evaluation, 'transcript-before.json')) == load(safe(evaluation, 'transcript.json'))
            == load(folder/'receipt/primary/transcript.json'), 'Formal evaluation changed wire originals')
    result = load(safe(evaluation, 'result.json'))
    require(result['run']['id'] == manifest['runId'] and result['target']['metadata_digest'] == 'sha256:'+manifest['targetMetadataSha256'], 'Formal target differs')
    rows = [c for r in result['requirements'] for c in r['cases']]
    require(len({r['id'] for r in rows}) == len(rows), 'Duplicate formal case')
    by = {r['id']: r for r in rows}
    for identity in sorted(CASES):
        before_path = safe(evaluation, 'stored-before-'+identity+'.json')
        after_path = safe(evaluation, 'stored-after-'+identity+'.json')
        before_doc = json.loads(java(runtime, pins_sha256, STORED, ['offline', before_path]))
        after_doc = json.loads(java(runtime, pins_sha256, STORED, ['offline', after_path]))
        if data is not None:
            bind_stored_to_database(runtime, pins_sha256, data, manifest['runId'], identity, after_doc)
        require(before_doc['runId'] == after_doc['runId'] == manifest['runId'] and set(before_doc['cases']) == set(after_doc['cases']) == {identity}, 'Foreign stored conclusion')
        before = before_doc['cases'][identity]
        after = after_doc['cases'][identity]
        require(before['outboxCount'] == after['outboxCount'] and after['status'] == 'FINISHED', 'Formal evaluation manufactured an action')
        outcome = dict(after['outcome'])
        details = dict(outcome['details'])
        previous = details.pop('previous_recorded_evidence_result', None)
        if previous is not None:
            old = before['outcome']
            require(old is not None and previous == dict(revision=before['revision'], updated_at=before['updatedAt'],
                outcome=old['outcome'], not_verified_reason=old['notVerifiedReason'], reason_code=old['reasonCode'],
                reason_message_key=old['reasonMessageKey'], evidence=old['evidence'], details=old['details']), 'Prior result audit differs')
        outcome['details'] = details
        proof = observed['production_outcomes'][identity]
        require(outcome == proof, 'Stored outcome differs from actual reader')
        row = by[identity]
        require(row['outcome'] == outcome['outcome'] and row['verdict'] == after['verdict']
                and row['reason_code'] == outcome['reasonCode'] and row['evidence'] == outcome['evidence']
                and row['attested'] is False and row['evidence_class'] == 'OPERATOR_ASSISTED', 'Central result/provenance differs')
    return result


def verify(folder, runtime, data, pins_sha256, receipt_sha256, diagnostic=False):
    manifest = verify_receipt(folder, receipt_sha256)
    observed = replay(folder, runtime, data, pins_sha256)
    recorded = load(safe(Path(folder), 'native-reader-replay.json'))
    require(observed == recorded, 'Archived actual reader replay differs')
    verify_replay(observed, manifest, not diagnostic)
    if not diagnostic:
        verify_formal(folder, runtime, pins_sha256, observed, manifest, data)
    return observed


def api(path, body=None):
    request = urllib.request.Request('http://localhost:18080'+path,
        data=None if body is None else json.dumps(body).encode(), headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.load(response)


def immutable(path, value):
    with Path(path).open('x') as handle:
        json.dump(value, handle, indent=2)
        handle.write('\n')


def suite_java(runtime, pins_sha256, helper, arguments, receipt=None):
    """Future explicit Suite-only action; all executable jars are archived and pinned."""
    cp = verify_runtime(runtime, pins_sha256)
    with tempfile.TemporaryDirectory(prefix='ssp-md05-suite-') as name:
        temporary = Path(name)
        classes = temporary/'classes'
        subprocess.run(['javac', '-sourcepath', '', '-cp', cp, '-d', str(classes), str(Path(runtime)/(helper+'.java'))],
                       check=True, capture_output=True, timeout=90)
        require(all(p.name.startswith(helper) for p in classes.rglob('*.class')), 'Helper shadows production')
        remote = '/tmp/'+temporary.name
        subprocess.run(['docker', 'exec', SUITE, 'mkdir', remote], check=True, capture_output=True, timeout=40)
        try:
            for local, target in ((classes, 'classes'), (Path(runtime)/'lib', 'lib')):
                subprocess.run(['docker', 'cp', str(local), SUITE+':'+remote+'/'+target], check=True, capture_output=True, timeout=90)
            if receipt is not None:
                subprocess.run(['docker', 'cp', str(receipt), SUITE+':'+remote+'/receipt'], check=True, capture_output=True, timeout=90)
            arguments = [str(x).replace('@receipt', remote+'/receipt').replace('@output', remote+'/replay.json') for x in arguments]
            result = subprocess.run(['docker', 'exec', SUITE, 'java', '-cp', remote+'/classes:'+remote+'/lib/*',
                PACKAGE+helper, *arguments], check=True, capture_output=True, timeout=120).stdout
            if any(x == remote+'/replay.json' for x in arguments):
                subprocess.run(['docker', 'cp', SUITE+':'+remote+'/replay.json', str(temporary/'replay.json')], check=True, capture_output=True, timeout=40)
                result = (temporary/'replay.json').read_bytes()
            return json.loads(result)
        finally:
            subprocess.run(['docker', 'exec', SUITE, 'rm', '-r', '--', remote], check=True, capture_output=True, timeout=60)


def verify_deployed_runtime(runtime, pins_sha256):
    verify_runtime(runtime, pins_sha256)
    with tempfile.TemporaryDirectory(prefix='ssp-md05-deployed-') as name:
        for jar in (Path(runtime)/'lib').glob('*.jar'):
            destination = Path(name)/jar.name
            subprocess.run(['docker', 'cp', SUITE+':/opt/samlscope/lib/'+jar.name, str(destination)], check=True, capture_output=True, timeout=90)
            require(SHA(destination.read_bytes()) == SHA(jar.read_bytes()), 'Deployed executable differs from archived runtime')


def install(folder, runtime, pins_sha256, receipt_sha256):
    folder = Path(folder)
    manifest = verify_receipt(folder, receipt_sha256)
    observed = suite_java(runtime, pins_sha256, HELPER, ['@receipt', '/data', '@output'], folder/'receipt')
    # This gate precedes receipt installation, formal evaluation and any capture
    # of stored results. An unqualified shadow cannot be adopted by a flag.
    verify_replay(observed, manifest, True)
    require(observed == load(safe(folder, 'native-reader-replay.json')), 'Live Suite replay differs')
    verify_deployed_runtime(runtime, pins_sha256)
    run = manifest['runId']
    for peer in manifest['peers']:
        require(api('/api/runs/'+peer['runId']+'/transcript') == load(folder/'receipt'/peer['label']/'transcript.json'), 'Live source Run history differs')
    evaluation = folder/'evaluation'
    evaluation.mkdir(exist_ok=False)
    immutable(evaluation/'result-before.json', api('/api/runs/'+run+'/result.json'))
    immutable(evaluation/'transcript-before.json', api('/api/runs/'+run+'/transcript'))
    for identity in sorted(CASES):
        stored = suite_java(runtime, pins_sha256, STORED, ['capture', run, identity])
        require(stored['runId'] == run and set(stored['cases']) == {identity}, 'Foreign stored before conclusion')
        immutable(evaluation/('stored-before-'+identity+'.json'), stored)
    destination = '/data/ssp-metadata-entity-identity-evidence/'+run
    absent = subprocess.run(['docker', 'exec', SUITE, 'test', '-e', destination], capture_output=True, timeout=40)
    require(absent.returncode == 1, 'Native receipt directory already owned or existence is unknown')
    subprocess.run(['docker', 'exec', SUITE, 'mkdir', '-p', '/data/ssp-metadata-entity-identity-evidence'], check=True, capture_output=True, timeout=40)
    subprocess.run(['docker', 'cp', str(folder/'receipt'), SUITE+':'+destination], check=True, capture_output=True, timeout=90)
    with tempfile.TemporaryDirectory(prefix='ssp-md05-install-') as name:
        readback = Path(name).resolve()/'receipt'
        subprocess.run(['docker', 'cp', SUITE+':'+destination, str(readback)], check=True, capture_output=True, timeout=90)
        expected = manifest['files'] | {'manifest.json': receipt_sha256}
        actual = {str(p.relative_to(readback)): SHA(safe(readback, str(p.relative_to(readback))).read_bytes()) for p in readback.rglob('*') if p.is_file() or p.is_symlink()}
        require(actual == expected, 'Installed receipt readback differs')
    immutable(folder/'receipt-installation.json', dict(path=destination, receiptSha256=receipt_sha256, readBackVerified=True, productOperations=0))


def formal(folder, runtime, pins_sha256, receipt_sha256):
    folder = Path(folder)
    manifest = verify_receipt(folder, receipt_sha256)
    installation = load(safe(folder, 'receipt-installation.json'))
    require(installation == dict(path='/data/ssp-metadata-entity-identity-evidence/'+manifest['runId'],
        receiptSha256=receipt_sha256, readBackVerified=True, productOperations=0), 'Installation unproven')
    observed = suite_java(runtime, pins_sha256, HELPER, ['@receipt', '/data', '@output'], folder/'receipt')
    verify_replay(observed, manifest, True)
    require(observed == load(safe(folder, 'native-reader-replay.json')), 'Formal replay differs')
    verify_deployed_runtime(runtime, pins_sha256)
    evaluation = folder/'evaluation'
    require(all((evaluation/('stored-before-'+case+'.json')).is_file() for case in CASES), 'Before conclusions must precede installation')
    run = manifest['runId']
    immutable(evaluation/'evaluate.json', api('/api/runs/'+run+'/protocol-evidence/evaluate', {}))
    immutable(evaluation/'result.json', api('/api/runs/'+run+'/result.json'))
    immutable(evaluation/'transcript.json', api('/api/runs/'+run+'/transcript'))
    for identity in sorted(CASES):
        stored = suite_java(runtime, pins_sha256, STORED, ['capture', run, identity])
        immutable(evaluation/('stored-after-'+identity+'.json'), stored)
    verify_formal(folder, runtime, pins_sha256, observed, manifest)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('folder', type=Path)
    p.add_argument('--runtime', type=Path, required=True)
    p.add_argument('--data', type=Path, help='Suite data with read-only DB, public metadata, transcript originals and saved Runs; no private keys are read')
    p.add_argument('--pins-sha256')
    p.add_argument('--receipt-sha256')
    p.add_argument('--archive-runtime', type=Path, help='Copy a deployed public lib directory and the verification helpers')
    p.add_argument('--record-replay', action='store_true')
    p.add_argument('--diagnostic-only', action='store_true')
    p.add_argument('--suite-replay', action='store_true', help='Explicit Suite-only replay using its read-only database; no product action')
    actions = p.add_mutually_exclusive_group()
    actions.add_argument('--install', action='store_true')
    actions.add_argument('--formal', action='store_true')
    a = p.parse_args(argv)
    if a.archive_runtime:
        print(pin_runtime(a.archive_runtime, a.runtime))
        return
    if not a.pins_sha256 or not a.receipt_sha256 or not (a.data or a.suite_replay or a.install or a.formal):
        p.error('--pins-sha256, --receipt-sha256 and either --data or --suite-replay are required')
    if a.install:
        install(a.folder, a.runtime, a.pins_sha256, a.receipt_sha256)
        return
    if a.formal:
        formal(a.folder, a.runtime, a.pins_sha256, a.receipt_sha256)
        return
    m = verify_receipt(a.folder, a.receipt_sha256)
    if a.record_replay:
        observed = (suite_java(a.runtime, a.pins_sha256, HELPER, ['@receipt', '/data', '@output'], a.folder/'receipt')
                    if a.suite_replay else replay(a.folder, a.runtime, a.data, a.pins_sha256))
        verify_replay(observed, m, False)
        dest = a.folder/'native-reader-replay.json'
        with dest.open('x') as f:
            json.dump(observed, f, indent=2)
            f.write('\n')
    else:
        require(a.data is not None, 'Offline verification requires --data; use --record-replay --suite-replay for Suite replay')
        verify(a.folder, a.runtime, a.data, a.pins_sha256, a.receipt_sha256, a.diagnostic_only)
        print('Diagnostic replay verified; no adoption' if a.diagnostic_only else 'Stored central adoption verified')


if __name__ == '__main__':
    main()
