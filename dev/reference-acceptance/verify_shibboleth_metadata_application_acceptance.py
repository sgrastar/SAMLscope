#!/usr/bin/env python3
"""Strict adoption of same-Run accepted metadata application; no target operations.

Archived production classes precede helper classes. Private polling/primary keys
remain in the Suite process. Developer consumer calibrations are never installed.
"""
import argparse, hashlib, importlib.util, json, pathlib, re, shutil, subprocess, tempfile, urllib.request

REPO = pathlib.Path(__file__).resolve().parents[2]
FOLDER = 'shibboleth-metadata-application-qualified-r1'
SUITE = 'samlscope-reference-suite'
NATIVE = 'samlscope-reference-shibboleth'
RUNTIME = 'runtime-v213-r2'
REPLAY = 'native-reader-replay-v213-r2.json'
EVALUATION = 'evaluation-v213'
CASES = ('IIP-MD06-a-idp-01', 'IIP-MD06-ab-idp-01')
HELPERS = ('VerifyShibbolethMetadataApplicationEvidence', 'VerifyNativeRoleKeyConsumption')
STORED = 'ReadShibbolethMetadataApplicationStoredOutcome'
JARS = ('runner', 'core', 'saml', 'store')
JAVA = '/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin/'
PINS = {
    'runner': 'b400ccfc5e1372c4cef77b674750c24c00dda18ed2b8484bba5000b31670a300',
    'core': '1d6e0020c915f50e78902554c06b61916a3f49e50de78d3bc23c6089d312babe',
    'saml': 'd8ea9ebf6048f82ba9773850d8302cca00b19751fa0aac4eca675506c8c737ca',
    'store': 'c4482cd06f9290a3592f0fceac2c9ec2d7603ea0557d1edc885e1c3d51bd8ece',
    'VerifyShibbolethMetadataApplicationEvidence': '12acff1d7171893332df8125c3e42095621d21586f7fab62afb8910f84517f9c',
    'VerifyNativeRoleKeyConsumption': 'fbcaaa5e541b17286348e1bfce9a3785db64e59d457b8476c8ff981d2d5c615e',
    'ReadShibbolethMetadataApplicationStoredOutcome': '126c3288a8a2197ce4ba7aca99a315fe558b4c3af3984a13cd260b7e62b1ee20'
}
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
READ = lambda path: json.loads(pathlib.Path(path).read_bytes())

def require(value, message):
    if not value:
        raise ValueError(message)

def save(path, value):
    with pathlib.Path(path).open('x') as output:
        output.write(json.dumps(value, indent=2) + '\n')

def command(args, timeout=90):
    return subprocess.run(args, capture_output=True, check=True, timeout=timeout)

def safe_file(root, path):
    root = pathlib.Path(root).absolute()
    path = pathlib.Path(path).absolute()
    require(path.resolve().is_relative_to(root.resolve()) and path.is_file()
            and not any(p.is_symlink() for p in [path, *path.parents]), 'Unsafe original path')
    return path

def locate(root):
    p = pathlib.Path(root).absolute()
    require(not any(x.is_symlink() for x in [p, *p.parents]), 'Unsafe evidence root')
    p = p.resolve()
    return p if p.name == FOLDER else p / FOLDER

def api(path, body=None):
    request = urllib.request.Request('http://localhost:18080' + path,
        data=None if body is None else json.dumps(body).encode(),
        headers={} if body is None else {'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.load(response)

def rows(result):
    return {c['id']: c for r in result['requirements'] for c in r['cases']}

def stored_helpers():
    spec = importlib.util.spec_from_file_location('_shib_application_stored',
        pathlib.Path(__file__).with_name('keycloak_registered_signer_stored_outcome.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.HELPER = STORED
    return module

def native_digest(path):
    return command(['docker', 'exec', SUITE, 'sha256sum', path]).stdout.decode().split()[0]

def capture_runtime(folder):
    archive = folder / RUNTIME
    archive.mkdir()
    pins = {}
    for name in JARS:
        remote = '/opt/samlscope/lib/' + name + '-0.1.0.jar'
        before = native_digest(remote)
        command(['docker', 'cp', SUITE + ':' + remote, str(archive / (name + '.jar'))])
        require(before == SHA((archive / (name + '.jar')).read_bytes()) == native_digest(remote),
                'Runtime changed during immutable byte capture')
        pins[name] = before
    for helper in (*HELPERS, STORED):
        source = pathlib.Path(__file__).with_name(helper + '.java')
        shutil.copyfile(source, archive / source.name)
        pins[helper] = SHA(source.read_bytes())
    paths = [pathlib.Path(p) for p in pathlib.Path('/private/tmp/samlscope-runner-runtime-classpath.txt').read_text().strip().split(':')
             if pathlib.Path(p).name not in [n + '-0.1.0.jar' for n in ('core', 'saml', 'store', 'runner', 'api', 'peer')]]
    require(all(p.is_file() and not p.is_symlink() for p in paths), 'Dependency original unavailable')
    save(archive / 'dependency-pins.json', [dict(path=str(p), sha256=SHA(p.read_bytes())) for p in paths])
    save(archive / 'pins.json', pins)
    save(archive / 'archive-placement.json', dict(actualContainerCopy=True, mutableProjectHardlinks=False,
        beforeAfterRuntimeHashesEqual=True, productSettings=0, saml=0, credentials=0))
    return pins

def classpath(folder):
    archive = folder / RUNTIME
    pins = READ(archive / 'pins.json')
    require(PINS is not None and pins == PINS, 'Actual runtime pins not finalized')
    for name in JARS:
        require(SHA(safe_file(archive, archive / (name + '.jar')).read_bytes()) == pins[name], 'Archived runtime changed')
    for helper in (*HELPERS, STORED):
        require(SHA(safe_file(archive, archive / (helper + '.java')).read_bytes()) == pins[helper], 'Archived helper changed')
    dependencies = READ(archive / 'dependency-pins.json')
    for item in dependencies:
        require(SHA(safe_file(pathlib.Path(item['path']).parent, item['path']).read_bytes()) == item['sha256'], 'Dependency changed')
    return ':'.join(str((archive / (n + '.jar')).resolve()) for n in JARS) + ':' + ':'.join(x['path'] for x in dependencies)

def replay(folder):
    cp = classpath(folder)
    with tempfile.TemporaryDirectory(prefix='shib-application-actual-') as name:
        temp = pathlib.Path(name)
        classes = temp / 'classes'
        command([JAVA + 'javac', '-sourcepath', '', '-cp', cp, '-d', str(classes),
                 *(str(folder / RUNTIME / (h + '.java')) for h in HELPERS)])
        require(all(any(p.name.startswith(h) for h in HELPERS) for p in classes.rglob('*.class')),
                'Detector helper shadows production classes')
        remote = '/tmp/' + temp.name
        try:
            command(['docker', 'exec', SUITE, 'mkdir', '-p', remote + '/runtime'])
            command(['docker', 'cp', str(folder), SUITE + ':' + remote + '/source'])
            command(['docker', 'cp', str(classes), SUITE + ':' + remote + '/classes'])
            for jar in JARS:
                command(['docker', 'cp', str(folder / RUNTIME / (jar + '.jar')), SUITE + ':' + remote + '/runtime/' + jar + '.jar'])
                require(native_digest(remote + '/runtime/' + jar + '.jar') == PINS[jar], 'Replay JAR placement differs')
            command(['docker', 'exec', '--user', '0:0', SUITE, 'chmod', '-R', 'a+rX', remote])
            remote_cp = ':'.join(remote + '/runtime/' + n + '.jar' for n in JARS) + ':' + remote + '/classes:/opt/samlscope/lib/*'
            command(['docker', 'exec', '--user', '0:0', SUITE, 'java', '-cp', remote_cp,
                'com.samlscope.runner.cases.' + HELPERS[0], remote + '/source', '/data', remote + '/report.json'])
            command(['docker', 'cp', SUITE + ':' + remote + '/report.json', str(temp / 'report.json')])
            return READ(temp / 'report.json')
        finally:
            command(['docker', 'exec', '--user', '0:0', SUITE, 'rm', '-rf', remote])

def cumulative_counts(folder):
    attempts = []
    total = dict(samlSubmissions=0, credentialPosts=0, productConfigurationWrites=0,
                 restorationWrites=0, productRestarts=0, nativeProviderReloads=0, personOperations=0)
    for index, sends in ((1, 1), (2, 5), (3, 18)):
        source = folder.parent / ('shibboleth-metadata-application-r' + str(index))
        counts, restore, ledger = (READ(source / n) for n in ('operation-counts.json', 'restoration.json', 'operations.json'))
        require(restore['restored'] is True and restore['failures'] == [] and restore['original'] == restore['final']
                and restore['backingFileRemoved'] is True, 'Attempt restoration incomplete')
        require(counts['productConfigurationWrites'] == sum(x['operation'] == 'product-config-write' for x in ledger)
                and counts['productRestarts'] == sum(x['operation'] == 'product-restart' for x in ledger), 'Attempt ledger differs')
        actual = counts['nativeBrowserPostAttempts'] + counts['nativeBrowserRedirectAttempts'] + counts['basicScopedTargetSubmissions']
        require(actual == sends and counts['personOperations'] == 0 and counts['allCredentialValuesPersisted'] is False,
                'Attempt protocol/credential costs inconsistent')
        require(READ(source / 'created.json')['run']['id'] == READ(folder / 'created.json')['run']['id'], 'Attempt Run changed')
        bindings = {str(p.relative_to(source)): SHA(p.read_bytes()) for p in source.rglob('*') if p.is_file()}
        attempts.append(dict(folder=source.name, newlySubmittedSaml=sends, reusedHistoricalSaml=3 if index == 3 else 0,
                             files=bindings, counts=counts))
        total['samlSubmissions'] += sends
        for key in total.keys() - {'samlSubmissions'}:
            total[key] += counts[key]
    expected = dict(samlSubmissions=24, credentialPosts=3, productConfigurationWrites=19,
                    restorationWrites=9, productRestarts=6, nativeProviderReloads=1, personOperations=0)
    require(total == expected, 'Cumulative costs differ from actual immutable attempts')
    diagnostics = []
    for name in ('shibboleth-metadata-application-selection-r1', 'shibboleth-metadata-application-selection-r2',
                 'shibboleth-metadata-application-selection-r3', 'shibboleth-metadata-application-calibration-r1'):
        source = folder.parent / name
        originals = {str(p.relative_to(source)): SHA(p.read_bytes()) for p in source.rglob('*') if p.is_file()}
        diagnostics.append(dict(folder=name, files=originals, productSettings=0, saml=0, credentials=0))
    return dict(schema='samlscope-metadata-application-cumulative-costs-v1', attempts=attempts, totals=total,
                selectorDiagnostics=diagnostics, readOnlyNativeCompilerCalls=4, readOnlyNativeJavaCalls=5,
                publicCauseExtractionCalls=3, reusedPriorRolloverNeverResent=True, costsAdvisory=True)

def bind_originals(folder):
    excluded = {RUNTIME, EVALUATION, 'acceptance-originals.json', 'cumulative-operation-counts.json',
                'receipt-installation.json', 'native-reader-replay.json'}
    bindings = {str(p.relative_to(folder)): SHA(p.read_bytes()) for p in folder.rglob('*')
                if p.is_file() and p.relative_to(folder).parts[0] not in excluded}
    save(folder / 'cumulative-operation-counts.json', cumulative_counts(folder))
    save(folder / 'acceptance-originals.json', dict(files=bindings, originalsUnchanged=True, calibrationInstalled=False))

def verify_originals(folder):
    binding = READ(folder / 'acceptance-originals.json')
    require(binding['originalsUnchanged'] is True and binding['calibrationInstalled'] is False, 'Original ownership differs')
    for name, digest in binding['files'].items():
        require(SHA(safe_file(folder, folder / name).read_bytes()) == digest, 'Immutable original changed')
    require(READ(folder / 'cumulative-operation-counts.json') == cumulative_counts(folder), 'Failed-attempt originals/costs changed')
    manifest = READ(folder / 'receipt/manifest.json')
    run = READ(folder / 'created.json')['run']['id']
    target = SHA((folder / 'target-metadata.xml').read_bytes())
    require(manifest['schema'] == 'samlscope-shibboleth-metadata-application-v1'
        and manifest['adapter'] == 'shibboleth-native-accepted-metadata-application-v1'
        and manifest['runId'] == run and manifest['targetMetadataSha256'] == target
        and 'calibration' not in manifest and all(not n.startswith('calibration/') for n in manifest['files']), 'Stock receipt scope differs')
    slot = READ(folder / 'actual-case-slot-preflight.json')
    require(slot['run']['id'] == run and slot['profile']['id'] == 'metadata-idp'
        and slot['target']['metadata_digest'] == 'sha256:' + target
        and all(rows(slot)[c]['mode'] == 'CONFIG' for c in CASES), 'Actual approved case slots missing')
    plan = READ(folder / 'plan.json')['plan']['plan']
    require(plan['profile'] == 'metadata_idp' and manifest['planId'] == plan['id']
            == READ(folder / 'created.json')['run']['planId'], 'Original Plan/Run changed')
    entries = READ(folder / 'transcript.json')
    require(len({e['id'] for e in entries}) == len(entries) and all(e['runId'] == run for e in entries), 'History foreign/duplicate')
    for e in entries:
        if e.get('decodedSamlRef'):
            require(e['decodedSamlRef'] == 'transcripts/' + run + '/' + e['id'] + '.saml.xml', 'Foreign decoded original')
    for name, digest in manifest['files'].items():
        require(SHA(safe_file(folder / 'receipt', folder / 'receipt' / name).read_bytes()) == digest, 'Receipt member changed')
    return manifest, run, target, entries

def capture_before(folder, run, entries):
    ev = folder / EVALUATION
    ev.mkdir()
    for case in CASES:
        stored_helpers().capture(folder, RUNTIME, EVALUATION + '/stored-before-' + case + '.json', run, case)
    save(ev / 'result-before.json', api('/api/runs/' + run + '/result.json'))
    save(ev / 'transcript-before.json', api('/api/runs/' + run + '/transcript'))
    require(READ(ev / 'transcript-before.json') == entries, 'History changed before placement')

def install(folder):
    manifest, run, target, entries = verify_originals(folder)
    base = '/data/shibboleth-metadata-application-evidence/' + run
    check = subprocess.run(['docker', 'exec', SUITE, 'test', '-e', base], capture_output=True, timeout=30)
    require(check.returncode == 1, 'Existing receipt ownership')
    capture_before(folder, run, entries)
    records = []
    # Stage only whitelisted public assets, then atomically expose the full directory.
    # Changes to permissions apply to these copies, never immutable host originals.
    with tempfile.TemporaryDirectory(prefix='shib-application-placement-') as name:
        temporary = pathlib.Path(name)
        stock = temporary / 'stock'
        stock.mkdir()
        for name in [*manifest['files'], 'manifest.json']:
            require(re.fullmatch(r'[A-Za-z0-9_./-]+', name) is not None, 'Unsafe public asset name')
            source = safe_file(folder / 'receipt', folder / 'receipt' / name)
            destination = stock / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            records.append(dict(file=name, path=base + '/' + name, sha256=SHA(source.read_bytes())))
        remote = '/data/.shib-application-placement-' + temporary.name
        try:
            command(['docker', 'exec', SUITE, 'mkdir', '-p', remote])
            command(['docker', 'cp', str(stock), SUITE + ':' + remote + '/stock'])
            command(['docker', 'exec', '--user', '0:0', SUITE, 'find', remote + '/stock', '-type', 'f', '-exec', 'chmod', '0644', '{}', '+'])
            command(['docker', 'exec', '--user', '0:0', SUITE, 'find', remote + '/stock', '-type', 'd', '-exec', 'chmod', '0755', '{}', '+'])
            actual = command(['docker', 'exec', SUITE, 'sha256sum', *(remote + '/stock/' + r['file'] for r in records)]).stdout.decode().splitlines()
            require(len(actual) == len(records) and all(line.split()[0] == row['sha256']
                    and line.split()[1] == remote + '/stock/' + row['file'] for line, row in zip(actual, records)),
                    'Suite-user public assets unreadable/different')
            command(['docker', 'exec', SUITE, 'mkdir', '-p', str(pathlib.PurePosixPath(base).parent)])
            require(subprocess.run(['docker', 'exec', SUITE, 'test', '-e', base], capture_output=True, timeout=30).returncode == 1,
                    'Receipt ownership changed during staging')
            command(['docker', 'exec', SUITE, 'mv', '-T', remote + '/stock', base])
        finally:
            command(['docker', 'exec', '--user', '0:0', SUITE, 'rm', '-rf', remote])
    save(folder / 'receipt-installation.json', dict(runId=run, files=records, readBackVerified=True,
        calibrationInstalled=False, publicFileMode='0644', publicDirectoryMode='0755', manifestPublishedLast=True,
        stockDirectoryPublishedAtomically=True,
        productSettings=0, saml=0, credentials=0, storedBeforePrecededResultGet=True))

def verify_completed_placement(folder):
    """Qualify exact existing copies after a failed move; never replace before originals."""
    manifest, run, target, entries = verify_originals(folder)
    ev = folder / EVALUATION
    require(all((ev / ('stored-before-' + c + '.json')).is_file() for c in CASES)
        and READ(ev / 'transcript-before.json') == entries and not (ev / 'evaluate.json').exists()
        and not (folder / 'receipt-installation.json').exists(), 'Placement recovery audit incomplete')
    failure = READ(folder / 'placement-failure-v213-r1.json')
    require(failure['runId'] == run and failure['exitCode'] == 1 and failure['formalPostPerformed'] is False
        and failure['atomicPublicationClaimed'] is False and failure['destinationFullReadbackEqual'] is True,
        'Unknown placement failure cannot be qualified')
    base = '/data/shibboleth-metadata-application-evidence/' + run
    names = [*manifest['files'], 'manifest.json']
    inventory = command(['docker', 'exec', SUITE, 'find', base, '-type', 'f']).stdout.decode().splitlines()
    links = command(['docker', 'exec', SUITE, 'find', base, '-type', 'l']).stdout.decode().splitlines()
    require(not links and set(inventory) == {base + '/' + n for n in names}, 'Foreign/partial placement assets')
    hashes = command(['docker', 'exec', SUITE, 'sha256sum', *(base + '/' + n for n in names)]).stdout.decode().splitlines()
    records = []
    require(len(hashes) == len(names), 'Incomplete placement readback')
    for name, line in zip(names, hashes):
        digest = SHA((folder / 'receipt' / name).read_bytes())
        require(line.split() == [digest, base + '/' + name], 'Placed bytes differ from public originals')
        records.append(dict(file=name, path=base + '/' + name, sha256=digest))
    save(folder / 'receipt-installation.json', dict(runId=run, files=records, readBackVerified=True,
        calibrationInstalled=False, publicFileMode='0644', publicDirectoryMode='0755',
        manifestPublishedLast=False, stockDirectoryPublishedAtomically=False,
        completedFailedPlacementQualified=True, failureOriginalSha256=SHA((folder / 'placement-failure-v213-r1.json').read_bytes()),
        productSettings=0, saml=0, credentials=0, storedBeforePrecededResultGet=True))

def formal(folder):
    manifest, run, target, entries = verify_originals(folder)
    ev = folder / EVALUATION
    require(all((ev / ('stored-before-' + c + '.json')).is_file() for c in CASES)
            and not (ev / 'evaluate.json').exists(), 'Formal before snapshots missing/already evaluated')
    readiness = api('/api/runs/' + run + '/protocol-evidence')
    save(ev / 'readiness.json', readiness)
    require(isinstance(readiness.get('cases'), list), 'Readiness unavailable: no evaluation POST')
    selected = {c['caseId']: c for c in readiness['cases'] if c.get('caseId') in CASES}
    current = api('/api/runs/' + run + '/result.json')
    save(ev / 'before-evaluate.json', current)
    require(current['run']['id'] == run and current['target']['metadata_digest'] == 'sha256:' + target,
            'Formal Run/target changed: no evaluation POST')
    require(all(selected[c]['ready'] is True if c in selected else rows(current)[c]['outcome'] == 'SATISFIED'
                for c in CASES), 'Native proof unready: no evaluation POST')
    save(ev / 'evaluate.json', api('/api/runs/' + run + '/protocol-evidence/evaluate', {}))
    save(ev / 'result.json', api('/api/runs/' + run + '/result.json'))
    save(ev / 'transcript.json', api('/api/runs/' + run + '/transcript'))
    for case in CASES:
        stored_helpers().capture(folder, RUNTIME, EVALUATION + '/stored-after-' + case + '.json', run, case)

def check_report(report, run, entries):
    require(report['runId'] == run and report['additionalProductOperations'] == 0
            and report['credentialsPersisted'] is False, 'Replay scope/secret invariant differs')
    controls = report['controls']
    require(len(controls['negativeControls']) == 35
        and all(c['outcome'] == 'NOT_VERIFIED' for c in controls['negativeControls'].values())
        and controls['allTranscriptEvidenceResolvesSameRun'] is True
        and controls['calibrationAssetsInstalled'] is False, 'Detection controls incomplete')
    ids = {e['id'] for e in entries}
    for case in CASES:
        outcome = report['outcomes'][case]
        require(outcome['outcome'] == 'SATISFIED' and outcome['details']['adapter'] == 'shibboleth-native-accepted-metadata-application-v1'
                and outcome['details']['run_id'] == run, 'Native stock outcome unproven')
        require(all(e['reference'] in ids for e in outcome['evidence'] if e['kind'] == 'transcript'), 'Unresolvable transcript evidence')
        life = report['wrapperLifecycle'][case]
        require(life['centralVerdict'] == 'PASS' and life['newOutboundActions'] == 0 and life['incompleteHistory'] == 'NOT_VERIFIED'
            and all(life[k] is True for k in ('start', 'ConfigConfirmed', 'statusReady', 'recordedNotVerified', 'conclusiveUnchanged')), 'Wrapper lifecycle differs')
    require(set(controls['approvedTriggerCalibrations']) == {'drop-accepted-b-secondary-acs', 'retain-conflicting-old-a-acs'}, 'Approved triggers missing')
    for value in controls['approvedTriggerCalibrations'].values():
        require(value['offlineOutcome']['outcome'] == 'VIOLATED' and value['publicOutcome']['outcome'] == 'NOT_VERIFIED'
            and value['centralVerdict'] == 'FAIL', 'Public/calibration detector boundary differs')

def compare_application_stored(folder, case, proof):
    """Retain the observed queued→native-missing→conclusive two-step history.

    A result GET completed the previously unobserved AB case before installation.
    Both that rendered NV and the subsequent complete native audit envelope are
    originals. This exception requires their exact known pending outcome; it
    does not permit arbitrary omitted revisions or conclusive replacements.
    """
    before_name = EVALUATION + '/stored-before-' + case + '.json'
    after_name = EVALUATION + '/stored-after-' + case + '.json'
    module = stored_helpers()
    before = module.verify(folder, RUNTIME, before_name, READ(folder / 'created.json')['run']['id'], case)
    after = module.verify(folder, RUNTIME, after_name, READ(folder / 'created.json')['run']['id'], case)
    if before['outcome'] is not None or after['revision'] == before['revision'] + 1:
        return module.compare_stored(folder, RUNTIME, case, proof, before_name=before_name, after_name=after_name)
    require(case == CASES[1] and before['status'] == 'WAITING_INBOUND' and before['outcome'] is None
        and before['verdict'] is None and before['revision'] == 1 and before['outboxCount'] == 1
        and after['status'] == 'FINISHED' and after['revision'] == 3 and after['outboxCount'] == 1,
        'Unobserved native history transition')
    outcome = dict(after['outcome'])
    details = dict(outcome['details'])
    previous = details.pop('previous_recorded_evidence_result', None)
    require(isinstance(previous, dict) and set(previous) == {'revision', 'updated_at', 'outcome',
        'not_verified_reason', 'reason_code', 'reason_message_key', 'evidence', 'details'}, 'Native pending envelope missing')
    expected = dict(revision=2, outcome='NOT_VERIFIED',
        not_verified_reason='native_metadata_supersession_originals_unavailable',
        reason_code='metadata.supersession.awaiting-native-receipt',
        reason_message_key='metadata.supersession.awaiting-native-receipt', evidence=[], details={})
    require({k: previous[k] for k in expected} == expected, 'Unexpected intermediate native outcome')
    require(module._instant_seconds(before['updatedAtIso']) < module._instant_seconds(previous['updated_at'])
        < module._instant_seconds(after['updatedAtIso']), 'Native causal history order differs')
    rendered = rows(READ(folder / EVALUATION / 'result-before.json'))[case]
    require((rendered['outcome'], rendered['verdict'], rendered['mode'], rendered['reason_code'],
        rendered['reason'], rendered['attested'], rendered['evidence_class'], rendered['evidence'])
        == ('NOT_VERIFIED', 'NOT_VERIFIED', 'CONFIG', expected['reason_code'], expected['reason_message_key'],
            False, 'OPERATOR_ASSISTED', []), 'Pre-placement missing-proof result differs')
    outcome['details'] = details
    require(outcome == proof, 'Stored native outcome differs from actual archived Reader')
    return after

def verify_adoption(root, live=False):
    folder = locate(root)
    manifest, run, target, entries = verify_originals(folder)
    report = replay(folder)
    require(report == READ(folder / REPLAY), 'Actual archived replay changed')
    check_report(report, run, entries)
    ev = folder / EVALUATION
    result = READ(ev / 'result.json')
    require(result['run']['id'] == run and result['profile']['id'] == 'metadata-idp'
        and result['target']['metadata_digest'] == 'sha256:' + target
        and READ(ev / 'transcript-before.json') == READ(ev / 'transcript.json') == entries, 'Formal Run/target/history changed')
    cases = rows(result)
    for case in CASES:
        stored = compare_application_stored(folder, case, report['outcomes'][case])
        row = cases[case]
        require((row['outcome'], row['verdict'], row['mode'], row['attested'], row['evidence_class'])
            == ('SATISFIED', 'PASS', 'CONFIG', False, 'OPERATOR_ASSISTED')
            and row['evidence'] == report['outcomes'][case]['evidence']
            and row['reason_code'] == report['outcomes'][case]['reasonCode'] and stored['verdict'] == 'PASS', 'Central result/provenance differs')
    placement = READ(folder / 'receipt-installation.json')
    require(placement['calibrationInstalled'] is False and placement['readBackVerified'] is True
        and placement['storedBeforePrecededResultGet'] is True
        and (placement.get('stockDirectoryPublishedAtomically') is True or placement.get('completedFailedPlacementQualified') is True)
        and {r['file'] for r in placement['files']} == {'manifest.json', *manifest['files']}, 'Stock placement differs')
    for row in placement['files']:
        require(SHA((folder / 'receipt' / row['file']).read_bytes()) == row['sha256'], 'Placed original changed')
    if placement.get('completedFailedPlacementQualified'):
        require(placement['failureOriginalSha256'] == SHA((folder / 'placement-failure-v213-r1.json').read_bytes()),
                'Failed placement original changed')
    outbox = READ(ev / 'outbox-state-after.json')
    require(outbox['runId'] == run and outbox['cases'][CASES[0]]['outboxStates'] == [{'status': 'SENT', 'count': 12}]
        and outbox['cases'][CASES[1]]['outboxStates'] == [{'status': 'PENDING', 'count': 1}], 'Owned outbox delivery scope differs')
    if live:
        current = json.loads(command(['docker', 'inspect', NATIVE]).stdout)
        require(len(current) == 1, 'Ambiguous native container')
        current = current[0]
        measured = READ(folder / 'receipt/selection-operations.json')['nativeContainerBefore']
        require(current['Id'] == measured['id'] and current['Image'] == measured['image']
            and current['Mounts'] == measured['mounts'] and current['State']['Running'] is True,
            'Live native identity/image/mount closure differs')
        require(api('/api/runs/' + run + '/transcript') == entries
            and all(rows(api('/api/runs/' + run + '/result.json'))[c] == cases[c] for c in CASES), 'Live outcome/history differs')
        for row in placement['files']:
            require(native_digest(row['path']) == row['sha256'], 'Live stock sidecar differs')
        restoration = READ(folder / 'receipt/restoration.json')
        paths = dict(providers='/opt/reference-idp/conf/metadata-providers.xml', audit='/opt/reference-idp/conf/audit.xml',
                     **{'public-metadata': '/opt/reference-idp/metadata/idp-metadata.xml'})
        for name, path in paths.items():
            require(SHA(command(['docker', 'exec', NATIVE, 'cat', path]).stdout) == restoration['original'][name], 'Native settings not restored')
        check = subprocess.run(['docker', 'exec', NATIVE, 'test', '-e', manifest['backingFile']], capture_output=True, timeout=30)
        require(check.returncode == 1, 'Application cache remains')
        for source in restoration['existingSources']:
            require(SHA(command(['docker', 'exec', NATIVE, 'cat', source['path']]).stdout) == source['sha256'], 'Existing provider source changed')
    return ev / 'result.json', {c: cases[c] for c in CASES}

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=pathlib.Path)
    for flag in ('capture-runtime', 'bind-originals', 'record-replay', 'install', 'verify-completed-placement', 'formal', 'live'):
        parser.add_argument('--' + flag, action='store_true')
    args = parser.parse_args()
    folder = locate(args.root)
    if args.capture_runtime:
        print(json.dumps(capture_runtime(folder), indent=2))
    if args.bind_originals:
        bind_originals(folder)
    if args.record_replay:
        report = replay(folder)
        check_report(report, READ(folder / 'created.json')['run']['id'], READ(folder / 'transcript.json'))
        save(folder / REPLAY, report)
    if args.install:
        install(folder)
    if args.verify_completed_placement:
        verify_completed_placement(folder)
    if args.formal:
        formal(folder)
    if not any((args.capture_runtime, args.bind_originals, args.record_replay, args.install, args.verify_completed_placement, args.formal)):
        print(verify_adoption(folder, args.live))
