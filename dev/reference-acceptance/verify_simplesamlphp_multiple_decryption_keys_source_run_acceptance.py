#!/usr/bin/env python3
"""Close one independent native CONFIG proof using a real, completed recipient Run.

The source stays incomplete. The recipient's existing normal SSO originals prove only
its identity; the separately captured native two-key campaign supplies the capability
oracle. This coordinator never logs in, changes product settings, or creates a case.
"""
import argparse, datetime, hashlib, json, pathlib, secrets, shutil, subprocess, tempfile, urllib.error, urllib.request

REPO = pathlib.Path(__file__).resolve().parents[2]
SUITE = 'samlscope-reference-suite'
HELPER = 'VerifySimpleSamlPhpMultipleDecryptionKeysSourceRun'
CASE = 'IIP-IDP19-b-idp-01'
DIGEST = 'sha256:f0804b19a640f8dc668635a12630d2ac5dbb50193f04bed346a0e4afcc2ab9a8'
SCOPE = 'independent-multiple-decryption-key-configuration'
SUFFIX = '.simplesamlphp-multiple-decryption-keys'
MODULES = ('runner', 'core', 'saml', 'store', 'api', 'peer')
JAVA = pathlib.Path('/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin')
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
READ = lambda path: json.loads(pathlib.Path(path).read_bytes())
_OPERATION_DIRECTORY = None
_OPERATIONS = []


def record_operation(kind, args, start, end, status, stdout, stderr, request=b''):
    if _OPERATION_DIRECTORY is None:
        return
    number = len(_OPERATIONS)
    (_OPERATION_DIRECTORY / (str(number) + '.stdout')).write_bytes(stdout)
    (_OPERATION_DIRECTORY / (str(number) + '.stderr')).write_bytes(stderr)
    _OPERATIONS.append(dict(kind=kind, command=list(map(str, args)), startedAt=start, finishedAt=end,
        exitCode=status if kind == 'process' else None, httpStatus=status if kind == 'suite-http' else None,
        stdoutSha256=SHA(stdout), stderrSha256=SHA(stderr), requestBytes=len(request), requestSha256=SHA(request)))
    (_OPERATION_DIRECTORY / 'operations.json').write_text(json.dumps(_OPERATIONS, indent=2) + '\n')


def require(value, why):
    if not value:
        raise ValueError(why)


def save(path, value):
    require(not path.exists(), 'Immutable output already exists: ' + str(path))
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def safe(path):
    path = pathlib.Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Acceptance original has symlinks')
    path = path.resolve()
    require(path.is_relative_to(REPO / 'build/acceptance') and path.exists(), 'Owned acceptance original required')
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Acceptance original has symlinks')
    require(subprocess.run(['git', 'check-ignore', '--quiet', str(path)], cwd=REPO, capture_output=True).returncode == 0,
            'Acceptance original must remain ignored')
    return path


def command(args, timeout=180):
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        result = subprocess.run(list(map(str, args)), capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as failure:
        record_operation('process', args, start, datetime.datetime.now(datetime.timezone.utc).isoformat(), None,
                         failure.stdout or b'', failure.stderr or b'Timeout; delivery/result unknown')
        raise
    record_operation('process', args, start, datetime.datetime.now(datetime.timezone.utc).isoformat(), result.returncode, result.stdout, result.stderr)
    require(result.returncode == 0, 'Read-only/receipt command failed: ' + result.stderr.decode(errors='replace')[-2000:])
    return result.stdout


def api(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request('http://localhost:18080' + path,
        data=data, headers={'Content-Type': 'application/json'})
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as failure:
        record_operation('suite-http', [request.get_method(), 'http://localhost:18080' + path], start,
                         datetime.datetime.now(datetime.timezone.utc).isoformat(), failure.code, failure.read(), b'', data or b'')
        raise
    except Exception as failure:
        record_operation('suite-http', [request.get_method(), 'http://localhost:18080' + path], start,
                         datetime.datetime.now(datetime.timezone.utc).isoformat(), None, b'', str(failure).encode(), data or b'')
        raise
    record_operation('suite-http', [request.get_method(), 'http://localhost:18080' + path], start,
                     datetime.datetime.now(datetime.timezone.utc).isoformat(), status, raw, b'', data or b'')
    return json.loads(raw)


def files(folder):
    safe(folder)
    result = {}
    for p in sorted(folder.rglob('*')):
        require(not p.is_symlink(), 'Original symlink')
        if p.is_file():
            require(p.stat().st_nlink == 1, 'Mutable hard-linked original')
            result[str(p.relative_to(folder))] = SHA(p.read_bytes())
    return result


def campaign(folder):
    folder = safe(folder)
    value = READ(folder / 'campaign.json')
    require(value['schema'] == 'samlscope-independent-config-adoption-v1' and value['caseId'] == CASE
            and value['caseDigest'] == DIGEST, 'Foreign adoption scope')
    source = safe(REPO / value['sourceReceipt'])
    binding = safe(REPO / value['bindingFolder'])
    require(source.name == value['sourceRunId'] + SUFFIX and binding.name == value['recipientRunId'], 'Foreign receipt paths')
    require(value['sourceRunId'] != value['recipientRunId'], 'Source was relabelled as recipient')
    sm, bm = READ(source / 'manifest.json'), READ(binding / 'manifest.json')
    require(sm['runId'] == value['sourceRunId'] and bm['sourceRunId'] == value['sourceRunId']
            and bm['runId'] == value['recipientRunId'] and bm['scope'] == SCOPE
            and bm['caseId'] == CASE and bm['caseDigest'] == DIGEST
            and bm['sourceTranscriptComplete'] is False and bm['recipientProtocolOperationsClaimed'] == 0,
            'Foreign or fabricated completion contract')
    for original, manifest in ((source, sm), (binding, bm)):
        expected = dict(manifest['files'], **{'manifest.json': SHA((original / 'manifest.json').read_bytes())})
        require(files(original) == expected, 'Receipt contains changed or unbound originals')
    require(SHA((source / 'manifest.json').read_bytes()) == bm['sourceManifestSha256'], 'Source epoch changed')
    return folder, value, source, binding


def verify_burden(folder):
    _, value, source, binding = campaign(folder)
    summary = READ(folder / 'operation-summary.json')
    require(summary['schema'] == 'samlscope-independent-config-burden-v1'
        and summary['sourceRunId'] == value['sourceRunId'] and summary['recipientRunId'] == value['recipientRunId'], 'Foreign burden accounting')
    originals = summary['originalCampaignCounts']
    for row in originals.values():
        original = safe(REPO / row['path'])
        require(SHA(original.read_bytes()) == row['sha256'] and READ(original) == row['counts'], 'Original campaign burden changed')
    src, dest = originals['source']['counts'], originals['recipient']['counts']
    require(src == READ(source / 'operation-counts.json') and src['restored'] and dest['restored']
        and src['nativeObservationInvocations'] == 2 and src['credentialPosts'] == src['samlProtocolOperations'] == 0
        and src['productConfigurationWriteAttempts'] == src['successfulHostWrites'] == 4 and src['restorationWrites'] == 2
        and dest['credentialPosts'] == 1 and dest['nativeConfigurationWrites'] == 4 and dest['restorationWrites'] == 2, 'Original native/recipient burden differs')
    source_ops = READ(source / 'operations.json')
    require(sum(op['label'] == 'native-restored' for op in source_ops) == 1 and src['dockerCommandsAttempted'] == len(source_ops), 'Source readback/command count differs')
    new = READ(binding / 'current-operations.json')
    public = READ(binding / 'current-time-source-operations.json')
    require(len(new) == 6 and len(public) == 3 and all(op['exitCode'] == 0 for op in new + public), 'Current capture burden differs')
    expected = dict(sourceConfiguredNativeObservations=2, sourceRestoredNativeReadbacks=1, newCurrentNativeReadbacks=1,
        newPublicTimeSourceReads=1, newTemporaryPublicHelperCreates=1, newTemporaryPublicHelperRemovals=1,
        newProductSettingsWrites=0, newLoginOperations=0, newSamlProtocolOperations=0, newHumanOperations=0,
        knownCumulativeCredentialPosts=1, knownCumulativeConfigurationWrites=8, knownCumulativeRestorationWrites=4)
    require(all(summary.get(key) == expected_value for key, expected_value in expected.items()), 'Cumulative burden was understated')
    total = failed = 0
    for row in summary['readOnlyPreparationAndCaptureLedgers']:
        original = safe(REPO / row['path'])
        require(SHA(original.read_bytes()) == row['sha256'], 'Preparation failure/capture ledger changed')
        ops = READ(original)
        require(len(ops) == row['commandAttempts'] and sum(op['exitCode'] != 0 for op in ops) == row['failedCommandAttempts'], 'Preparation counts differ')
        total += row['commandAttempts']; failed += row['failedCommandAttempts']
    require(total == summary['readOnlyCommandsAttempted'] and failed == summary['readOnlyFailedCommandAttempts']
        and summary['totalNetworkAttempts'] is None, 'Unknown retries were inferred or failed work omitted')
    return summary


def live_projects():
    raw = command(['docker', 'exec', SUITE, 'sha256sum', *['/opt/samlscope/lib/' + n + '-0.1.0.jar' for n in MODULES]])
    return {line.split()[1].rsplit('/', 1)[-1]: line.split()[0] for line in raw.decode().splitlines()}


def archive(folder, qualification, generation='reader-qualified'):
    folder, _, _, _ = campaign(folder)
    q = safe(qualification)
    runtime, overlay = READ(q / 'runtime-live-verification.json'), READ(q / 'isolated-test-overlay.json')
    require(runtime['healthStatus'] == 200 and runtime['projectJars'] == overlay['projectJars'] == live_projects(),
            'Actual six modules differ from qualified runtime')
    require(runtime['liveMatchesIndependentArchive'] and overlay['allArchiveLinkCountsOne'], 'No independent runtime archive')
    require(generation.startswith('reader-qualified') and '/' not in generation and '\\' not in generation and '..' not in generation, 'Unsafe qualified reader generation')
    selected = folder / generation
    selected.mkdir()
    # Reuse the existing independent qualification archive; no mutable Gradle output or hard link.
    projects = {n + '-0.1.0.jar': q / 'runtime-built' / (n + '-0.1.0.jar') for n in MODULES}
    dependencies = {name: q / 'isolated-compile/dependencies/runtime' / name for name in runtime['runtimeDependencySha256']}
    hashes = dict(runtime['projectJars'], **runtime['runtimeDependencySha256'])
    for name, path in dict(projects, **dependencies).items():
        require(path.is_file() and path.stat().st_nlink == 1 and SHA(path.read_bytes()) == hashes[name], 'Qualified archive changed: ' + name)
    helper = selected / (HELPER + '.java')
    shutil.copyfile(REPO / 'dev/reference-acceptance' / helper.name, helper)
    cp = ':'.join(str(path) for path in (*projects.values(), *dependencies.values()))
    command([JAVA / 'javac', '-sourcepath', '', '-cp', cp, '-d', selected / 'classes', helper])
    classes = files(selected / 'classes')
    require(classes and all(path.rsplit('/', 1)[-1].startswith(HELPER) for path in classes), 'Verifier shadows production classes')
    save(selected / 'pins.json', dict(qualification=str(q.relative_to(REPO)),
        qualificationSha256={name: SHA((q / name).read_bytes()) for name in ('runtime-live-verification.json', 'isolated-test-overlay.json')},
        projectPaths={name: str(path.relative_to(REPO)) for name, path in projects.items()},
        dependencyPaths={name: str(path.relative_to(REPO)) for name, path in dependencies.items()},
        archiveSha256=hashes, helperSha256=SHA(helper.read_bytes()), classes=classes))
    pointer=folder / 'active-reader.json'
    if pointer.exists():
        previous=READ(pointer)
        pointer.rename(folder / ('previous-reader-' + previous['directory'] + '-' + previous['pinsSha256'][:12] + '.json'))
    save(pointer, dict(directory=generation, pinsSha256=SHA((selected / 'pins.json').read_bytes())))
    return selected


def reader(folder):
    pointer = READ(folder / 'active-reader.json')
    require(pointer['directory'].startswith('reader-qualified') and '/' not in pointer['directory'] and '..' not in pointer['directory'], 'Foreign archive selection')
    selected = safe(folder / pointer['directory'])
    require(SHA((selected / 'pins.json').read_bytes()) == pointer['pinsSha256'], 'Archive pins changed')
    pins = READ(selected / 'pins.json')
    paths = dict(pins['projectPaths'], **pins['dependencyPaths'])
    for name, path in paths.items():
        p = safe(REPO / path)
        require(p.is_file() and p.stat().st_nlink == 1 and SHA(p.read_bytes()) == pins['archiveSha256'][name], 'Independent archive changed')
    q = safe(REPO / pins['qualification'])
    for name, digest in pins['qualificationSha256'].items():
        require(SHA((q / name).read_bytes()) == digest, 'Runtime qualification changed')
    require(SHA((selected / (HELPER + '.java')).read_bytes()) == pins['helperSha256'] and files(selected / 'classes') == pins['classes'], 'Verifier changed')
    return selected, pins


def remote(folder, mode, output):
    folder, value, source, binding = campaign(folder)
    selected, pins = reader(folder)
    require(not pathlib.Path(output).exists(), 'Immutable verifier output already exists')
    def dependency_readback():
        raw = command(['docker', 'exec', SUITE, 'sha256sum', *['/opt/samlscope/lib/' + name for name in pins['dependencyPaths']]])
        return {line.split()[1].rsplit('/', 1)[-1]: line.split()[0] for line in raw.decode().splitlines()}
    expected_dependencies = {name: pins['archiveSha256'][name] for name in pins['dependencyPaths']}
    require(dependency_readback() == expected_dependencies, 'Actual process dependency classpath differs')
    temporary = '/tmp/ssp-config-source-reader-' + secrets.token_hex(12)
    command(['docker', 'exec', SUITE, 'mkdir', '-p', temporary + '/sources', temporary + '/bindings'])
    try:
        for name, path in pins['projectPaths'].items():
            command(['docker', 'cp', REPO / path, SUITE + ':' + temporary + '/' + name])
        command(['docker', 'cp', selected / 'classes', SUITE + ':' + temporary + '/classes'])
        command(['docker', 'cp', source, SUITE + ':' + temporary + '/sources/' + source.name])
        command(['docker', 'cp', binding, SUITE + ':' + temporary + '/bindings/' + binding.name])
        command(['docker', 'exec', '--user', '0', SUITE, 'chmod', '-R', 'a+rwX', temporary])
        if mode in ('state', 'transition', 'installed'):
            require(live_projects() == {name: pins['archiveSha256'][name] for name in pins['projectPaths']}, 'Actual six modules differ before state/registry read')
            cp = '/opt/samlscope/lib/*:' + temporary + '/classes'
        else:
            cp = ':'.join(temporary + '/' + n + '-0.1.0.jar' for n in MODULES) + ':' + temporary + '/classes:' + ':'.join('/opt/samlscope/lib/' + n for n in pins['dependencyPaths'])
        command(['docker', 'exec', SUITE, 'java', '-Xmx512m', '-cp', cp, 'com.samlscope.runner.cases.' + HELPER,
            mode, '/data', value['recipientRunId'], value['sourceRunId'], temporary + '/sources/' + source.name,
            temporary + '/bindings/' + binding.name, temporary + '/output.json'], 300)
        command(['docker', 'cp', SUITE + ':' + temporary + '/output.json', output])
        require(dependency_readback() == expected_dependencies, 'Actual process dependencies changed during replay')
        value = READ(output)
        if mode in ('state', 'transition', 'installed'):
            origins = value['actualModuleCodeSources']
            require(set(origins) == set(MODULES) and all(origins[n]['path'] == '/opt/samlscope/lib/' + n + '-0.1.0.jar'
                and origins[n]['sha256'] == pins['archiveSha256'][n + '-0.1.0.jar'] for n in MODULES), 'Actual class CodeSources differ')
        return value
    finally:
        command(['docker', 'exec', '--user', '0', SUITE, 'rm', '-rf', '--', temporary])


def installed_readback(folder):
    _, value, source, binding = campaign(folder)
    destinations = {'source': '/data/native-configuration-source-evidence/' + source.name,
                    'binding': '/data/native-configuration-source-bindings/' + binding.name}
    rows = {}
    for name, original in (('source', source), ('binding', binding)):
        path = destinations[name]
        require(not command(['docker', 'exec', SUITE, 'find', path, '-type', 'l']), 'Installed receipt symlink')
        require(not command(['docker', 'exec', SUITE, 'find', path, '-type', 'f', '!', '-perm', '0644']), 'Installed public file mode differs')
        raw = command(['docker', 'exec', SUITE, 'sh', '-c', 'cd "$1" && find . -type f -exec sha256sum {} +', 'receipt-readback', path])
        actual = {}
        for line in raw.decode().splitlines():
            digest, key = line.split('  ', 1)
            require(key.startswith('./') and key[2:] not in actual, 'Ambiguous installed original')
            actual[key[2:]] = digest
        require(actual == files(original), 'Installed original bytes differ')
        rows[name] = dict(path=path, files=actual)
    return rows


def replay_ok(report):
    result = report['fullProductionReaderPositive']
    require(result['outcome'] == 'SATISFIED' and result['reasonCode'] == 'configuration.multiple-decryption-keys.source-run-native-proven'
        and report['productionWrapperVerified'] and report['allControlsRejected']
        and len(report['controls']) == 48 and set(report['controls'].values()) == {'NOT_VERIFIED'}
        and report['sourceContextTranscriptComplete'] is False and report['sourceCaseExecutionCreated'] is False
        and report['targetOperations'] == 0, 'Full native/source/current/witness replay did not qualify')
    return result


def identical_capture(folder, mode, output):
    if not output.exists():
        return remote(folder, mode, output)
    with tempfile.TemporaryDirectory(prefix='ssp-config-source-retry-') as temporary:
        actual = remote(folder, mode, pathlib.Path(temporary) / 'current.json')
    require(actual == READ(output), 'Earlier immutable preflight differs; refusing retry')
    return actual


def install(folder):
    folder, value, source, binding = campaign(folder)
    verify_burden(folder)
    _, pins = reader(folder)
    require(live_projects() == {name: pins['archiveSha256'][name] for name in pins['projectPaths']}, 'Actual Suite differs from qualification')
    replay_ok(identical_capture(folder, 'replay', folder / 'qualified-reader-replay.json'))
    identical_capture(folder, 'state', folder / 'state-before.json')
    actual_result = api('/api/runs/' + value['recipientRunId'] + '/result.json')
    if (folder / 'result-before.json').exists():
        require(actual_result == READ(folder / 'result-before.json'), 'Earlier immutable result differs before installation')
    else:
        save(folder / 'result-before.json', actual_result)
    for label, original, base in (('source', source, '/data/native-configuration-source-evidence'), ('binding', binding, '/data/native-configuration-source-bindings')):
        destination = base + '/' + original.name
        stage = base + '/.stage-' + secrets.token_hex(12)
        for p in (destination, stage):
            require(subprocess.run(['docker', 'exec', SUITE, 'test', '-e', p], capture_output=True).returncode == 1,
                    'Refusing installed original overwrite')
            require(subprocess.run(['docker', 'exec', SUITE, 'test', '-L', p], capture_output=True).returncode == 1,
                    'Refusing installed symlink overwrite')
        with tempfile.TemporaryDirectory(prefix='ssp-config-source-placement-') as temporary:
            copy = pathlib.Path(temporary) / original.name
            shutil.copytree(original, copy)
            for p in (copy, *copy.rglob('*')):
                p.chmod(0o755 if p.is_dir() else 0o644)
            command(['docker', 'exec', '--user', '0', SUITE, 'mkdir', '-p', base])
            command(['docker', 'cp', copy, SUITE + ':' + stage])
            command(['docker', 'exec', '--user', '0', SUITE, 'mv', '-T', stage, destination])
    save(folder / 'installed.json', installed_readback(folder))
    remote(folder, 'installed', folder / 'actual-registry-before-formal.json')


def transition_ok(folder, report):
    baseline = replay_ok(report)
    before, after, transition = (READ(folder / name) for name in ('state-before.json', 'state-final.json', 'state-transition.json'))
    actual_transition = dict(transition)
    for name in ('stateAuditEqualsOutcomeAudit', 'stateWithoutPriorAuditSha256', 'priorResultAudit', 'transitionKind'):
        actual_transition.pop(name)
    require(actual_transition == after, 'Transition audit belongs to another stored snapshot')
    require(before['fence'] == after['fence'] and before['sourceExecutions'] == after['sourceExecutions'] == {}, 'Source/history/outbox/metadata changed')
    require({k: v for k, v in before['executions'].items() if k != CASE} == {k: v for k, v in after['executions'].items() if k != CASE}, 'Another case changed, including IDP19.a/c')
    old, new = before['caseExecution'], after['caseExecution']
    first = old['status'] == 'WAITING_CONFIG' and old['outcome'] is None
    require((first or old['status'] == 'FINISHED' and old['outcome'] is not None and old['outcome']['outcome'] == 'NOT_VERIFIED')
        and new['outcome']['outcome'] == 'SATISFIED'
        and new['caseId'] == old['caseId'] == CASE and new['runId'] == old['runId'] == after['recipientRunId']
        and new['status'] == 'FINISHED' and new['revision'] == old['revision'] + 1 and after['verdict'] == 'PASS', 'Wrong formal case transition')
    require(transition['stateWithoutPriorAuditSha256'] == before['caseStateSha256']
        and after['caseDocumentSha256'] == after['executions'][CASE], 'Central state changed beyond supported finish/audit')
    if first:
        require(old['state']['phase'] == 'await-configuration' and old['waitCondition']['kind'] == 'CONFIG'
            and new['state'] == old['state'] and new['waitCondition'] is None
            and transition['transitionKind'] == 'configuration-first-outcome' and not transition['stateAuditEqualsOutcomeAudit']
            and transition['priorResultAudit'] is None and 'previous_recorded_evidence_result' not in new['outcome']['details']
            and new['outcome'] == baseline, 'First actual configuration finish changed state or fabricated a prior audit')
        return after
    require(transition['transitionKind'] == 'recorded-evidence-reevaluation' and transition['stateAuditEqualsOutcomeAudit']
        and before['caseWaitSha256'] == after['caseWaitSha256'], 'Recorded reevaluation wait/audit differs')
    outcome = dict(new['outcome']); details = dict(outcome['details']); prior = details.pop('previous_recorded_evidence_result'); outcome['details'] = details
    require(outcome == baseline and prior == transition['priorResultAudit']
        and prior['revision'] == old['revision'] and prior['updated_at'] == before['caseUpdatedAt'], 'Stored outcome/prior audit differs')
    for key, field in (('outcome', 'outcome'), ('not_verified_reason', 'notVerifiedReason'), ('reason_code', 'reasonCode'),
                       ('reason_message_key', 'reasonMessageKey'), ('evidence', 'evidence'), ('details', 'details')):
        require(prior.get(key) == old['outcome'].get(field), 'Prior result audit changed')
    return after


def formal(folder):
    folder, value, _, _ = campaign(folder)
    require((folder / 'installed.json').is_file(), 'Qualified originals must be installed first')
    verify_burden(folder)
    _, pins = reader(folder)
    require(live_projects() == {name: pins['archiveSha256'][name] for name in pins['projectPaths']}, 'Runtime changed before formal reevaluation')
    require(installed_readback(folder) == READ(folder / 'installed.json'), 'Installed originals changed before formal reevaluation')
    with tempfile.TemporaryDirectory(prefix='ssp-config-source-formal-preflight-') as temporary:
        temp = pathlib.Path(temporary)
        current = remote(folder, 'state', temp / 'state.json')
        require(current == READ(folder / 'state-before.json') and current['caseExecution']['status'] == 'FINISHED'
                and current['caseExecution']['outcome']['outcome'] == 'NOT_VERIFIED', 'Recipient/source changed before formal reevaluation')
        registered = remote(folder, 'installed', temp / 'registry.json')
        require(registered == READ(folder / 'actual-registry-before-formal.json'), 'Actual registry changed before formal reevaluation')
        replay_ok(remote(folder, 'replay', temp / 'replay.json'))
    save(folder / 'evaluate.json', api('/api/runs/' + value['recipientRunId'] + '/protocol-evidence/evaluate', {}))
    save(folder / 'result-final.json', api('/api/runs/' + value['recipientRunId'] + '/result.json'))
    remote(folder, 'state', folder / 'state-final.json')
    close(folder)


def recover_automatic_completion(folder):
    folder, value, _, _ = campaign(folder)
    _,pins=reader(folder)
    require(live_projects()=={name:pins['archiveSha256'][name] for name in pins['projectPaths']}
            and installed_readback(folder)==READ(folder/'installed.json'),'Actual qualified runtime/originals changed before recovery')
    verify_burden(folder)
    trigger=folder/'actual-api-readiness-before.json'
    require(trigger.is_file(),'Original API GET trigger response missing')
    before=READ(folder/'state-before.json')
    require(before['caseExecution']['status']=='WAITING_CONFIG' and before['caseExecution']['outcome'] is None
            and before['caseExecution']['waitCondition']['kind']=='CONFIG','Automatic recovery requires exact preserved configuration wait')
    observation_path=folder/'automatic-completion-observation.json';observation=READ(observation_path)
    require(observation['formalPostAttempts']==0 and observation['preUpdateStateOriginal']=='state-before.json'
            and observation['readinessObservationOriginal']==trigger.name
            and observation['readback']['bodySha256']==SHA((folder/'result-after-automatic-readiness.json').read_bytes()),'Actual automatic completion observation differs')
    save(folder/'automatic-completion.json',dict(originalObservationSha256=SHA(observation_path.read_bytes()),
            readinessResponseSha256=SHA(trigger.read_bytes()),exactTriggerGetOrdinal=observation['exactTriggerGetOrdinal'],
            recoveryGetPurpose='Current result readback and sealing; not the original completion trigger',
            normalRoute='M1Runtime.protocolEvidenceStatus -> reconcileTranscriptEvidenceNow -> evaluateReady -> resume(ConfigConfirmed)',
            formalPostDelivered=False,sourceRunRelabelled=False,sourceCaseCreated=False,newProtocolOperations=0,newLoginOperations=0))
    save(folder/'result-final.json',api('/api/runs/'+value['recipientRunId']+'/result.json'))
    remote(folder,'state',folder/'state-final.json')
    close(folder)


def close(folder):
    folder, _, source, binding = campaign(folder)
    require((folder / 'result-final.json').is_file(), 'Actual formal result missing')
    verify_burden(folder)
    report = remote(folder, 'replay', folder / 'closed-reader-replay.json')
    remote(folder, 'transition', folder / 'state-transition.json')
    transition_ok(folder, report)
    require(installed_readback(folder) == READ(folder / 'installed.json'), 'Installed originals changed')
    remote(folder, 'installed', folder / 'actual-registry-final.json')
    selected, pins = reader(folder)
    expected = {name: pins['archiveSha256'][name] for name in pins['projectPaths']}
    require(live_projects() == expected, 'Formal runtime changed')
    originals = {str(p.relative_to(REPO)): SHA(p.read_bytes()) for original in (source, binding, folder)
                 for p in original.rglob('*') if p.is_file()}
    # Qualification archives are already independent and shared across this explicit deployment.
    originals.update({path: pins['archiveSha256'][name] for name, path in dict(pins['projectPaths'], **pins['dependencyPaths']).items()})
    summary = READ(folder / 'operation-summary.json')
    originals.update({row['path']: row['sha256'] for row in summary['originalCampaignCounts'].values()})
    originals.update({row['path']: row['sha256'] for row in summary['readOnlyPreparationAndCaptureLedgers']})
    save(folder / 'acceptance-originals.json', originals)


def verify_adoption(folder, live=False):
    global _OPERATION_DIRECTORY, _OPERATIONS
    if _OPERATION_DIRECTORY is None:
        _OPERATION_DIRECTORY = pathlib.Path(folder) / 'operation-attempts' / ('library-verify-' + secrets.token_hex(8))
        _OPERATION_DIRECTORY.mkdir(parents=True)
        _OPERATIONS = []
    folder, value, source, binding = campaign(pathlib.Path(folder))
    for path, digest in READ(folder / 'acceptance-originals.json').items():
        original = safe(REPO / path)
        require(original.is_file() and SHA(original.read_bytes()) == digest, 'Sealed acceptance original changed')
    selected, pins = reader(folder)
    verify_burden(folder)
    with tempfile.TemporaryDirectory(prefix='ssp-config-source-final-replay-') as temporary:
        temp = pathlib.Path(temporary)
        observed = remote(folder, 'replay', temp / 'replay.json')
        state = remote(folder, 'state', temp / 'state.json')
        require(observed == READ(folder / 'closed-reader-replay.json') and state == READ(folder / 'state-final.json'), 'Fresh reader/state differs')
        cp = ':'.join(str(REPO / p) for p in pins['projectPaths'].values()) + ':' + str(selected / 'classes') + ':' + ':'.join(str(REPO / p) for p in pins['dependencyPaths'].values())
        command([JAVA / 'java', '-cp', cp, 'com.samlscope.runner.cases.' + HELPER, 'offline', folder / 'state-final.json', temp / 'central.json'])
        require(READ(temp / 'central.json') == state, 'Archived central Evaluator differs')
    after = transition_ok(folder, observed)
    result = READ(folder / 'result-final.json')
    matches = [case for requirement in result['requirements'] for case in requirement.get('cases', []) if case['id'] == CASE]
    require(result['run']['id'] == value['recipientRunId'] and len(matches) == 1
        and result['target']['metadata_digest'] == 'sha256:' + READ(binding / 'manifest.json')['recipientTargetMetadataSha256'], 'Foreign formal result')
    chosen = matches[0]
    require(chosen['mode'] == 'CONFIG' and chosen['outcome'] == 'SATISFIED' and chosen['verdict'] == 'PASS' and chosen['attested'] is False
        and chosen['evidence'] == after['caseExecution']['outcome']['evidence']
        and chosen['reason_code'] == after['caseExecution']['outcome']['reasonCode'], 'Formal native result differs')
    require(READ(folder / 'actual-registry-final.json')['actualRegistryClass'] == 'com.samlscope.runner.cases.NativeConfigurationSourceRunTestCase', 'Actual registry not qualified')
    if live:
        require(installed_readback(folder) == READ(folder / 'installed.json') and live_projects() == {name: pins['archiveSha256'][name] for name in pins['projectPaths']}, 'Live receipt/runtime changed')
    return folder / 'result-final.json', {CASE: chosen}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=pathlib.Path)
    parser.add_argument('--mode', choices=['archive', 'install', 'formal', 'recover', 'close', 'verify'], required=True)
    parser.add_argument('--qualification', type=pathlib.Path)
    parser.add_argument('--reader-generation', default='reader-qualified')
    args = parser.parse_args()
    folder = args.folder.resolve()
    _OPERATION_DIRECTORY = folder / 'operation-attempts' / (args.mode + '-' + secrets.token_hex(8))
    _OPERATION_DIRECTORY.mkdir(parents=True)
    if args.mode == 'archive':
        require(args.qualification is not None, 'Qualified runtime required')
        print(archive(folder, args.qualification.resolve(),args.reader_generation))
    elif args.mode == 'install':
        install(folder); print('Qualified original source/binding receipts installed and read back')
    elif args.mode == 'formal':
        formal(folder); print('One real b case reevaluated and sealed')
    elif args.mode == 'recover':
        recover_automatic_completion(folder); print('Actual automatic GET-triggered configuration finish sealed; no formal POST sent')
    elif args.mode == 'close':
        close(folder); print('Actual formal native CONFIG adoption sealed')
    else:
        print(verify_adoption(folder)[0])
