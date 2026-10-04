"""Typed closure of a fresh actual-JAR whole-case replay; this module issues no verdicts.

The caller must execute the archived helper and compare its entire fresh output with the
saved replay before constructing this proof. Native cause/attempt semantics belong to
the same production reader used by that helper, not to labels interpreted here.
"""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import zipfile
from datetime import datetime, timezone
import math

CASE = 'IIP-IDP17-r-idp-01'
VARIANT = 'IIP-IDP17.r#v-2cdca3181d'
MUTANT = 'mut-iip-idp17-r-idp'
RUN = re.compile(r'run_[0-9A-HJKMNP-TV-Z]{26}')
SHA256 = re.compile(r'[a-f0-9]{64}')
PRODUCTION_CLASSES = {
    'com.samlscope.runner.cases.ShibbolethNativeSloContinuationEvidence': 'runner',
    'com.samlscope.runner.cases.SoapSloPropagationTestCase': 'runner',
    'com.samlscope.runner.cases.LogoutBrowserEvidenceTestCase': 'runner',
    'com.samlscope.runner.cases.SloContinuationProof': 'runner',
    'com.samlscope.runner.cases.SloContinuationActorEvidence': 'runner',
    'com.samlscope.core.evaluation.CaseOutcome': 'core',
    'com.samlscope.saml.normal.SecureXml': 'saml',
    'com.samlscope.store.JsonCodec': 'store',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def public_bytes(path, allow_empty=False):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'Symbolic proof original')
    require(path.is_file() and (0 if allow_empty else 1) <= path.stat().st_size <= 64 * 1024 * 1024,
            'Missing or oversized proof original')
    return path.read_bytes()


def public_relative(root, name):
    require(isinstance(name, str) and name and '\\' not in name, 'Invalid original reference')
    relative = Path(name)
    require(not relative.is_absolute() and all(p not in ('', '.', '..') for p in name.split('/')),
            'Original reference escapes proof directory')
    return Path(root) / relative


@dataclass(frozen=True)
class Original:
    file: str
    sha256: str

    @classmethod
    def parse(cls, value):
        require(isinstance(value, dict) and set(value) == {'file', 'sha256'}, 'Invalid original descriptor')
        require(isinstance(value['sha256'], str) and SHA256.fullmatch(value['sha256']), 'Invalid original digest')
        public_relative(Path('.'), value['file'])
        return cls(value['file'], value['sha256'])

    def read(self, root, allow_empty=False):
        raw = public_bytes(public_relative(root, self.file), allow_empty)
        require(digest(raw) == self.sha256, 'Control original changed')
        return raw


@dataclass(frozen=True)
class WholeCaseResult:
    outcome: str
    evidence: tuple

    @classmethod
    def parse(cls, value, expected):
        require(isinstance(value, dict) and value.get('outcome') == expected,
                'Whole-case conclusion is incomplete or differs')
        require(isinstance(value.get('reasonCode'), str) and value['reasonCode'], 'Case reason is missing')
        refs = value.get('evidence')
        require(isinstance(refs, list) and refs, 'Whole-case evidence references are missing')
        result = []
        for ref in refs:
            require(isinstance(ref, dict) and set(ref) == {'kind', 'reference'}
                    and all(isinstance(v, str) and v for v in ref.values()), 'Malformed case evidence reference')
            result.append((ref['kind'], ref['reference']))
        require(len(set(result)) == len(result), 'Duplicate whole-case evidence reference')
        return cls(expected, tuple(result))


def class_bindings(archive, pins):
    expected = {}
    for name, jar in PRODUCTION_CLASSES.items():
        path = Path(archive) / (jar + '.jar')
        raw = public_bytes(path)
        require(pins.get(jar) == digest(raw) and path.stat().st_nlink == 1,
                'Production code archive is changed or shares mutable bytes')
        with zipfile.ZipFile(path) as source:
            member = name.replace('.', '/') + '.class'
            require(source.namelist().count(member) == 1, 'Ambiguous production class original')
            expected[name] = {'jar': path.name, 'jarSha256': digest(raw),
                              'classSha256': digest(source.read(member))}
    return expected


@dataclass(frozen=True)
class FullCaseAdoptionProof:
    run_id: str
    target_metadata_sha256: str
    positive: WholeCaseResult
    negative: WholeCaseResult
    control_manifest: Original

    @classmethod
    def validate(cls, *, fresh_report, saved_report, archive, pins, positive_manifest,
                 positive_root, calibration_root):
        """Validate only after an actual fresh helper execution, never a receipt-only report."""
        require(fresh_report == saved_report, 'Fresh full archived replay differs from its immutable report')
        require(isinstance(fresh_report, dict) and fresh_report.get('schema') == 'samlscope-soap-continuation-replay-v2',
                'Full-case replay schema is unavailable')
        run = fresh_report.get('runId')
        require(isinstance(run, str) and RUN.fullmatch(run) and run == positive_manifest.get('runId'),
                'Positive replay belongs to another Run')
        require(fresh_report.get('caseId') == CASE, 'Replay owns another case')
        require(fresh_report.get('readOnly') is True and fresh_report.get('outboundActions') == 0
                and type(fresh_report.get('outboundActions')) is int
                and fresh_report.get('privateKeyExported') is False
                and fresh_report.get('fullWrapperLifecycleChecked') is True,
                'Replay changed the operation or wrapper boundary')
        target = positive_manifest.get('targetMetadataSha256')
        require(isinstance(target, str) and SHA256.fullmatch(target), 'Fixed target original is missing')
        require(fresh_report.get('targetMetadataSha256') == target, 'Replay changed its fixed target')
        require(digest(public_bytes(Path(positive_root) / 'target-metadata.xml')) == target,
                'Positive target metadata changed')
        positive_original = Original.parse(fresh_report.get('positiveManifestOriginal'))
        require(json.loads(positive_original.read(positive_root)) == positive_manifest,
                'Positive manifest is not the actual replay original')
        positive_files = positive_manifest.get('files')
        require(isinstance(positive_files, dict) and positive_files, 'Positive public originals are missing')
        for name, sha in positive_files.items():
            Original.parse({'file': name, 'sha256': sha}).read(positive_root, allow_empty=True)
        stock_native_manifest(positive_manifest)
        positive = WholeCaseResult.parse(fresh_report.get('outcome'), 'SATISFIED')
        bindings = class_bindings(archive, pins)
        require(fresh_report.get('classBindings') == bindings, 'Whole-case classes or CodeSources differ')
        control = fresh_report.get('approvedNegativeControl')
        require(isinstance(control, dict) and control.get('schema') == 'samlscope-soap-continuation-approved-control-v1',
                'Approved full-case negative proof is unavailable')
        control_run = control.get('runId')
        require(isinstance(control_run, str) and RUN.fullmatch(control_run)
                and control.get('caseId') == CASE and control.get('approvedVariantId') == VARIANT
                and control.get('mutantId') == MUTANT, 'Calibration owns another case, Run, or approved variant')
        # This association grants no cross-Run protocol borrowing. The isolated target
        # retains its own Run/metadata/TX; none of its refs enter the adopted CaseOutcome.
        require(control.get('nativeAssociation') == {'runId': run, 'targetMetadataSha256': target,
                'manifestSha256': positive_original.sha256}, 'Calibration association changed')
        require(control.get('counterfactualCalibrationOnly') is True and control.get('controlsAdopted') is False
                and control.get('fullWrapperLifecycleChecked') is True
                and control.get('sameProductionPredicate') is True,
                'Control bypasses the common whole-case or adoption boundary')
        require(control.get('classBindings') == bindings, 'Control uses a different production reader or wrapper')
        negative = WholeCaseResult.parse(control.get('outcome'), 'VIOLATED')
        original, mutant_manifest, mutant_root = actor_manifest(control, calibration_root, bindings, 'StopAfterErrorActor')
        baseline = control.get('normalControl')
        require(isinstance(baseline, dict), 'Paired continuing actor proof is missing')
        WholeCaseResult.parse(baseline.get('outcome'), 'SATISFIED')
        require(baseline.get('classBindings') == bindings and baseline.get('fullWrapperLifecycleChecked') is True
                and baseline.get('sameProductionPredicate') is True, 'Paired control changed its whole-case predicate')
        _, baseline_manifest, baseline_root = actor_manifest(baseline, calibration_root, bindings, 'ContinuingActor')
        require(baseline_manifest['runId'] == control_run == mutant_manifest['runId']
                and baseline_manifest['targetMetadataSha256'] == mutant_manifest['targetMetadataSha256'],
                'Paired actor Run or target differs')
        for trial in ('failure', 'all-success'):
            normal = next(row for row in baseline_manifest['trials'] if row['trial'] == trial)
            mutant = next(row for row in mutant_manifest['trials'] if row['trial'] == trial)
            require(public_bytes(public_relative(baseline_root, normal['operationInputFile']))
                    == public_bytes(public_relative(mutant_root, mutant['operationInputFile'])),
                    'Paired control changed its selected input or sessions')
        invocation_original = Original.parse(control.get('invocationOriginal'))
        invocation = json.loads(invocation_original.read(calibration_root))
        validate_invocation(invocation, calibration_root, baseline_manifest, mutant_manifest)
        for key in ('sourceOriginal', 'classesOriginal', 'inputOriginal', 'outputOriginal', 'operationOriginal'):
            ref = Original.parse(control.get(key))
            require(mutant_manifest['files'].get(ref.file) == ref.sha256, 'Native actor original is outside its manifest')
            ref.read(mutant_root)
        return cls(run, target, positive, negative, original)


def stock_native_manifest(manifest):
    """Admission boundary only; computeOutcome never switches on these source labels.

    Genuine native SAT and the independent actor's normative VIOL are reported separately.
    A diagnostic source can never become a product finding by falsifying a counterflag.
    Native terminal failure has not been observed in the stock product campaign.
    """
    require(manifest.get('schema') == 'samlscope-shibboleth-native-soap-continuation-v1',
            'Only original stock-native receipts may be adopted')
    for flag in ('counterfactual', 'diagnosticOnly', 'calibrationOnly', 'developerBehavior', 'counterfactualCalibrationOnly'):
        require(flag not in manifest or manifest[flag] is False, 'Diagnostic originals cannot be adopted as the stock product')
    require(not any(key in manifest for key in ('actorClass', 'producerSourceFile', 'producerClassesFile', 'publicCallbackBase')),
            'A diagnostic producer cannot be rebranded as stock native')
    trials = manifest.get('trials')
    require(isinstance(trials, list) and len(trials) == 2
            and {row.get('trial') for row in trials if isinstance(row, dict)} == {'failure', 'all-success'},
            'Complete stock-native trial set is missing')
    require(all(not any(key in row for key in ('operationInputFile', 'operationOutputFile', 'operationTraceFile'))
                and isinstance(row.get('beforeFile'), str) and isinstance(row.get('afterFile'), str) for row in trials),
            'Stock native scope/read-back is absent')


ACTOR_MUTATIONS = {'duplicate-recorded-entry', 'missing-signed-origin-final', 'tampered-signed-origin-final',
    'foreign-manifest-run', 'foreign-fixed-target', 'changed-selected-producer-source', 'foreign-operation-input',
    'foreign-operation-output', 'tampered-signed-complete-operation'}


def actor_manifest(report, calibration_root, bindings, actor):
    require(report.get('readOnly') is True and type(report.get('outboundActions')) is int
            and report['outboundActions'] == 0 and report.get('ephemeralFactoryKeyPersisted') is False
            and report.get('stockPlacementPermitted') is False, 'Control replay issued or adopted an operation')
    original = Original.parse(report.get('manifestOriginal'))
    manifest = json.loads(original.read(calibration_root))
    root = public_relative(calibration_root, original.file).parent
    require(isinstance(manifest, dict) and manifest.get('schema') == 'samlscope-suite-actor-soap-continuation-v1'
            and manifest.get('runId') == report.get('runId') and manifest.get('actorClass')
            == 'com.samlscope.runner.cases.SoapContinuationActor$' + actor,
            'Selected control actor or original Run differs')
    files = manifest.get('files')
    require(isinstance(files, dict) and files, 'Actor/source/operation originals are missing')
    for name, sha in files.items():
        Original.parse({'file': name, 'sha256': sha}).read(root, allow_empty=True)
    require(manifest.get('targetMetadataSha256') == report.get('targetMetadataSha256')
            == digest(public_bytes(root.parent / 'target-metadata.xml')), 'Control target original differs')
    trials = manifest.get('trials')
    require(isinstance(trials, list) and len(trials) == 2
            and {row.get('trial') for row in trials if isinstance(row, dict)} == {'failure', 'all-success'},
            'Complete actor trial set is missing')
    mutations = report.get('negativeControls')
    require(isinstance(mutations, dict) and set(mutations) == ACTOR_MUTATIONS,
            'Meaningful trace mutation controls are missing')
    for value in mutations.values():
        require(isinstance(value, dict) and value.get('outcome') == 'NOT_VERIFIED',
                'Contaminated operation evidence was concluded')
    return original, manifest, root


def validate_invocation(invocation, root, baseline, mutant):
    require(isinstance(invocation, dict)
            and invocation.get('schema') == 'samlscope-soap-continuation-actor-invocation-v1'
            and type(invocation.get('exitCode')) is int and invocation['exitCode'] == 0,
            'Actual paired actor invocation failed or is missing')
    argv = invocation.get('argv')
    require(isinstance(argv, list) and len(argv) == 7 and argv[0] == 'java' and argv[1] == '-cp'
            and argv[3] == 'com.samlscope.runner.cases.SoapContinuationActor'
            and argv[5] == 'paired' and argv[6] == invocation.get('sourceOriginal'),
            'Selected actor argv differs')
    require(invocation.get('sourceSha256') == baseline.get('producerSourceSha256') == mutant.get('producerSourceSha256'),
            'Actor invocation selected another source')
    start = datetime.fromisoformat(invocation['startedAt'].replace('Z', '+00:00'))
    end = datetime.fromisoformat(invocation['finishedAt'].replace('Z', '+00:00'))
    require(start < end, 'Actor invocation clock window is invalid')
    outputs = invocation.get('outputs')
    require(isinstance(outputs, dict) and set(outputs) == {'baseline', 'mutant'}, 'Paired invocation outputs are incomplete')
    for name, manifest in [('baseline', baseline), ('mutant', mutant)]:
        inventory = outputs[name]
        require(isinstance(inventory, dict) and inventory, 'Invocation original inventory is missing')
        for file, sha in inventory.items():
            Original.parse({'file': name + '/' + file, 'sha256': sha}).read(root, allow_empty=True)
        require(inventory.get('receipt/manifest.json') == digest(public_bytes(root / name / 'receipt/manifest.json')),
                'Invocation selected another control manifest')
        classes = json.loads(public_bytes(root / name / 'receipt' / manifest['producerClassesFile']))
        require(classes == invocation.get('classes'), 'Actor invocation selected other compiled classes')
        entries = json.loads(public_bytes(root / name / 'transcript.json'))
        require(isinstance(entries, list) and entries, 'Actor transport originals are missing')
        # JsonCodec serializes actual TranscriptEntry Instant as epoch seconds. Some
        # historical public projections use ISO strings; neither is a host clock guess.
        def instant(value):
            if type(value) in (int, float):
                require(math.isfinite(value), 'Nonfinite transport Instant')
                return datetime.fromtimestamp(value, timezone.utc)
            require(isinstance(value, str), 'Transport Instant has an unknown representation')
            result = datetime.fromisoformat(value.replace('Z', '+00:00'))
            require(result.tzinfo is not None, 'Transport Instant lacks timezone')
            return result
        times = [instant(row['timestamp']) for row in entries]
        require(start <= min(times) <= max(times) <= end, 'Actor transport escaped its actual invocation')
    for channel in ('stdout', 'stderr'):
        Original.parse({'file': invocation[channel + 'File'], 'sha256': invocation[channel + 'Sha256']}).read(root, allow_empty=True)
