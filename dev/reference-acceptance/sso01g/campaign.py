"""Offline campaign plans and an injectable lifecycle; no transport or conformance claims.

The full SAML campaign has no live backend. Keycloak management-only investigation
is separate; see SELF-REVIEW-KC.md and PLAN.md for unresolved native/outbox prerequisites. Drivers are trusted collectors, never operator JSON confirmations.
"""
import argparse
import copy
from dataclasses import asdict, dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
JOB = Path('/Users/yuta/.claude/codex-jobs/20261031-154936-kc-g-impl')
PRODUCTS = ('keycloak', 'simplesamlphp')
DIGESTS = dict(zip(('ga', 'gb', 'gc', 'gj'), (
    '765d35ba28060794b59849437e24158b120872a6c4206ecf58688f9edfc897e8',
    '1bd2950222633a51bd756b9ac18629c82fb654b2821afc407d3fff84615d8c19',
    '2907382964c0928d342d883bc76dd3331922dea687a1dcd64c8f363fa25a325c',
    '87b0066aa931850eb730d22136df8bf53253518c4b662a01ea60bec9e87dba15')))
CASES = {f'IIP-SSO01-{case}-idp-01': 'sha256:' + value for case, value in DIGESTS.items()}
HEX = re.compile(r'[0-9a-f]{64}')
REQUIRED_PROOFS = ('definition_compatible', 'native_ordering', 'native_declaration',
                   'native_comparisons', 'complete_availability', 'fixed_login_input',
                   'all_conditions_persisted_outbox', 'normal_control', 'controls_replayed')


def module_at(name, relative):
    """Only fixed, public, side-effect-free helpers are imported. No product campaign imports."""
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixtures = module_at('sso01g_shibboleth_inputs', 'dev/shibboleth/authn_context_preparation.py')


def conditions():
    rows = copy.deepcopy(fixtures.inputs())
    for row in rows:
        row['mode'] = 'maximum' if row['id'].startswith(('gc-', 'control-')) else 'normal'
    # Additional normal-mode availability controls for the ordered pair, not case variants.
    for kind, label in [('CLASS', 'class'), ('DECLARATION', 'declaration')]:
        for rank in ('low', 'high'):
            rows.append(dict(id=f'control-{label}-{rank}', kind=kind, mode='normal',
                             comparison='EXACT', references=[fixtures.reference(kind, rank)]))
    return rows


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def plan(product):
    if product not in PRODUCTS:
        raise ValueError('Unknown product')
    rows = conditions()
    blockers = ['Native DeclRef selection/output unqualified',
                'CONFIG cases expose no browser action keys; all conditions need existing persisted outbox binding',
                'Live SAML/outbox driver and product-specific independent receipt reader not included']
    blockers.append('SAML step-up feature, URI/LoA map, comparisons and exhaustive availability unqualified'
                    if product == 'keycloak' else
                    'Archived standard selector explicitly does not implement minimum/better/maximum')
    return dict(schema='samlscope-sso01g-offline-plan-v1', product=product,
                profile='browser_sso_idp', caseDigests=CASES, conditions=rows,
                modeGroups=['normal', 'maximum', 'restore'], blockers=blockers,
                liveExecutionAvailable=False, ledgerChanged=False,
                plannedExternalOperationsNow=0,
                conditionalEstimates=dict(conditionExchanges=len(rows), initialNormalExchanges='0..1',
                    restoredNormalExchanges=1, loginSubmissions='0..26; actual unmeasured',
                    explicitLogouts=0, humanClicks='unmeasured',
                    minimumSettingWriteAttempts=3, actualSettingWrites='dependency count unqualified',
                    minimumHostWriteSuccesses=3 if product == 'simplesamlphp' else 0,
                    hostWritesApplicable=product == 'simplesamlphp',
                    effectiveModeApplications=2, effectiveRestorations=1,
                    effectiveReadbacks=2 + 2 + 2 * len(rows) + 1),
                lifecycle=['preflight actual Run/profile/cases/native proofs/outbox',
                    'capture original public native state and effective product read-back',
                    'apply normal; native read-back; each condition before/after native read-back',
                    'apply maximum; native read-back; each condition before/after native read-back',
                    'finally restore even on partial failure; compare original native effective state',
                    'existing-outbox restored normal SSO; independent original-backed controls/reader'],
                evidenceStatus='supplemental-unadopted')


@dataclass
class Counters:
    setting_write_attempts: int = 0
    host_write_successes: int = 0
    native_write_successes: int = 0
    product_effective_applications: int = 0
    restoration_write_attempts: int = 0
    restoration_host_write_successes: int = 0
    restoration_native_write_successes: int = 0
    product_effective_restorations: int = 0
    effective_readbacks: int = 0
    condition_dispatch_attempts: int = 0
    condition_receipts: int = 0
    restored_normal_dispatch_attempts: int = 0

    def write(self, operation, *, location, restoring=False):
        """Call once PER write; record attempts before invoking any writer.

        A native write success is an API acknowledgment, not effective application.
        A transport error after applying must not invent success; driver restore must
        read back the possibly applied state before deciding whether to overwrite it.
        """
        if location not in ('host', 'native'):
            raise ValueError('Unknown write location')
        self.setting_write_attempts += 1
        if restoring:
            self.restoration_write_attempts += 1
        value = operation()
        name = location + '_write_successes'
        setattr(self, name, getattr(self, name) + 1)
        if restoring:
            name = 'restoration_' + name
            setattr(self, name, getattr(self, name) + 1)
        return value


def effective(driver, counters):
    counters.effective_readbacks += 1
    row = driver.read_effective()
    if (set(row) != {'origin', 'sha256'} or row['origin'] != 'product-runtime'
            or not HEX.fullmatch(row['sha256'])):
        raise ValueError('Effective product state unavailable')
    return copy.deepcopy(row)


def check_scope(scope, product):
    if (scope.get('product') != product or scope.get('profile') != 'browser_sso_idp'
            or scope.get('role') != 'idp' or scope.get('caseDigests') != CASES
            or not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', scope.get('runId', ''))
            or not HEX.fullmatch(scope.get('targetMetadataSha256', ''))
            or not HEX.fullmatch(scope.get('loginInputBindingSha256', ''))
            or any(scope.get(key) is not True for key in REQUIRED_PROOFS)):
        raise ValueError('Native or Run prerequisites unqualified')


def check_receipt(row, scope, condition, seen, mode):
    # Correlation envelope only. Signature/cryptographic qualification belongs to
    # the independent Suite reader; this function never declares an observation conformant.
    if (row.get('runId') != scope['runId'] or row.get('condition') != condition
            or row.get('mode') != mode
            or row.get('targetMetadataSha256') != scope['targetMetadataSha256']
            or row.get('transport') != 'persisted-outbox-recorder'
            or row.get('delivery') != 'observed'
            or not re.fullmatch(r'_[A-Za-z0-9_-]+', row.get('requestId', ''))):
        raise ValueError('Uncertain or foreign operation')
    for key in ('requestId', 'actionId', 'requestReference', 'responseReference'):
        value = row.get(key)
        if not isinstance(value, str) or not value or value in seen:
            raise ValueError('Missing or reused operation reference')
        seen.add(value)
    if not all(HEX.fullmatch(row.get(key, '')) for key in ('requestSha256', 'responseSha256')):
        raise ValueError('Missing original digest')
    # Persist only this public envelope, never arbitrary driver data/HTML/headers.
    return {key: row[key] for key in ('runId', 'condition', 'mode', 'targetMetadataSha256',
        'transport', 'delivery', 'requestId', 'actionId', 'requestReference',
        'responseReference', 'requestSha256', 'responseSha256')}


def run_campaign(product, driver):
    """Exercise the lifecycle with a reviewed driver; tests use in-memory doubles.

    This is NOT an execution/adoption CLI. The driver must capture public settings,
    preserve originals in memory, count each actual write, reject concurrent edits,
    and consume only existing Suite outbox actions. No arbitrary commands accepted.
    """
    report = dict(product=product, status='incomplete', restored=False,
                  evidenceStatus='supplemental-unadopted', observations=[], errors=[])
    counters, seen = Counters(), set()
    dirty, original, baseline = False, None, None
    try:
        if product not in PRODUCTS:
            raise ValueError('Unknown product')
        scope = driver.preflight(product, CASES.copy())
        check_scope(scope, product)
        # Keep the recovery snapshot private to this process. Never dump full configs.
        original = driver.capture()
        baseline = effective(driver, counters)
        for mode in ('normal', 'maximum'):
            dirty = True  # Even an apply that raises may have changed the product.
            expected = driver.apply(mode, counters)
            if effective(driver, counters) != expected:
                raise ValueError('Native configuration not effective')
            counters.product_effective_applications += 1
            for row in conditions():
                if row['mode'] != mode:
                    continue
                if effective(driver, counters) != expected:
                    raise ValueError('Native configuration drift before exchange')
                counters.condition_dispatch_attempts += 1
                receipt = driver.collect_existing_outbox(copy.deepcopy(row))
                if effective(driver, counters) != expected:
                    raise ValueError('Native configuration drift after exchange')
                public = check_receipt(receipt, scope, row['id'], seen, mode)
                report['observations'].append(public)
                counters.condition_receipts += 1
        report['status'] = 'collected-unqualified'
    except Exception as error:
        report['errors'].append(dict(stage='collection', type=type(error).__name__))
    finally:
        if dirty:
            try:
                driver.restore(original, counters)
                report['restored'] = effective(driver, counters) == baseline
                if not report['restored']:
                    raise ValueError('Native restoration mismatch')
                counters.product_effective_restorations += 1
            except Exception as error:
                report['errors'].append(dict(stage='restoration', type=type(error).__name__))
                report['restored'] = False
        if report['status'] == 'collected-unqualified' and report['restored']:
            try:
                counters.restored_normal_dispatch_attempts += 1
                normal = driver.collect_restored_normal_outbox()
                report['restoredNormal'] = check_receipt(normal, scope, 'M0_RESTORED', seen, 'restored')
                if effective(driver, counters) != baseline:
                    raise ValueError('Native drift after restored normal control')
            except Exception as error:
                report['errors'].append(dict(stage='restored-normal', type=type(error).__name__))
        if report['errors'] or not report['restored']:
            report['status'] = 'incomplete'
        report['counts'] = asdict(counters)
    return report


def output_path(path):
    path = path.absolute()
    # Resolve every existing ancestor; no symlink aliases to protected trees.
    resolved = path.resolve()
    if resolved != path or not any(resolved.is_relative_to(root) and resolved != root
                                    for root in (OUT, JOB)):
        raise ValueError('Output must be a non-symlink child of the two authorized directories')
    return resolved


def cli(product):
    parser = argparse.ArgumentParser(description='Offline preparation only; no live backend')
    parser.add_argument('--dry-run', action='store_true', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = output_path(args.out)
    result = plan(product)  # No product paths, credentials, socket, HTTP or subprocess reads.
    out.mkdir(parents=True, exist_ok=True)
    with (out / 'plan.json').open('x', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps(result, ensure_ascii=False, indent=2))
