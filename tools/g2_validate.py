#!/usr/bin/env python3
"""Validate G2 design artifacts without generating or rewriting them."""
import os
import sys

if not sys.flags.isolated:
    os.execv(sys.executable, [sys.executable, '-I', os.path.abspath(__file__), *sys.argv[1:]])
script_dir = os.path.dirname(os.path.abspath(__file__))
if sys.path and os.path.abspath(sys.path[0] or '') == script_dir:
    del sys.path[0]

import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import uuid

import jsonschema
import yaml

ROOT = pathlib.Path(os.environ.get('G2_REPO_ROOT') or pathlib.Path(__file__).resolve().parents[1]).resolve()
BUILD = ROOT / 'build'
APPROVAL_REL = 'tests/approvals/g2.yaml'
APPROVAL_PATH = ROOT / APPROVAL_REL

STATIC_PROTECTED_PATHS = {
    'tests/cases.yaml', 'tests/feasibility.yaml',
    'tests/mutants/baselines.yaml', 'tests/mutants/catalog.yaml',
    'tests/mutants/control-mutants.yaml',
    'tests/coverage.yaml', 'tests/specs.yaml', 'tests/predicates.yaml',
    'tests/approvals/g1.yaml', APPROVAL_REL,
    'schema/cases-v1.json', 'schema/mutants-v1.json',
    'schema/g2-feasibility-v1.json', 'schema/g2-approval-v1.json',
    'tools/g2_validate.py', 'tools/g2_trusted_verify.py',
    'tools/g2_ci_verify.sh', 'tools/release_check.py',
    'tools/tests/test_release_check.py', 'tools/requirements.lock',
    '.github/workflows/g2.yml', '.github/workflows/build.yml',
    'Dockerfile', '.dockerignore', 'dev/keycloak/compose.yml', 'dev/keycloak/prepare-smoke.sh',
    'dev/keycloak/smoke.py', 'dev/keycloak/test_smoke.py',
    'dev/keycloak/prepare-smoke-apple.py', 'dev/keycloak/test_prepare_smoke_apple.py',
    'dev/keycloak/realm-samlscope.json',
    'build.gradle.kts', 'settings.gradle.kts',
    'gradle/libs.versions.toml', 'gradle/verification-metadata.xml',
    'gradle/wrapper/gradle-wrapper.properties', 'gradle/wrapper/gradle-wrapper.jar',
    'saml/build.gradle.kts', 'api/build.gradle.kts', 'peer/build.gradle.kts',
    'saml/src/main/java/com/samlscope/saml/binding/RedirectSignatureInput.java',
    'saml/src/main/java/com/samlscope/saml/ecp/EcpEnvelopeForwarder.java',
    'saml/src/main/java/com/samlscope/saml/logout/LogoutExchange.java',
    'saml/src/main/java/com/samlscope/saml/metadata/MetadataVariantRegistry.java',
    'saml/src/main/java/com/samlscope/saml/raw/BytePreservingRawMessageBuilder.java',
    'peer/src/main/java/com/samlscope/peer/PeerIdentity.java',
    'api/src/main/java/com/samlscope/api/SamlScopeApplication.java',
    'api/src/main/java/com/samlscope/api/FunctionalProfileDocuments.java',
    'api/src/main/java/com/samlscope/api/M1Runtime.java',
    'core/src/main/java/com/samlscope/core/evaluation/Evaluator.java',
    'core/src/main/java/com/samlscope/core/evaluation/RunResultInvariantValidator.java',
    'core/src/main/java/com/samlscope/core/plan/TestPlan.java',
    'runner/src/main/java/com/samlscope/runner/ApprovedCaseStarter.java',
    'runner/src/main/java/com/samlscope/runner/AutomatedCaseRunner.java',
    'runner/src/main/java/com/samlscope/runner/CatalogApplicabilityProvider.java',
    'runner/src/main/java/com/samlscope/runner/PinnedFunctionalCaseDefinitionResolver.java',
    'runner/src/main/java/com/samlscope/runner/QuickCheckService.java',
    'runner/src/main/java/com/samlscope/runner/RunEvaluationService.java',
    'runner/src/main/java/com/samlscope/runner/result/DefaultResultContextProvider.java',
    'runner/src/main/java/com/samlscope/runner/result/ResultDocumentAssembler.java',
    'runner/src/main/java/com/samlscope/runner/result/ResultPublicationService.java',
    'store/src/main/java/com/samlscope/store/FunctionalProfileJsonModule.java',
    'store/src/main/java/com/samlscope/store/PlanWritePolicy.java',
    'store/src/main/java/com/samlscope/store/SqlitePlanRepository.java',
    'saml/src/test/java/com/samlscope/saml/G2FeasibilitySpikeTest.java',
    'peer/src/test/java/com/samlscope/peer/PeerG2FeasibilityTest.java',
}
PROTECTED_PREFIXES = (
    'tests/fixtures/',
    'core/src/main/java/com/samlscope/core/profile/',
    'dev/profile-migration/',
    'profiles/',
)
NON_EVALUATIVE = {
    'IIP-MD05.am', 'IIP-MD05.at', 'IIP-MD05.c4', 'IIP-MD05.ed',
    'IIP-MD06.aa', 'IIP-SSO07.a', 'IIP-EXT01.b1', 'IIP-EXT01.c1',
    'IIP-IDP09.b', 'IIP-IDP12.d', 'IIP-IDP13.o', 'IIP-IDP13.p',
    'IIP-IDP13.r', 'IIP-IDP13.b', 'IIP-IDP14.b', 'IIP-IDP17.b4',
    'IIP-IDP17.c', 'IIP-SP02.c',
    'IIP-ALG05.a', 'IIP-MD06.a4', 'IIP-SP14.c',
    'IIP-SSO01.ax', 'IIP-SSO01.bk', 'IIP-SSO01.z',
    'IIP-MD03.e', 'IIP-MD05.au',
}
TRIGGER_OVERRIDES = {
    'IIP-G02.c': 'IIP-G02.c#v-59304685a7',
    'IIP-IDP16.a': 'IIP-IDP16.a#v-13ac186e94',
}
GROUP_OVERRIDES = {
    'IIP-IDP12.d': [('one_of', {'v-188d32eb7f', 'v-f4c580ba77'})],
    'IIP-G02.c': [
        ('one_of_available', {'v-5fd589e897', 'v-59304685a7'}),
        ('all_of', {'v-12bc7d3a9f'}),
    ],
    'IIP-MD03.e': [('one_of', {'v-cf5ab2560b', 'v-a38c9f2c43'})],
    'IIP-SSO01.dy': [
        ('one_of', {'v-d6e3c96d7a', 'v-2aed0f0d69'}),
        ('all_of', {'v-eafd71a824'}),
    ],
}
DESTRUCTIVE_SESSIONS = {
    'IIP-SP14.p', 'IIP-SP14.q', 'IIP-SP14.y', 'IIP-SP14.z',
    'IIP-IDP17.d', 'IIP-IDP17.e', 'IIP-IDP17.p', 'IIP-IDP17.q',
}
SESSION_REQUIRED = DESTRUCTIVE_SESSIONS | {'IIP-IDP17.o'}
TARGET_ISSUED_SLO_SESSION_REQUIREMENTS = {
    'IIP-IDP17.ai', 'IIP-IDP17.aj', 'IIP-IDP17.b3', 'IIP-IDP17.v',
    'IIP-SP14.aa', 'IIP-SP14.ao', 'IIP-SP14.ap',
}
SESSION_REQUIRED |= TARGET_ISSUED_SLO_SESSION_REQUIREMENTS
EVIDENCE_KIND = {
    'AUTOMATED': 'transcript', 'BROWSER': 'browser_and_transcript',
    'CONFIG': 'configuration_and_transcript', 'ATTESTED': 'attestation_or_instrumented_trace',
}

checks = []

def check(cid, description, passed, detail=''):
    checks.append({'id': cid, 'description': description,
                   'result': 'PASS' if passed else 'FAIL', 'detail': str(detail)[:1000]})
    return passed

def load_yaml(relative):
    return yaml.safe_load((ROOT / relative).read_text(encoding='utf-8'))

def load_json(relative):
    return json.loads((ROOT / relative).read_text(encoding='utf-8'))

def sha_bytes(value):
    return 'sha256:' + hashlib.sha256(value).hexdigest()

def canonical_digest(value):
    return sha_bytes(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())

def git(*args, binary=False):
    return subprocess.run(['git', '-C', str(ROOT), *args], capture_output=True,
                          text=not binary, timeout=60, check=False)

def exact_commit(value):
    value = str(value or '')
    if not re.fullmatch(r'[0-9a-f]{40}', value):
        return False
    result = git('rev-parse', '--verify', '--quiet', value + '^{commit}')
    return result.returncode == 0 and result.stdout.strip() == value

def commit_time(commit):
    result = git('show', '-s', '--format=%cI', commit)
    if result.returncode != 0:
        raise ValueError(f'cannot read commit time for {commit}')
    return datetime.datetime.fromisoformat(result.stdout.strip().replace('Z', '+00:00'))

def protected_paths(commit):
    result = git('ls-tree', '-r', '--name-only', commit)
    if result.returncode != 0:
        return set(STATIC_PROTECTED_PATHS)
    tracked = set(result.stdout.splitlines())
    return {path for path in STATIC_PROTECTED_PATHS if path in tracked or path == APPROVAL_REL} | {
        path for path in tracked if path.startswith(PROTECTED_PREFIXES)
    }

coverage = load_yaml('tests/coverage.yaml')
predicates = load_yaml('tests/predicates.yaml')['predicates']
g1_approval = load_yaml('tests/approvals/g1.yaml')
case_doc = load_yaml('tests/cases.yaml')
baseline_doc = load_yaml('tests/mutants/baselines.yaml')
mutant_doc = load_yaml('tests/mutants/catalog.yaml')
control_doc = load_yaml('tests/mutants/control-mutants.yaml')
feasibility = load_yaml('tests/feasibility.yaml')

schema_errors = []
for relative, document, schema_relative in (
    ('tests/cases.yaml', case_doc, 'schema/cases-v1.json'),
    ('tests/mutants/baselines.yaml', baseline_doc, 'schema/mutants-v1.json'),
    ('tests/mutants/catalog.yaml', mutant_doc, 'schema/mutants-v1.json'),
    ('tests/mutants/control-mutants.yaml', control_doc, 'schema/mutants-v1.json'),
    ('tests/feasibility.yaml', feasibility, 'schema/g2-feasibility-v1.json'),
):
    try:
        jsonschema.Draft202012Validator(load_json(schema_relative)).validate(document)
    except Exception as error:
        schema_errors.append(f'{relative}: {error}')
check('G2-01', 'all G2 artifacts satisfy their JSON Schemas', not schema_errors, schema_errors[:5])

all_obligations = {o['key']: o for requirement in coverage['requirements'] for o in requirement['obligations']}
targets = {key: value for key, value in all_obligations.items() if value['testability'] != 'NOT_OBSERVABLE'}
cases = case_doc.get('cases') or []
case_by_id = {case.get('id'): case for case in cases}
mutants = mutant_doc.get('mutants') or []
mutant_by_id = {mutant.get('id'): mutant for mutant in mutants}
baselines = {base['id']: base for base in baseline_doc.get('baselines') or []}
outcomes = baseline_doc.get('outcomes') or {}

check('G2-02', 'the case catalog is bound to the approved G1 target commit',
      case_doc.get('catalog_commit') == g1_approval.get('target_commit'))
case_ids = [case.get('id') for case in cases]
mutant_ids = [mutant.get('id') for mutant in mutants]
check('G2-03', 'case IDs are unique', len(case_ids) == len(set(case_ids)), len(case_ids))
check('G2-04', 'mutant IDs are unique', len(mutant_ids) == len(set(mutant_ids)), len(mutant_ids))
case_obligations = {case.get('obligation') for case in cases}
check('G2-05', 'every observable obligation and no NOT_OBSERVABLE obligation has a case',
      case_obligations == set(targets), {'missing': sorted(set(targets) - case_obligations)[:8]})

role_errors = []
for key, obligation in targets.items():
    actual = {case['role'] for case in cases if case.get('obligation') == key}
    if actual != set(obligation['roles']):
        role_errors.append(f'{key}: expected={obligation["roles"]} actual={sorted(actual)}')
check('G2-06', 'every obligation is designed independently for every target role', not role_errors, role_errors[:8])

def expand_variants(key, seen=None):
    seen = set() if seen is None else set(seen)
    if key in seen:
        raise ValueError(f'linked-obligation cycle at {key}')
    if key not in all_obligations:
        raise ValueError(f'unknown linked obligation {key}')
    seen.add(key)
    owner = all_obligations[key]
    result = {f"{key}#{item['id']}": 'owner_condition' for item in owner.get('required_variants') or []}
    for link in owner.get('linked_obligations') or []:
        linked_key = link['obligation']
        if linked_key not in all_obligations:
            raise ValueError(f'unknown linked obligation {linked_key}')
        linked = all_obligations[linked_key]
        selected = set(link.get('variants') or [v['id'] for v in linked.get('required_variants') or []])
        scope = link.get('variant_applicability', 'owner_condition')
        for variant in linked.get('required_variants') or []:
            if variant['id'] in selected:
                result[f"{linked_key}#{variant['id']}"] = scope
        for reference, inherited_scope in expand_variants(linked_key, seen).items():
            origin, variant_id = reference.split('#', 1)
            if origin != linked_key or variant_id in selected:
                result.setdefault(reference, scope if inherited_scope == 'owner_condition' else inherited_scope)
    return result

def variant_description(reference):
    key, variant_id = reference.split('#', 1)
    return next((v['description_en'] for v in all_obligations[key].get('required_variants') or []
                 if v['id'] == variant_id), None)

def expected_variant_treatment(owner_key, reference):
    description = (variant_description(reference) or '').strip().lower()
    if owner_key in NON_EVALUATIVE:
        return 'informational'
    if description.startswith('out of scope'):
        return 'out_of_scope'
    if (description.startswith('information only') or 'record as information' in description
            or 'informational evidence' in description or 'do not evaluate' in description
            or 'do not use it for the verdict' in description):
        return 'informational'
    if description.startswith('control:') or description.startswith('negative control:'):
        return 'control'
    return 'verdict'

variant_errors = []
mode_errors = []
digest_errors = []
control_errors = []
mutant_reference_errors = []
for case in cases:
    key = case.get('obligation')
    obligation = targets.get(key)
    if obligation is None:
        continue
    try:
        expected = expand_variants(key)
    except ValueError as error:
        variant_errors.append(f'{case.get("id")}: {error}')
        expected = {}
    if set(case.get('covers_variants') or []) != set(expected):
        variant_errors.append(f"{case['id']}: variant set mismatch")
    if case.get('variant_scopes') != {ref: expected[ref] for ref in sorted(expected)}:
        variant_errors.append(f"{case['id']}: variant scope mismatch")
    plan = case.get('variant_plan') or []
    if {item.get('reference') for item in plan} != set(expected):
        variant_errors.append(f"{case['id']}: variant plan set mismatch")
    for item in plan:
        ref = item.get('reference')
        if ref in expected and (item.get('applicability') != expected[ref]
                                or item.get('instruction_en') != variant_description(ref)):
            variant_errors.append(f"{case['id']}: variant plan is not G1-bound for {ref}")
        if ref in expected and item.get('treatment') != expected_variant_treatment(key, ref):
            variant_errors.append(f"{case['id']}: treatment is not G1-bound for {ref}")
    group_members = [member for group in case.get('variant_groups') or [] for member in group.get('members') or []]
    if len(group_members) != len(set(group_members)) or set(group_members) != set(expected):
        variant_errors.append(f"{case['id']}: variant groups do not partition covered variants")
    for kind, suffixes in GROUP_OVERRIDES.get(key, []):
        wanted = {f'{key}#{suffix}' for suffix in suffixes}
        if not any(group.get('kind') == kind and set(group.get('members') or []) == wanted
                   for group in case.get('variant_groups') or []):
            variant_errors.append(f"{case['id']}: missing reviewed {kind} group")
    if case.get('mode') != obligation['testability']:
        mode_errors.append(f"{case['id']}: mode")
    if obligation['testability'] == 'CONFIG':
        if case.get('configuration_failure_semantics') != obligation.get('configuration_failure_semantics'):
            mode_errors.append(f"{case['id']}: configuration semantics")
    elif 'configuration_failure_semantics' in case:
        mode_errors.append(f"{case['id']}: unexpected configuration semantics")

    non_eval = key in NON_EVALUATIVE
    controls = case.get('controls') or []
    kinds = [control.get('kind') for control in controls]
    positive = {c.get('fixture') for c in controls if c.get('kind') == 'positive'}
    negative = {c.get('fixture') for c in controls if c.get('kind') == 'negative'}
    informational = {c.get('fixture') for c in controls if c.get('kind') == 'informational'}
    if non_eval:
        if positive or negative or len(informational) != 1 or not case.get('control_waiver_en'):
            control_errors.append(case['id'] + ': non-evaluative control shape')
        if case.get('detected_by_mutants') or not case.get('mutant_waiver'):
            mutant_reference_errors.append(case['id'] + ': non-evaluative mutant shape')
    else:
        if positive != {case.get('baseline')} or negative != set(case.get('detected_by_mutants') or []):
            control_errors.append(case['id'] + ': fixture mismatch')
        if not ({'positive', 'negative'} <= set(kinds)):
            control_errors.append(case['id'] + ': missing paired controls')
        if not case.get('detected_by_mutants') and not case.get('mutant_waiver'):
            mutant_reference_errors.append(case['id'] + ': no mutant or waiver')
    if not case.get('counterexample_en'):
        control_errors.append(case['id'] + ': counterexample')
    for mutant_id in case.get('detected_by_mutants') or []:
        if mutant_id not in mutant_by_id:
            mutant_reference_errors.append(case['id'] + ':' + mutant_id)
    canonical = {name: value for name, value in case.items() if name not in ('case_digest', 'review')}
    if case.get('case_digest') != canonical_digest(canonical):
        digest_errors.append(case['id'])
    if case.get('obligation_digest') != obligation['review']['obligation_digest']:
        digest_errors.append(case['id'] + ':obligation')

check('G2-07', 'variants are cycle-safe, G1-bound, scoped, and grouped without OR-to-AND conversion',
      not variant_errors, variant_errors[:8])
check('G2-08', 'case mode and configuration semantics match G1', not mode_errors, mode_errors[:8])
check('G2-09', 'evaluative cases have paired controls and non-evaluative cases have waivers',
      not control_errors, control_errors[:8])
check('G2-10', 'all case and obligation digests match canonical content', not digest_errors, digest_errors[:8])
check('G2-11', 'mutant references and non-evaluative waivers are complete',
      not mutant_reference_errors, mutant_reference_errors[:8])

dependency_errors = []
graph = {case['id']: list((case.get('requires') or {}).get('passed_cases') or []) for case in cases}
session_fixture = load_yaml('tests/fixtures/session/fresh-authenticated-session.yaml')
if session_fixture.get('id') != 'fresh-authenticated-session' or (session_fixture.get('on_failure') or {}).get('outcome') != 'not_verified':
    dependency_errors.append('fresh-authenticated-session: invalid setup')
for case_id, dependencies in graph.items():
    case = case_by_id[case_id]
    key = case.get('obligation')
    for dependency in dependencies:
        if dependency not in case_by_id:
            dependency_errors.append(f'{case_id}: unknown {dependency}')
    requirements = case.get('requires') or {}
    if requirements.get('session') == 'required' and requirements.get('setup_fixture') != 'fresh-authenticated-session':
        dependency_errors.append(f'{case_id}: required session lacks fixture')
    if requirements.get('session') != 'required' and requirements.get('setup_fixture'):
        dependency_errors.append(f'{case_id}: fixture without required session')
    if case.get('destroys_session'):
        if requirements.get('session') != 'required' or not case.get('session_effect_reason_en'):
            dependency_errors.append(f'{case_id}: destructive case lacks isolation/reason')
        reason = case.get('session_effect_reason_en', '').lower()
        if not any(word in reason for word in ('terminate', 'invalidat', 'destroy', 'logout')):
            dependency_errors.append(f'{case_id}: reason does not identify state transition')
    elif case.get('session_effect_reason_en'):
        dependency_errors.append(f'{case_id}: non-destructive case has reason')
    if key in SESSION_REQUIRED and requirements.get('session') != 'required':
        dependency_errors.append(f'{case_id}: reviewed SLO flow lacks session')
    if bool(case.get('destroys_session')) != (key in DESTRUCTIVE_SESSIONS):
        dependency_errors.append(f'{case_id}: destruction classification mismatch')

visiting = set()
visited = set()
def visit(case_id):
    if case_id in visiting:
        dependency_errors.append(f'cycle at {case_id}')
        return
    if case_id in visited:
        return
    visiting.add(case_id)
    for dependency in graph.get(case_id, []):
        visit(dependency)
    visiting.remove(case_id)
    visited.add(case_id)
for case_id in graph:
    visit(case_id)
check('G2-12', 'dependencies and session effects are explicit, isolated, and acyclic',
      not dependency_errors, dependency_errors[:8])
check('G2-13', 'all cases are assigned to M1, M2, or M3',
      all(case.get('milestone') in ('M1', 'M2', 'M3') for case in cases))

def expected_conditions(role, features, target, controlled):
    values = {
        'claims_mdq_support': features['mdq'],
        'supports_outbound_encryption': features['assertion_encryption'],
        'claims_slo_support_sp': features['single_logout'],
        'supports_slo_sp': features['single_logout'],
        'supports_slo_initiation_sp': features['single_logout'],
        'supports_cbc': features['cbc'],
        'peer_declares_algorithm_support': controlled['peer_declares_algorithm_support'],
        'setting_supported_by_implementation': features['supported_settings'],
        'not_token_translation_proxy': target['kind'] != 'token_translation_proxy',
        'supports_name_identifier_management': features['name_identifier_management'],
        'proxies_to_non_saml_provider': target['upstream_kind'] == 'non_saml',
        'uses_small_integer_sessionindex': features['sessionindex_scheme'] == 'small_integer',
        'uses_random_identifier_generation': features['random_id_generation'],
        'supports_authnrequest_proxying': features['authnrequest_proxying'],
        'emits_idplist_getcomplete': features['idplist_getcomplete'],
        'unsolicited_acs_from_metadata': features['idp_initiated_sso'] and features['metadata_driven_acs'],
        'derives_url_from_relaystate': features['relaystate_as_url'],
        'allowcreate_general_interoperability_case': not features['allowcreate_specific_use'],
        'proxy_allowcreate_general_interoperability_case': features['authnrequest_proxying'] and not features['allowcreate_specific_use'],
        'relaystate_privacy_required': target['relaystate_privacy'] == 'required',
        'slo_relaystate_privacy_required': target['slo_relaystate_privacy'] == 'required',
        'supports_unsolicited_responses': features['idp_initiated_sso'],
        'supports_slo_idp': features['single_logout'],
        'supports_artifact_binding': features['artifact_binding'],
        'supports_encrypted_nameid': features['encrypted_nameid'],
        'reissues_foreign_persistent_identifier': features['proxy_idp'],
    }
    relevant = {o['condition']['predicate'] for o in targets.values()
                if o.get('condition') and role in o['roles']}
    return {name: ('TRUE' if values[name] else 'FALSE') for name in sorted(relevant)}

baseline_errors = []
required_baselines = {'sp-full-slo-enc', 'sp-core-minimal', 'idp-full', 'idp-core-no-ecp', 'idp-proxy'}
if set(baselines) != required_baselines or set(outcomes) != required_baselines:
    baseline_errors.append('baseline matrix IDs differ from five reviewed scenarios')
for base_id, base in baselines.items():
    vector = outcomes.get(base_id) or {}
    fixture_path = ROOT / base.get('config_fixture', '') / 'config.yaml'
    if not fixture_path.is_file():
        baseline_errors.append(f'{base_id}: fixture missing')
        continue
    fixture = yaml.safe_load(fixture_path.read_text(encoding='utf-8')) or {}
    expected_fixture = {
        'role': base.get('role'), 'profile': base.get('profile'),
        'features': base.get('declared_features'), 'target': base.get('target'),
        'controlled_inputs': base.get('controlled_inputs'), 'conditions': base.get('condition_results'),
        'condition_evidence': base.get('condition_evidence'),
    }
    for field, wanted in expected_fixture.items():
        if fixture.get(field) != wanted:
            baseline_errors.append(f'{base_id}: fixture {field} differs')
    try:
        derived = expected_conditions(base['role'], base['declared_features'], base['target'], base['controlled_inputs'])
    except (KeyError, TypeError) as error:
        baseline_errors.append(f'{base_id}: cannot derive conditions: {error}')
        derived = {}
    if base.get('condition_results') != derived:
        baseline_errors.append(f'{base_id}: conditions are not derived')
    evidence = base.get('condition_evidence') or {}
    if set(evidence) != set(derived) or any(item.get('result') != derived[name] for name, item in evidence.items()):
        baseline_errors.append(f'{base_id}: condition evidence mismatch')
    for name, result in derived.items():
        definition = predicates[name]
        declared_inputs = {}
        for path in definition.get('declared') or []:
            source, field = path.split('.', 1)
            container = base['declared_features'] if source == 'declared_features' else base['target']
            if field not in container:
                baseline_errors.append(f'{base_id}:{name}: missing declared input {path}')
            else:
                declared_inputs[path] = container[field]
        controlled_evidence = ({'suite.peer_declares_algorithm_support':
                                base['controlled_inputs']['peer_declares_algorithm_support']}
                               if name == 'peer_declares_algorithm_support' else {})
        wanted_evidence = {
            'result': result, 'declared_inputs': declared_inputs,
            'controlled_inputs': controlled_evidence,
        }
        if evidence.get(name) != wanted_evidence:
            baseline_errors.append(f'{base_id}:{name}: evidence inputs are not exact')
    if derived.get('not_token_translation_proxy') == 'TRUE' and derived.get('proxies_to_non_saml_provider') == 'TRUE':
        baseline_errors.append(f'{base_id}: incompatible proxy classifications')
    if not base['declared_features'].get('mdq'):
        baseline_errors.append(f'{base_id}: unconditional MDQ capability absent')
    if set(vector) != set(targets):
        baseline_errors.append(f'{base_id}: outcome vector incomplete')
        continue
    is_core = base['profile'].endswith('-core')
    for key, obligation in targets.items():
        if base['role'] not in obligation['roles']:
            wanted = {'outcome': 'not_applicable', 'reason_code': 'role_mismatch'}
        elif is_core and obligation['level_assignment'][base['role']] == 'full':
            wanted = {'outcome': 'not_verified', 'reason_code': 'profile_not_selected'}
        elif obligation.get('condition') and derived.get(obligation['condition']['predicate']) == 'FALSE':
            wanted = {'outcome': 'not_applicable', 'reason_code': 'condition_false'}
        else:
            wanted = {'outcome': 'satisfied'}
        if vector.get(key) != wanted:
            baseline_errors.append(f'{base_id}:{key}: expected {wanted}, got {vector.get(key)}')
check('G2-14', 'baselines derive conditions and apply role/profile/condition precedence',
      not baseline_errors, baseline_errors[:8])

mutant_errors = []
detected = set()
for mutant in mutants:
    mid = mutant.get('id', '<missing>')
    canonical = {name: value for name, value in mutant.items() if name != 'mutant_digest'}
    if mutant.get('mutant_digest') != canonical_digest(canonical):
        mutant_errors.append(mid + ':digest')
    base = mutant.get('base')
    if base not in baselines:
        mutant_errors.append(mid + ':base')
        continue
    changes = mutant.get('expected_changes') or {}
    executor = mutant.get('executor') or {}
    if set(changes) & NON_EVALUATIVE:
        mutant_errors.append(mid + ': non-evaluative violation')
    matching_cases = [case for case in cases if case.get('obligation') in changes
                      and case.get('role') == mutant.get('target_role')]
    if len(matching_cases) != 1 or executor.get('trigger_variant') not in matching_cases[0].get('covers_variants', []):
        mutant_errors.append(mid + ': non-executable trigger')
        continue
    owner_key = matching_cases[0]['obligation']
    trigger_ref = executor.get('trigger_variant')
    mutation_refs = set(executor.get('mutation_variants') or [trigger_ref])
    trigger_key, trigger_id = trigger_ref.split('#', 1)
    trigger_obligation = all_obligations.get(trigger_key) or {}
    trigger = next((item for item in trigger_obligation.get('required_variants') or []
                    if item.get('id') == trigger_id), None)
    expected_trigger = None if trigger is None else f"{trigger_obligation['summary_en']} — Variant: {trigger['description_en']}"
    if trigger is None or executor.get('trigger_en') != expected_trigger:
        mutant_errors.append(mid + ': trigger is not G1-bound')
    if trigger_ref not in mutation_refs or not mutation_refs <= set(matching_cases[0].get('covers_variants') or []):
        mutant_errors.append(mid + ': mutation variants are not executable')
    trigger_groups = [group for group in matching_cases[0].get('variant_groups') or []
                      if trigger_ref in (group.get('members') or [])]
    expected_mutation_refs = {trigger_ref}
    if len(trigger_groups) == 1 and trigger_groups[0].get('kind') == 'one_of':
        expected_mutation_refs = set(trigger_groups[0].get('members') or [])
    if mutation_refs != expected_mutation_refs:
        mutant_errors.append(mid + ': mutation set does not make the selected logical group fail')
    if TRIGGER_OVERRIDES.get(owner_key) and trigger_ref != TRIGGER_OVERRIDES[owner_key]:
        mutant_errors.append(mid + ': reviewed trigger not used')
    observation = executor.get('observation') or {}
    obligation = targets[owner_key]
    if observation.get('evidence_kind') != EVIDENCE_KIND[obligation['testability']]:
        mutant_errors.append(mid + ': evidence kind')
    signal = f"{obligation['summary_en']} — Trigger {trigger_ref}: {trigger['description_en'] if trigger else ''}"
    if observation.get('signal_en') != signal:
        mutant_errors.append(mid + ': signal')
    if observation.get('unavailable_outcome') != 'not_verified':
        mutant_errors.append(mid + ': unavailable outcome')
    isolation = observation.get('isolation_en', '')
    if owner_key not in isolation or 'Preserve every other baseline behavior' not in isolation:
        mutant_errors.append(mid + ': isolation')
    if owner_key == 'IIP-IDP16.a' and ('ECP' not in isolation or 'outside' not in isolation):
        mutant_errors.append(mid + ': ECP isolation')
    if executor.get('adapter') != mutant.get('target_role') + '-mutant-target' or executor.get('mutation_point') not in changes:
        mutant_errors.append(mid + ': executor scope')
    for key, expected in changes.items():
        if key not in targets or expected != {'outcome': 'violated'}:
            mutant_errors.append(mid + ':' + key + ':expected change')
            continue
        if outcomes[base][key].get('outcome') != 'satisfied':
            mutant_errors.append(mid + ':' + key + ':baseline')
        operation = executor.get('operation')
        semantics = targets[key].get('configuration_failure_semantics')
        if targets[key]['testability'] == 'CONFIG' and semantics == 'test_precondition' and operation == 'remove_required_capability':
            mutant_errors.append(mid + ':' + key + ':precondition mutation')
        if targets[key]['testability'] == 'CONFIG' and semantics == 'normative_capability' \
                and targets[key]['level'] not in ('MUST_NOT', 'SHOULD_NOT') and operation != 'remove_required_capability':
            mutant_errors.append(mid + ':' + key + ':capability mutation')
        if targets[key]['testability'] == 'ATTESTED' and operation not in ('emit_nonconforming_evidence', 'emit_prohibited_behavior'):
            mutant_errors.append(mid + ':' + key + ':attested evidence')
        detected.add(key)
    if mutant.get('unchanged_required') != 'all_others':
        mutant_errors.append(mid + ':unchanged')
check('G2-15', 'mutants have executable G1-bound triggers, evidence, isolation, and all-others oracle',
      not mutant_errors, mutant_errors[:8])

waived = {case['obligation'] for case in cases if case.get('mutant_waiver')}
check('G2-16', 'every observable obligation is detected or has a non-evaluative fixture',
      detected | waived == set(targets) and waived == NON_EVALUATIVE,
      {'missing': sorted(set(targets) - detected - waived)[:8], 'waivers': sorted(waived - NON_EVALUATIVE)[:8]})

control_mutants = {item['id']: item for item in control_doc.get('control_mutants') or []}
accept_expected = sorted(case['id'] for case in cases
                         if (case.get('universal_control_applicability') or {}).get('accept_everything') == 'changes')
reject_expected = sorted(case['id'] for case in cases
                         if (case.get('universal_control_applicability') or {}).get('reject_everything') == 'changes')
alternative_expected = {case['mutant_waiver']['alternative_control_fixture']: case['id']
                        for case in cases if case.get('mutant_waiver')}
alternative_actual = {item.get('id'): item.get('case') for item in control_doc.get('alternative_fixtures') or []}
control_mutant_ok = (
    set(control_mutants) == {'accept-everything', 'reject-everything'}
    and control_mutants['accept-everything'].get('must_change_cases') == accept_expected
    and control_mutants['reject-everything'].get('must_change_cases') == reject_expected
    and set(control_mutants['accept-everything'].get('bases') or []) == set(baselines)
    and set(control_mutants['reject-everything'].get('bases') or []) == set(baselines)
    and alternative_actual == alternative_expected)
check('G2-17', 'universal controls apply only to explicit receiver decisions', control_mutant_ok,
      {'accept': len(accept_expected), 'reject': len(reject_expected), 'alternatives': len(alternative_expected)})

spikes = {spike['id']: spike for spike in feasibility.get('spikes') or []}
test_sources = {}
for module in ('saml', 'api', 'peer'):
    source_root = ROOT / module / 'src/test'
    if source_root.exists():
        for path in source_root.rglob('*.java'):
            test_sources[f'{module}:{path.stem}'] = path.read_text(encoding='utf-8')
spike_errors = []
seen_verifiers = set()
for spike_id in [f'S{number}' for number in range(1, 7)]:
    spike = spikes.get(spike_id)
    if not spike or spike.get('status') != 'PASS':
        spike_errors.append(spike_id + ':status')
        continue
    for assertion in spike.get('assertions') or []:
        verifier = assertion.get('verified_by', '')
        if verifier in seen_verifiers:
            spike_errors.append(spike_id + ': duplicate verifier ' + verifier)
        seen_verifiers.add(verifier)
        module, symbol = verifier.split(':', 1) if ':' in verifier else ('', '')
        class_name, method = symbol.rsplit('.', 1) if '.' in symbol else ('', '')
        source = test_sources.get(f'{module}:{class_name}', '')
        if not source or not re.search(r'\bvoid\s+' + re.escape(method) + r'\s*\(', source):
            spike_errors.append(spike_id + ': missing verifier ' + verifier)
check('G2-18', 'all feasibility assertions map one-to-one to named executable tests',
      not spike_errors and set(spikes) == {f'S{number}' for number in range(1, 7)}, spike_errors[:8])

forbidden_keys = []
forbidden_values = []
verdict_pattern = re.compile(r'\b(?:PASS|FAIL|WARNING|CONFORMANT|NOT_SUPPORTED|SHOULD_CLASS|MUST_CLASS)\b')
def scan(value, path='', allow_g1_text=False):
    if isinstance(value, dict):
        for name, child in value.items():
            child_path = path + '/' + str(name)
            if name.lower() in ('level', 'verdict'):
                forbidden_keys.append(child_path)
            scan(child, child_path, allow_g1_text or name in (
                'interpretation_constraints', 'trigger_en', 'expected_behavior_en', 'instruction_en', 'signal_en',
                'status'))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan(child, path + f'/{index}', allow_g1_text)
    elif isinstance(value, str) and not allow_g1_text and verdict_pattern.search(value):
        forbidden_values.append(path)
for name, document in (('cases', case_doc), ('mutants', mutant_doc), ('baselines', baseline_doc),
                       ('controls', control_doc), ('feasibility', feasibility)):
    scan(document, '/' + name)
check('G2-19', 'G2 has no case-side level/Verdict fields or newly authored Verdict logic',
      not forbidden_keys and not forbidden_values, {'keys': forbidden_keys[:6], 'values': forbidden_values[:6]})

approval = None
approval_errors = []
approved_cases = set()
signature_info = None
if APPROVAL_PATH.exists():
    log = git('log', '-1', '--format=%H', '--', APPROVAL_REL)
    approval_commit = log.stdout.strip() if log.returncode == 0 else ''
    if not approval_commit:
        approval_errors.append('approval record is not committed')
    else:
        if git('verify-commit', approval_commit).returncode != 0:
            approval_errors.append('approval commit signature verification failed')
        blob = git('show', f'{approval_commit}:{APPROVAL_REL}', binary=True)
        if blob.returncode != 0:
            approval_errors.append('approval record cannot be read from signed commit')
        else:
            approval = yaml.safe_load(blob.stdout.decode()) or {}
            approval['_signed_commit'] = approval_commit
            try:
                jsonschema.Draft202012Validator(load_json('schema/g2-approval-v1.json')).validate(
                    {name: value for name, value in approval.items() if name != '_signed_commit'})
            except Exception as error:
                approval_errors.append(f'approval schema: {error}')
            target_commit = approval.get('target_commit')
            if not exact_commit(target_commit):
                approval_errors.append('target_commit is not an exact commit SHA')
            elif git('merge-base', '--is-ancestor', target_commit, approval_commit).returncode != 0:
                approval_errors.append('approval commit does not descend from target commit')
            else:
                changed = sorted(git('diff', '--name-only', f'{target_commit}..{approval_commit}').stdout.split())
                if changed != [APPROVAL_REL]:
                    approval_errors.append(f'C..A changes are not limited to {APPROVAL_REL}: {changed[:6]}')
                protected = protected_paths(target_commit)
                for relative in protected:
                    current = ROOT / relative
                    signed = git('show', f'{approval_commit}:{relative}', binary=True)
                    if not current.exists() or signed.returncode != 0 or sha_bytes(current.read_bytes()) != sha_bytes(signed.stdout):
                        approval_errors.append(relative + ' differs from signed approval commit')
                expected_artifacts = protected - {APPROVAL_REL}
                actual_artifacts = set((approval.get('artifact_digests') or {}).keys())
                if actual_artifacts != expected_artifacts:
                    approval_errors.append('artifact_digests do not cover protected target tree exactly')
                for relative in expected_artifacts:
                    target_blob = git('show', f'{target_commit}:{relative}', binary=True)
                    if target_blob.returncode != 0 or sha_bytes(target_blob.stdout) != approval['artifact_digests'].get(relative):
                        approval_errors.append(relative + ': target artifact digest mismatch')
            entries = approval.get('approvals') or []
            entry_map = {entry.get('case'): entry for entry in entries}
            if len(entry_map) != len(entries):
                approval_errors.append('approval case entries are not unique')
            try:
                lower = commit_time(target_commit)
                upper = commit_time(approval_commit)
            except Exception as error:
                approval_errors.append(str(error))
                lower = upper = None
            for case_id, case in case_by_id.items():
                entry = entry_map.get(case_id)
                if not entry or entry.get('case_digest') != case.get('case_digest'):
                    approval_errors.append(case_id + ': missing or stale approval')
                    continue
                if entry.get('reviewer') == case.get('authored_by'):
                    approval_errors.append(case_id + ': reviewer equals author')
                try:
                    parsed = datetime.datetime.fromisoformat(str(entry.get('approved_at')).replace('Z', '+00:00'))
                    if parsed.tzinfo is None or (lower and not (lower <= parsed <= upper)):
                        raise ValueError()
                except Exception:
                    approval_errors.append(case_id + ': approved_at is outside target..approval interval')
                approved_cases.add(case_id)
            signer = git('log', '-1', '--format=%GS|%GK|%GT', approval_commit)
            if signer.returncode == 0:
                parts = signer.stdout.strip().split('|')
                signature_info = {'signer': parts[0] if parts else None,
                                  'key': parts[1] if len(parts) > 1 else None,
                                  'trust': parts[2] if len(parts) > 2 else None}
                declared = {entry.get('reviewer') for entry in entries}
                evidence_reviewers = set((approval.get('evidence') or {}).get('reviewers') or [])
                if evidence_reviewers != declared:
                    approval_errors.append('evidence reviewers differ from per-case reviewers')
                if parts and declared - {parts[0]}:
                    approval_errors.append('approval reviewer does not match signing principal')

check('G2-30', 'signed approval record is valid when present', not approval_errors, approval_errors[:8])
pending = set(case_by_id) - approved_cases
check('G2-31', 'all role-specific case designs are independently approved', not pending, f'{len(pending)}/{len(case_by_id)} unapproved')

pending_ids = {'G2-31'}
blocking = [item for item in checks if item['result'] == 'FAIL' and item['id'] not in pending_ids]
complete = not blocking and not pending
report = {
    'task': 'g2Check', 'run_id': str(uuid.uuid4()),
    'executed_at': datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
    'provenance': {
        'repo_root': str(ROOT),
        'validator_source': os.environ.get('G2_VALIDATOR_SOURCE') or 'working-tree',
        'validator_source_kind': os.environ.get('G2_VALIDATOR_SOURCE_KIND') or 'working-tree',
        'runner_source': os.environ.get('G2_RUNNER_SOURCE') or 'working-tree',
    },
    'totals': {
        'requirements': len(coverage['requirements']), 'obligations': len(all_obligations),
        'case_target_obligations': len(targets), 'role_cases': len(cases),
        'mutants': len(mutants), 'baselines': len(baselines),
        'feasibility_spikes': len(spikes), 'checks': len(checks),
        'passed': sum(item['result'] == 'PASS' for item in checks),
        'failed': sum(item['result'] == 'FAIL' for item in checks),
        'blocking_failures': len(blocking),
    },
    'g2_approval': None if approval is None else {
        'target_commit': approval.get('target_commit'), 'approval_commit': approval.get('_signed_commit'),
        'signature': signature_info, 'approved_cases': len(approved_cases),
        'artifact_digests': approval.get('artifact_digests')},
    'g2': {
        'state': 'APPROVED' if complete else 'PENDING_REVIEW', 'unapproved': len(pending),
        'blocking_failures': [item['id'] for item in blocking], 'complete': complete,
        'complete_formula': 'no blocking failures AND every role-specific case approved by a signed record'},
    'checks': checks,
}
BUILD.mkdir(exist_ok=True)
(BUILD / 'g2-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(f"{report['totals']['passed']}/{report['totals']['checks']} PASS  (blocking failures: {len(blocking)})")
for item in checks:
    if item['result'] == 'FAIL':
        prefix = 'g2-pending' if item['id'] in pending_ids else 'BLOCK'
        print(f"  {prefix} {item['id']} {item['description']} | {item['detail'][:160]}")
sys.exit(1 if blocking else 0)
