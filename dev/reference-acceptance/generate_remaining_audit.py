"""Account for every unresolved observation without inferring a product verdict."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

# This generator adopts only independently replayed evidence.  Python removes
# assertions under -O, so fail before reading any evidence in that mode.
if not __debug__:
    raise RuntimeError('remaining-audit generation must not run with Python optimization')

import yaml

GROUPS = {
 'browser_oracle_missing': ('No automated evaluation after browser completion', 'Suite implementation', 'BrowserEvidenceTestCase returns browser.oracle-unavailable after completion. Implement the corresponding input generation, observations, and positive and negative controls.'),
 'partial_fixture': ('Only some test conditions are implemented', 'Suite implementation', 'Implement input generation and observations for every approved variant. Additional logins alone cannot complete verification.'),
 'configuration_evidence': ('Evidence verification and attestation after configuration', 'Configuration and evidence', 'Execute every variant and control for the case and collect evidence supporting the result. Attestation is disabled in the current Plan. Checking configuration alone does not establish Success.'),
 'attestation_disabled': ('Attestation is disabled', 'Configuration and evidence', 'Review the target configuration, operations, and implementation documentation. Include only items supported by collected evidence in a test plan with evidence verification enabled.'),
 'metadata_evidence': ('Additional metadata tests and observations are missing', 'Test-path investigation', 'Identify fixtures that have not been fetched or used, then run additional tests through the target import path. For rejection tests, silence alone does not establish success; determine how rejection can be proved.'),
 'browser_transcript': ('Additional browser and SLO observations are missing', 'Test-path investigation', 'Identify the required reception evidence. Check whether the Suite provides paths for IdP-initiated operations, alternate ACS endpoints, and additional Logout operations; implement missing paths.'),
 'pending_no_action': ('Old waiting results have expired by resume time', 'Retest in a new Run', 'On resume, the cases ended with delivery_or_response_unknown. Execute positive controls and common tests in a new Run and save evidence separately from the original SLO results.'),
 'inconclusive': ('Executed without a conclusive result', 'Individual diagnosis', 'Inspect reason codes and positive controls to distinguish Suite, configuration, and product causes. Do not turn silence or insufficient evidence into a product FAIL.'),
}

# Current code can supersede an old interaction mode without superseding its verdict.
IMPLEMENTATION_UPDATES = {
    'IIP-MD05-a3-idp-01': {
        'source_marker': 'id.startsWith("IIP-MD05-a3-")',
        'category': 'metadata_evidence',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/MetadataFixtureObservationTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/MetadataConfigCaseFactory.java',
        'registration': 'Map.entry("IIP-MD05.a3",',
        'next_action': 'Organization, ContactPerson, and AffiliationDescriptor inputs and Organization/Extensions negative controls have been added. Input acceptance is separate from the namespace qualification obligation; acceptance alone does not establish a product FAIL. A path for directly checking the namespace of published or configured extension points is required.',
    },
    'IIP-IDP19-b-idp-01': {
        'category': 'configuration_evidence',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/MultipleDecryptionKeysConfigurationTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedConfigCaseRegistry.java',
        'registration': 'new MultipleDecryptionKeysConfigurationTestCase(testCase,keys,executions)',
        'next_action': 'A path has been added to verify multiple-key configuration capability using successful single-key and multiple-key controls within the same Run. After deployment, execute it in a new Run and check reevaluation without configuration answers and evidence provenance. Metadata publication alone does not establish success.',
    },
    'IIP-IDP19-c-idp-01': {
        'category': 'browser_transcript',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/IdpBasicLogoutScenarioTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
        'registration': 'new IdpBasicLogoutScenarioTestCase(testCase.id(),',
        'next_action': 'A dedicated multiple-decryption-key path is registered. Prepare distinct encryption keys, observe rejection with an unregistered key, then verify decryption using the second metadata key in a new session. Product deployment, key configuration, and evidence collection are still required.',
    },
    'IIP-IDP19-a-idp-01': {
        'category': 'browser_transcript',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/IdpBasicLogoutScenarioTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
        'registration': 'new IdpBasicLogoutScenarioTestCase(testCase.id(),',
        'next_action': 'A dedicated EncryptedID decryption path is registered. After deployment, verify an unregistered-key rejection control and a successful response using a registered key in a new session. Failed controls or silence remain Not verified.',
    },
    'IIP-IDP18-a-idp-01': {
        'category': 'browser_transcript',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/IdpBasicLogoutScenarioTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
        'registration': 'new IdpBasicLogoutScenarioTestCase(testCase.id(),',
        'next_action': 'A dedicated Redirect acceptance scenario is registered. After deployment, use a fresh login in a new Run, send a signed Redirect LogoutRequest, and observe a response with verified signature and correlation. Substitution with POST or silence does not establish success.',
    },
    'IIP-IDP17-a-idp-01': {
        'category': 'browser_transcript',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/IdpBasicLogoutScenarioTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
        'registration': 'new IdpBasicLogoutScenarioTestCase(testCase.id(),',
        'next_action': 'The basic SP-initiated SLO scenario is registered. In a new Run after deployment, observe signature and session positive controls, LogoutRequest transmission, and a correlated LogoutResponse. Silence does not establish a product FAIL.',
    },
    'IIP-ALG03-a-idp-01': {
        'category': 'metadata_evidence',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/EcSignatureSupportTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
        'registration': 'return new EcSignatureSupportTestCase();',
        'next_action': 'ECDSA observation is implemented. Execute RSA positive, ECDSA positive, and invalid ECDSA signature controls in a new Run, collecting correlated responses and the complete history. An HTTP error alone does not prove rejection.',
    },
}

# The decryption-backed algorithm oracle exists even when an old Run says oracle-unavailable.
from verify_encrypted_sso_diagnosis import CASES as ENCRYPTION_DIAGNOSIS_CASES
IMPLEMENTATION_UPDATES.update({case_id: {
    'category': 'browser_transcript',
    'source': 'runner/src/main/java/com/samlscope/runner/cases/EncryptionAlgorithmObservation.java',
    'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
    'registration': 'new EncryptionAlgorithmBrowserEvidenceTestCase(',
    'next_action': 'Decryption-backed encryption algorithm evaluation is implemented. Enable target encryption during normal SSO and observe responses for the required generation algorithms and every combination.',
} for case_id in ENCRYPTION_DIAGNOSIS_CASES})

# Classification only: these labels describe why an observation is still unresolved.
# They never change a Verdict and are not product failures.
DIAGNOSIS = {
    'feature-absent': ('The product does not publish the feature, as confirmed from public metadata or equivalent evidence',
                       'This test cannot run because the product does not offer the feature (equivalent to skipped)'),
    'role-inapplicable': ('A variant requests an artifact that the target does not consume in its role',
                          'The variant is not consumed in the IdP role and is outside the execution scope; inapplicability has been established'),
    'evidence-form-mismatch': ('The product response does not match the evidence format required by the approved evaluation conditions',
                               'Not verified because the evidence format does not match the approved conditions; requirement interpretation needs review'),
    'operator-attestation-available': ('Can be verified through attestation or operator testimony',
                                       'Can be verified through operator testimony, with one answer per case. Attestation is disabled in the current Plan'),
    'suite-observation-gap': ('The Suite observation or execution path is not connected',
                              'Not verified that can be resolved by implementing the Suite path'),
}
_FEATURE_ABSENT = {
    'IIP-MD05-f7-idp-01', 'IIP-MD05-f8-idp-01', 'IIP-MD05-f9-idp-01', 'IIP-MD05-fa-idp-01',
    'IIP-MD05-fb-idp-01', 'IIP-MD05-fh-idp-01', 'IIP-MD05-fj-idp-01',
}
_ROLE_INAPPLICABLE = {'IIP-EXT01-b-idp-01', 'IIP-EXT01-c-idp-01'}
# Keycloak metadata consumption has no runtime fetch/aggregation path in its client model.
_KEYCLOAK_METADATA_FEATURE_ABSENT = {
    'IIP-MD01-a-idp-01', 'IIP-MD02-a-idp-01', 'IIP-MD02-b-idp-01', 'IIP-MD02-c-idp-01',
    'IIP-MD02-d-idp-01', 'IIP-MD03-a-idp-01', 'IIP-MD03-b-idp-01', 'IIP-MD03-c-idp-01',
    'IIP-MD03-d-idp-01', 'IIP-MD04-a-idp-01', 'IIP-MD04-b-idp-01', 'IIP-MD04-c-idp-01',
    'IIP-MD05-a-idp-01', 'IIP-MD05-a1-idp-01', 'IIP-MD05-a2-idp-01', 'IIP-MD05-a3-idp-01',
    'IIP-MD05-a5-idp-01', 'IIP-MD05-a8-idp-01', 'IIP-MD05-ac-idp-01', 'IIP-MD05-ad-idp-01',
    'IIP-MD05-ae-idp-01', 'IIP-MD05-af-idp-01', 'IIP-MD05-ah-idp-01', 'IIP-MD05-am-idp-01',
    'IIP-MD05-an-idp-01', 'IIP-MD05-ao-idp-01', 'IIP-MD05-ap-idp-01', 'IIP-MD05-aq-idp-01',
    'IIP-MD05-ar-idp-01', 'IIP-MD05-as-idp-01', 'IIP-MD05-b-idp-01',
    'IIP-MD05-c-idp-01', 'IIP-MD05-c2-idp-01', 'IIP-MD05-c3-idp-01', 'IIP-MD05-cd-idp-01',
    'IIP-MD05-d-idp-01', 'IIP-MD05-d1-idp-01', 'IIP-MD05-e-idp-01', 'IIP-MD05-e5-idp-01',
    'IIP-MD05-e7-idp-01', 'IIP-MD05-e8-idp-01', 'IIP-MD05-e9-idp-01', 'IIP-MD05-ea-idp-01',
    'IIP-MD05-eb-idp-01', 'IIP-MD05-g-idp-01', 'IIP-MD06-a1-idp-01', 'IIP-MD06-a2-idp-01',
    'IIP-MD06-a3-idp-01', 'IIP-MD06-a6-idp-01', 'IIP-MD06-a7-idp-01', 'IIP-MD06-a9-idp-01',
    'IIP-MD06-ab-idp-01', 'IIP-MD06-b-idp-01', 'IIP-MD07-a-idp-01',
}
# Cases whose sound observation needs the target to verify the metadata document signature. The
# reference Shibboleth metadata-providers.xml configures bare FilesystemMetadataProviders with no
# SignatureValidation filter, so the signed XPath transform is never applied and acceptance of a
# reject fixture does not by itself prove a target violation.
_SHIBBOLETH_SIGNATURE_DEPENDENT = {
    'IIP-MD03-a-idp-01', 'IIP-MD03-b-idp-01', 'IIP-MD04-a-idp-01',
    'IIP-MD05-am-idp-01', 'IIP-MD05-an-idp-01', 'IIP-MD05-ao-idp-01',
}
# The Suite can drive an admin import and then judge the product behavior, once the oracle exists.
_KEYCLOAK_METADATA_IMPORT_GAP = {
    'IIP-MD05-a4-idp-01', 'IIP-MD05-av-idp-01', 'IIP-MD05-aw-idp-01', 'IIP-MD05-c1-idp-01',
    'IIP-MD06-a-idp-01', 'IIP-MD06-a5-idp-01', 'IIP-MD06-a8-idp-01', 'IIP-MD07-b-idp-01',
    'IIP-MD11-a-idp-01', 'IIP-MD12-a-idp-01', 'IIP-MD12-b-idp-01', 'IIP-MD12-c-idp-01',
    'IIP-MD12-d-idp-01',
}
_KEYCLOAK_METADATA_ATTESTATION = {
    'IIP-MD05-c5-idp-01', 'IIP-MD05-c6-idp-01', 'IIP-MD05-c7-idp-01',
    'IIP-MD06-c-idp-01', 'IIP-MD09-a-idp-01', 'IIP-MD09-b-idp-01',
}
_EVIDENCE_FORM = {
    'idp.signed-request.inconclusive', 'idp.error-assertion.inconclusive',
    'idp.error-response.inconclusive', 'idp.version.inconclusive',
    'idp.acs-probe.inconclusive', 'idp.authn-context.inconclusive',
    'idp.nameid-policy.inconclusive', 'request.signing.unavailable',
    'control_failed', 'metadata.rsa-sha1.unobserved', 'delivery_or_response_unknown',
    'slo.encrypted-id.key-unavailable', 'slo.encrypted-id.multiple-keys.key-unavailable',
    'slo.encrypted-id.negative-control-failed',
}

def verify_keycloak_metadata_sets():
    sets = {
        'feature-absent': _KEYCLOAK_METADATA_FEATURE_ABSENT,
        'import-gap': _KEYCLOAK_METADATA_IMPORT_GAP,
        'attestation': _KEYCLOAK_METADATA_ATTESTATION,
    }
    names = list(sets)
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            overlap = sets[names[i]] & sets[names[j]]
            if overlap:
                raise ValueError(f'Keycloak metadata sets overlap: {names[i]}/{names[j]} {sorted(overlap)}')


verify_keycloak_metadata_sets()

def diagnose(row):
    case = row['case']
    reason = row['reason_code']
    if row.get('product') == 'keycloak' and row.get('profile') == 'metadata_idp':
        if case in _KEYCLOAK_METADATA_ATTESTATION:
            return 'operator-attestation-available'
        if case in _KEYCLOAK_METADATA_IMPORT_GAP or case in _KEYCLOAK_METADATA_FEATURE_ABSENT:
            # Absence could not be confirmed on the investigated path, so the classification
            # matches the fact: the Suite still needs the product's own import path.
            return 'suite-observation-gap'
    if case in _FEATURE_ABSENT:
        return 'feature-absent'
    if case in _ROLE_INAPPLICABLE:
        return 'role-inapplicable'
    if reason == 'attestation.interaction-disallowed' or row.get('mode') == 'ATTESTED':
        return 'operator-attestation-available'
    if reason in _EVIDENCE_FORM:
        return 'evidence-form-mismatch'
    return 'suite-observation-gap'

def implementation_audit():
    result = {}
    for case_id, update in IMPLEMENTATION_UPDATES.items():
        source = Path(update['source']).read_bytes()
        registry = Path(update['registry']).read_bytes()
        if update['registration'] not in registry.decode() or update.get('source_marker', case_id) not in source.decode():
            raise ValueError(f'Implementation registration needs re-audit: {case_id}')
        result[case_id] = dict(update, source_sha256=hashlib.sha256(source).hexdigest(),
                              registry_sha256=hashlib.sha256(registry).hexdigest())
    return result

def classify(row):
    reason=row['reason_code']; interaction=row.get('interaction') or {}
    if row['case'] in IMPLEMENTATION_UPDATES and reason in {'case.pending-interaction', 'browser.oracle-unavailable'}:
        return IMPLEMENTATION_UPDATES[row['case']]['category']
    if reason=='browser.oracle-unavailable': return 'browser_oracle_missing'
    if reason=='browser_fixture_partial': return 'partial_fixture'
    if reason=='attestation.interaction-disallowed': return 'attestation_disabled'
    if reason!='case.pending-interaction': return 'inconclusive'
    kind,mode=interaction.get('kind'),interaction.get('completionMode')
    if kind=='BROWSER' and mode=='OPERATOR': return 'browser_oracle_missing'
    if kind=='CONFIGURATION' and mode=='OPERATOR': return 'configuration_evidence'
    if kind=='CONFIGURATION' and mode=='TRANSCRIPT_OR_OPERATOR': return 'metadata_evidence'
    if kind=='BROWSER' and mode=='TRANSCRIPT': return 'browser_transcript'
    if not interaction:return 'pending_no_action'
    raise ValueError(f'Unclassified interaction: {row}')

def render(root,definitions,output):
    # Adopted campaign originals are immutable. Reuse their complete verification only within
    # this generation; a later invocation must re-read and verify the originals again.
    campaign_checks = {}

    def check_once(verifier, *args, **kwargs):
        def freeze(value):
            if isinstance(value, dict):
                return tuple(sorted((key, freeze(item)) for key, item in value.items()))
            if isinstance(value, (tuple, list)):
                return tuple(freeze(item) for item in value)
            return value
        key = (verifier, freeze(args), freeze(kwargs))
        if key not in campaign_checks:
            campaign_checks[key] = verifier(*args, **kwargs)
        return campaign_checks[key]

    implementations=implementation_audit()
    rows=json.loads((root/'baseline.json').read_text())
    catalog={c['id']:c for c in yaml.safe_load(definitions.read_text())['cases']}
    baseline_count=len(rows)
    refreshed=[]; transitions=[]
    qualified_full_ui = set()
    for row in rows:
        if classify(row)=='pending_no_action':
            path=root/row['product']/'fresh_common/result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent),interaction=None)
            row['verdict']=case['verdict']; row['evidence']=case['evidence']
            transitions.append(dict(row))
        additional = {'browser_sso_idp': {'IIP-G03-b-idp-01', 'IIP-SSO07-b-idp-01'},
                      'metadata_idp': {'IIP-MD05-fi-idp-01'}}
        if row['case'] in additional.get(row['profile'], set()):
            batch = ('literal-integrated-implementation' if row['case']=='IIP-G02-a-idp-01' else 'crypto-integrated-implementation' if row['case']=='IIP-SSO07-b-idp-01' else 'additional-implementation')
            path=root.parent/batch/row['product']/row['profile']/'result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent),interaction=None,
                       verdict=case['verdict'],evidence=case['evidence'],diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        if row['product']=='shibboleth' and ((row['profile']=='browser_sso_idp' and row['case']=='IIP-IDP12-c-idp-01') or row['profile']=='metadata_idp' and row['case'] in {'IIP-MD07-a-idp-01', 'IIP-MD06-a9-idp-01', 'IIP-MD06-a7-idp-01', 'IIP-MD06-a5-idp-01', 'IIP-MD05-ad-idp-01'}):
            folder='polling-bssso' if row['profile']=='browser_sso_idp' else 'polling'
            path=root.parent/'integrated-implementation/shibboleth'/folder/'result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            assert case['verdict']=='PASS' and case['reason_code']=='metadata.fixture-probe.satisfied'
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent),interaction=None,
                       verdict=case['verdict'],evidence=case['evidence'])
            transitions.append(dict(row))
        from verify_shibboleth_import_batch import verify as verify_shib_import
        shib_import_evidence={
            'IIP-MD05-ff-idp-01':('shibboleth-md05ff-v99',['disco-hints-ipv6-cidr','disco-hints-ipv4-cidr']),
            'IIP-MD05-d-idp-01':('shibboleth-md05d-v104',['entity-attributes-direct','entity-attributes-assertion',
                'entity-attributes-assertion-conditions','entity-attributes-multiple']),
            'IIP-MD05-c2-idp-01':('shibboleth-md05c2-v105',['nested-entities','roles-sp-second']),
            'IIP-MD05-e-idp-01':('shibboleth-md05e-v106',['algorithm-signing-256-keysize-excluded',
                'algorithm-entity-sha256','algorithm-encryption-multiple','algorithm-absent']),
            'IIP-MD05-f-idp-01':('shibboleth-md05f-v107',['full-ui-info']),
            'IIP-MD05-b-idp-01':('shibboleth-md05b-v110',['schema-global-element-families',
                'schema-additional-metadata-location','schema-localized-name-boundary',
                'schema-attribute-consuming-service','schema-sso-endpoint-set']),
            'IIP-MD02-b-idp-01':('shibboleth-md02b-v110',['redirect-301','redirect-302','redirect-307']),
            'IIP-MD05-ap-idp-01':('shibboleth-md05apaq-v111',['nested-valid-until-child-shorter','nested-entities']),
            'IIP-MD05-aq-idp-01':('shibboleth-md05apaq-v111',['nested-cache-duration-parent-shorter','nested-entities'])}
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case'] in shib_import_evidence and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            folder,variants=shib_import_evidence[row['case']]
            path, imported_cases = check_once(verify_shib_import, root.parent.parent/'reference-20260918',
                    folder=folder, adopted={row['case']:variants})
            raw=path.read_bytes(); result=json.loads(raw); case=imported_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       result_file=path.name,
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        from verify_simplesamlphp_import_batch import verify as verify_ssp_import2
        ssp_import_evidence={
            'IIP-MD05-ff-idp-01':('simplesamlphp-md05ff-v99',['disco-hints-ipv6-cidr','disco-hints-ipv4-cidr']),
            'IIP-MD05-d-idp-01':('simplesamlphp-md05d-v104',['entity-attributes-direct','entity-attributes-assertion',
                'entity-attributes-assertion-conditions','entity-attributes-multiple']),
            'IIP-MD05-c2-idp-01':('simplesamlphp-md05c2-v105',['nested-entities','roles-sp-second']),
            'IIP-MD05-e-idp-01':('simplesamlphp-md05e-v106',['algorithm-signing-256-keysize-excluded',
                'algorithm-entity-sha256','algorithm-encryption-multiple','algorithm-absent']),
            'IIP-MD05-f-idp-01':('simplesamlphp-md05f-v107',['full-ui-info']),
            'IIP-MD02-b-idp-01':('simplesamlphp-md02b-v110',['redirect-301','redirect-302','redirect-307']),
            'IIP-MD05-ap-idp-01':('simplesamlphp-md05apaq-v111',['nested-valid-until-child-shorter','nested-entities']),
            'IIP-MD05-aq-idp-01':('simplesamlphp-md05apaq-v111',['nested-cache-duration-parent-shorter','nested-entities'])}
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case'] in ssp_import_evidence and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            folder,variants=ssp_import_evidence[row['case']]
            path, imported_cases = check_once(verify_ssp_import2, 
                root.parent.parent/'reference-20260918', folder=folder, adopted={row['case']: variants})
            raw=path.read_bytes(); result=json.loads(raw); case=imported_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       result_file=path.name,
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        from verify_keycloak_md05ff import verify as verify_kc_import2
        kc_import_evidence={
            'IIP-MD05-ff-idp-01':('keycloak-md05ff-v99',['disco-hints-ipv6-cidr','disco-hints-ipv4-cidr']),
            'IIP-MD05-d-idp-01':('keycloak-md05d-v104',['entity-attributes-direct','entity-attributes-assertion',
                'entity-attributes-assertion-conditions','entity-attributes-multiple']),
            'IIP-MD05-e-idp-01':('keycloak-md05e-v106',['algorithm-signing-256-keysize-excluded',
                'algorithm-entity-sha256','algorithm-encryption-multiple','algorithm-absent']),
            'IIP-MD02-b-idp-01':('keycloak-md02b-v110',['redirect-301','redirect-302','redirect-307'])}
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case'] in kc_import_evidence and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            folder,variants=kc_import_evidence[row['case']]
            path, imported_cases = check_once(verify_kc_import2, root.parent.parent/'reference-20260918',
                    folder=folder, adopted={row['case']:variants})
            raw=path.read_bytes(); result=json.loads(raw); case=imported_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       result_file=path.name,
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' and row['case'] in {'IIP-IDP06-a-idp-01','IIP-IDP06-b-idp-01'}:
            batch='literal-integrated-implementation' if row['case']=='IIP-IDP06-a-idp-01' else 'queue-integrated-implementation'
            path=root.parent/batch/'simplesamlphp/browser_sso_idp/result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            assert case['verdict']=='PASS' and case['reason_code']=='force_authn_fresh_authentication_observed'
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent),interaction=None,
                       verdict=case['verdict'],evidence=case['evidence'])
            transitions.append(dict(row))
        if row['profile']=='single_logout_idp' and row['case'] in {'IIP-IDP17-a-idp-01','IIP-IDP18-a-idp-01'}:
            path=root.parent/'slo-redirect-receiver-integrated'/row['product']/'single_logout_idp/result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            expected='slo.basic.synchronous-response-observed' if row['case']=='IIP-IDP17-a-idp-01' else 'slo.redirect.logout-request-accepted.satisfied'
            assert case['verdict']=='PASS' and case['reason_code']==expected
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent),interaction=None,
                       verdict=case['verdict'],evidence=case['evidence'])
            transitions.append(dict(row))
        if row['profile']=='single_logout_idp' and row['case']=='IIP-IDP19-a-idp-01':
            path=root.parent/'slo-encrypted-id-integrated'/row['product']/'single_logout_idp/result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            expected={'keycloak':('NOT_VERIFIED','slo.encrypted-id.key-unavailable'),
                      'shibboleth':('PASS','slo.encrypted-id.decryption-observed'),
                      'simplesamlphp':('NOT_VERIFIED','slo.encrypted-id.negative-control-failed')}[row['product']]
            assert (case['verdict'],case['reason_code'])==expected
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent),interaction=None,
                       verdict=case['verdict'],evidence=case['evidence'])
            transitions.append(dict(row))
        if row['profile']=='single_logout_idp' and row['case']=='IIP-IDP19-c-idp-01':
            path=root.parent/'slo-multiple-keys-integrated'/row['product']/'single_logout_idp/result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            expected={'keycloak':('NOT_VERIFIED','slo.encrypted-id.multiple-keys.key-unavailable'),
                      'shibboleth':('PASS','slo.encrypted-id.multiple-keys.decryption-observed'),
                      'simplesamlphp':('NOT_VERIFIED','slo.encrypted-id.multiple-keys.configuration-unavailable')}[row['product']]
            assert (case['verdict'],case['reason_code'])==expected
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent),interaction=None,
                       verdict=case['verdict'],evidence=case['evidence'])
            transitions.append(dict(row))
        if row['profile']=='single_logout_idp' and row['product']=='shibboleth' and row['case']=='IIP-IDP19-b-idp-01':
            path=root.parent/'key-capability-integrated'/row['product']/'single_logout_idp/result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            expected={'keycloak':('NOT_VERIFIED','slo.encrypted-id.key-unavailable'),
                      'shibboleth':('PASS','configuration.multiple-decryption-keys.observed'),
                      'simplesamlphp':('NOT_VERIFIED','slo.encrypted-id.negative-control-failed')}[row['product']]
            assert (case['verdict'],case['reason_code'])==expected
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent),interaction=None,
                       verdict=case['verdict'],evidence=case['evidence'])
            transitions.append(dict(row))
        alg_products={'keycloak','shibboleth'}|({'simplesamlphp'} if row['profile']=='browser_sso_idp' else set())
        if row['case'] in {'IIP-ALG04-a-idp-01','IIP-ALG04-b-idp-01','IIP-ALG06-a-idp-01',
                           'IIP-ALG06-b-idp-01','IIP-ALG06-c-idp-01','IIP-ALG06-d-idp-01'} \
                and row['profile'] in {'browser_sso_idp','ecp_idp'} and row['product'] in alg_products:
            expected={'keycloak':{'IIP-ALG04-b-idp-01':('PASS','browser.encryption.aes256-gcm.decrypted'),
                                  'IIP-ALG06-b-idp-01':('PASS','browser.encryption.rsa-oaep.decrypted')},
                      'shibboleth':{'IIP-ALG04-a-idp-01':('PASS','browser.encryption.aes128-gcm.decrypted'),
                                    'IIP-ALG06-a-idp-01':('PASS','browser.encryption.rsa-oaep-mgf1p.decrypted')},
                      'simplesamlphp':{}}[row['product']]
            path=root.parent.parent/'reference-20260915/algorithm-observation-batch'/row['product']/row['profile']/'result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            want=expected.get(row['case'],('NOT_VERIFIED','case.pending-interaction'))
            assert (case['verdict'],case['reason_code'])==want, (row['product'],row['profile'],row['case'],case['verdict'],case['reason_code'])
            interactions_path=path.parent/'interactions'
            interaction=None
            if interactions_path.exists():
                interaction=next((i for i in json.loads(interactions_path.read_text()) if i.get('caseId')==row['case']),None)
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent.relative_to(root.parents[3])),interaction=interaction,
                       verdict=case['verdict'],evidence=case['evidence'],diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        peer_retests={
            ('keycloak','browser_sso_idp'):'reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo',
            ('shibboleth','browser_sso_idp'):'reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp',
            ('keycloak','ecp_idp'):'reference-20260915/peer-intent/keycloak/ecp_alg',
            ('simplesamlphp','browser_sso_idp'):'reference-20260915/peer-intent/simplesamlphp/browser_alg_enc',
            ('simplesamlphp','ecp_idp'):'reference-20260915/peer-intent/simplesamlphp/ecp_alg_enc',
            ('keycloak','single_logout_idp'):'reference-20260915/supplemental-key-integrated/keycloak/single_logout_idp',
            ('shibboleth','single_logout_idp'):'reference-20260915/peer-intent/shibboleth/slo_target_logout',
            ('simplesamlphp','single_logout_idp'):'reference-20260914/slo-receive-integrated/simplesamlphp/single_logout_idp',
        }
        peer_expectations={
            ('keycloak','browser_sso_idp'):{
                'IIP-ALG04-a-idp-01':('PASS','browser.encryption.aes128-gcm.decrypted'),
                'IIP-ALG06-a-idp-01':('PASS','browser.encryption.rsa-oaep-mgf1p.decrypted'),
                'IIP-ALG06-c-idp-01':('PASS','browser.encryption.digest-combinations.decrypted'),
                'IIP-SSO01-g-idp-01':('PASS','browser.normal-flow.success-responses-have-assertions'),
                'IIP-SSO01-z-idp-01':('WARNING','browser.normal-flow.unsolicited-sso-observed')},
            ('shibboleth','browser_sso_idp'):{
                'IIP-SSO01-g-idp-01':('PASS','browser.normal-flow.success-responses-have-assertions'),
                'IIP-SSO01-k-idp-01':('PASS','browser.normal-flow.bearer-recipient-and-expiry-valid'),
                'IIP-SSO01-z-idp-01':('WARNING','browser.normal-flow.unsolicited-sso-observed')},
            ('keycloak','ecp_idp'):{
                'IIP-ALG04-a-idp-01':('PASS','browser.encryption.aes128-gcm.decrypted'),
                'IIP-ALG06-a-idp-01':('PASS','browser.encryption.rsa-oaep-mgf1p.decrypted')},
            ('simplesamlphp','browser_sso_idp'):{
                'IIP-ALG06-a-idp-01':('PASS','browser.encryption.rsa-oaep-mgf1p.decrypted'),
                'IIP-IDP09-a-idp-01':('PASS','configuration.passive.assertion-encryption-capability')},
            ('simplesamlphp','ecp_idp'):{
                'IIP-ALG06-a-idp-01':('PASS','browser.encryption.rsa-oaep-mgf1p.decrypted')},
            ('keycloak','single_logout_idp'):{
                'IIP-IDP17-c-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP17-r-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP17-s-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP18-b-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP18-c-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP18-d-idp-01':('NOT_VERIFIED','browser.oracle-unavailable')},
            ('shibboleth','single_logout_idp'):{
                'IIP-IDP17-c-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP17-n-idp-01':('NOT_VERIFIED','slo.identifier.strong-match-unobservable'),
                'IIP-IDP17-r-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP17-s-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP17-u-idp-01':('NOT_VERIFIED','slo.not-on-or-after.correlation-unavailable'),
                'IIP-IDP18-b-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP18-c-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP18-d-idp-01':('NOT_VERIFIED','browser.oracle-unavailable')},
            ('simplesamlphp','single_logout_idp'):{
                'IIP-IDP17-c-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP17-r-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP17-s-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP18-b-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP18-c-idp-01':('NOT_VERIFIED','browser.oracle-unavailable'),
                'IIP-IDP18-d-idp-01':('NOT_VERIFIED','browser.oracle-unavailable')},
        }
        peer_key=(row['product'],row['profile'])
        if peer_key in peer_retests and row['case'] in peer_expectations[peer_key] and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            path=root.parent.parent/peer_retests[peer_key]/'result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            want=peer_expectations[peer_key][row['case']]
            assert (case['verdict'],case['reason_code'])==want,(row['product'],row['case'],case['verdict'],case['reason_code'])
            interactions_path=path.parent/'interactions'
            interaction=None
            if interactions_path.exists():
                interaction=next((i for i in json.loads(interactions_path.read_text()) if i.get('caseId')==row['case']),None)
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=interaction,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        slo_probe={
            'keycloak':'reference-20260915/slo-oracle/keycloak/slo_probe_browser',
            'shibboleth':'reference-20260915/slo-oracle/shibboleth/slo_probe_browser',
            'simplesamlphp':'reference-20260915/slo-oracle/simplesamlphp/slo_probe_browser',
        }
        probe_expectations={
            'keycloak':{
                'IIP-IDP17-b-idp-01':('PASS','slo.async.mismatch-not-applied'),
                'IIP-IDP17-b1-idp-01':('FAIL','slo.async.response-returned'),
                'IIP-IDP17-b2-idp-01':('PASS','slo.async.feedback.distinguishes-success-and-failure'),
                'IIP-IDP17-x-idp-01':('PASS','slo.destination-mismatch.not-applied'),
                'IIP-IDP17-y-idp-01':('FAIL','slo.rejection.applied-to-session'),
                'IIP-IDP17-z-idp-01':('FAIL','slo.rejection.applied-to-session'),
                'IIP-IDP17-aa-idp-01':('WARNING','slo.invalid-signature.accepted-as-success'),
                'IIP-IDP17-al-idp-01':('FAIL','slo.rejection.applied-to-session')},
            'shibboleth':{
                'IIP-IDP17-b-idp-01':('PASS','slo.async.mismatch-not-applied'),
                'IIP-IDP17-b1-idp-01':('PASS','slo.async.no-response'),
                'IIP-IDP17-b2-idp-01':('PASS','slo.async.feedback.distinguishes-success-and-failure'),
                'IIP-IDP17-x-idp-01':('PASS','slo.destination-mismatch.not-applied'),
                'IIP-IDP17-y-idp-01':('WARNING','slo.tampered-signature.not-applied'),
                'IIP-IDP17-z-idp-01':('WARNING','slo.invalid-signature.not-relied-upon'),
                'IIP-IDP17-aa-idp-01':('WARNING','slo.invalid-signature.no-error-response'),
                'IIP-IDP17-al-idp-01':('PASS','slo.excluded-content.rejected')},
            'simplesamlphp':{
                'IIP-IDP17-b-idp-01':('FAIL','slo.async.mismatch-response-returned'),
                'IIP-IDP17-b1-idp-01':('FAIL','slo.async.response-returned'),
                'IIP-IDP17-b2-idp-01':('NOT_VERIFIED','slo.async.feedback.unrecognized'),
                'IIP-IDP17-x-idp-01':('FAIL','slo.rejection.applied-to-session'),
                'IIP-IDP17-y-idp-01':('WARNING','slo.tampered-signature.not-applied'),
                'IIP-IDP17-z-idp-01':('WARNING','slo.invalid-signature.not-relied-upon'),
                'IIP-IDP17-aa-idp-01':('WARNING','slo.invalid-signature.no-error-response'),
                'IIP-IDP17-al-idp-01':('PASS','slo.excluded-content.rejected')},
        }
        if row['profile']=='single_logout_idp' and row['product'] in slo_probe \
                and row['case'] in probe_expectations[row['product']] and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            path=root.parent.parent/slo_probe[row['product']]/'result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            want=probe_expectations[row['product']][row['case']]
            assert (case['verdict'],case['reason_code'])==want,(row['product'],row['case'],case['verdict'],case['reason_code'])
            interactions_path=path.parent/'interactions'
            interaction=None
            if interactions_path.exists():
                interaction=next((i for i in json.loads(interactions_path.read_text()) if i.get('caseId')==row['case']),None)
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=interaction,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        slo_18b={
            'keycloak':'reference-20260915/slo-oracle/keycloak/slo_18b',
            'shibboleth':'reference-20260915/slo-oracle/shibboleth/slo_18b',
            'simplesamlphp':'reference-20260915/slo-oracle/simplesamlphp/slo_18b',
        }
        if row['profile']=='single_logout_idp' and row['case']=='IIP-IDP18-b-idp-01' \
                and row['product'] in slo_18b and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            path=root.parent.parent/slo_18b[row['product']]/'result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            assert (case['verdict'],case['reason_code'])==('PASS','slo.redirect-response.observed'),(
                row['product'],case['verdict'],case['reason_code'])
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        target_initiated={
            'shibboleth':'reference-20260915/peer-intent/shibboleth/slo_audit',
            'keycloak':'reference-20260915/peer-intent/keycloak/slo_audit',
            'simplesamlphp':'reference-20260915/peer-intent/simplesamlphp/slo_audit',
        }
        target_expectations={
            'shibboleth':{
                'IIP-IDP17-c-idp-01':('WARNING','slo.propagation.choice-recorded'),
                'IIP-IDP17-r-idp-01':('NOT_VERIFIED','slo.propagation.failure-induction-unavailable'),
                'IIP-IDP17-s-idp-01':('NOT_VERIFIED','slo.partial-logout.unobserved'),
                'IIP-IDP18-c-idp-01':('PASS','slo.redirect-request.observed'),
                'IIP-IDP18-d-idp-01':('NOT_VERIFIED','slo.redirect-response.unavailable')},
            'keycloak':{
                'IIP-IDP17-c-idp-01':('NOT_VERIFIED','slo.propagation.not-observed'),
                'IIP-IDP17-r-idp-01':('NOT_VERIFIED','slo.propagation.not-observed'),
                'IIP-IDP17-s-idp-01':('NOT_VERIFIED','slo.partial-logout.not-observed'),
                'IIP-IDP18-c-idp-01':('NOT_VERIFIED','slo.redirect-request.not-observed'),
                'IIP-IDP18-d-idp-01':('NOT_VERIFIED','slo.redirect-response.not-observed')},
            'simplesamlphp':{
                'IIP-IDP17-c-idp-01':('NOT_VERIFIED','slo.propagation.not-observed'),
                'IIP-IDP17-r-idp-01':('NOT_VERIFIED','slo.propagation.not-observed'),
                'IIP-IDP17-s-idp-01':('NOT_VERIFIED','slo.partial-logout.not-observed'),
                'IIP-IDP18-c-idp-01':('NOT_VERIFIED','slo.redirect-request.not-observed'),
                'IIP-IDP18-d-idp-01':('NOT_VERIFIED','slo.redirect-response.not-observed')},
        }
        if row['profile']=='single_logout_idp' and row['product'] in target_initiated \
                and row['case'] in target_expectations[row['product']] \
                and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            path=root.parent.parent/target_initiated[row['product']]/'result.json'
            raw=path.read_bytes(); result=json.loads(raw)
            case=next(c for req in result['requirements'] for c in req['cases'] if c['id']==row['case'])
            want=target_expectations[row['product']][row['case']]
            assert (case['verdict'],case['reason_code'])==want,(row['product'],row['case'],case['verdict'],case['reason_code'])
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        # Participant sessions captured through the target's unsolicited SSO profile correlate the
        # target-issued LogoutRequest with the established participant session, resolving the
        # identifier strong-match and the NotOnOrAfter bound.
        from verify_slo_participant_capture import ADOPTED as SLO_PARTICIPANT_ADOPTED, verify as verify_slo_participant
        if row['profile']=='single_logout_idp' and row['product']=='shibboleth' \
                and row['case'] in SLO_PARTICIPANT_ADOPTED and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            path, verified_cases = check_once(verify_slo_participant, root.parent.parent/'reference-20260918')
            raw=path.read_bytes(); result=json.loads(raw); case=verified_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        # Suite participant sessions established through SimpleSAMLphp's unsolicited SSO profile
        # let the product's own logout propagate LogoutRequests to the participants, recording the
        # informational propagation and the HTTP-Redirect LogoutRequest binding. IIP-IDP18.c's
        # variant additionally requires the participant SLO endpoint to be Redirect-only.
        from verify_slo_ssp_propagation import ADOPTED as SSP_SLO_ADOPTED, verify as verify_ssp_slo
        if row['profile']=='single_logout_idp' and row['product']=='simplesamlphp' \
                and row['case'] in SSP_SLO_ADOPTED and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            path, verified_cases = check_once(verify_ssp_slo, root.parent.parent/'reference-20260918')
            raw=path.read_bytes(); result=json.loads(raw); case=verified_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        # The reference IdP's own iframe logout presents an explicit Continue button after an
        # induced participant failure. The one-click repeat proves the final PartialLogout,
        # but not continuation to another participant; IIP-IDP17.r remains NOT_VERIFIED.
        from verify_ssp_iframe_partial_logout import ADOPTED as SSP_PARTIAL_ADOPTED, verify as verify_ssp_partial
        if row['profile']=='single_logout_idp' and row['product']=='simplesamlphp' \
                and row['case'] in SSP_PARTIAL_ADOPTED and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            path, verified_cases = check_once(verify_ssp_partial, root.parent.parent/'reference-20260930')
            raw=path.read_bytes(); result=json.loads(raw); case=verified_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        # An exact RequestedAuthnContext yielded a correlated encrypted Success whose
        # decrypted class differs. The read-only in-container audit is bound to the
        # exported request/response originals and the Run's existing plan key.
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-IDP05-a-idp-01' and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            from verify_keycloak_idp_error_response import verify as verify_idp_error_response
            path, verified_cases = check_once(verify_idp_error_response, root)
            raw=path.read_bytes(); result=json.loads(raw); case=verified_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        # Product parsers explicitly rejected both approved DTD variants, while the
        # same Run retained a correlated baseline SSO success and restored config.
        if row['product'] in ('keycloak','simplesamlphp','shibboleth') and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-G03-b-idp-01' and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            from verify_keycloak_dtd_acceptance import verify as verify_keycloak_dtd
            path, verified_cases = check_once(verify_keycloak_dtd, 
                root, 'ssp' if row['product']=='simplesamlphp' else row['product'])
            raw=path.read_bytes(); result=json.loads(raw); case=verified_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        # The SimpleSAMLphp browser chain adds an IdP-initiated (unsolicited) success to the
        # SP-initiated success, so IIP-SSO01.g sees both success paths with an Assertion and
        # IIP-SSO01.z records the unsolicited success.
        from verify_ssp_browser_chain import ADOPTED as SSP_BROWSER_ADOPTED, verify as verify_ssp_browser
        if row['profile']=='browser_sso_idp' and row['product']=='simplesamlphp' \
                and row['case'] in SSP_BROWSER_ADOPTED and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            path, verified_cases = check_once(verify_ssp_browser, root.parent.parent/'reference-20260918')
            raw=path.read_bytes(); result=json.loads(raw); case=verified_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        # A native target-initiated logout proves continuation through the product's SAML
        # originals, the Suite's correlated response, and byte-exact metadata restoration.
        from verify_shibboleth_target_slo_continue import CASE as SLO_PROPAGATION_CASE, verify as verify_slo_propagation
        if row['profile']=='single_logout_idp' and row['product']=='shibboleth' \
                and row['case']==SLO_PROPAGATION_CASE and row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':
            path, verified_cases = check_once(verify_slo_propagation, root.parent.parent/'reference-20260930')
            if row['case'] in verified_cases:
                raw=path.read_bytes(); result=json.loads(raw); case=verified_cases[row['case']]
                row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
                row.update(run=result['run']['id'],reason_code=case['reason_code'],
                           result_sha256=hashlib.sha256(raw).hexdigest(),
                           evidence_folder=str(path.parent.relative_to(root.parents[3])),
                           interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                           diagnostics=case.get('diagnostics',{}))
                transitions.append(dict(row))
        # Do not adopt the older slo_target_logout_18cd/rs result for IIP-IDP18-d: its
        # 'SATISFIED slo.redirect-response.consumed' outcome predates the current
        # LogoutTranscriptProfileCase.TARGET_REDIRECT_RESPONSE_CONSUMED oracle, which has no
        # positive path (only VIOLATED or NOT_VERIFIED). A successful page load is explicitly not
        # proof that the IdP consumed the response, so the observation stays NOT_VERIFIED.
        # Native console import followed by signed SSO, with per-fixture cleanup evidence.
        from verify_keycloak_import_batch import ADOPTED, verify as verify_import_batch
        if row['product']=='keycloak' and row['profile']=='metadata_idp' and row['case'] in ADOPTED:
            path, imported_cases = check_once(verify_import_batch, root.parent.parent/'reference-20260917')
            raw=path.read_bytes(); result=json.loads(raw); case=imported_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        from verify_simplesamlphp_import_batch import ADOPTED as SSP_ADOPTED, verify as verify_ssp_import
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case'] in SSP_ADOPTED:
            path, imported_cases = check_once(verify_ssp_import, root.parent.parent/'reference-20260917')
            raw=path.read_bytes(); result=json.loads(raw); case=imported_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        # Adopt only explicit absence notes and the tested aggregate child-count obligation.
        from verify_publisher_ui_batch import ADOPTED as UI_ADOPTED, verify as verify_ui
        selected = None
        # The native-console ACS URL campaign retains the complete imported-client
        # read-back, deterministic temporary redirect-URI mutation, restored/deleted
        # state, request/response originals, and runtime bindings.  Its verifier is
        # fail-closed and accepts only the two correlated IDP12.e fixtures.
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-IDP12-e-idp-01':
            from verify_keycloak_idp12e_acceptance import verify as verify_keycloak_idp12e
            selected = check_once(verify_keycloak_idp12e, 
                root.parent.parent/'reference-20260930'/'keycloak-idp12e-v145')
        # Recorder-backed target-local terminal errors can now conclude exactly three approved
        # SSO scenarios.  The adoption gate independently replays every request/response/body
        # original, the positive controls and signed mutants, target/Suite runtime identity,
        # byte-exact restoration, formal re-evaluation, and nine evidence tamper mutations.
        if row['profile']=='browser_sso_idp' and row['product'] in {
                'keycloak','shibboleth','simplesamlphp'} and row['case'] in {
                'IIP-SSO01-d-idp-01','IIP-SSO01-ak-idp-01','IIP-SSO01-em-idp-01'}:
            from verify_terminal_http_acceptance import PRODUCT_CASES as TERMINAL_HTTP_CASES
            from verify_terminal_http_acceptance import verify as verify_terminal_http
            if row['case'] in TERMINAL_HTTP_CASES[row['product']]:
                selected = check_once(verify_terminal_http, root.parent.parent/'reference-20260930', row['product'])
        # The IDP12.b adoption gate replays the eight approved fixtures, wire XML
        # signatures, native other-entity registration, target runtime identity,
        # browser originals, hostile-ACS non-arrival, and exact restoration before
        # returning this single result.  Merely finding result.json is insufficient.
        if row['product'] in {'keycloak','shibboleth'} and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-IDP12-b-idp-01':
            from verify_idp12b_acceptance import verify as verify_idp12b
            selected = check_once(verify_idp12b, root.parent.parent/'reference-20260930', row['product'])
        # Reuse the sealed Keycloak EXT01.b browser Run for SSO01.k only after its dedicated
        # gate has bound the approved definition, exact five Recorder references, normal-flow
        # and alternate-ACS controls, wire signatures, encrypted Assertions, pinned runtimes,
        # and complete native restoration.  The gate is read-only and rejects evidence
        # mutation; locating the EXT01.b result alone is not sufficient for adoption.
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-k-idp-01':
            from verify_sso01k_keycloak_acceptance import verify_adoption as verify_sso01k_keycloak
            ext_root = root.parent.parent/'reference-20260930'/'ext01b-keycloak-v158'
            selected = check_once(verify_sso01k_keycloak, ext_root)
        # EXT01.b is an all-of check over the three approved extension placements plus the
        # successful baseline.  Adopt only independently Run-bound four-profile batches after
        # the gate has replayed every Recorder request/response original, exact formal evidence
        # set, target/Suite runtime identity, native restoration, and tamper controls.
        ext01b_roots = {
            'keycloak': 'ext01b-keycloak-v158',
            'shibboleth': 'ext01b-shibboleth-v155',
            'simplesamlphp': 'ext01b-simplesamlphp-v158',
        }
        if row['product'] in ext01b_roots and row['profile'] in {
                'browser_sso_idp','ecp_idp','metadata_idp','single_logout_idp'} \
                and row['case']=='IIP-EXT01-b-idp-01':
            from verify_ext01b_acceptance import verify_batch as verify_ext01b
            ext_root = root.parent.parent/'reference-20260930'/ext01b_roots[row['product']]
            accepted = check_once(verify_ext01b, ext_root, row['product'])
            accepted_runs = {value['profile']: value['run'] for value in accepted['observations']}
            path = ext_root/row['profile']/'evaluation-terminal-http-v1'/'result.json'
            result = json.loads(path.read_text())
            cases = {case['id']: case for requirement in result['requirements']
                     for case in requirement['cases']}
            if result['run']['id'] != accepted_runs.get(row['profile']):
                raise ValueError('EXT01.b accepted Run/profile binding mismatch')
            selected = (path, cases)
        # EXT01.c is likewise an all-of observation: three active-protocol placements plus
        # the control and all thirteen metadata attribute placements must succeed in the
        # same Run.  The Shibboleth gate replays every original, the native filesystem
        # provider reads, the resolver reloads, the formal evidence set, and byte-exact
        # restoration before any of the four profile observations can leave the ledger.
        if row['product']=='shibboleth' and row['profile'] in {
                'browser_sso_idp','ecp_idp','metadata_idp','single_logout_idp'} \
                and row['case']=='IIP-EXT01-c-idp-01':
            from verify_ext01c_shibboleth_acceptance import verify_batch as verify_ext01c_shibboleth
            ext_root = root.parent.parent/'reference-20260930'/'ext01c-shibboleth-v158'
            accepted = check_once(verify_ext01c_shibboleth, ext_root)
            accepted_runs = {value['profile']: value['run'] for value in accepted['observations']}
            path = ext_root/row['profile']/'metadata'/'evaluation-terminal-http-v1'/'result.json'
            result = json.loads(path.read_text())
            cases = {case['id']: case for requirement in result['requirements']
                     for case in requirement['cases']}
            if result['run']['id'] != accepted_runs.get(row['profile']):
                raise ValueError('EXT01.c accepted Run/profile binding mismatch')
            selected = (path, cases)
        # The Keycloak replacement retains each original profile Run. Its full native
        # parser projection, all attribute placements and controls are replayed before
        # reading the corresponding central conclusion; an endpoint-only parse is not used.
        if row['product']=='keycloak' and row['profile'] in {
                'browser_sso_idp','ecp_idp','metadata_idp','single_logout_idp'} \
                and row['case']=='IIP-EXT01-c-idp-01':
            ext_root = root.parent.parent/'reference-20261004'/'keycloak-extension-attribute-parser-r2'
            if (ext_root/'adopted.json').is_file():
                from verify_keycloak_extension_attribute_parser_acceptance import verify_adoption as verify_keycloak_extension_parser
                selected = check_once(verify_keycloak_extension_parser, ext_root)[row['profile']]
        # Keycloak target-initiated logout is driven through the native browser endpoint.
        # The gate requires an authenticated product session, the emitted LogoutRequest and
        # correlated Suite response originals, completed session removal, exact client cleanup,
        # pinned runtimes, formal transcript evidence, and tamper rejection.  A confirmation
        # page or session deletion alone is intentionally insufficient.
        if row['product']=='keycloak' and row['profile']=='single_logout_idp' \
                and row['case'] in {'IIP-IDP17-n-idp-01','IIP-IDP17-u-idp-01'}:
            from verify_keycloak_target_logout_absence import verify as verify_keycloak_target_logout
            selected = check_once(verify_keycloak_target_logout, root.parent.parent/'reference-20260930')
        # MD06.b requires one native metadata source to serve two distinct Suite peers
        # without a second target-side configuration.  The gate replays both correlated
        # Success responses and their XML originals, verifies the unchanged configured
        # source between peers, exact restoration, pinned runtimes, formal result, and
        # ten evidence mutations before allowing either product row out of the ledger.
        md06b_roots = {
            'shibboleth': 'md06b-shibboleth-v158-r3',
            'simplesamlphp': 'md06b-simplesamlphp-v158',
        }
        if row['product'] in md06b_roots and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD06-b-idp-01':
            from verify_md06b_multi_peer_acceptance import verify as verify_md06b
            md06b_root = root.parent.parent/'reference-20260930'/md06b_roots[row['product']]
            check_once(verify_md06b, md06b_root)
            path = md06b_root/'result.json'
            result = json.loads(path.read_text())
            cases = {case['id']: case for requirement in result['requirements']
                     for case in requirement['cases']}
            receipt = json.loads((md06b_root/'receipt.json').read_text())
            if result['run']['id'] != receipt['primaryRun']:
                raise ValueError('MD06.b accepted Run/result binding mismatch')
            selected = (path, cases)
        # MD03.d is a two-source all-of observation.  Both products consumed metadata
        # signed by K from source A while rejecting the same K-signed document from source B,
        # whose native source configuration trusted only K2.  The gate verifies both signed
        # originals, native acceptance/rejection, absence of a contradictory Success,
        # unchanged source configuration, exact restoration, runtimes, and tamper controls.
        md03d_roots = {
            'shibboleth': 'md03d-shibboleth-v158',
            'simplesamlphp': 'md03d-simplesamlphp-v158',
        }
        if row['product'] in md03d_roots and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD03-d-idp-01':
            from verify_md03d_source_scoped_trust_acceptance import verify as verify_md03d
            md03d_root = root.parent.parent/'reference-20260930'/md03d_roots[row['product']]
            check_once(verify_md03d, md03d_root)
            path = md03d_root/'result.json'
            result = json.loads(path.read_text())
            cases = {case['id']: case for requirement in result['requirements']
                     for case in requirement['cases']}
            receipt = json.loads((md03d_root/'receipt.json').read_text())
            if result['run']['id'] != receipt['primaryRun']:
                raise ValueError('MD03.d accepted Run/result binding mismatch')
            selected = (path, cases)
        # Keycloak exposes the same approved obligations through a different native model.
        # The fail-closed gate proves, from all 348 runtime JARs and every installed provider,
        # that both native metadata import entry points converge on the single-entity converter
        # and expose no source-scoped trust input.  Two independent clients and correlated
        # Success responses are required as controls, followed by exact deletion read-back.
        # The adoption verifier also replays eighteen evidence mutations before returning either
        # formal capability_absent result.
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD06-b-idp-01','IIP-MD03-d-idp-01'}:
            from verify_keycloak_metadata_source_capability_absence import \
                verify_adoption as verify_keycloak_metadata_source_absence
            metadata_source_path, metadata_source_cases = check_once(verify_keycloak_metadata_source_absence, 
                root.parent.parent/'reference-20260930')
            if metadata_source_path.is_absolute():
                metadata_source_path = metadata_source_path.relative_to(Path.cwd())
            selected = (metadata_source_path, metadata_source_cases)
        # MD03.a/b/c have normative-capability semantics.  Adopt Keycloak's product failure
        # only after the dedicated gate independently verifies the valid/unsigned/bad-signature
        # controls, the out-of-band signer/embedded-KeyInfo split, all certificate variants,
        # native UI/API read-back, full runtime/provider scan, exact restoration, and tamper set.
        # The expired/not-yet-valid follow-up SSO rejections are retained as separate runtime
        # observations and are not used as the MD03.c conclusion.
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD03-a-idp-01','IIP-MD03-b-idp-01',
                                    'IIP-MD03-c-idp-01'}:
            from verify_keycloak_metadata_signature_capability_absence import \
                verify_adoption as verify_keycloak_metadata_signature_absence
            signature_path, signature_cases = check_once(verify_keycloak_metadata_signature_absence, 
                root.parent.parent/'reference-20260930')
            if signature_path.is_absolute():
                signature_path = signature_path.relative_to(Path.cwd())
            selected = (signature_path, signature_cases)
        # Keycloak's native metadata-URL converter and correlated SSO flows consumed the
        # no-validUntil and expired documents.  The adoption gate pins the running product,
        # all 348 JARs, the Suite Run/runtime, fetched originals, request/response signatures,
        # same-variant invalid-signature controls, and exact temporary-client cleanup.
        # MD05.as is adopted only from the expired document's unique signing key plus its
        # control chain; configuration unavailability remains a test precondition.  MD04.c uses
        # a separate minimal Run whose formal configuration conclusion is capability_absent.
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD04-a-idp-01','IIP-MD04-b-idp-01',
                                    'IIP-MD04-c-idp-01','IIP-MD05-as-idp-01'}:
            from verify_keycloak_validity_capability_absence import verify as verify_keycloak_validity
            selected = check_once(verify_keycloak_validity, root.parent.parent/'reference-20260930', row['case'])
        # Keycloak's native metadata-URL campaigns prove both the MDQ acquisition path and
        # a second fetch with a changed document, correlated key use, invalid/old-key controls,
        # exact client deletion, receipt read-back, pinned runtimes/classes, and tamper mutations.
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD01-a-idp-01','IIP-MD02-a-idp-01'}:
            from verify_keycloak_metadata_url_acceptance import verify as verify_keycloak_metadata_url
            selected = check_once(verify_keycloak_metadata_url, root.parent.parent/'reference-20260930', row['case'])
        if row['profile']=='browser_sso_idp' and row['case']=='IIP-G02-a-idp-01':
            from verify_g02_browser_chain import verify as verify_g02_browser
            selected = check_once(verify_g02_browser, root.parent.parent/'reference-20260928', row['product'])
        if row['profile']=='metadata_idp' and row['case'] in UI_ADOPTED:
            selected = check_once(verify_ui, root.parent.parent/'reference-20260918', row['product'])
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case']=='IIP-MD02-d-idp-01':
            selected = check_once(verify_ssp_import, root.parent.parent/'reference-20260918',
                folder='simplesamlphp-aggregate-import', adopted={
                    'IIP-MD02-d-idp-01': ['entities-root-one','entities-root-two','entities-root-fifty']})
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case']=='IIP-MD06-a1-idp-01':
            selected = check_once(verify_ssp_import, root.parent.parent/'reference-20260918',
                folder='simplesamlphp-metadata-fixture-v67', adopted={
                    'IIP-MD06-a1-idp-01': ['entity-root','entities-root-one','nested-entities']})
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' and row['case']=='IIP-IDP12-c-idp-01':
            from verify_default_acs_batch import verify as verify_default_acs
            selected = check_once(verify_default_acs, root.parent.parent/'reference-20260918')
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' and row['case'] in {
                'IIP-SSO01-an-idp-01','IIP-SSO01-gi-idp-01'}:
            from verify_invalid_request_acceptance import verify as verify_invalid_request
            selected = check_once(verify_invalid_request, root.parent.parent/'reference-20260918','simplesamlphp')
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' and row['case'] in {
                'IIP-SSO01-an-idp-01','IIP-SSO01-gi-idp-01'}:
            from verify_invalid_request_acceptance import verify as verify_invalid_request
            selected = check_once(verify_invalid_request, root.parent.parent/'reference-20260918','keycloak')
        if row['product'] in {'shibboleth','keycloak'} and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-IDP06-a-idp-01':
            from verify_force_authn_acceptance import verify as verify_force_authn
            selected = check_once(verify_force_authn, root.parent.parent/'reference-20260918', row['product'])
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-IDP08-a-idp-01':
            from verify_authn_context_exact_acceptance import verify as verify_authn_context_exact
            selected = check_once(verify_authn_context_exact, root.parent.parent/'reference-20260918')
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-IDP08-a-idp-01':
            from verify_shibboleth_exact_authn_context_acceptance import verify as verify_shibboleth_exact
            selected = check_once(verify_shibboleth_exact, root.parent.parent/'reference-20261002')
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case']=='IIP-MD05-a3-idp-01':
            path=root.parent.parent/'reference-20260918/simplesamlphp-extension-points-corrected/result.json'
            result=json.loads(path.read_text())
            cases={c['id']:c for req in result['requirements'] for c in req['cases']}
            assert cases[row['case']]['verdict']=='NOT_VERIFIED'
            protocol=json.loads((path.parent/'protocol-evidence.json').read_text())
            observed=next(c for c in protocol['cases'] if c['caseId']==row['case'])
            assert not observed['ready']
            assert observed['details']['consumer_acceptance_proves_namespace_qualification'] is False
            assert observed['details']['missing_namespace_qualification_evidence']==['extension-points']
            selected=(path,cases)
        if row['profile']=='metadata_idp' and row['case']=='IIP-MD05-ae-idp-01':
            from verify_single_signing_key_batch import verify as verify_single_key
            selected=check_once(verify_single_key, root.parent.parent/'reference-20260918',row['product'])
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' and row['case']=='IIP-IDP12-c-idp-01':
            from audit_keycloak_default_acs import verify as verify_keycloak_acs
            selected=check_once(verify_keycloak_acs, root.parent.parent/'reference-20260918')
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' and row['case']=='IIP-SSO01-cz-idp-01':
            path=root.parent.parent/'reference-20260918/simplesamlphp-opaque-principal-control/result.json'
            result=json.loads(path.read_text())
            cases={c['id']:c for req in result['requirements'] for c in req['cases']}
            case=cases[row['case']]
            assert (case['verdict'],case['reason_code'])==('NOT_VERIFIED','saml.subject-principal.undetermined')
            assert cases['IIP-ALG06-a-idp-01']['reason_code']=='browser.encryption.rsa-oaep-mgf1p.decrypted'
            selected=(path,cases)
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' and row['case'] in {
                'IIP-ALG04-a-idp-01','IIP-ALG04-b-idp-01'}:
            from verify_shared_gcm_batch import verify as verify_shared_gcm
            selected=check_once(verify_shared_gcm, root.parent.parent/'reference-20260918',
                128 if row['case']=='IIP-ALG04-a-idp-01' else 256)
        if row['product']=='simplesamlphp' and row['profile']=='ecp_idp' and row['case'] in {
                'IIP-ALG04-a-idp-01','IIP-ALG04-b-idp-01'}:
            from verify_shared_gcm_batch import verify as verify_shared_gcm
            selected=check_once(verify_shared_gcm, root.parent.parent/'reference-20260929',
                128 if row['case']=='IIP-ALG04-a-idp-01' else 256, 'ecp_idp')
        if row['product'] in {'simplesamlphp','keycloak','shibboleth'} and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD05-ea-idp-01','IIP-MD05-eb-idp-01'}:
            from verify_metadata_algorithm_outcomes import verify as verify_algorithm_outcomes
            selected=check_once(verify_algorithm_outcomes, root.parent.parent/'reference-20260918',row['product'])
        if row['product'] in {'simplesamlphp','keycloak','shibboleth'} and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD05-e5-idp-01','IIP-MD05-e9-idp-01'}:
            from verify_algorithm_followup import verify as verify_algorithm_followup
            selected=check_once(verify_algorithm_followup, root.parent.parent/'reference-20260918',row['product'])
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' and row['case']=='IIP-MD05-e8-idp-01':
            from verify_metadata_intersection import verify as verify_intersection
            selected=check_once(verify_intersection, root.parent.parent/'reference-20260918')
        if row['product']=='shibboleth' and row['profile'] in {'browser_sso_idp','ecp_idp'} and row['case'] in {
                'IIP-ALG04-b-idp-01','IIP-ALG06-b-idp-01','IIP-ALG06-c-idp-01'}:
            from verify_producer_algorithms import verify as verify_producer
            selected=check_once(verify_producer, root.parent.parent/'reference-20260918',row['profile'])
        if row['product']=='shibboleth' and row['profile'] in {'browser_sso_idp','ecp_idp'} and row['case'] in {
                'IIP-ALG08-a-idp-01','IIP-ALG08-b-idp-01'}:
            if row['profile']=='browser_sso_idp':
                from verify_algorithm_prevention_acceptance import verify_adoption as verify_prevention
            else:
                from verify_algorithm_prevention_ecp_acceptance import verify_adoption as verify_prevention
            selected=check_once(verify_prevention, root.parent.parent/'reference-20260930')
        if row['product']=='keycloak' and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD12-b-idp-01','IIP-MD12-d-idp-01'}:
            from verify_native_certificate_acceptance import verify as verify_native_certificates
            selected=check_once(verify_native_certificates, root.parent.parent/'reference-20260918')
        if row['product']=='keycloak' and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD06-a8-idp-01','IIP-MD07-a-idp-01'}:
            from verify_metadata_key_acceptance import verify as verify_metadata_keys
            selected=check_once(verify_metadata_keys, root.parent.parent/'reference-20260918')
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD06-a8-idp-01','IIP-MD07-b-idp-01'}:
            from verify_metadata_key_acceptance import verify as verify_metadata_keys
            selected=check_once(verify_metadata_keys, root.parent.parent/'reference-20260918','simplesamlphp')
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD06-a8-idp-01','IIP-MD07-b-idp-01'}:
            from verify_metadata_key_acceptance import verify as verify_metadata_keys
            selected=check_once(verify_metadata_keys, root.parent.parent/'reference-20260918','shibboleth')
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD03-a-idp-01','IIP-MD04-a-idp-01','IIP-MD04-b-idp-01','IIP-MD04-c-idp-01',
                'IIP-MD05-a2-idp-01','IIP-MD05-as-idp-01','IIP-MD05-an-idp-01','IIP-MD05-am-idp-01'}:
            from verify_native_metadata_rejection_acceptance import verify as verify_native_rejection
            selected=check_once(verify_native_rejection, root.parent.parent/'reference-20260918','shibboleth',row['case'])
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' and row['case']=='IIP-MD05-e7-idp-01':
            from verify_metadata_algorithm_preference import verify as verify_algorithm_preference
            selected=check_once(verify_algorithm_preference, root.parent.parent/'reference-20260918','shibboleth')
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' and row['case']=='IIP-MD05-c-idp-01':
            from verify_mdiop_acceptance import verify as verify_mdiop
            selected=check_once(verify_mdiop, root.parent.parent/'reference-20260918','shibboleth')
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' and row['case']=='IIP-MD03-b-idp-01':
            from verify_native_signature_key_acceptance import verify as verify_native_signature_key
            selected=check_once(verify_native_signature_key, root.parent.parent/'reference-20260918','shibboleth')
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' and row['case']=='IIP-MD01-a-idp-01':
            from verify_shibboleth_mdq_acceptance import verify as verify_native_mdq
            selected=check_once(verify_native_mdq, root.parent.parent/'reference-20260930')
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case']=='IIP-MD01-a-idp-01':
            from verify_ssp_mdq_acceptance import verify as verify_ssp_mdq
            selected=check_once(verify_ssp_mdq, root.parent.parent/'reference-20260930')
        # Product-native signature verification accepts the document signed by the configured
        # out-of-band key and rejects bad-signature and embedded-anchor controls.  The adoption
        # verifier regenerates the 29-control production-reader replay from the pinned Runner JAR
        # before either case can leave the inventory.
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD03-b-idp-01', 'IIP-MD03-c-idp-01'}:
            from verify_ssp_metadata_signature_acceptance import verify as verify_ssp_metadata_signature
            selected=check_once(verify_ssp_metadata_signature, root.parent.parent/'reference-20260930')
        # One restored native signature campaign supplies the refusal, XPath and KeyInfo
        # obligations. Replay the pinned gate, rejection reader and case implementations;
        # the earlier malformed XPath attempt is not adopted.
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD03-a-idp-01', 'IIP-MD05-am-idp-01', 'IIP-MD05-an-idp-01', 'IIP-MD05-ao-idp-01'}:
            from verify_ssp_metadata_signature_consumer_acceptance import verify as verify_ssp_signature_consumers
            selected=check_once(verify_ssp_signature_consumers,
                root.parent.parent/'reference-20260930')
        # MD02.a requires a real A-to-B recurring fetch, not the existing one-shot MDQ proof.
        # The adoption gate pins the running Suite/JARs and target runtime, independently verifies
        # the disjoint A/B signing keys, requires the B invalid-signature rejection plus correlated
        # B success, checks the approved wait and exact restoration, and runs tamper controls.
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD02-a-idp-01':
            from verify_metadata_refresh_acceptance import verify as verify_metadata_refresh
            refresh_path, refresh_cases, _ = check_once(verify_metadata_refresh, 
                root.parent.parent/'reference-20260930'/'ssp-metadata-refresh-v153')
            selected = (refresh_path, refresh_cases)
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD04-b-idp-01', 'IIP-MD05-as-idp-01'}:
            from verify_ssp_native_mdq_rejection import verify as verify_ssp_native_rejection
            selected=check_once(verify_ssp_native_rejection, root.parent.parent/'reference-20260930', row['case'])
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD04-a-idp-01', 'IIP-MD04-c-idp-01'}:
            from verify_ssp_validity_capability_absence import verify as verify_ssp_validity
            selected=check_once(verify_ssp_validity, root.parent.parent/'reference-20260930')
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case']=='IIP-MD05-b-idp-01':
            from verify_ssp_schema_positive_rejection import verify as verify_ssp_schema_refusal
            selected=check_once(verify_ssp_schema_refusal, root.parent.parent/'reference-20260930')
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case']=='IIP-MD05-av-idp-01':
            from verify_ssp_default_acs_acceptance import verify as verify_ssp_default_acs
            selected=check_once(verify_ssp_default_acs, root.parent.parent/'reference-20260930')
        # MD05.ah is an all-of capability: the target must both publish metadata signed with
        # RSA-SHA1 and natively verify RSA-SHA1 signatures.  The independent verifier replays
        # the signed original, product-native positive/three negative controls, pinned runtime
        # sources, receipt/run/hash bindings, and byte-exact configuration restoration.  An
        # algorithm URI in metadata alone is intentionally insufficient for adoption.
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-ah-idp-01':
            from verify_ssp_rsa_sha1_metadata_acceptance import verify as verify_ssp_rsa_sha1
            selected=check_once(verify_ssp_rsa_sha1, root.parent.parent/'reference-20260930')
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-ah-idp-01':
            from verify_keycloak_rsa_sha1_metadata_acceptance import verify as verify_keycloak_rsa_sha1
            selected=check_once(verify_keycloak_rsa_sha1, root.parent.parent/'reference-20260930')
        if row['product']=='keycloak' and row['profile']=='metadata_idp' and row['case']=='IIP-MD05-av-idp-01':
            from verify_keycloak_default_acs_acceptance import verify as verify_keycloak_default_acs
            selected=check_once(verify_keycloak_default_acs, root.parent.parent/'reference-20260930')
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' and row['case']=='IIP-MD05-av-idp-01':
            from verify_shibboleth_default_acs_acceptance import verify as verify_shibboleth_default_acs
            selected=check_once(verify_shibboleth_default_acs, root.parent.parent/'reference-20260930')
        if row['product'] in {'keycloak','shibboleth','simplesamlphp'} and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-af-idp-01':
            from verify_publisher_root_signature_acceptance import verify as verify_publisher_root
            selected=check_once(verify_publisher_root, root.parent.parent/'reference-20260930', row['product'])
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' and row['case']=='IIP-MD05-ao-idp-01':
            from verify_native_keyinfo_omission_acceptance import verify as verify_keyinfo_omission
            selected=check_once(verify_keyinfo_omission, root.parent.parent/'reference-20260918','shibboleth')
        if row['product']=='keycloak' and row['profile']=='metadata_idp' and row['case']=='IIP-MD06-a9-idp-01':
            from verify_native_certificate_acceptance import verify as verify_native_certificates
            selected=check_once(verify_native_certificates, root.parent.parent/'reference-20260918',runtime=True)
        if row['product'] in {'keycloak','shibboleth','simplesamlphp'} and row['profile']=='browser_sso_idp' and row['case']=='IIP-SSO04-a-idp-01':
            from verify_signature_modes_acceptance import verify as verify_signature_modes
            selected=check_once(verify_signature_modes, root.parent.parent/'reference-20260918',row['product'])
        if row['product']=='keycloak' and row['profile']=='ecp_idp' and row['case']=='IIP-ALG06-c-idp-01':
            from verify_native_producer_acceptance import verify as verify_native_producer
            selected=check_once(verify_native_producer, root.parent.parent/'reference-20260918')
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' and row['case']=='IIP-ALG06-d-idp-01':
            from verify_producer_algorithms import verify_default_mgf_withdrawal
            row['audit_withdrawal']=check_once(verify_default_mgf_withdrawal, root.parent.parent/'reference-20260918')
            assert row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED'
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case']=='IIP-MD05-e8-idp-01':
            # Preserve the complete original matrix and additionally require native
            # SHA256/SHA384 capability controls with the same actual signing key.
            from verify_ssp_intersection_capability_acceptance import verify as verify_ssp_intersection
            selected=check_once(verify_ssp_intersection, root.parent.parent/'reference-20260930')
        if row['product'] in {'simplesamlphp','shibboleth'} and row['profile']=='browser_sso_idp' and row['case']=='IIP-IDP01-a-idp-01':
            from verify_attribute_name_capability import verify as verify_attribute_names
            selected=check_once(verify_attribute_names, root.parent.parent/'reference-20260918',row['product'])
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' and row['case'] in {'IIP-IDP03-a-idp-01','IIP-IDP04-a-idp-01','IIP-IDP04-b-idp-01'}:
            from verify_attribute_policy_acceptance import verify as verify_attribute_policy
            selected=check_once(verify_attribute_policy, root.parent.parent/'reference-20260918')
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' \
                and row['case'] in {'IIP-IDP03-a-idp-01','IIP-IDP04-a-idp-01'}:
            from verify_ssp_attribute_policy_acceptance import verify as verify_ssp_attribute_policy
            selected=check_once(verify_ssp_attribute_policy, root.parent.parent/'reference-20260930')
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' and row['case']=='IIP-MD05-f9-idp-01':
            from verify_ui_logo_acceptance import verify as verify_ui_logo
            selected=check_once(verify_ui_logo, root.parent.parent/'reference-20260918')
        # Native policy set/add/remove controls prove prevention, separately from selecting an
        # encryption algorithm. Replay the archived production reader; browser evidence is not
        # reused for an ECP observation.
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' and row['case'] in {
                'IIP-ALG08-a-idp-01', 'IIP-ALG08-b-idp-01'}:
            from verify_keycloak_algorithm_policy_acceptance import verify_adoption as verify_keycloak_algorithm_policy
            selected=check_once(verify_keycloak_algorithm_policy,
                root.parent.parent/'reference-20260930', live=False)
        if row['product']=='keycloak' and row['profile']=='ecp_idp' and row['case'] in {
                'IIP-ALG08-a-idp-01', 'IIP-ALG08-b-idp-01'}:
            from verify_keycloak_ecp_algorithm_policy_acceptance import verify_adoption as verify_keycloak_ecp_algorithm_policy
            selected=check_once(verify_keycloak_ecp_algorithm_policy,
                root.parent.parent/'reference-20260930', live=False)
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD02-a-idp-01':
            from verify_shibboleth_metadata_refresh_acceptance import verify as verify_shibboleth_metadata_refresh
            selected=check_once(verify_shibboleth_metadata_refresh,
                root.parent.parent/'reference-20260930')
        # Replay the native short-flow positive and separate 257-character producer
        # control, including signed originals and exact restoration. ECP has no a2 case.
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO05-a2-idp-01':
            from verify_ssp_persistent_length_acceptance import verify as verify_ssp_persistent_length
            selected=check_once(verify_ssp_persistent_length,
                root.parent.parent/'reference-20260930')
        # Native imports preserve every imported key and apply the same signature policy
        # before the twelve-condition matrix. Re-run the pinned reader and its 121 controls;
        # the first-key control for MD07.b remains deliberately unqualified.
        if row['product']=='keycloak' and row['profile']=='metadata_idp' and row['case'] in {
                'IIP-MD05-ad-idp-01', 'IIP-MD05-cd-idp-01', 'IIP-MD06-a5-idp-01',
                'IIP-MD06-a7-idp-01', 'IIP-MD06-a3-idp-01'}:
            from verify_keycloak_native_key_policy_acceptance import verify_adoption as verify_keycloak_native_key_policy
            selected=check_once(verify_keycloak_native_key_policy,
                root.parent.parent/'reference-20260930', live=False)
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' and row['case'] in {
                'IIP-SSO05-a-idp-01', 'IIP-SSO05-a2-idp-01', 'IIP-SSO05-a3-idp-01'}:
            from verify_shibboleth_persistent_pairwise_acceptance import verify as verify_shibboleth_persistent
            selected=check_once(verify_shibboleth_persistent,
                root.parent.parent/'reference-20260930')
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO05-a3-idp-01':
            from verify_ssp_persistent_pairwise_acceptance import verify as verify_ssp_pairwise
            selected=check_once(verify_ssp_pairwise,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-cz-idp-01':
            from verify_ssp_subject_principal_acceptance import verify as verify_ssp_subject_principal
            selected=check_once(verify_ssp_subject_principal,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD05-cd-idp-01', 'IIP-MD06-a5-idp-01', 'IIP-MD06-a7-idp-01'}:
            from verify_ssp_keyvalue_runtime_acceptance import verify as verify_ssp_keyvalue_runtime
            selected=check_once(verify_ssp_keyvalue_runtime,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-ah-idp-01':
            from verify_shibboleth_rsa_sha1_metadata_acceptance import verify as verify_shibboleth_rsa_sha1
            selected=check_once(verify_shibboleth_rsa_sha1,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-ae-idp-01':
            from verify_shibboleth_authentication_identity_acceptance import verify as verify_shibboleth_identity
            selected=check_once(verify_shibboleth_identity,
                root.parent.parent/'reference-20260930')
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-ae-idp-01':
            from verify_ssp_authentication_identity_acceptance import verify as verify_ssp_authentication_identity
            selected=check_once(verify_ssp_authentication_identity,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-ae-idp-01':
            from verify_keycloak_authentication_identity_acceptance import verify_adoption as verify_keycloak_identity
            selected=check_once(verify_keycloak_identity,
                root.parent.parent/'reference-20261002', live=False)
        # Reuse one restored native campaign for all three effective-expiry variants.
        # The native readers require before-expiry use, explicit native invalidation,
        # original clocks/configuration, controls and exact restoration. Their adopters
        # replay the deployed classes and the central stored outcome without more logins.
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-ar-idp-01':
            from verify_shibboleth_metadata_validity_acceptance import verify as verify_shibboleth_validity
            selected=check_once(verify_shibboleth_validity,
                root.parent.parent/'reference-20261002')
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-ar-idp-01':
            from verify_ssp_metadata_validity_acceptance import verify_adoption as verify_ssp_native_validity
            selected=check_once(verify_ssp_native_validity,
                root.parent.parent/'reference-20261002', live=False)
        # Two identity obligations share the same native import, two authenticated
        # peer flows and exact cleanup. Replay their recorded runtime once; adopting
        # another applicable case must not repeat the operator's login or setup.
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD05-a1-idp-01', 'IIP-MD05-a2-idp-01'}:
            from verify_keycloak_metadata_entity_identity_acceptance import verify_adoption as verify_keycloak_entity_identity
            selected=check_once(verify_keycloak_entity_identity,
                root.parent.parent/'reference-20261002', live=False)
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD06-a2-idp-01':
            from verify_metadata_role_key_acceptance import verify as verify_native_role_keys
            selected=check_once(verify_native_role_keys,
                root.parent.parent/'reference-20261002')
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD06-a2-idp-01':
            from verify_native_metadata_role_key_acceptance import verify as verify_ssp_native_role_keys
            selected=check_once(verify_ssp_native_role_keys,
                root.parent.parent/'reference-20261002', product='simplesamlphp')
        # Each native campaign supplies one correlated operation transcript and
        # exact restored state. Formal acceptance replays those originals rather
        # than requesting another login for the same observation.
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-al-idp-01':
            from verify_keycloak_registered_signer_acceptance import verify_adoption as verify_keycloak_registered_signer
            selected=check_once(verify_keycloak_registered_signer,
                root.parent.parent/'reference-20261002', live=False)
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-al-idp-01':
            from verify_ssp_registered_signer_acceptance import verify_adoption as verify_ssp_registered_signer
            selected=check_once(verify_ssp_registered_signer,
                root.parent.parent/'reference-20261002', live=False)
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-al-idp-01':
            from verify_shibboleth_registered_signer_acceptance import verify_adoption as verify_shib_registered_signer
            selected=check_once(verify_shib_registered_signer,
                root.parent.parent/'reference-20261003', live=False)
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD06-a6-idp-01':
            from verify_metadata_certificate_runtime_acceptance import verify as verify_certificate_runtime
            selected=check_once(verify_certificate_runtime,
                root.parent.parent/'reference-20261002')
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD06-a6-idp-01':
            from verify_ssp_certificate_runtime_acceptance import verify_adoption as verify_ssp_certificate_runtime
            selected=check_once(verify_ssp_certificate_runtime,
                root.parent.parent/'reference-20261002', live=False)
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-IDP06-b-idp-01':
            from verify_shibboleth_forceauthn_mechanism_acceptance import verify as verify_shibboleth_forceauthn_mechanism
            selected=check_once(verify_shibboleth_forceauthn_mechanism,
                root.parent.parent/'reference-20261001')
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-c-idp-01':
            from verify_keycloak_mdiop_representation_acceptance import verify_adoption as verify_keycloak_mdiop
            selected=check_once(verify_keycloak_mdiop,
                root.parent.parent/'reference-20260930', live=False)
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-c-idp-01':
            from verify_shibboleth_mdiop_full_acceptance import verify as verify_shibboleth_mdiop_full
            selected=check_once(verify_shibboleth_mdiop_full,
                root.parent.parent/'reference-20260930')
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-cd-idp-01':
            from verify_shibboleth_hintfree_key_acceptance import verify as verify_shibboleth_hintfree
            selected=check_once(verify_shibboleth_hintfree,
                root.parent.parent/'reference-20260930')
        if row['product'] in {'keycloak','simplesamlphp'} and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO03-b-idp-01':
            from verify_post_error_binding_acceptance import verify_adoption as verify_post_error_binding
            selected=check_once(verify_post_error_binding,
                root.parent.parent/'reference-20260930', row['product'], live=False)
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO03-b-idp-01':
            from verify_shibboleth_post_error_binding_acceptance import verify as verify_shibboleth_post_error
            selected=check_once(verify_shibboleth_post_error,
                root.parent.parent/'reference-20261001')
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-G02-a-idp-01':
            from verify_shibboleth_g02_known_subject_acceptance import verify as verify_shibboleth_g02_known_subject
            selected=check_once(verify_shibboleth_g02_known_subject,
                root.parent.parent/'reference-20261001')
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO07-b-idp-01':
            from verify_shibboleth_requested_subject_match_acceptance import verify as verify_shibboleth_requested_subject
            selected=check_once(verify_shibboleth_requested_subject,
                root.parent.parent/'reference-20261001')
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-fp-idp-01':
            from verify_ssp_transient_allow_create_acceptance import verify as verify_ssp_transient_allow_create
            selected=check_once(verify_ssp_transient_allow_create,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-fp-idp-01':
            from verify_keycloak_transient_allow_create_acceptance import verify_adoption as verify_keycloak_transient_allow_create
            selected=check_once(verify_keycloak_transient_allow_create,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-fp-idp-01':
            from verify_shibboleth_transient_allow_create_acceptance import verify as verify_shibboleth_transient_allow_create
            selected=check_once(verify_shibboleth_transient_allow_create,
                root.parent.parent/'reference-20261001')
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-b-idp-01':
            from verify_keycloak_native_schema_admission_acceptance import verify_adoption as verify_keycloak_native_schema
            selected=check_once(verify_keycloak_native_schema,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' \
                and row['case'] in {'IIP-SSO01-fr-idp-01','IIP-SSO01-gd-idp-01'}:
            from verify_ssp_subject_confirmation_acceptance import verify as verify_ssp_subject_confirmation
            selected=check_once(verify_ssp_subject_confirmation,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case'] in {'IIP-SSO01-fr-idp-01','IIP-SSO01-gd-idp-01'}:
            from verify_keycloak_subject_confirmation_acceptance import verify_adoption as verify_keycloak_subject_confirmation
            selected=check_once(verify_keycloak_subject_confirmation,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' \
                and row['case'] in {'IIP-SSO01-fr-idp-01','IIP-SSO01-gd-idp-01'}:
            from verify_shibboleth_subject_confirmation_acceptance import verify as verify_shibboleth_subject_confirmation
            selected=check_once(verify_shibboleth_subject_confirmation,
                root.parent.parent/'reference-20261001')
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-IDP04-b-idp-01':
            from verify_ssp_attribute_service_index_acceptance import verify as verify_ssp_attribute_service_index
            selected=check_once(verify_ssp_attribute_service_index,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD06-ab-idp-01':
            from verify_keycloak_supersession_counterexample_acceptance import verify_adoption as verify_keycloak_supersession_counterexample
            selected=check_once(verify_keycloak_supersession_counterexample,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='simplesamlphp' and row['profile']=='single_logout_idp' \
                and row['case']=='IIP-IDP19-c-idp-01':
            from verify_ssp_encrypted_logout_acceptance import verify as verify_ssp_native_encrypted_logout
            selected=check_once(verify_ssp_native_encrypted_logout,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO05-a3-idp-01':
            from verify_keycloak_persistent_pairwise_acceptance import verify_adoption as verify_keycloak_pairwise
            selected=check_once(verify_keycloak_pairwise,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='shibboleth' and row['profile']=='single_logout_idp' \
                and row['case']=='IIP-IDP17-s-idp-01':
            from verify_shibboleth_native_slo_acceptance import verify as verify_shibboleth_native_slo
            selected=check_once(verify_shibboleth_native_slo,
                root.parent.parent/'reference-20261001')
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-a1-idp-01':
            from verify_shibboleth_entityid_uniqueness_acceptance import verify as verify_shibboleth_entityid_uniqueness
            selected=check_once(verify_shibboleth_entityid_uniqueness,
                root.parent.parent/'reference-20261001')
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-fj-idp-01':
            from verify_ssp_consent_ui_acceptance import verify as verify_ssp_consent_ui
            selected=check_once(verify_ssp_consent_ui,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-f9-idp-01':
            from verify_ssp_consent_logo_acceptance import verify as verify_ssp_consent_logo
            selected=check_once(verify_ssp_consent_logo,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD05-fb-idp-01','IIP-MD05-fh-idp-01'}:
            from verify_ssp_consent_uri_acceptance import verify as verify_ssp_consent_uri
            selected=check_once(verify_ssp_consent_uri,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-fg-idp-01':
            from verify_ssp_consent_safety_acceptance import verify as verify_ssp_consent_safety
            selected=check_once(verify_ssp_consent_safety,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-c-idp-01':
            from verify_ssp_mdiop_admission_acceptance import verify as verify_ssp_mdiop
            selected=check_once(verify_ssp_mdiop,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD05-fb-idp-01','IIP-MD05-fg-idp-01',
                                    'IIP-MD05-fh-idp-01','IIP-MD05-fj-idp-01'}:
            from verify_shibboleth_native_ui_acceptance import verify as verify_shibboleth_native_ui
            selected=check_once(verify_shibboleth_native_ui,
                root.parent.parent/'reference-20261001')
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD06-a-idp-01':
            from verify_keycloak_metadata_supersession_acceptance import verify_adoption as verify_keycloak_application
            selected=check_once(verify_keycloak_application,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD06-c-idp-01':
            from verify_keycloak_self_contained_trust_acceptance import verify_adoption as verify_keycloak_self_contained_trust
            selected=check_once(verify_keycloak_self_contained_trust,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD06-c-idp-01':
            from verify_simplesamlphp_self_contained_trust_acceptance import verify as verify_ssp_self_contained_trust
            selected=check_once(verify_ssp_self_contained_trust,
                root.parent.parent/'reference-20261002')
        # One native role-key campaign supplies the complete self-contained trust
        # proof. Its adopter checks the deployed reader, exact restoration and
        # unchanged transcript; diagnostic controls never become product results.
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD06-c-idp-01':
            from verify_shibboleth_self_contained_trust_acceptance import verify_adoption as verify_shib_self_contained_trust
            selected=check_once(verify_shib_self_contained_trust,
                root.parent.parent/'reference-20261003', live=False)
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD06-a-idp-01','IIP-MD06-ab-idp-01'}:
            from verify_shibboleth_metadata_application_acceptance import verify_adoption as verify_shib_metadata_application
            selected=check_once(verify_shib_metadata_application,
                root.parent.parent/'reference-20261003', live=False)
        # Reuse the completed native XML-signature controls and restored state.
        # The approved case permits a note when no incoming LogoutResponse was
        # observed; its central WARNING remains distinct from product failure.
        if row['product'] in {'keycloak','shibboleth','simplesamlphp'} and row['profile']=='single_logout_idp' \
                and row['case']=='IIP-IDP17-ab-idp-01':
            from verify_slo_registered_signer_acceptance import verify_adoption as verify_slo_registered_signer
            selected=check_once(verify_slo_registered_signer,
                root.parent.parent/'reference-20261004', row['product'], live=False)
        # The selected browser Run includes both terminal variants and its normal
        # control. The adopter partitions actual target sends from Suite-only
        # aborted requests and preserves the centrally evaluated note/Warning.
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-SSO01-ep-idp-01':
            from verify_version_mismatch_acceptance import verify as verify_version_mismatch
            path, verified_ids=check_once(verify_version_mismatch,
                root.parent.parent/'reference-20261004', live=False)
            result=json.loads(path.read_bytes())
            cases=[case for requirement in result['requirements']
                   for case in requirement['cases'] if case['id'] in verified_ids]
            if verified_ids!={row['case']} or len(cases)!=1:
                raise ValueError('Version mismatch adoption has an unexpected case scope')
            selected=(path,{cases[0]['id']:cases[0]})
        # Adopt the stock native Run only after its full SOAP trials and the
        # separately executed approved mutant pass the same archived predicate.
        if row['product']=='shibboleth' and row['profile']=='single_logout_idp' \
                and row['case']=='IIP-IDP17-r-idp-01':
            native_root=root.parent.parent/'reference-20261004'
            native_result=native_root/'shibboleth-soap-slo-continuation-r5/evaluation-actual/result.json'
            if native_result.is_file():
                from verify_slo_soap_continuation_acceptance import verify as verify_soap_continuation
                path,verified_ids=check_once(verify_soap_continuation,native_root,live=False)
                result=json.loads(path.read_bytes())
                cases=[case for requirement in result['requirements']
                       for case in requirement['cases'] if case['id'] in verified_ids]
                if verified_ids!={row['case']} or len(cases)!=1:
                    raise ValueError('SOAP continuation adoption has an unexpected case scope')
                selected=(path,{cases[0]['id']:cases[0]})
        # The browser proof belongs to its original Run. Other profiles require
        # an explicit source-Run binding and their own installed case identity.
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-ALG08-c-idp-01':
            from verify_shibboleth_default_algorithm_acceptance import verify as verify_shib_default_algorithms
            selected=check_once(verify_shib_default_algorithms,
                root.parent.parent/'reference-20261004')
        if row['product']=='shibboleth' and row['profile']=='ecp_idp' \
                and row['case']=='IIP-ALG08-c-idp-01':
            source_root = root.parent.parent/'reference-20261004'/'shibboleth-default-algorithm-ecp-source-r1'
            if (source_root/'result-final.json').is_file():
                from verify_default_algorithm_source_run_acceptance import verify_adoption as verify_default_algorithm_source_run
                selected=check_once(verify_default_algorithm_source_run, source_root, live=False)
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-fg-idp-01':
            from verify_keycloak_ui_safety_acceptance import verify_adoption as verify_keycloak_ui_safety
            selected=check_once(verify_keycloak_ui_safety,
                root.parent.parent/'reference-20261003', live=False)
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD05-f9-idp-01','IIP-MD05-fh-idp-01'}:
            from verify_keycloak_native_ui_consumer_acceptance import verify_adoption as verify_keycloak_native_ui
            selected=check_once(verify_keycloak_native_ui,
                root.parent.parent/'reference-20261001', live=False)
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-e8-idp-01':
            from verify_keycloak_intersection_capability_acceptance import verify_adoption as verify_keycloak_intersection
            selected=check_once(verify_keycloak_intersection,
                root.parent.parent/'reference-20260930'/'keycloak-intersection-capability-sha512-v167', live=False)
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD06-a3-idp-01':
            from verify_shibboleth_role_signing_transport_acceptance import verify as verify_shibboleth_http_role
            selected=check_once(verify_shibboleth_http_role,
                root.parent.parent/'reference-20260930')
        # Keycloak's product console import, full Admin API read-back, native converter,
        # request-bound login decision, pinned runtime classes, correlated Success, and exact
        # deletion read-back prove the approved no-feature note for these two cases only.
        # Logo and URL cases are deliberately excluded because the native converter consumes Logo.
        if row['product']=='keycloak' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD05-fb-idp-01','IIP-MD05-fj-idp-01'}:
            from verify_keycloak_ui_feature_absence import verify as verify_keycloak_ui_absence
            selected=check_once(verify_keycloak_ui_absence, root.parent.parent/'reference-20260930')
        if row['product'] in {'shibboleth','simplesamlphp','keycloak'} and row['profile']=='browser_sso_idp' and row['case']=='IIP-IDP02-a-idp-01':
            from verify_relying_party_attribute_acceptance import verify as verify_relying_party_attributes
            selected=check_once(verify_relying_party_attributes, root.parent.parent/'reference-20260918',row['product'])
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' and row['case']=='IIP-IDP11-a-idp-01':
            from verify_nameid_omission_acceptance import verify as verify_nameid_omission
            selected=check_once(verify_nameid_omission, root.parent.parent/'reference-20260918')
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' and row['case']=='IIP-IDP11-a-idp-01':
            from verify_keycloak_nameid_omission_absence import verify_adoption as verify_keycloak_nameid_absence
            selected=check_once(verify_keycloak_nameid_absence, root.parent.parent/'reference-20260930')
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' and row['case'] in {
                'IIP-SSO01-ga-idp-01','IIP-SSO01-gb-idp-01','IIP-SSO01-gc-idp-01','IIP-SSO01-gj-idp-01'}:
            from verify_authn_context_acceptance import verify as verify_authn_context
            selected=check_once(verify_authn_context, root.parent.parent/'reference-20260918')
        if row['product'] in {'shibboleth','keycloak','simplesamlphp'} and row['profile'] in {'browser_sso_idp','metadata_idp','ecp_idp','single_logout_idp'} and row['case']=='IIP-ALG03-a-idp-01':
            from verify_native_ec_acceptance import verify as verify_native_ec
            selected=check_once(verify_native_ec, root.parent.parent/'reference-20260918',row['profile'],row['product'])
        if row['product'] in {'simplesamlphp','keycloak'} and row['case'] in {'IIP-ALG01-a-idp-01','IIP-ALG02-a-idp-01'}:
            from verify_native_signed_acceptance import verify as verify_native_signed
            selected=check_once(verify_native_signed, root.parent.parent/'reference-20260918',row['profile'],row['product'])
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' and row['case']=='IIP-IDP01-a-idp-01':
            from verify_keycloak_attribute_name_absence import verify as verify_keycloak_attribute_names
            selected=check_once(verify_keycloak_attribute_names, root.parent.parent/'reference-20260930')
        # Keycloak's two metadata-driven attribute-policy obligations have normative-capability
        # semantics.  Adopt only the fail-closed native capability audit: both installed import
        # paths, all installed SAML mapper providers, converter/runtime originals, a correlated
        # signed SSO control, credential-redacted client read-back, and exact deletion restoration.
        # IDP04.b remains excluded because its approved semantics are test_precondition.
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' and row['case'] in {
                'IIP-IDP03-a-idp-01','IIP-IDP04-a-idp-01'}:
            from verify_keycloak_attribute_policy_capability_absence import verify as verify_keycloak_policy_absence
            policy_path, policy_cases = check_once(verify_keycloak_policy_absence, 
                root.parent.parent/'reference-20260930')
            if policy_path.is_absolute():
                policy_path = policy_path.relative_to(Path.cwd())
            selected=(policy_path, policy_cases)
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-f-idp-01':
            native_root = root.parent.parent/'reference-20261003'
            native_result = native_root/'shibboleth-full-ui-r2/evaluation-v206/result.json'
            if native_result.is_file():
                from verify_shibboleth_full_ui_acceptance import verify_adoption as verify_shib_full_ui
                selected=check_once(verify_shib_full_ui, native_root, live=False)
                qualified_full_ui.add((row['product'], row['profile'], row['case']))
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-IDP06-b-idp-01':
            mechanism_root = root.parent.parent/'reference-20261004'/'keycloak-forceauthn-mechanism-r2'
            if (mechanism_root/'acceptance-originals.json').is_file():
                from verify_keycloak_forceauthn_mechanism_acceptance import verify_adoption as verify_keycloak_forceauthn_mechanism
                selected=check_once(verify_keycloak_forceauthn_mechanism, mechanism_root, live=False)
        # These two conclusions require original saved state, signed source messages,
        # actual native construction replay, controls, restoration, and a formal
        # stored-result transition. A UUID-shaped sample alone has no detection power.
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case'] in {'IIP-SSO05-a1-idp-01','IIP-SSO05-a8-idp-01'}:
            identifier_root = root.parent.parent/'reference-20261004'/'keycloak-persistent-opaque-r1'
            if (identifier_root/'acceptance-originals.json').is_file():
                from verify_keycloak_persistent_identifier_acceptance import verify_adoption as verify_keycloak_identifiers
                selected=check_once(verify_keycloak_identifiers, identifier_root, live=False)
        # A currently used native signer absent from unchanged published metadata
        # is a concrete all-of counterexample. Unknown other role purposes remain
        # unproven; the adopter checks both original peer Runs without relabelling.
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' \
                and row['case'] in {'IIP-MD05-c1-idp-01','IIP-MD05-c3-idp-01'}:
            publisher_root = root.parent.parent/'reference-20261004'/'simplesamlphp-publisher-used-signers-r2'
            if (publisher_root/'evaluation-actual/result.json').is_file():
                from verify_native_publisher_used_signers_acceptance import verify as verify_used_native_signers
                selected=check_once(verify_used_native_signers, publisher_root, live=False)
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' \
                and row['case']=='IIP-MD05-c1-idp-01':
            publisher_root = root.parent.parent/'reference-20261004'
            if (publisher_root/'shibboleth-publisher-endpoints-r3/evaluation-actual/result.json').is_file():
                from verify_shibboleth_publisher_endpoint_acceptance import verify as verify_shib_publisher_endpoints
                selected=check_once(verify_shib_publisher_endpoints, publisher_root, live=False)
        if selected is not None:
            path, selected_cases = selected
            if path.is_absolute():
                path = path.relative_to(Path.cwd())
            raw=path.read_bytes(); result=json.loads(raw); case=selected_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       result_file=path.name,
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        if row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':refreshed.append(row)
    from audit_algorithm_verification_evidence import withdrawals as algorithm_withdrawals
    withdrawn=algorithm_withdrawals(root.parent)
    keys={(r['product'],r['profile'],r['case']) for r in withdrawn}
    refreshed=[r for r in refreshed if (r['product'],r['profile'],r['case']) not in keys]
    transitions=[r for r in transitions if (r['product'],r['profile'],r['case']) not in keys]
    for row in withdrawn:
        if row['product'] in {'shibboleth','simplesamlphp','keycloak'}:
            from verify_native_signed_acceptance import verify as verify_native_signed
            path,cases=check_once(verify_native_signed, root.parent.parent/'reference-20260918',row['profile'],row['product'])
            raw=path.read_bytes();result=json.loads(raw);case=cases[row['case']]
            row=dict(row)
            row['previous_audit_withdrawal']=row.pop('audit_withdrawal')
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],verdict=case['verdict'],
                result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent.relative_to(root.parents[3])),
                interaction=None,evidence=case['evidence'],diagnostics=case.get('diagnostics',{}))
            transitions.append(row)
        else:
            refreshed.append(row)
    (root/'algorithm-verification-withdrawals.json').write_text(json.dumps(withdrawn,ensure_ascii=False,indent=2)+'\n')
    from audit_force_authn_mechanism_evidence import withdrawals as force_authn_withdrawals
    mechanism_withdrawn = force_authn_withdrawals(root.parent)
    mechanism_keys = {(r['product'],r['profile'],r['case']) for r in mechanism_withdrawn}
    refreshed = [r for r in refreshed if (r['product'],r['profile'],r['case']) not in mechanism_keys]
    transitions = [r for r in transitions if (r['product'],r['profile'],r['case']) not in mechanism_keys]
    for row in mechanism_withdrawn:
        native_root = root.parent.parent/'reference-20261004'
        native_result = native_root/'ssp-forceauthn-mechanism-r3/evaluation/result.json'
        selected_mechanism = None
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-IDP06-b-idp-01' and native_result.is_file():
            from verify_ssp_forceauthn_mechanism_acceptance import verify as verify_ssp_forceauthn_mechanism
            selected_mechanism=check_once(verify_ssp_forceauthn_mechanism, native_root)
        keycloak_root = native_root/'keycloak-forceauthn-mechanism-r2'
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-IDP06-b-idp-01' and (keycloak_root/'result-final.json').is_file():
            from verify_keycloak_forceauthn_mechanism_acceptance import verify_adoption as verify_keycloak_forceauthn_mechanism
            selected_mechanism=check_once(verify_keycloak_forceauthn_mechanism, keycloak_root, live=False)
        if selected_mechanism is not None:
            path,cases=selected_mechanism
            raw=path.read_bytes();result=json.loads(raw);case=cases[row['case']]
            row=dict(row)
            row['previous_audit_withdrawal']=row.pop('audit_withdrawal')
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],verdict=case['verdict'],
                result_sha256=hashlib.sha256(raw).hexdigest(),evidence_folder=str(path.parent.relative_to(root.parents[3])),
                result_file=path.name,interaction=None,evidence=case['evidence'],diagnostics=case.get('diagnostics',{}))
            transitions.append(row)
        else:
            refreshed.append(row)
    (root/'force-authn-mechanism-withdrawals.json').write_text(json.dumps(mechanism_withdrawn,ensure_ascii=False,indent=2)+'\n')
    from audit_async_feedback_failure_evidence import withdrawals as async_feedback_withdrawals
    feedback_withdrawn = check_once(async_feedback_withdrawals, root.parent)
    feedback_keys = {(r['product'],r['profile'],r['case']) for r in feedback_withdrawn}
    refreshed = [r for r in refreshed if (r['product'],r['profile'],r['case']) not in feedback_keys]
    transitions = [r for r in transitions if (r['product'],r['profile'],r['case']) not in feedback_keys]
    refreshed.extend(feedback_withdrawn)
    (root/'async-feedback-failure-withdrawals.json').write_text(json.dumps(feedback_withdrawn,ensure_ascii=False,indent=2)+'\n')
    from audit_metadata_full_ui_evidence import withdrawals as metadata_full_ui_withdrawals
    # Retain the pinned legacy withdrawal unless the independent native adopter
        # has verified a replacement Run's complete values, controls and restoration.
    ui_withdrawn = [r for r in check_once(metadata_full_ui_withdrawals, root.parent)
                   if (r['product'], r['profile'], r['case']) not in qualified_full_ui]
    ui_keys = {(r['product'], r['profile'], r['case']) for r in ui_withdrawn}
    refreshed = [r for r in refreshed if (r['product'], r['profile'], r['case']) not in ui_keys]
    transitions = [r for r in transitions if (r['product'], r['profile'], r['case']) not in ui_keys]
    refreshed.extend(ui_withdrawn)
    (root/'metadata-full-ui-withdrawals.json').write_text(json.dumps(ui_withdrawn,ensure_ascii=False,indent=2)+'\n')
    rows=refreshed
    (root/'retest-delta.json').write_text(json.dumps(transitions,ensure_ascii=False,indent=2)+'\n')
    counts=Counter(); indexed=defaultdict(list)
    diagnoses=Counter()
    for row in rows:
        group=classify(row);row['category']=group;counts[group]+=1
        c=catalog[row['case']]
        row['mode']=c.get('mode')
        row['capability_diagnosis']=diagnose(row);diagnoses[row['capability_diagnosis']]+=1
        row['variant_references']=[v['reference'] for v in c['variant_plan']]
        row['variant_instructions']=[v['instruction_en'] for v in c['variant_plan']]
        row['controls']=[{'id':v['id'],'kind':v['kind'],'fixture':v.get('fixture')} for v in c['controls']]
        row['next_action']=GROUPS[group][2]
        if row.get('product')=='keycloak' and row.get('profile')=='metadata_idp':
            if row['case'] in _KEYCLOAK_METADATA_FEATURE_ABSENT:
                row['next_action']=('The investigated paths (admin API attribute listings, availability of a server-side import API, and the single-certificate model) '
                    'did not confirm the capability. Absence is unconfirmed. Submit the original fixture through the product import path (admin console) '
                    'and verify the subsequent behavior.')
                row['absence_basis']='not-confirmed-investigated-path'
            elif row.get('capability_diagnosis')=='suite-observation-gap':
                row['next_action']=('Submit the original fixture through the product import path and observe subsequent behavior (signature verification, key selection, '
                    'and certificate acceptance). Suite XML-to-attribute conversion is not evidence of product metadata interpretation.')
            elif row.get('capability_diagnosis')=='operator-attestation-available':
                row['next_action']='Use operator testimony to verify publication and operational evidence, including key rollover history, revocation handling, and whether Trust configuration is required.'
        if row.get('product')=='shibboleth' and row.get('profile')=='metadata_idp' \
                and row['case'] in _SHIBBOLETH_SIGNATURE_DEPENDENT:
            row['next_action']=('The reference Shibboleth configuration has no Filter that verifies metadata document signatures '
                '(metadata-providers.xml uses a plain FilesystemMetadataProvider). Signature and XPath transform evaluations require '
                'a SignatureValidation filter trusting the poll-<sha256(variant)[:16]> key (xsi:type=SignatureValidation, '
                'requireSignedRoot=true, certificateFile), plus configuration equivalent to '
                'failFastInitialization=false to avoid initialization failure with rejection fixtures. Retain NOT_VERIFIED until configured; '
                'do not convert acceptance to VIOLATED. Observations are recorded in reference-20260918/shibboleth-md05-consumer-v76/finding.json.')
            row['observation_gap']='metadata-signature-validation-not-configured'
        if row.get('product')=='simplesamlphp' and row.get('profile')=='metadata_idp' \
                and row['case'] in {
                    'IIP-MD03-a-idp-01','IIP-MD03-b-idp-01','IIP-MD03-c-idp-01',
                    'IIP-MD04-a-idp-01','IIP-MD04-b-idp-01','IIP-MD05-as-idp-01'}:
            row['next_action']=('The SimpleSAMLphp CLI metadata parser path neither verifies document signatures nor enforces validUntil, '
                'so fixtures expected to be rejected are observed as used and incorrectly produce VIOLATED '
                '(including reference-20260918/simplesamlphp-md04ab-v136). Until a runtime metadata source '
                '(HTTP fetch) is configured to enforce signatures and expiration, retain NOT_VERIFIED '
                'and do not turn CLI import acceptance into a product FAIL.')
            row['observation_gap']='native-cli-parser-does-not-enforce-signature-or-validity'
        if row.get('product')=='simplesamlphp' and row.get('profile')=='metadata_idp' \
                and row['case']=='IIP-MD05-b-idp-01':
            row['next_action']=('PDPDescriptor.php in SimpleSAMLphp bundled saml2-legacy has an inverted condition that throws '
                '"Must have at least one AuthzService" when AuthzService exists, preventing parsing of '
                'schema-conforming metadata containing PDPDescriptor (reference-20260918/simplesamlphp-md05b-v138; '
                'the other 4 variants were accepted). Retain NOT_VERIFIED until retesting with a corrected library; '
                'do not turn rejection of a valid fixture into a product FAIL.')
            row['observation_gap']='product-library-pdpdescriptor-inverted-check'
        if row.get('product')=='keycloak' and row.get('profile')=='metadata_idp' and row['case'] in {
                'IIP-MD02-d-idp-01','IIP-MD05-b-idp-01','IIP-MD05-c2-idp-01',
                'IIP-MD05-f-idp-01','IIP-MD06-a1-idp-01'}:
            row['next_action']=('Keycloak console Import client reliably imports only simple role descriptors in a single EntityDescriptor. '
                'Multiple entities (entities-root-two/fifty), nesting (nested-entities), multiple role '
                'descriptors (schema-global-element-families), and complex UIInfo cause import timeouts or uncorrelated subsequent SSO '
                '(including reference-20260918/keycloak-md05b-v140). Evaluate acceptance only for successfully imported fixtures; '
                'do not turn inability to import into a product FAIL.')
            row['observation_gap']='keycloak-console-import-single-entity-only'
        if row.get('product') in {'simplesamlphp','keycloak'} and row.get('profile')=='browser_sso_idp' \
                and row['case'] in {'IIP-IDP03-a-idp-01','IIP-IDP04-a-idp-01','IIP-IDP04-b-idp-01'}:
            row['next_action']=('The native campaign drives comparisons under a fixed attribute release policy (baseline / entity-present / entity-absent / '
                'requested-required / requested-optional / requested-absent / index-0 / index-1 / index-0-repeat) '
                'and registers a preparation receipt in AttributePolicyPreparationFile; it is implemented '
                'only for Shibboleth. Live probes (reference-20260918/simplesamlphp-attrpolicy-probe-v1/v2, '
                'run_YGKQCX7PDWHFW4XGN1RE5J5T1B) showed that SimpleSAMLphp native parsing imports SP metadata '
                'AttributeConsumingService into `attributes`: requested-absent returns all attributes, '
                'while requested-required/optional returns none because the authentication source lacks attributes with the requested OID names. '
                'entity-present/absent returns the same attributes, without observed EntityAttributes-driven release. '
                'The evaluator requires release of markers named `urn:samlscope:test:policy:*`, whereas SSP release follows SP parsed '
                '`attributes` (urn:oid:*), so the namespaces differ. Required-name marker attributes must be added to the authentication source, '
                'with condition-specific release mappings (such as authproc) and receipt issuance and registration. '
                'Successful configuration storage does not establish generation capability.')
            row['observation_gap']='attribute-policy-conditions-campaign-not-implemented'
        if row.get('product')=='simplesamlphp' and row.get('profile')=='browser_sso_idp' \
                and row['case']=='IIP-IDP11-a-idp-01':
            row['next_action']=('Investigate a dedicated NameID omission configuration path and compare normal and omitted generation using the same input. '
                'Diagnostic-only invocation confirmed that the loaded SAML2.php normal path always adds NameID in buildAssertion '
                'and falls back to transient when NameIDFormat is empty or unknown '
                '（reference-20261004/ssp-nameid-omission-readonly-preflight）。'
                'This diagnosis checks candidate configuration in advance; it does not evaluate capability in actual SSO. '
                'Retain Not verified until a dedicated path or evidence supporting absence of the approved normative_capability is available.')
            row['observation_gap']='native-nameid-omission-configuration-unproven'
        if row.get('product')=='simplesamlphp' and row.get('profile')=='browser_sso_idp' \
                and row['case']=='IIP-IDP04-b-idp-01':
            row['next_action']=('The product-native attribute policy campaign completed all 9 conditions and restored the original configuration. '
                'SimpleSAMLphp 2.5.0 always selected the first of multiple AttributeConsumingService entries in the same metadata, '
                'returning the same attributes as index 0 even with AuthnRequest AttributeConsumingServiceIndex=1. '
                'Retain NOT_VERIFIED because the approved case does not turn unmet configuration prerequisites into a product FAIL. '
                'Originals and formal results are in reference-20260930/simplesamlphp-attribute-policy-v152-r2 and '
                'simplesamlphp-attribute-policy-evaluation-v153。')
            row['observation_gap']='product-native-attribute-consuming-service-index-unavailable'
        if row.get('product')=='keycloak' and row.get('profile')=='browser_sso_idp' \
                and row['case'] in {'IIP-IDP03-a-idp-01','IIP-IDP04-a-idp-01','IIP-IDP04-b-idp-01'}:
            row['next_action']=('The Keycloak 26.7.2 product-native metadata converter was executed directly on the original fixture. '
                'EntityAttributes were not retained in client configuration; RequestedAttribute isRequired produced identical '
                'required/optional mappers, and multiple AttributeConsumingService entries were flattened into all mappers without index information. '
                'Retain NOT_VERIFIED because the approved case does not turn unmet configuration prerequisites into a product FAIL. '
                'Audit originals are in reference-20260930/keycloak-attribute-policy-native-audit.')
            row['observation_gap']='product-native-attribute-policy-semantics-unavailable'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-a1-idp-01':
            row['next_action']=('The product detected duplicate entityID values, surfaced a WARN, and used the first descriptor. The obligation says '
                '"reject or surface", so whether log surfacing satisfies the alternative depends on interpretation. The approved observer treats only non-use '
                'as rejection and therefore produces VIOLATED, but retain NOT_VERIFIED pending G2 interpretation review.')
            row['observation_gap']='surface-semantics-undecided'
        if row.get('profile') in ('browser_sso_idp','ecp_idp') and row['case'] in {
                'IIP-ALG04-a-idp-01','IIP-ALG04-b-idp-01','IIP-ALG06-b-idp-01',
                'IIP-ALG06-c-idp-01','IIP-ALG06-d-idp-01'}:
            row['next_action']=('EncryptionAlgorithmBrowserEvidenceTestCase decrypts the EncryptedAssertion in a correlated SSO response '
                'with the Suite key to evaluate generation algorithms (decrypted-target-assertion is required). '
                'Suite SP metadata variants can now advertise EncryptionMethod (MetadataEncryptionAlgorithmFixtures), '
                'and the SSP producer campaign has --metadata-variant. However, the root cause was identified: '
                'MetadataService.endpoint(plan, path, variant, runId) adds mdv=<variant> to ACS/SSO '
                'Location when variant!=BASELINE. Serving Suite SP metadata with a variant makes the m0-roundtrip '
                'response ACS URL include mdv, causing the SP peer to treat it as a metadata-probe response (metadataProbeAccepted=false), '
                'so the Run does not reach COMPLETED. A prototype added MetadataService.generateSuiteMetadata '
                '(applying attribute variants with baseline endpoints) in an unprotected file, with a serving route '
                '/p/{plan}/metadata?baselineEndpoints=true. The route was withdrawn because its file is G2-protected '
                '(SamlScopeApplication.java), preserving G2-30. The capability remains in the unprotected component. '
                'Live measurement also showed that even with baselineEndpoints enabled and GCM advertised to SSP, '
                'SSP ignores SP metadata EncryptionMethod and encrypts with the defaults (rsa-oaep-mgf1p/aes128-cbc) '
                '(Run run_9SMXBQY2MGZS4VFF0PC0C354H6: observed_content_algorithms=[aes128-cbc])。'
                'Therefore SP metadata advertisement cannot produce observations of ALG04-a/b GCM; investigate SSP encryption algorithm '
                'configuration, including support. Route wiring requires G2 reapproval.')
            row['observation_gap']='sp-encryption-algorithm-control-missing'
        if row.get('profile')=='single_logout_idp' and row.get('category')=='inconclusive' \
                and row['case'].startswith(('IIP-IDP17','IIP-IDP18','IIP-IDP19')):
            row['next_action']=('The SLO browser chain (SSO/initial login) works on the product, but these cases require target-emitted '
                'logout messages and specific scenarios (continued propagation, partial logout, Redirect requests/responses, and multiple-key encrypted ID). '
                'Add SP-initiated and IdP-initiated logout operations to the driver to complete Suite SLO probes. '
                'Silence and probe-no-response do not establish FAIL.')
            row['observation_gap']='slo-logout-action-not-driven'
        if row.get('product')=='simplesamlphp' and row.get('profile')=='single_logout_idp' \
                and row['case'] in {'IIP-IDP17-r-idp-01','IIP-IDP17-s-idp-01'}:
            row['next_action']=('Browser console observation confirmed that SSP iframe logout blocks participant frames under the reference CSP '
                "(default-src 'none', no frame-src; reference-20260918/ssp-slo-iframe-v11: "
                '"Framing http://localhost:18080/ violates ... default-src \'none\' ... blocked"）。'
                'Traditional logout breaks the browser chain at a failing participant, so no final LogoutResponse/PartialLogout arrives. '
                'Retain NOT_VERIFIED until product or operator configuration permits frame-src and provides the logout operation path; '
                'silence and unavailable do not establish a product FAIL.')
            row['observation_gap']='slo-iframe-csp-frame-src-blocks-propagation'
        if row['product']=='shibboleth' and row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-fj-idp-01':
            row['next_action']=('Campaign changes and receipt reevaluation brought the Run to COMPLETED, case startup, and receipt loading '
                '(reference-20260918/shibboleth-display-precedence-v94b). The remaining NOT_VERIFIED is caused by '
                'the Shibboleth login template guard suppressing entity names (login.vm: '
                '<h1> is rendered only when $serviceName && !$rpContext.getRelyingPartyId().contains($serviceName)); '
                'the ENTITY condition without UIInfo DisplayName/ServiceName does not display entityID/hostname '
                'and produces selection_unobserved_entity. No current path establishes entity-fallback without changing the product template; '
                'VerifyUiDisplayEvidence is also designed to accept this issue as NOT_VERIFIED. '
                'Do not label the default product suppression behavior as nonconforming.')
            row['observation_gap']='ui-display-entity-name-suppressed-by-template'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-aw-idp-01':
            row['next_action']=('The "TLS with use=signing" variant requires observing the IdP TLS path, which the reference Shibboleth '
                'does not expose. If a safe TLS path cannot be configured within the constraints, use NOT_VERIFIED. '
                'XML signature and encryption key wrapping can be observed, but neither alone satisfies all_of.')
            row['observation_gap']='tls-usage-path-unimplemented'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-d-idp-01':
            row['next_action']=('The case covers 4 mdattr:EntityAttributes variants (direct Attribute, signed Assertion, Conditions, and multiple Attributes). '
                'The current Suite generates only one EntityAttributes fixture form for attribute-policy, without signed Assertion or '
                'Conditions forms, so it cannot satisfy all variants. Dedicated fixtures must be added.')
            row['observation_gap']='mdattr-assertion-fixtures-unimplemented'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-b-idp-01':
            row['next_action']=('An aggregate case requiring acceptance of the entire SAML V2.0 Metadata Schema (13 variants: role descriptors, KeyDescriptor, '
                'AttributeConsumingService, Organization/ContactPerson, EndpointType, AuthnAuthority/PDP/'
                'AttributeAuthority, and others). Dedicated fixtures are not implemented; coverage '
                'under separate IDs from existing cases is needed. Inventory support for each variant before partial implementation.')
            row['observation_gap']='metadata-schema-fixture-matrix-unimplemented'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-c-idp-01':
            row['next_action']=('MD05.c evaluates acceptance of MDIOP representations; key interpretation is delegated to MD06.a. '
                'With a KeyValue-only fixture, the fixture observer requires signature discrimination (a SAML error response is mandatory). '
                'Shibboleth returns HTTP errors for invalid signatures, so this cannot be satisfied. Design and implement '
                'an acceptance-only evidence path that does not require discrimination.')
            row['observation_gap']='mdiop-acceptance-triggers-out-of-scope-discrimination'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-a3-idp-01':
            row['next_action']=('The signed MD05.a3 constraints separate namespace qualification from unknown-extension acceptance '
                'and require a dedicated evidence path; consumer acceptance is not evidence. Design and implement a dedicated '
                'passive metadata check for namespace qualification of extensions published by the target.')
            row['observation_gap']='namespace-qualification-evidence-path-unimplemented'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD11-a-idp-01':
            row['next_action']=('All 3 variants (XML signature verification, TLS/SSL, and encryption key wrapping) are required by all_of. '
                'Dedicated implementation including TLS observation is needed; NOT_VERIFIED is permitted if constraints prevent safe TLS configuration. '
                'Individually verify that a key in KeyDescriptor with use omitted works for all 3 purposes.')
            row['observation_gap']='tls-usage-path-unimplemented'
        if row['case']=='IIP-MD05-ah-idp-01' and row.get('profile')=='metadata_idp':
            row['next_action']=('The approved target-side variant "the target itself signs metadata with RSA-SHA1" concerns '
                'internal remote IdP behavior that cannot be observed over SAML. Because all_of is incomplete, the design remains partial '
                'and retains NOT_VERIFIED. Implementing only the verification variant (Suite serving RSA-SHA1-signed metadata) '
                'cannot resolve it.')
            row['observation_gap']='target-side-signing-not-observable'
        if row['case']=='IIP-G02-a-idp-01' and row.get('diagnostics',{}).get('remaining_conditions'):
            row['next_action']='Implement inputs, positive controls, and response observations for the remaining conditions: '+', '.join(row['diagnostics']['remaining_conditions'])
        if row['case'] in implementations:
            row['implementation_observation']=implementations[row['case']]
            row['next_action']=implementations[row['case']]['next_action']
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' and row['case'] in ENCRYPTION_DIAGNOSIS_CASES:
            from verify_encrypted_sso_diagnosis import verify as verify_encryption_diagnosis
            diagnostic_run,diagnostic_cases=check_once(verify_encryption_diagnosis, root.parent.parent/'reference-20260918')
            row['individual_diagnosis']='reference-20260918/simplesamlphp-normal-encrypted-sso/protocol-evidence-diagnostics.json'
            row['additional_observation']={'run':diagnostic_run,'details':diagnostic_cases[row['case']]['details']}
            row['next_action']='Normal SSO proved encryption generation and decryption with the Run key. AES128-CBC and rsa-oaep-mgf1p were observed. Configuration or another path is needed to generate GCM, rsa-oaep(1.1), and the required Digest/MGF combinations. Defaults alone do not establish lack of support.'
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' and row['case']=='IIP-IDP01-a-idp-01':
            diagnostic_path=root.parent.parent/'reference-20260918/keycloak-attribute-name-capability/configure.json'
            row['individual_diagnosis']='reference-20260918/keycloak-attribute-name-capability/configure.json'
            row['additional_observation']={'details':json.loads(diagnostic_path.read_text())['outcome']['details'],
                'sha256':hashlib.sha256(diagnostic_path.read_bytes()).hexdigest()}
            row['next_action']='URI and arbitrary string attribute names were verified in signed, decrypted responses. Custom NameFormat was retained in standard User Property mapper configuration read-back but was not observed in responses. Investigate another standard configuration path. Successful configuration storage does not establish generation capability.'
        if row['product']=='keycloak' and row['case'] in {'IIP-IDP19-a-idp-01','IIP-IDP19-b-idp-01','IIP-IDP19-c-idp-01'}:
            row['next_action']='An encryption provider exists. Runtime bytecode confirmed that SAML metadata generation selects signing keys only. Adding keys alone cannot resolve Suite key acquisition. Preserve public metadata and add a supplemental input path for test public keys with pinned provenance, then execute controls.'
            row['individual_diagnosis']='keycloak-decryption-keys/diagnosis.json'
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' and row['case'] in {'IIP-SSO05-a-idp-01','IIP-SSO05-a2-idp-01'}:
            row['next_action']='A successful response with persistent NameID is required. IdP persistentId generation (saml-nameid.properties) was temporarily enabled and tested twice, but no flow canonicalized the Subject in the request, causing SubjectCanonicalizationError rejection. Retest after preparing prerequisites including c14n configuration. Attempts and restoration are recorded in shib-config/diagnosis.json.'
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case'] in {'IIP-MD05-ea-idp-01','IIP-MD05-eb-idp-01'}:
            folder=root.parent.parent/'reference-20260918/simplesamlphp-algorithm-recorded-metadata'
            path=folder/'algorithm-selection-diagnosis.json'
            diagnosis=json.loads(path.read_text())
            for name,digest in diagnosis['source_sha256'].items():
                assert hashlib.sha256((folder/name).read_bytes()).hexdigest()==digest
            proof=json.loads((folder/'verified-algorithm-signatures.json').read_text())
            assert diagnosis['run']==proof['run']
            assert len(proof['observations'])==13 and all(o['signed_response_verified'] for o in proof['observations'])
            prepared_path=folder/'prepared-metadata-verification.json'
            prepared=json.loads(prepared_path.read_text())
            assert prepared['run']==diagnosis['run'] and len(prepared['receipts'])==13
            row['additional_observations']={'run':diagnosis['run'],'diagnosis_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                'prepared_metadata_verification_sha256':hashlib.sha256(prepared_path.read_bytes()).hexdigest(),
                'evidence_folder':str(folder.relative_to(root.parents[3])),'affects_verdict':False}
            row['next_action']='Originals, native import, and correlated signed responses support the conclusion. Role-priority MD05.eb is separately confirmed FAIL. MD05.ea selects SHA256 even after reordering, but local policy and SHA384 usability are unconfirmed, so it remains NOT_VERIFIED. Retest with verified policy.'
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' and row['case']=='IIP-SSO01-cz-idp-01':
            row['next_action']='Live measurement verified the fix preventing an undecrypted EncryptedAssertion from establishing success through apparent Subject absence. Safely pass decrypted contents to principal evaluation and collect evidence semantically mapping identifiers, including SubjectConfirmation and attributes, to the authenticated principal.'
        if row['product']=='shibboleth' and row['profile']=='metadata_idp' and row['case'] in {'IIP-MD05-e-idp-01','IIP-MD05-e8-idp-01'}:
            folder=root.parent.parent/'reference-20260918/shibboleth-encryption-metadata'
            path=folder/'encryption-selection-observations.json'
            observation=json.loads(path.read_text())
            for name,digest in observation['source_sha256'].items():
                assert hashlib.sha256((folder/name).read_bytes()).hexdigest()==digest
            decrypted=json.loads((folder/'verified-encryption-decryption.json').read_text())
            assert decrypted['run']==observation['run']
            assert decrypted['signed_evidence_sha256']==hashlib.sha256((folder/'verified-algorithm-signatures.json').read_bytes()).hexdigest()
            assert len(decrypted['observations'])==16 and all(x['decrypted_assertions']>0 and x['wrong_key_rejected'] and x['advertised_key_matched'] for x in decrypted['observations'])
            row['additional_observations']={'run':observation['run'],'evidence_folder':str(folder.relative_to(root.parents[3])),
                'encryption_observation_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                'decryption_verification_sha256':hashlib.sha256((folder/'verified-encryption-decryption.json').read_bytes()).hexdigest(),'affects_verdict':False}
            row['next_action']='Added 15 inputs varying encryption method, OAEP Digest/MGF, and key size. Across 16 conditions including controls, original-byte equality, signed responses, decryption with the corresponding key, and failure with another key were proved. Pass metadata campaign variant keys to evaluation and connect it after verifying all approved case conditions and controls. Current measurements alone do not establish Success for every case.'
        indexed[row['case']].append(row)
    assert sum(counts.values())==len(rows)
    (root/'implementation-audit.json').write_text(json.dumps(implementations,ensure_ascii=False,indent=2)+'\n')
    (root/'inventory.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n')
    lines=['# Complete inventory of unverified observations', '',
           'This inventory covers NOT_VERIFIED observations remaining after the previous follow-up and their additional retests. Counts are observations per product, profile, and case. Only retested cases adopt evidence from new Runs; other existing evidence is retained. These counts do not represent a complete single Run or a conformance rate.', '',
           '| Before retesting | Conclusive (Success / Failed / Warning) | Currently unverified | Distinct unverified case IDs |', '|---:|---:|---:|---:|',f'| {baseline_count} | {baseline_count-len(rows)} | {len(rows)} | {len(indexed)} |', '',
           '## Breakdown', '', '| Cause and current path | Count | Next scope |', '|---|---:|---|']
    for k,(title,owner,action) in GROUPS.items():lines.append(f'| {title} | {counts[k]} | {owner} |')
    partial=[r for r in rows if r['case']=='IIP-G02-a-idp-01' and r.get('diagnostics',{}).get('remaining_conditions')]
    if partial:
        lines+=['', '### Verified and remaining G02 conditions', '',
                'The following are partial observations and are excluded from counts of conclusively evaluated cases. Value preservation and truncation are separate obligations and are not added to acceptance conditions; they are separated according to the approved definitions.', '',
                '| Product | Standard-string test inputs | Extension-attribute response inputs | Remaining conditions |', '|---|---:|---:|---|']
        for row in partial:
            d=row['diagnostics']
            lines.append(f"| {row['product']} | {len(d.get('confirmed_character_fixtures',[]))} | {len(d.get('responded_extension_string_fixtures',[]))} | "+', '.join(d['remaining_conditions'])+' |')
    lines+=['', 'Classification uses result reason codes, interaction types, and Suite implementation. "Test-path investigation" does not guarantee that execution is possible. Configuration and evidence paths also cannot guarantee results merely by enabling attestation.', '',
            'ECDSA cases retain browser waiting results from old Runs, but the currently registered class is EcSignatureSupportTestCase. Classification changed from missing automated evaluation to missing metadata retrieval and signature-control evidence. Verdicts and the total unverified count are unchanged. Current source and registration SHA-256 values are saved in implementation-audit.json.', '', 'Basic SP-initiated SLO IIP-IDP17-a and Redirect acceptance IIP-IDP18-a adopt evidence from product retests with dedicated implementations deployed. EncryptedID decryption IIP-IDP19-a was also retested, adopting Shibboleth success. Keycloak missing encryption keys and SimpleSAMLphp failed negative controls remain unverified with updated reasons.', '', '## Correction to the explanation', '',
            'The earlier explanation that "most required operations are incomplete" incorrectly grouped missing browser completion implementations, partial fixtures, and disabled evidence verification paths as incomplete operations. Unverified observations are not product failures, but neither do they establish that all tests are implemented and completed.', '',
            '## Execution paths examined in this follow-up', '',
            'Starting and resuming existing SLO Runs for all 3 products showed that common cases marked as waiting in old output had ended with delivery_or_response_unknown. active-probe FINISHED describes the state after this expiration. Positive controls and common tests were rerun in new Runs and additional evidence was saved. There were 5 additional Success observations; the remaining observations were 9 partially implemented cases and 4 pending signature evaluations. The start and resume APIs were each invoked once per product; one positive-control/common-test Run was created per product. Product configuration changes up to this point totaled 0. Signature-required configurations were then attempted for Keycloak and SimpleSAMLphp but failed at positive-control startup and were not adopted. Keycloak reception completion could not be confirmed, while the SimpleSAMLphp auxiliary client failed XML parsing. These are not classified as product FAIL. Each product incurred 2 configuration writes for changes and restoration, with restoration verified. Browser operations and human user operations were 0; execution used a protocol client.', '',
            'Retests after additional implementation automatically confirmed unpublished-URL notes for all 3 products (Warning) and confirmed Subject mismatches for Keycloak and SimpleSAMLphp (Failed). These are not whole-product conformance conclusions. See the [additional implementation record](27-additional-implementation.md).', '', '## Actions by cause', '']
    default_acs_notes=[]
    if any(row['case'] == 'IIP-MD05-av-idp-01' and row['product'] == 'keycloak'
           and row['profile'] == 'metadata_idp' and row['verdict'] == 'FAIL' for row in transitions):
        default_acs_notes.append(
            'In Keycloak 26.7.2, IIP-MD05-av control, '
            'explicit-first, and all-false fixtures imported through the product Import client path reached the correct ACS. However, omitted default after explicit-false '
            'reached ACS 0 instead of ACS 1, and metadata with duplicate AssertionConsumerService indices under the same parent '
            'was also imported, read back, and used for a Success response. This FAIL is a limited measurement that correlated container images, '
            'startup times, runtime VERSION at campaign start and end, deletion read-back of each temporary client, original fixtures, request/response correlation, '
            'and the Suite runtime JAR within the same Run.')
    if any(row['case'] == 'IIP-MD05-av-idp-01' and row['product'] == 'shibboleth'
           and row['profile'] == 'metadata_idp' and row['verdict'] == 'FAIL' for row in transitions):
        default_acs_notes.append(
            'In Shibboleth IdP 5.2.3, IIP-MD05-av fixtures imported through the product FilesystemMetadataProvider path '
            'reached the correct ACS for control, explicit-first, and all-false. However, omitted default after explicit-false '
            'reached ACS 0 instead of ACS 1, and metadata with duplicate AssertionConsumerService indices under the same parent '
            'was also fetched and used for a Success response. This FAIL is a limited measurement correlating container images, startup times, runtime VERSION at campaign start and end, '
            'byte-identical restoration to the original configuration, original fixtures, request/response correlation, and the Suite runtime JAR within the same Run.')
    if any(row['case'] == 'IIP-MD05-av-idp-01' and row['product'] == 'simplesamlphp'
           and row['profile'] == 'metadata_idp' and row['verdict'] == 'FAIL' for row in transitions):
        default_acs_notes.append(
            'In SimpleSAMLphp 2.5.0, the 3 IIP-MD05-av default-selection controls reached the correct ACS. However, '
            'metadata with duplicate AssertionConsumerService indices under the same parent was also fetched and used for a Success response. '
            'This FAIL is a limited measurement correlating container images, startup times, runtime VERSION at campaign start and end, configuration restoration, native MDQ fetches, '
            'and request/response correlation within the same Run.')
    if default_acs_notes:
        lines[lines.index('## Actions by cause')] = '\n\n'.join(default_acs_notes)+'\n\n## Actions by cause'
    for k,(title,owner,action) in GROUPS.items():lines += [f'### {title}', '', action, '']
    # Keep every historical trial in retest-delta.json, but display the final
    # selected result for each product/profile/case. Dict insertion order keeps
    # the existing profile preference when a case belongs to several profiles.
    latest_transitions = {
        (row['product'], row['profile'], row['case']): row for row in transitions
    }
    lines += ['## Additional retest results by product', '', '| Test | Keycloak | Shibboleth | SimpleSAMLphp |', '|---|---|---|---|']
    for case_id in sorted({r['case'] for r in transitions}):
        cells=[]
        for product in ('keycloak','shibboleth','simplesamlphp'):
            item=next((r for r in latest_transitions.values() if r['case']==case_id and r['product']==product), None)
            if item is None:
                item=next((r for r in rows if r['case']==case_id and r['product']==product
                           and r.get('audit_withdrawal')), None)
            if item is None:
                cells.append('Not verified (outside this retest scope)')
                continue
            cells.append({'PASS':'Success','FAIL':'Failed (Product)','WARNING':'Warning'}.get(item['verdict'], 'Not verified: '+item['reason_code']))
        lines.append(f'| `{case_id}` | '+' | '.join(cells)+' |')
    lines += ['', '## Case-level inventory', '',
              'Product columns list profiles with remaining unverified observations. Where a case has several reasons, the cause column lists each. An em dash means absence from this unverified set; it does not establish whole-product PASS.', '',
              '| Test | Keycloak | Shibboleth | SimpleSAMLphp | Cause |', '|---|---|---|---|---|']
    for case,items in sorted(indexed.items()):
        cells=['、'.join(sorted({r['profile'] for r in items if r['product']==p})) or '—' for p in ('keycloak','shibboleth','simplesamlphp')]
        why=' / '.join(GROUPS[g][0] for g in sorted({r['category'] for r in items}))
        lines.append(f'| `{case}` | '+' | '.join(cells)+f' | {why} |')
    lines+=['', '## Classification of inconclusive observations (diagnosis)', '',
             'This classification describes unverified reasons without changing Verdicts. feature-absent means feature absence confirmed from public metadata or equivalent evidence; role-inapplicable means a variant is not consumed in the role; evidence-form-mismatch means mismatch with the approved evidence format; operator-attestation-available means verification through operator testimony is possible; suite-observation-gap means Suite implementation can resolve the gap.', '',
             '| Diagnosis | Count | Meaning | Proposed display |', '|---|---:|---|---|']
    for key,count in diagnoses.most_common():
        meaning,display=DIAGNOSIS[key]
        lines.append(f'| `{key}` | {count} | {meaning} | {display} |')
    for key in DIAGNOSIS:
        ids=sorted({r['case'] for r in rows if r.get('capability_diagnosis')==key})
        if ids:
            lines+=['', f'### {key}', '', ', '.join('`'+i+'`' for i in ids), '']
    lines+=['', '## Evidence', '',
            'The local `build/acceptance/reference-20260914/remaining-audit/inventory.json` records every current unverified observation with its Run, case ID, reason code, test conditions, controls, next action, and source result.json SHA-256. Complete additional retest results are in `retest-delta.json`; the earlier set is in `baseline.json`. Original results and approved case definitions are unchanged.', '',
            'Implementation references: `BrowserEvidenceTestCase`, `IdpExecutableBrowserFixtureScenarioTestCase`, `ApprovedConfigCaseRegistry`, and `AttestedOutcomeTestCase`. Case conditions are taken from `tests/cases.yaml`.', '',
            'Inventory generation compares every unverified observation against approved conditions, positive and negative controls, and the source result.json Run, SHA-256, Verdict, and reason code. Any mismatch fails generation. Complete case conditions, variant groups, prerequisites, and interpretation constraints are stored in `unresolved-contract-audit.json`. Passing this audit does not establish completed evaluation implementation.', '',
            'Regenerate: `.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit`.','']
    from audit_unresolved_contracts import audit
    contract_audit = audit(root.parent, definitions)
    (root/'unresolved-contract-audit.json').write_text(json.dumps(contract_audit, ensure_ascii=False, indent=2)+'\n')
    if contract_audit['errors']:
        raise ValueError('Unresolved inventory failed contract/evidence audit; see unresolved-contract-audit.json')
    output.write_text('\n'.join(lines))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence-root',type=Path,required=True);p.add_argument('--definitions',type=Path,default=Path('tests/cases.yaml'));p.add_argument('--output',type=Path,default=Path('docs/26-unverified-case-inventory.md'));a=p.parse_args()
    from acceptance_dependency_discovery import dependency_discovery_scope
    with dependency_discovery_scope():
        render(a.evidence_root,a.definitions,a.output)
