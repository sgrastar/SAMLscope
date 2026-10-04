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
 'browser_oracle_missing': ('ブラウザ完了後の自動判定がない', 'Suite実装', 'BrowserEvidenceTestCaseは完了後にbrowser.oracle-unavailableを返す。対応する入力生成・観測・正負対照を実装する。'),
 'partial_fixture': ('一部の試験条件しか実装されていない', 'Suite実装', 'approved variant全体の入力生成と観測を実装する。追加ログインだけでは完了しない。'),
 'configuration_evidence': ('設定後の証拠確認・自己申告経路', '設定・証拠', 'ケースの全variantと対照を実施し、結果を裏付ける証拠を収集する。現Planでは自己申告が無効。設定確認だけをSuccessにしない。'),
 'attestation_disabled': ('自己申告が無効', '設定・証拠', '対象の設定・運用・実装資料を確認する。根拠を収集できた項目だけ、証拠確認を有効にした試験計画で扱う。'),
 'metadata_evidence': ('メタデータの追加試験・観測不足', '試験経路確認', '未取得・未使用のfixtureを確認し、対象の取込方式で追加実行する。拒否側は無応答だけで成功とせず、拒否の証明方法を確認する。'),
 'browser_transcript': ('ブラウザ・SLOの追加観測不足', '試験経路確認', '要求される受信証拠を確認する。IdP起点・別ACS・追加Logoutなどの経路をSuiteが提供するか確認し、不足なら実装する。'),
 'pending_no_action': ('古い待機結果・再開時には期限切れ', '新Runで再試験', '再開時にはdelivery_or_response_unknownで終了していた。新Runで正常系対照と共通試験を再実行し、元のSLO結果とは別に証拠を保存する。'),
 'inconclusive': ('実行したが確定できない', '個別診断', '理由コードと正常系対照を確認し、Suite・構成・製品を切り分ける。無応答や証拠不足を製品FAILに変更しない。'),
}

# Current code can supersede an old interaction mode without superseding its verdict.
IMPLEMENTATION_UPDATES = {
    'IIP-MD05-a3-idp-01': {
        'source_marker': 'id.startsWith("IIP-MD05-a3-")',
        'category': 'metadata_evidence',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/MetadataFixtureObservationTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/MetadataConfigCaseFactory.java',
        'registration': 'Map.entry("IIP-MD05.a3",',
        'next_action': 'Organization・ContactPerson・AffiliationDescriptorの入力とOrganization/Extensions負の対照を追加済み。入力受理と名前空間修飾義務を分離し、受理だけで製品FAILにしない。公開・設定した拡張点の名前空間を直接確認する経路が必要。',
    },
    'IIP-IDP19-b-idp-01': {
        'category': 'configuration_evidence',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/MultipleDecryptionKeysConfigurationTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedConfigCaseRegistry.java',
        'registration': 'new MultipleDecryptionKeysConfigurationTestCase(testCase,keys,executions)',
        'next_action': '複数鍵の設定能力について同一Runの単一鍵・複数鍵の対照付き成功から確認する経路を追加。稼働環境へ反映後に新Runで実行し、設定回答なしの再評価と出所を確認する。メタデータ掲載のみでは成功にしない。',
    },
    'IIP-IDP19-c-idp-01': {
        'category': 'browser_transcript',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/IdpBasicLogoutScenarioTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
        'registration': 'new IdpBasicLogoutScenarioTestCase(testCase.id(),',
        'next_action': '複数復号鍵の専用経路を登録。異なる暗号化鍵を用意し、未登録鍵への拒否対照後、新セッションでメタデータの2番目の鍵による復号を確認する。実製品反映と鍵設定・証拠収集は別途必要。',
    },
    'IIP-IDP19-a-idp-01': {
        'category': 'browser_transcript',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/IdpBasicLogoutScenarioTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
        'registration': 'new IdpBasicLogoutScenarioTestCase(testCase.id(),',
        'next_action': 'EncryptedID復号の専用経路を登録。反映後、未登録鍵の拒否対照と新セッションでの登録鍵による成功応答を検証する。対照不成立・無応答はNot verifiedを維持する。',
    },
    'IIP-IDP18-a-idp-01': {
        'category': 'browser_transcript',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/IdpBasicLogoutScenarioTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
        'registration': 'new IdpBasicLogoutScenarioTestCase(testCase.id(),',
        'next_action': '専用のRedirect受理シナリオを登録。反映後の新Runで新鮮なログインから署名付きRedirect LogoutRequestを送り、署名と相関を検証した応答を観測する。POSTへの代替や無応答を成功にはしない。',
    },
    'IIP-IDP17-a-idp-01': {
        'category': 'browser_transcript',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/IdpBasicLogoutScenarioTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
        'registration': 'new IdpBasicLogoutScenarioTestCase(testCase.id(),',
        'next_action': 'SP起点SLOの基本シナリオは登録済み。稼働環境へ反映した新Runで、署名・セッション正常系、LogoutRequest送信、相関したLogoutResponseを観測する。無応答は製品FAILにしない。',
    },
    'IIP-ALG03-a-idp-01': {
        'category': 'metadata_evidence',
        'source': 'runner/src/main/java/com/samlscope/runner/cases/EcSignatureSupportTestCase.java',
        'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
        'registration': 'return new EcSignatureSupportTestCase();',
        'next_action': 'ECDSA観測処理は実装済み。新RunでRSA正常系・ECDSA正常系・不正ECDSA署名の対照を実行し、相関した応答と完全な履歴を集める。HTTPエラーだけでは拒否確認にしない。',
    },
}

# The decryption-backed algorithm oracle exists even when an old Run says oracle-unavailable.
from verify_encrypted_sso_diagnosis import CASES as ENCRYPTION_DIAGNOSIS_CASES
IMPLEMENTATION_UPDATES.update({case_id: {
    'category': 'browser_transcript',
    'source': 'runner/src/main/java/com/samlscope/runner/cases/EncryptionAlgorithmObservation.java',
    'registry': 'runner/src/main/java/com/samlscope/runner/cases/ApprovedBrowserCaseRegistry.java',
    'registration': 'new EncryptionAlgorithmBrowserEvidenceTestCase(',
    'next_action': '復号を伴う暗号アルゴリズム判定は実装済み。通常SSOで対象の暗号化生成を有効にし、必要な生成アルゴリズムと全組合せの応答を観測する。',
} for case_id in ENCRYPTION_DIAGNOSIS_CASES})

# Classification only: these labels describe why an observation is still unresolved.
# They never change a Verdict and are not product failures.
DIAGNOSIS = {
    'feature-absent': ('製品が機能として公開していない（公開メタデータ等から確認済み）',
                       'この製品は機能として提供していないため、この試験は実行できません（skipped相当）'),
    'role-inapplicable': ('ロール上、対象が消費しない成果物を要求するvariant',
                          'IdPロールでは消費されないvariantのため実行対象外（対象外であることは判定済み）'),
    'evidence-form-mismatch': ('承認済み判定条件が要求する証拠形式と製品応答が不一致',
                               '証拠形式が承認済み条件と一致しないためNot verified（要件解釈の再確認が必要）'),
    'operator-attestation-available': ('自己申告または運用者証言で確認可能',
                                       '運用者証言（ケースごとに1回答）で確認可能。現在のPlanは自己申告無効'),
    'suite-observation-gap': ('Suite側の観測・実行経路が未接続',
                              'Suite側の実装で解消可能なNot verified'),
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
        # The unchanged default policy and all native algorithm controls belong
        # to this browser Run. Do not reuse it for another profile's obligation.
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' \
                and row['case']=='IIP-ALG08-c-idp-01':
            from verify_shibboleth_default_algorithm_acceptance import verify as verify_shib_default_algorithms
            selected=check_once(verify_shib_default_algorithms,
                root.parent.parent/'reference-20261004')
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
    refreshed.extend(mechanism_withdrawn)
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
                row['next_action']=('調査した経路（管理APIの属性一覧、サーバー側取込APIの有無、単一証明書モデル）では'
                    '該当能力を確認できない。不存在は未確認。製品自身の取込経路（管理コンソール）へ元fixtureを'
                    '渡し、その後の挙動で確認する。')
                row['absence_basis']='not-confirmed-investigated-path'
            elif row.get('capability_diagnosis')=='suite-observation-gap':
                row['next_action']=('製品自身の取込経路へ元fixtureを渡し、その後の挙動（署名検証・鍵選択・'
                    '証明書受理）を観測する。SuiteのXML→属性変換はメタデータ解釈の証拠にしない。')
            elif row.get('capability_diagnosis')=='operator-attestation-available':
                row['next_action']='公開・運用の証拠（鍵ロールオーバー履歴、失効扱い、Trust設定の要否）を運用者証言で確認する。'
        if row.get('product')=='shibboleth' and row.get('profile')=='metadata_idp' \
                and row['case'] in _SHIBBOLETH_SIGNATURE_DEPENDENT:
            row['next_action']=('参照Shibbolethはメタデータ文書署名を検証するFilterを構成していない'
                '（metadata-providers.xmlは素のFilesystemMetadataProvider）。署名・XPath transform依存の判定には'
                'poll-<sha256(variant)[:16]>鍵を信頼するSignatureValidationフィルタ（xsi:type=SignatureValidation、'
                'requireSignedRoot=true、certificateFile）と、拒否fixtureでの初期化失敗を避ける'
                'failFastInitialization=false 相当の構成が必要。構成できるまでNOT_VERIFIEDを維持し、'
                '受理をVIOLATEDへ変換しない。観測は reference-20260918/shibboleth-md05-consumer-v76/finding.json に記録済み。')
            row['observation_gap']='metadata-signature-validation-not-configured'
        if row.get('product')=='simplesamlphp' and row.get('profile')=='metadata_idp' \
                and row['case'] in {
                    'IIP-MD03-a-idp-01','IIP-MD03-b-idp-01','IIP-MD03-c-idp-01',
                    'IIP-MD04-a-idp-01','IIP-MD04-b-idp-01','IIP-MD05-as-idp-01'}:
            row['next_action']=('SimpleSAMLphpのCLIメタデータパーサ経路は文書署名の検証もvalidUntilの強制も'
                '行わないため、reject期待のfixtureを「使用」として観測しVIOLATEDを誤って生む'
                '（reference-20260918/simplesamlphp-md04ab-v136等）。ランタイムのメタデータソース'
                '（HTTP取得）で署名・有効期限を強制する構成を用意するまで、CLI取込の受理を製品FAILへ'
                '変換せずNOT_VERIFIEDを維持する。')
            row['observation_gap']='native-cli-parser-does-not-enforce-signature-or-validity'
        if row.get('product')=='simplesamlphp' and row.get('profile')=='metadata_idp' \
                and row['case']=='IIP-MD05-b-idp-01':
            row['next_action']=('SimpleSAMLphp同梱saml2-legacyのPDPDescriptor.phpはAuthzServiceが存在すると'
                '「Must have at least one AuthzService」を投げる条件反転バグがあり、PDPDescriptorを含む'
                'スキーマ適合メタデータを解析できない（reference-20260918/simplesamlphp-md05b-v138、'
                '他4variantは受理済み）。ライブラリ修正版で再試験するまでNOT_VERIFIEDを維持し、'
                '正しいfixtureの拒否を製品FAILへ変換しない。')
            row['observation_gap']='product-library-pdpdescriptor-inverted-check'
        if row.get('product')=='keycloak' and row.get('profile')=='metadata_idp' and row['case'] in {
                'IIP-MD02-d-idp-01','IIP-MD05-b-idp-01','IIP-MD05-c2-idp-01',
                'IIP-MD05-f-idp-01','IIP-MD06-a1-idp-01'}:
            row['next_action']=('KeycloakコンソールのImport clientは単一EntityDescriptorの単純なrole記述子だけを'
                '安定して取り込む。複数entity（entities-root-two/fifty）・入れ子（nested-entities）・複数role'
                '記述子（schema-global-element-families）・複雑なUIInfoでは取込がtimeoutするか後続SSOが'
                '相関しない（reference-20260918/keycloak-md05b-v140等）。取込できたfixtureのみ受理を判定し、'
                '取込不能を製品FAILへ変換しない。')
            row['observation_gap']='keycloak-console-import-single-entity-only'
        if row.get('product') in {'simplesamlphp','keycloak'} and row.get('profile')=='browser_sso_idp' \
                and row['case'] in {'IIP-IDP03-a-idp-01','IIP-IDP04-a-idp-01','IIP-IDP04-b-idp-01'}:
            row['next_action']=('固定した属性公開ポリシーの条件別比較（baseline / entity-present / entity-absent / '
                'requested-required / requested-optional / requested-absent / index-0 / index-1 / index-0-repeat）を'
                '駆動し、preparation receiptをAttributePolicyPreparationFileへ登録するネイティブキャンペーンは'
                'Shibbolethのみ実装。実機probe（reference-20260918/simplesamlphp-attrpolicy-probe-v1/v2, '
                'run_YGKQCX7PDWHFW4XGN1RE5J5T1B）で判明: SimpleSAMLphpのネイティブパーサはSPメタデータの'
                'AttributeConsumingServiceを`attributes`へ取り込み、requested-absentは全属性、'
                'requested-required/optionalは要求OID名の属性が認証ソースに無いため0件を返す。'
                'entity-present/absentは同一属性のみでEntityAttributes由来の解放は観測されない。'
                '判定側は`urn:samlscope:test:policy:*`名のmarker解放を要求するが、SSPの解放はSPのparsed'
                '`attributes`（urn:oid:*）に従うため名前空間が一致せず、認証ソースへの要求名marker属性追加と'
                '条件対応の解放マッピング（authproc等）およびreceipt発行・登録が必要。'
                '設定保存の成功を生成能力の成功にしない。')
            row['observation_gap']='attribute-policy-conditions-campaign-not-implemented'
        if row.get('product')=='simplesamlphp' and row.get('profile')=='browser_sso_idp' \
                and row['case']=='IIP-IDP11-a-idp-01':
            row['next_action']=('NameID省略の専用設定経路を確認し、同一入力の正常生成と省略生成を比較する。'
                '実際にロードされたSAML2.phpの通常経路はbuildAssertionでNameIDを必ず付加し、'
                'NameIDFormatが空または未知でもtransientへ戻ることを診断専用呼出しで確認した'
                '（reference-20261004/ssp-nameid-omission-readonly-preflight）。'
                'この診断は実SSOの能力判定ではなく、設定候補の事前確認である。'
                '専用経路または承認済みnormative_capabilityの不在を裏付ける証拠が揃うまで未検証を維持する。')
            row['observation_gap']='native-nameid-omission-configuration-unproven'
        if row.get('product')=='simplesamlphp' and row.get('profile')=='browser_sso_idp' \
                and row['case']=='IIP-IDP04-b-idp-01':
            row['next_action']=('製品ネイティブの属性ポリシーキャンペーンは9条件を完走し、設定を原本へ復元した。'
                'SimpleSAMLphp 2.5.0は同一メタデータの複数AttributeConsumingServiceから常に先頭を選び、'
                'AuthnRequestのAttributeConsumingServiceIndex=1でもindex 0と同じ属性を返した。'
                '承認済みケースは設定前提が成立しない結果を製品FAILへ変換しないためNOT_VERIFIEDを維持する。'
                '原本と正式結果はreference-20260930/simplesamlphp-attribute-policy-v152-r2および'
                'simplesamlphp-attribute-policy-evaluation-v153。')
            row['observation_gap']='product-native-attribute-consuming-service-index-unavailable'
        if row.get('product')=='keycloak' and row.get('profile')=='browser_sso_idp' \
                and row['case'] in {'IIP-IDP03-a-idp-01','IIP-IDP04-a-idp-01','IIP-IDP04-b-idp-01'}:
            row['next_action']=('Keycloak 26.7.2の製品ネイティブmetadata converterを原本fixtureへ直接実行した。'
                'EntityAttributesはclient設定へ保持されず、RequestedAttributeのisRequiredはrequired/optionalで'
                '同一mapperになり、複数AttributeConsumingServiceは索引情報なしに全mapperへ平坦化された。'
                '承認済みケースは設定前提が成立しない結果を製品FAILへ変換しないためNOT_VERIFIEDを維持する。'
                '監査原本はreference-20260930/keycloak-attribute-policy-native-audit。')
            row['observation_gap']='product-native-attribute-policy-semantics-unavailable'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-a1-idp-01':
            row['next_action']=('製品は重複entityIDを検出しWARNでsurfaceしたうえで最初の記述子を使用した。義務文は'
                '「reject or surface」のため、ログsurfaceが代替を満たすかは解釈依存。承認済みobserverは非使用のみを'
                'rejectとして扱うためVIOLATEDとなるが、G2解釈レビューまでNOT_VERIFIEDを維持する。')
            row['observation_gap']='surface-semantics-undecided'
        if row.get('profile') in ('browser_sso_idp','ecp_idp') and row['case'] in {
                'IIP-ALG04-a-idp-01','IIP-ALG04-b-idp-01','IIP-ALG06-b-idp-01',
                'IIP-ALG06-c-idp-01','IIP-ALG06-d-idp-01'}:
            row['next_action']=('EncryptionAlgorithmBrowserEvidenceTestCaseは相関SSO応答中の'
                'EncryptedAssertionをSuite鍵で復号して生成アルゴリズムを判定する（decrypted-target-assertion必須）。'
                'Suite SPメタデータのvariantでEncryptionMethodを広告できる（MetadataEncryptionAlgorithmFixtures）'
                'ようにし、SSP producer campaignに --metadata-variant を追加した。しかし根本原因を特定: '
                'MetadataService.endpoint(plan, path, variant, runId) は variant!=BASELINE のとき ACS/SSO の '
                'Location に mdv=<variant> を付けるため、variant付きでSuite SPメタデータを配ると m0-roundtrip の '
                '応答ACS URLが mdv付きになり SP peer がそれを metadata-probe 応答（metadataProbeAccepted=false）'
                'として扱い RunがCOMPLETEDにならない。対処として MetadataService.generateSuiteMetadata '
                '（属性variantを適用しつつendpointはbaseline）を非保護ファイルに追加し、配布経路 '
                '/p/{plan}/metadata?baselineEndpoints=true を試作したが、同ルートはG2保護ファイル'
                '(SamlScopeApplication.java)のため撤回（G2-30維持）。capabilityは非保護側に残置。'
                'さらに、baselineEndpoints を有効にしてSSPでGCMを広告しても、SSPはSPメタデータの '
                'EncryptionMethodを無視し既定(rsa-oaep-mgf1p/aes128-cbc)で暗号化することを実測'
                '(Run run_9SMXBQY2MGZS4VFF0PC0C354H6: observed_content_algorithms=[aes128-cbc])。'
                'よってALG04-a/bのGCMはSPメタデータ広告では観測できず、SSP側の暗号化アルゴリズム設定'
                '（対応可否を含む）を確認する必要がある。ルート配線には G2 再承認が必要。')
            row['observation_gap']='sp-encryption-algorithm-control-missing'
        if row.get('profile')=='single_logout_idp' and row.get('category')=='inconclusive' \
                and row['case'].startswith(('IIP-IDP17','IIP-IDP18','IIP-IDP19')):
            row['next_action']=('SLOブラウザchain（SSO/初期ログイン）は実機で動作するが、対象ケースはtargetが'
                '送出するlogoutメッセージと特定シナリオ（伝播継続・部分ログアウト・Redirect要求/応答・暗号化ID複数鍵）'
                'を要する。driverにSP起点・IdP起点のlogout操作を追加し、SuiteのSLOプローブを完了させる必要がある。'
                '無応答・probe-no-responseはFAILにしない。')
            row['observation_gap']='slo-logout-action-not-driven'
        if row.get('product')=='simplesamlphp' and row.get('profile')=='single_logout_idp' \
                and row['case'] in {'IIP-IDP17-r-idp-01','IIP-IDP17-s-idp-01'}:
            row['next_action']=('SSPのiframe logoutは参照構成のCSP（default-src \'none\'、frame-src未指定）で'
                '参加者フレームがブロックされることをブラウザconsoleで実測（reference-20260918/ssp-slo-iframe-v11: '
                '"Framing http://localhost:18080/ violates ... default-src \'none\' ... blocked"）。'
                'traditional logoutでは失敗参加者でブラウザ連鎖が途切れ、最終LogoutResponse/PartialLogoutが来ない。'
                'frame-srcを許可する製品/運用設定とログアウト操作経路を用意するまでNOT_VERIFIEDを維持し、'
                '無応答・unavailableを製品FAILにしない。')
            row['observation_gap']='slo-iframe-csp-frame-src-blocks-propagation'
        if row['product']=='shibboleth' and row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-fj-idp-01':
            row['next_action']=('campaign改修とreceipt再評価によりRunはCOMPLETED・case起動・receipt読込まで到達'
                '（reference-20260918/shibboleth-display-precedence-v94b）。残るNOT_VERIFIEDの原因は'
                'Shibbolethログインテンプレートのentity名抑制ガード（login.vm: '
                '$serviceName && !$rpContext.getRelyingPartyId().contains($serviceName) のときだけ <h1> を描画）で、'
                'UIInfo DisplayName/ServiceNameが無いENTITY条件ではentityID/hostnameが表示されず '
                'selection_unobserved_entity となる。製品テンプレートを改変せずにentity-fallbackを確定する経路は'
                '現状なく、VerifyUiDisplayEvidenceも同issueをNOT_VERIFIEDとして許容する設計。'
                '製品の既定挙動（抑制）を非適合と断定しない。')
            row['observation_gap']='ui-display-entity-name-suppressed-by-template'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-aw-idp-01':
            row['next_action']=('variant「TLS with use=signing」はIdPのTLS経路の観測を要し、参照Shibbolethは'
                'TLS経路を公開しない。制約に従い安全なTLS経路を構成できない場合はNOT_VERIFIED。'
                'XML署名・暗号鍵ラップの2用途は観測可能だが、all_ofのため単独では確定しない。')
            row['observation_gap']='tls-usage-path-unimplemented'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-d-idp-01':
            row['next_action']=('mdattr:EntityAttributes の4variant（直接Attribute/署名Assertion/Conditions/複数Attribute）を'
                '対象とする。現Suiteはattribute-policy用のEntityAttributes fixtureを1形態のみ生成し、署名Assertionや'
                'Conditions形態がないため全variantを充足できない。専用fixtureの追加が必要。')
            row['observation_gap']='mdattr-assertion-fixtures-unimplemented'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-b-idp-01':
            row['next_action']=('SAML V2.0 Metadata Schema全体（13variant: ロール記述子・KeyDescriptor・'
                'AttributeConsumingService・Organization/ContactPerson・EndpointType・AuthnAuthority/PDP/'
                'AttributeAuthority 等）の受理を要求する集約ケース。専用fixture群が未実装で、既存ケースとは'
                '別IDの網羅が必要。個別variantの対応可否を棚卸ししてから部分実装する。')
            row['observation_gap']='metadata-schema-fixture-matrix-unimplemented'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-c-idp-01':
            row['next_action']=('MD05.cはMDIOP表現の「受理」を評価し、キー解釈はMD06.aに委譲される。'
                'KeyValue-only表現のfixtureを使うとfixture observerが署名判別（SAMLエラー応答必須）を要求し、'
                'Shibbolethは不正署名にHTTPエラーを返すため充足不能。受理専用（判別を要求しない）証拠経路を'
                '設計・実装する必要がある。')
            row['observation_gap']='mdiop-acceptance-triggers-out-of-scope-discrimination'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD05-a3-idp-01':
            row['next_action']=('署名済みMD05.a3制約はnamespace qualificationとunknown-extension受理を分離し、'
                '専用の証拠経路を要求する（consumer acceptanceは証拠にならない）。targetが公開する拡張の'
                '名前空間修飾を検査する専用パス（passive metadata check）を設計・実装する必要がある。')
            row['observation_gap']='namespace-qualification-evidence-path-unimplemented'
        if row.get('profile')=='metadata_idp' and row['case']=='IIP-MD11-a-idp-01':
            row['next_action']=('3variant（XML署名検証・TLS/SSL・暗号鍵ラップ）をall_ofで要求。TLS観測を含む'
                '専用実装が必要（制約によりTLS経路が安全に構成できない場合はNOT_VERIFIED可）。'
                'KeyDescriptorのuse省略keyが3用途で有効であることを個別に確認する。')
            row['observation_gap']='tls-usage-path-unimplemented'
        if row['case']=='IIP-MD05-ah-idp-01' and row.get('profile')=='metadata_idp':
            row['next_action']=('approved variant「target自身がRSA-SHA1でメタデータに署名」(target-side)は'
                '遠隔IdPの内部挙動でありSAML通信から観測できない。all_ofが揃わないため設計上partialで'
                'NOT_VERIFIEDを維持する。検証側variant（SuiteがRSA-SHA1署名メタデータを配布）だけを'
                '実装しても解消しない。')
            row['observation_gap']='target-side-signing-not-observable'
        if row['case']=='IIP-G02-a-idp-01' and row.get('diagnostics',{}).get('remaining_conditions'):
            row['next_action']='残条件の入力・正常系対照・応答観測を実装する: '+', '.join(row['diagnostics']['remaining_conditions'])
        if row['case'] in implementations:
            row['implementation_observation']=implementations[row['case']]
            row['next_action']=implementations[row['case']]['next_action']
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' and row['case'] in ENCRYPTION_DIAGNOSIS_CASES:
            from verify_encrypted_sso_diagnosis import verify as verify_encryption_diagnosis
            diagnostic_run,diagnostic_cases=check_once(verify_encryption_diagnosis, root.parent.parent/'reference-20260918')
            row['individual_diagnosis']='reference-20260918/simplesamlphp-normal-encrypted-sso/protocol-evidence-diagnostics.json'
            row['additional_observation']={'run':diagnostic_run,'details':diagnostic_cases[row['case']]['details']}
            row['next_action']='通常SSOで暗号化生成とRun鍵での復号を実証済み。AES128-CBCとrsa-oaep-mgf1pを観測した。GCM・rsa-oaep(1.1)・要求されたDigest/MGF組合せを生成する設定または別経路が必要。既定値だけでは非対応と判定しない。'
        if row['product']=='keycloak' and row['profile']=='browser_sso_idp' and row['case']=='IIP-IDP01-a-idp-01':
            diagnostic_path=root.parent.parent/'reference-20260918/keycloak-attribute-name-capability/configure.json'
            row['individual_diagnosis']='reference-20260918/keycloak-attribute-name-capability/configure.json'
            row['additional_observation']={'details':json.loads(diagnostic_path.read_text())['outcome']['details'],
                'sha256':hashlib.sha256(diagnostic_path.read_bytes()).hexdigest()}
            row['next_action']='URI属性名と任意文字列属性名は署名・復号した応答で確認済み。独自NameFormatは標準User Property mapperへの設定読戻しでは保持されたが、応答で未観測。別の標準設定経路を調査する。設定保存成功を生成能力の成功にはしない。'
        if row['product']=='keycloak' and row['case'] in {'IIP-IDP19-a-idp-01','IIP-IDP19-b-idp-01','IIP-IDP19-c-idp-01'}:
            row['next_action']='暗号化プロバイダーは既存。SAMLメタデータ生成が署名鍵だけを選ぶことを稼働バイトコードで確認。鍵を増やすだけではSuiteの鍵取得は解消しない。公開メタデータを改変せず、出所を固定した試験用公開鍵の補助入力経路を追加して対照を実行する。'
            row['individual_diagnosis']='keycloak-decryption-keys/diagnosis.json'
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' and row['case'] in {'IIP-SSO05-a-idp-01','IIP-SSO05-a2-idp-01'}:
            row['next_action']='persistent NameIDの成功応答が必要。IdPのpersistentId生成（saml-nameid.properties）を一時有効化して2回再試験したが、要求内のSubjectをcanonicalizeするflowがなくSubjectCanonicalizationErrorで拒否された。c14n設定を含む前提の整備後に再試験する。試行と復元はshib-config/diagnosis.jsonに記録。'
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
            row['next_action']='原本・ネイティブ取込・署名済み応答の相関から判定済み。Role優先のMD05.ebは別途FAIL確定。MD05.eaは順序交換時もSHA256を選ぶが、ローカルポリシーとSHA384の使用可能性が未確認のためNOT_VERIFIEDを維持。ポリシーを確認した再試験が必要。'
        if row['product']=='simplesamlphp' and row['profile']=='browser_sso_idp' and row['case']=='IIP-SSO01-cz-idp-01':
            row['next_action']='未復号EncryptedAssertionをSubject不在として成功にしない修正を実測済み。principal判定へ復号済み内容を安全に渡し、SubjectConfirmation・属性を含む識別子を認証principalへ意味的に対応付ける証拠が必要。'
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
            row['next_action']='暗号化方式・OAEPのDigest/MGF・鍵サイズを変える15入力を追加し、対照を含む16条件で原本一致、署名応答、対応鍵での復号と別鍵での失敗を実証済み。metadata campaignのvariant鍵を判定経路へ渡し、承認済みケースの全条件と対照を確認して接続する。現時点の実測だけで全ケースをSuccessにはしない。'
        indexed[row['case']].append(row)
    assert sum(counts.values())==len(rows)
    (root/'implementation-audit.json').write_text(json.dumps(implementations,ensure_ascii=False,indent=2)+'\n')
    (root/'inventory.json').write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n')
    lines=['# 未検証項目の全件台帳', '',
           '対象は前回の追加試験後に残ったNOT_VERIFIEDと、その追加再試験です。件数は製品・プロファイル・ケース単位の延べ観測数です。追加再試験の対象ケースだけ新Runの証拠を採用し、それ以外の既存証拠は保持しています。単一Runの完走・適合率ではありません。', '',
           '| 再試験前 | 確定（Success / Failed / Warning） | 現在の未検証 | 未検証の異なるケースID |', '|---:|---:|---:|---:|',f'| {baseline_count} | {baseline_count-len(rows)} | {len(rows)} | {len(indexed)} |', '',
           '## 内訳', '', '| 原因・現在の経路 | 件数 | 次に扱う範囲 |', '|---|---:|---|']
    for k,(title,owner,action) in GROUPS.items():lines.append(f'| {title} | {counts[k]} | {owner} |')
    partial=[r for r in rows if r['case']=='IIP-G02-a-idp-01' and r.get('diagnostics',{}).get('remaining_conditions')]
    if partial:
        lines+=['', '### G02の確認済み条件と残条件', '',
                '次は部分的な確認であり、ケース全体の確定件数には含めません。値保持・切詰めの別義務を受理条件へ追加せず、承認済み定義に従って分けています。', '',
                '| 製品 | 標準文字列の確認入力数 | 拡張属性の応答入力数 | 残条件 |', '|---|---:|---:|---|']
        for row in partial:
            d=row['diagnostics']
            lines.append(f"| {row['product']} | {len(d.get('confirmed_character_fixtures',[]))} | {len(d.get('responded_extension_string_fixtures',[]))} | "+', '.join(d['remaining_conditions'])+' |')
    lines+=['', '分類は実行結果の理由コード、interaction種別、Suiteの実装を基にしています。「試験経路確認」は実行可能を保証する分類ではありません。設定・証拠の経路も、自己申告を有効にするだけで結果を保証しません。', '',
            'ECDSAケースは旧Runのブラウザ待機結果が残っていますが、現在の登録クラスはEcSignatureSupportTestCaseです。自動判定なしの分類から、メタデータ取得と署名対照の証拠不足へ変更しました。結果のVerdictと未検証総数は変更していません。現在のソース・登録箇所のSHA-256はimplementation-audit.jsonに保存します。', '', 'SP起点SLOの基本ケースIIP-IDP17-aとRedirect受理IIP-IDP18-aは、専用実装を反映した実製品再試験の証拠を採用しています。EncryptedID復号IIP-IDP19-aも再試験し、Shibbolethの成功を採用しました。Keycloakの暗号化鍵不足とSimpleSAMLphpの負の対照不成立は未検証のまま理由を更新しています。', '', '## 説明の訂正', '',
            '「大半は必要な操作が未完了」という説明では、実装のないブラウザ完了処理や部分的なfixture、無効化された証拠確認経路を操作不足にまとめてしまっていました。未検証項目を製品の失敗とは扱いませんが、全試験の実装・完走が済んでいるとも扱えません。', '',
            '## 今回確認した実行経路', '',
            'SLOプロファイルの3製品で既存Runの開始・再開を確認したところ、古い出力では待機中だった共通ケースがdelivery_or_response_unknownで終了していました。active-probeのFINISHEDはこの期限切れ後の状態です。新Runで正常系対照と共通試験を再実行し、追加証拠を保存しました。追加Successは5件、残りは部分実装9件と署名試験の判定保留4件でした。開始・再開APIは各製品1回、正常系・共通試験用Runは各製品1回作成しました。ここまでの製品設定変更は0回です。続けてKeycloakとSimpleSAMLphpで署名必須設定を試しましたが、正常系の開始で失敗したため採用していません。Keycloakは受信完了を確認できず、SimpleSAMLphpは補助クライアントのXML解析が失敗しました。これらを製品FAILとは判定しません。変更と復元で各製品2回の設定書き込みが発生し、復元を検証済みです。ブラウザ操作・ユーザー本人の操作は0回で、プロトコルクライアントによる実行です。', '',
            '追加実装後の再試験では、公開URL未発行の注記を3製品で自動確定（Warning）し、Subject不一致をKeycloakとSimpleSAMLphpで確認（Failed）しました。これらは製品全体の適合判定ではありません。[追加実装記録](27-additional-implementation.md)を参照してください。', '', '## 原因別の対応', '']
    default_acs_notes=[]
    if any(row['case'] == 'IIP-MD05-av-idp-01' and row['product'] == 'keycloak'
           and row['profile'] == 'metadata_idp' and row['verdict'] == 'FAIL' for row in transitions):
        default_acs_notes.append(
            'Keycloak 26.7.2では、製品自身のImport client経路で取り込んだIIP-MD05-avのcontrol・'
            'explicit-first・all-falseは正しいACSへ到達した一方、explicit-falseの後のomitted defaultは'
            'ACS 1ではなくACS 0へ到達し、同一親要素内で重複するAssertionConsumerService indexを含む'
            'metadataも取込・read-back・Success応答まで進みました。このFAILは、開始・終了時のコンテナimage・'
            '起動時刻・実行時VERSION、各一時clientの削除read-back、原本fixture、要求・応答の相関、'
            'Suite実行JARを同じRunで照合した限定的な実測です。')
    if any(row['case'] == 'IIP-MD05-av-idp-01' and row['product'] == 'shibboleth'
           and row['profile'] == 'metadata_idp' and row['verdict'] == 'FAIL' for row in transitions):
        default_acs_notes.append(
            'Shibboleth IdP 5.2.3では、製品自身のFilesystemMetadataProvider経路で取り込んだIIP-MD05-avの'
            'control・explicit-first・all-falseは正しいACSへ到達した一方、explicit-falseの後のomitted defaultは'
            'ACS 1ではなくACS 0へ到達し、同一親要素内で重複するAssertionConsumerService indexを含むmetadataも'
            '取得・使用してSuccessを返しました。このFAILは、開始・終了時のコンテナimage・起動時刻・実行時VERSION、'
            '設定の原本とのバイト一致による復元、原本fixture、要求・応答の相関、Suite実行JARを同じRunで照合した限定的な実測です。')
    if any(row['case'] == 'IIP-MD05-av-idp-01' and row['product'] == 'simplesamlphp'
           and row['profile'] == 'metadata_idp' and row['verdict'] == 'FAIL' for row in transitions):
        default_acs_notes.append(
            'SimpleSAMLphp 2.5.0では、IIP-MD05-avの3つのdefault選択対照は正しいACSへ到達した一方、'
            '同一親要素内で重複するAssertionConsumerService indexを含むmetadataも取得・使用してSuccessを返しました。'
            'このFAILは、開始・終了時のコンテナimage・起動時刻・実行時VERSION、設定の復元、native MDQ取得、'
            '要求・応答の相関を同じRunで照合した限定的な実測です。')
    if default_acs_notes:
        lines[lines.index('## 原因別の対応')] = '\n\n'.join(default_acs_notes)+'\n\n## 原因別の対応'
    for k,(title,owner,action) in GROUPS.items():lines += [f'### {title}', '', action, '']
    # Keep every historical trial in retest-delta.json, but display the final
    # selected result for each product/profile/case. Dict insertion order keeps
    # the existing profile preference when a case belongs to several profiles.
    latest_transitions = {
        (row['product'], row['profile'], row['case']): row for row in transitions
    }
    lines += ['## 追加再試験の製品別結果', '', '| Test | Keycloak | Shibboleth | SimpleSAMLphp |', '|---|---|---|---|']
    for case_id in sorted({r['case'] for r in transitions}):
        cells=[]
        for product in ('keycloak','shibboleth','simplesamlphp'):
            item=next((r for r in latest_transitions.values() if r['case']==case_id and r['product']==product), None)
            if item is None:
                item=next((r for r in rows if r['case']==case_id and r['product']==product
                           and r.get('audit_withdrawal')), None)
            if item is None:
                cells.append('Not verified（今回の再試験対象外）')
                continue
            cells.append({'PASS':'Success','FAIL':'Failed (Product)','WARNING':'Warning'}.get(item['verdict'], 'Not verified: '+item['reason_code']))
        lines.append(f'| `{case_id}` | '+' | '.join(cells)+' |')
    lines += ['', '## ケース単位の一覧', '',
              '製品列には未検証が残るプロファイルを記載します。同じケースに複数の理由がある場合は原因列に併記します。—は今回の未検証集合にないことを示し、製品全体のPASSを意味しません。', '',
              '| Test | Keycloak | Shibboleth | SimpleSAMLphp | 原因 |', '|---|---|---|---|---|']
    for case,items in sorted(indexed.items()):
        cells=['、'.join(sorted({r['profile'] for r in items if r['product']==p})) or '—' for p in ('keycloak','shibboleth','simplesamlphp')]
        why=' / '.join(GROUPS[g][0] for g in sorted({r['category'] for r in items}))
        lines.append(f'| `{case}` | '+' | '.join(cells)+f' | {why} |')
    lines+=['', '## 判定不能の分類（診断）', '',
             'Verdictは変更せず、未検証の理由だけを分類します。feature-absentは公開メタデータ等から機能の不在を確認済みのもの、role-inapplicableはロール上消費されないvariant、evidence-form-mismatchは承認済み証拠形式との不一致、operator-attestation-availableは運用者証言で確認可能、suite-observation-gapはSuite実装で解消可能です。', '',
             '| 診断 | 件数 | 意味 | 表示案 |', '|---|---:|---|---|']
    for key,count in diagnoses.most_common():
        meaning,display=DIAGNOSIS[key]
        lines.append(f'| `{key}` | {count} | {meaning} | {display} |')
    for key in DIAGNOSIS:
        ids=sorted({r['case'] for r in rows if r.get('capability_diagnosis')==key})
        if ids:
            lines+=['', f'### {key}', '', ', '.join('`'+i+'`' for i in ids), '']
    lines+=['', '## 証拠', '',
            'ローカルの `build/acceptance/reference-20260914/remaining-audit/inventory.json` に現在の全未検証観測のRun、ケースID、理由コード、試験条件、対照、次の作業、元result.jsonのSHA-256を保存しています。追加再試験の全結果は `retest-delta.json`、変更前の集合は `baseline.json` に保存しています。元の結果や承認済みケース定義は変更していません。', '',
            '実装確認: `BrowserEvidenceTestCase`、`IdpExecutableBrowserFixtureScenarioTestCase`、`ApprovedConfigCaseRegistry`、`AttestedOutcomeTestCase`。ケースごとの条件は `tests/cases.yaml` を参照しています。', '',
            '台帳生成時に、全未検証観測の承認済み条件・正負対照と元result.jsonのRun・SHA-256・Verdict・理由コードを照合します。不一致があれば生成を失敗させます。ケース単位の全条件・variantグループ・前提・解釈制約は `unresolved-contract-audit.json` に保存します。この監査の成功は判定実装の完了を意味しません。', '',
            '再生成: `.venv/bin/python dev/reference-acceptance/generate_remaining_audit.py --evidence-root build/acceptance/reference-20260914/remaining-audit`。','']
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
