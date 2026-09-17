"""Account for every unresolved observation without inferring a product verdict."""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
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
        if update['registration'] not in registry.decode() or case_id not in source.decode():
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
    implementations=implementation_audit()
    rows=json.loads((root/'baseline.json').read_text())
    catalog={c['id']:c for c in yaml.safe_load(definitions.read_text())['cases']}
    baseline_count=len(rows)
    refreshed=[]; transitions=[]
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
        additional = {'browser_sso_idp': {'IIP-G02-a-idp-01', 'IIP-G03-b-idp-01', 'IIP-SSO07-b-idp-01'},
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
                'IIP-ALG06-d-idp-01':('PASS','browser.encryption.mgf1-sha1-default.decrypted'),
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
        # Native console import followed by signed SSO, with per-fixture cleanup evidence.
        from verify_keycloak_import_batch import ADOPTED, verify as verify_import_batch
        if row['product']=='keycloak' and row['profile']=='metadata_idp' and row['case'] in ADOPTED:
            path, imported_cases = verify_import_batch(root.parent.parent/'reference-20260917')
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
            path, imported_cases = verify_ssp_import(root.parent.parent/'reference-20260917')
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
        if row['profile']=='metadata_idp' and row['case'] in UI_ADOPTED:
            selected = verify_ui(root.parent.parent/'reference-20260918', row['product'])
        if row['product']=='simplesamlphp' and row['profile']=='metadata_idp' and row['case']=='IIP-MD02-d-idp-01':
            selected = verify_ssp_import(root.parent.parent/'reference-20260918',
                folder='simplesamlphp-aggregate-import', adopted={
                    'IIP-MD02-d-idp-01': ['entities-root-one','entities-root-two','entities-root-fifty']})
        if selected is not None:
            path, selected_cases = selected
            raw=path.read_bytes(); result=json.loads(raw); case=selected_cases[row['case']]
            row['baseline']={k:row.get(k) for k in ('run','reason_code','result_sha256','evidence_folder','interaction')}
            row.update(run=result['run']['id'],reason_code=case['reason_code'],
                       result_sha256=hashlib.sha256(raw).hexdigest(),
                       evidence_folder=str(path.parent.relative_to(root.parents[3])),
                       interaction=None,verdict=case['verdict'],evidence=case['evidence'],
                       diagnostics=case.get('diagnostics',{}))
            transitions.append(dict(row))
        if row.get('verdict','NOT_VERIFIED')=='NOT_VERIFIED':refreshed.append(row)
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
        if row['case']=='IIP-G02-a-idp-01' and row.get('diagnostics',{}).get('remaining_conditions'):
            row['next_action']='残条件の入力・正常系対照・応答観測を実装する: '+', '.join(row['diagnostics']['remaining_conditions'])
        if row['case'] in implementations:
            row['implementation_observation']=implementations[row['case']]
            row['next_action']=implementations[row['case']]['next_action']
        if row['product']=='keycloak' and row['case'] in {'IIP-IDP19-a-idp-01','IIP-IDP19-b-idp-01','IIP-IDP19-c-idp-01'}:
            row['next_action']='暗号化プロバイダーは既存。SAMLメタデータ生成が署名鍵だけを選ぶことを稼働バイトコードで確認。鍵を増やすだけではSuiteの鍵取得は解消しない。公開メタデータを改変せず、出所を固定した試験用公開鍵の補助入力経路を追加して対照を実行する。'
            row['individual_diagnosis']='keycloak-decryption-keys/diagnosis.json'
        if row['product']=='shibboleth' and row['profile']=='browser_sso_idp' and row['case'] in {'IIP-SSO05-a-idp-01','IIP-SSO05-a2-idp-01'}:
            row['next_action']='persistent NameIDの成功応答が必要。IdPのpersistentId生成（saml-nameid.properties）を一時有効化して2回再試験したが、要求内のSubjectをcanonicalizeするflowがなくSubjectCanonicalizationErrorで拒否された。c14n設定を含む前提の整備後に再試験する。試行と復元はshib-config/diagnosis.jsonに記録。'
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
    for k,(title,owner,action) in GROUPS.items():lines += [f'### {title}', '', action, '']
    lines += ['## 追加再試験の製品別結果', '', '| Test | Keycloak | Shibboleth | SimpleSAMLphp |', '|---|---|---|---|']
    for case_id in sorted({r['case'] for r in transitions}):
        cells=[]
        for product in ('keycloak','shibboleth','simplesamlphp'):
            item=next((r for r in transitions if r['case']==case_id and r['product']==product), None)
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
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--evidence-root',type=Path,required=True);p.add_argument('--definitions',type=Path,default=Path('tests/cases.yaml'));p.add_argument('--output',type=Path,default=Path('docs/26-unverified-case-inventory.md'));a=p.parse_args();render(a.evidence_root,a.definitions,a.output)
