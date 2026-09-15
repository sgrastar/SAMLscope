"""Render a review-qualified comparison without changing signed definitions or raw results."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

PRODUCTS = ("keycloak", "shibboleth", "simplesamlphp")
COMMON_RETESTS = {"IIP-G01-a-idp-01", "IIP-EXT01-a-idp-01", "IIP-EXT01-b-idp-01",
                  "IIP-EXT01-c-idp-01", "IIP-ALG01-a-idp-01", "IIP-ALG02-a-idp-01"}
ADDITIONAL_RETESTS = {
    "browser_sso_idp": {"IIP-G02-a-idp-01", "IIP-G03-b-idp-01", "IIP-SSO07-b-idp-01",
                        "IIP-IDP09-a-idp-01", "IIP-SSO01-ez-idp-01", "IIP-SSO01-fd-idp-01", "IIP-SSO01-fe-idp-01"},
    "metadata_idp": {"IIP-MD05-fi-idp-01"},
}
POLLING_RETESTS = {'IIP-MD07-a-idp-01', 'IIP-MD06-a9-idp-01', 'IIP-MD06-a7-idp-01', 'IIP-MD06-a5-idp-01', 'IIP-MD05-ad-idp-01'}
ALG_CASES = {'IIP-ALG04-a-idp-01', 'IIP-ALG04-b-idp-01', 'IIP-ALG06-a-idp-01',
             'IIP-ALG06-b-idp-01', 'IIP-ALG06-c-idp-01', 'IIP-ALG06-d-idp-01'}
SELECTION = {
    "browser_sso_idp": ("interaction-followup/after/keycloak/browser_sso_idp", "interaction-followup/after/shibboleth/browser_sso_idp", "interaction-followup/after/simplesamlphp/browser_sso_idp"),
    "metadata_idp": ("keycloak/metadata_idp/run2", "interaction-followup/after/shibboleth/metadata_idp", "interaction-followup/after/simplesamlphp/metadata_idp"),
    "ecp_idp": ("keycloak/ecp_idp/run5", "shibboleth/ecp_idp/run4", "simplesamlphp/ecp_idp/run6"),
    "single_logout_idp": ("keycloak/single_logout_idp/browser2", "shibboleth/single_logout_idp/browser5", "simplesamlphp/single_logout_idp/browser2"),
}
QUALIFICATIONS = {
    ("keycloak", "IIP-IDP10-d-idp-01"): ("Not verified (Suite)", "S1"),
    ("keycloak", "IIP-IDP12-a-idp-01"): ("Not verified (Configuration)", "C1"),
}

CONFIRMED_FAILURES = {
    "IIP-SSO07-b-idp-01", "IIP-SSO01-fk-idp-01", "IIP-SSO01-ag-idp-01", "IIP-SSO05-b2-idp-01",
    "IIP-SSO05-a-idp-01", "IIP-IDP10-b-idp-01", "IIP-IDP10-d-idp-01",
    "IIP-IDP05-a-idp-01", "IIP-IDP08-a-idp-01", "IIP-IDP17-t-idp-01",
    "IIP-IDP17-m-idp-01", "IIP-IDP15-a-idp-01",
}

def render(root, output):
    sections = []
    manifest = []
    alg_adopted = set()
    peer_adopted = set()
    unresolved = {product: Counter() for product in PRODUCTS}
    for profile, folders in SELECTION.items():
        columns = []
        for product, folder in zip(PRODUCTS, folders, strict=True):
            path = root / folder / "result.json"
            raw = path.read_bytes()
            data = json.loads(raw)
            cases = {c["id"]: c for req in data["requirements"] for c in req["cases"]}
            assert len(cases) == sum(len(req["cases"]) for req in data["requirements"])
            if profile == "single_logout_idp":
                supplement_folder = f"remaining-audit/{product}/fresh_common"
                supplement_raw = (root / supplement_folder / "result.json").read_bytes()
                supplement = json.loads(supplement_raw)
                extra = {c["id"]: c for req in supplement["requirements"] for c in req["cases"]}
                for case_id in COMMON_RETESTS:
                    if cases[case_id]["verdict"] != "NOT_VERIFIED":
                        raise ValueError(f"Retest would replace an evaluated case: {case_id}")
                    cases[case_id] = extra[case_id]
                manifest.append({"profile": profile, "product": product, "folder": supplement_folder,
                                 "run": supplement["run"]["id"], "cases": sorted(COMMON_RETESTS),
                                 "result_sha256": hashlib.sha256(supplement_raw).hexdigest(),
                                 "suite_image": supplement["suite"]["image_digest"]})
            if profile == "single_logout_idp":
                supplement_folder = f"slo-redirect-receiver-integrated/{product}/single_logout_idp"
                supplement_raw = (root / supplement_folder / "result.json").read_bytes()
                supplement = json.loads(supplement_raw)
                case_ids = ["IIP-IDP17-a-idp-01", "IIP-IDP18-a-idp-01"]
                for case_id in case_ids:
                    replacement = next(c for req in supplement["requirements"] for c in req["cases"] if c["id"] == case_id)
                    expected = "slo.basic.synchronous-response-observed" if case_id == "IIP-IDP17-a-idp-01" else "slo.redirect.logout-request-accepted.satisfied"
                    assert replacement["verdict"] == "PASS" and replacement["reason_code"] == expected
                    cases[case_id] = replacement
                manifest.append({"profile": profile, "product": product, "folder": supplement_folder,
                                 "run": supplement["run"]["id"], "cases": case_ids,
                                 "result_sha256": hashlib.sha256(supplement_raw).hexdigest(),
                                 "suite_image": supplement["suite"]["image_digest"]})
            if profile == "single_logout_idp":
                supplement_folder = f"slo-encrypted-id-integrated/{product}/single_logout_idp"
                supplement_raw = (root / supplement_folder / "result.json").read_bytes()
                supplement = json.loads(supplement_raw)
                case_id = "IIP-IDP19-a-idp-01"
                replacement = next(c for req in supplement["requirements"] for c in req["cases"] if c["id"] == case_id)
                expected = {"keycloak": ("NOT_VERIFIED", "slo.encrypted-id.key-unavailable"),
                            "shibboleth": ("PASS", "slo.encrypted-id.decryption-observed"),
                            "simplesamlphp": ("NOT_VERIFIED", "slo.encrypted-id.negative-control-failed")}[product]
                assert (replacement["verdict"], replacement["reason_code"]) == expected
                cases[case_id] = replacement
                manifest.append({"profile": profile, "product": product, "folder": supplement_folder,
                                 "run": supplement["run"]["id"], "cases": [case_id],
                                 "result_sha256": hashlib.sha256(supplement_raw).hexdigest(),
                                 "suite_image": supplement["suite"]["image_digest"]})
            if profile == "single_logout_idp":
                supplement_folder = f"slo-multiple-keys-integrated/{product}/single_logout_idp"
                supplement_raw = (root / supplement_folder / "result.json").read_bytes()
                supplement = json.loads(supplement_raw)
                case_id = "IIP-IDP19-c-idp-01"
                replacement = next(c for req in supplement["requirements"] for c in req["cases"] if c["id"] == case_id)
                expected = {"keycloak": ("NOT_VERIFIED", "slo.encrypted-id.multiple-keys.key-unavailable"),
                            "shibboleth": ("PASS", "slo.encrypted-id.multiple-keys.decryption-observed"),
                            "simplesamlphp": ("NOT_VERIFIED", "slo.encrypted-id.multiple-keys.configuration-unavailable")}[product]
                assert (replacement["verdict"], replacement["reason_code"]) == expected
                cases[case_id] = replacement
                manifest.append({"profile": profile, "product": product, "folder": supplement_folder,
                                 "run": supplement["run"]["id"], "cases": [case_id],
                                 "result_sha256": hashlib.sha256(supplement_raw).hexdigest(),
                                 "suite_image": supplement["suite"]["image_digest"]})
            if profile == "single_logout_idp" and product == "shibboleth":
                supplement_folder = f"key-capability-integrated/{product}/single_logout_idp"
                supplement_raw = (root / supplement_folder / "result.json").read_bytes()
                supplement = json.loads(supplement_raw)
                case_id = "IIP-IDP19-b-idp-01"
                replacement = next(c for req in supplement["requirements"] for c in req["cases"] if c["id"] == case_id)
                expected = {"keycloak": ("NOT_VERIFIED", "slo.encrypted-id.key-unavailable"),
                            "shibboleth": ("PASS", "configuration.multiple-decryption-keys.observed"),
                            "simplesamlphp": ("NOT_VERIFIED", "slo.encrypted-id.negative-control-failed")}[product]
                assert (replacement["verdict"], replacement["reason_code"]) == expected
                cases[case_id] = replacement
                manifest.append({"profile": profile, "product": product, "folder": supplement_folder,
                                 "run": supplement["run"]["id"], "cases": [case_id],
                                 "result_sha256": hashlib.sha256(supplement_raw).hexdigest(),
                                 "suite_image": supplement["suite"]["image_digest"]})
            retest_batches = {
                'additional-implementation': ADDITIONAL_RETESTS.get(profile, set()) - {'IIP-G02-a-idp-01', 'IIP-SSO07-b-idp-01'},
                'crypto-integrated-implementation': {'IIP-SSO07-b-idp-01'} if profile == 'browser_sso_idp' else set(),
                'literal-integrated-implementation': ({'IIP-G02-a-idp-01'} | ({'IIP-IDP06-a-idp-01'} if product == 'simplesamlphp' else set())) if profile == 'browser_sso_idp' else set(),
                'queue-integrated-implementation': ({'IIP-IDP06-b-idp-01'} if product == 'simplesamlphp' else {'IIP-SSO01-fk-idp-01','IIP-SSO01-fu-idp-01','IIP-SSO01-gi-idp-01'} if product == 'shibboleth' else set()) if profile == 'browser_sso_idp' else set(),
            }
            for batch, retest_cases in retest_batches.items():
                if not retest_cases:
                    continue
                supplement_folder = f"{batch}/{product}/{profile}"
                supplement_raw = (root / supplement_folder / "result.json").read_bytes()
                supplement = json.loads(supplement_raw)
                extra = {c["id"]: c for req in supplement["requirements"] for c in req["cases"]}
                for case_id in retest_cases:
                    if (batch, case_id) in {('literal-integrated-implementation','IIP-IDP06-a-idp-01'), ('queue-integrated-implementation','IIP-IDP06-b-idp-01')}:
                        assert extra[case_id]['verdict'] == 'PASS'
                        assert extra[case_id]['reason_code'] == 'force_authn_fresh_authentication_observed'
                    if batch == 'queue-integrated-implementation' and product == 'shibboleth':
                        assert extra[case_id]['verdict'] == 'PASS'
                        expected = 'idp.invalid-request.satisfied' if case_id == 'IIP-SSO01-gi-idp-01' else 'idp.signed-request.satisfied'
                        assert extra[case_id]['reason_code'] == expected
                    cases[case_id] = extra[case_id]
                manifest.append({"profile": profile, "product": product, "folder": supplement_folder,
                                 "run": supplement["run"]["id"], "cases": sorted(retest_cases),
                                 "result_sha256": hashlib.sha256(supplement_raw).hexdigest(),
                                 "suite_image": supplement["suite"]["image_digest"]})
            if product == 'shibboleth' and profile in {'metadata_idp', 'browser_sso_idp'}:
                polling_cases = POLLING_RETESTS if profile == 'metadata_idp' else {'IIP-IDP12-c-idp-01'}
                polling_folder = 'polling' if profile == 'metadata_idp' else 'polling-bssso'
                supplement_folder = f'integrated-implementation/shibboleth/{polling_folder}'
                supplement_raw = (root / supplement_folder / 'result.json').read_bytes()
                supplement = json.loads(supplement_raw)
                extra = {c['id']: c for req in supplement['requirements'] for c in req['cases']}
                for case_id in polling_cases:
                    assert cases[case_id]['verdict'] == 'NOT_VERIFIED'
                    assert extra[case_id]['verdict'] == 'PASS' and extra[case_id]['reason_code'] == 'metadata.fixture-probe.satisfied'
                    cases[case_id] = extra[case_id]
                manifest.append({'profile': profile, 'product': product, 'folder': supplement_folder,
                                 'run': supplement['run']['id'], 'cases': sorted(polling_cases),
                                 'result_sha256': hashlib.sha256(supplement_raw).hexdigest(),
                                 'suite_image': supplement['suite']['image_digest']})
            alg_products = {'keycloak', 'shibboleth'} | ({'simplesamlphp'} if profile == 'browser_sso_idp' else set())
            if profile in {'browser_sso_idp', 'ecp_idp'} and product in alg_products:
                supplement_folder = f'../reference-20260915/algorithm-observation-batch/{product}/{profile}'
                supplement_raw = (root / supplement_folder / 'result.json').read_bytes()
                supplement = json.loads(supplement_raw)
                extra = {c['id']: c for req in supplement['requirements'] for c in req['cases']}
                expected = {'keycloak': {'IIP-ALG04-b-idp-01': ('PASS', 'browser.encryption.aes256-gcm.decrypted'),
                                         'IIP-ALG06-b-idp-01': ('PASS', 'browser.encryption.rsa-oaep.decrypted')},
                            'shibboleth': {'IIP-ALG04-a-idp-01': ('PASS', 'browser.encryption.aes128-gcm.decrypted'),
                                           'IIP-ALG06-a-idp-01': ('PASS', 'browser.encryption.rsa-oaep-mgf1p.decrypted')},
                            'simplesamlphp': {}}[product]
                for case_id in ALG_CASES:
                    assert cases[case_id]['verdict'] == 'NOT_VERIFIED'
                    replacement = extra[case_id]
                    assert (replacement['verdict'], replacement['reason_code']) == expected.get(
                        case_id, ('NOT_VERIFIED', 'case.pending-interaction'))
                    cases[case_id] = replacement
                    alg_adopted.add((product, profile, case_id))
                manifest.append({'profile': profile, 'product': product,
                                 'folder': f'build/acceptance/reference-20260915/algorithm-observation-batch/{product}/{profile}',
                                 'run': supplement['run']['id'], 'cases': sorted(ALG_CASES),
                                 'result_sha256': hashlib.sha256(supplement_raw).hexdigest(),
                                 'suite_image': supplement['suite']['image_digest']})
            peer_expected = {
                ('keycloak', 'browser_sso_idp'): {
                    'folder': '../reference-20260915/algorithm-observation-batch/keycloak/browser_alg_combo',
                    'cases': {
                        'IIP-ALG04-a-idp-01': ('PASS', 'browser.encryption.aes128-gcm.decrypted'),
                        'IIP-ALG06-a-idp-01': ('PASS', 'browser.encryption.rsa-oaep-mgf1p.decrypted'),
                        'IIP-ALG06-c-idp-01': ('PASS', 'browser.encryption.digest-combinations.decrypted'),
                        'IIP-ALG06-d-idp-01': ('PASS', 'browser.encryption.mgf1-sha1-default.decrypted'),
                        'IIP-SSO01-g-idp-01': ('PASS', 'browser.normal-flow.success-responses-have-assertions'),
                        'IIP-SSO01-z-idp-01': ('WARNING', 'browser.normal-flow.unsolicited-sso-observed')}},
                ('shibboleth', 'browser_sso_idp'): {
                    'folder': '../reference-20260915/algorithm-observation-batch/shibboleth/browser_sso_idp',
                    'cases': {
                        'IIP-SSO01-g-idp-01': ('PASS', 'browser.normal-flow.success-responses-have-assertions'),
                        'IIP-SSO01-k-idp-01': ('PASS', 'browser.normal-flow.bearer-recipient-and-expiry-valid'),
                        'IIP-SSO01-z-idp-01': ('WARNING', 'browser.normal-flow.unsolicited-sso-observed')}},
                ('shibboleth', 'single_logout_idp'): {
                    'folder': '../reference-20260915/peer-intent/shibboleth/slo_target_logout',
                    'cases': {
                        'IIP-IDP17-j-idp-01': ('PASS', 'slo.LogoutRequest.issuer-count.satisfied'),
                        'IIP-IDP17-k-idp-01': ('PASS', 'slo.LogoutRequest.issuer-value.satisfied'),
                        'IIP-IDP17-l-idp-01': ('PASS', 'slo.LogoutRequest.issuer-format.satisfied'),
                        'IIP-IDP17-m-idp-01': ('PASS', 'slo.LogoutRequest.signature.satisfied'),
                        'IIP-IDP17-t-idp-01': ('FAIL', 'slo.logout-request.not-on-or-after.violated'),
                        'IIP-IDP17-n-idp-01': ('NOT_VERIFIED', 'slo.identifier.strong-match-unobservable'),
                        'IIP-IDP17-u-idp-01': ('NOT_VERIFIED', 'slo.not-on-or-after.correlation-unavailable')}},
            }
            peer = peer_expected.get((product, profile))
            if peer:
                peer_raw = (root / peer['folder'] / 'result.json').read_bytes()
                peer_result = json.loads(peer_raw)
                peer_cases = {c['id']: c for req in peer_result['requirements'] for c in req['cases']}
                for case_id, want in peer['cases'].items():
                    if case_id not in cases:
                        continue
                    replacement = peer_cases[case_id]
                    assert (replacement['verdict'], replacement['reason_code']) == want, (
                        product, case_id, replacement['verdict'], replacement['reason_code'])
                    cases[case_id] = replacement
                    peer_adopted.add((product, profile, case_id))
                manifest.append({'profile': profile, 'product': product,
                                 'folder': peer['folder'].replace('../', 'build/acceptance/'),
                                 'run': peer_result['run']['id'], 'cases': sorted(peer['cases']),
                                 'result_sha256': hashlib.sha256(peer_raw).hexdigest(),
                                 'suite_image': peer_result['suite']['image_digest']})
            columns.append(cases)
            unresolved[product].update(c["reason_code"] for c in cases.values() if c["verdict"] == "NOT_VERIFIED")
            manifest.append({"profile": profile, "product": product, "folder": folder,
                             "run": data["run"]["id"], "result_sha256": hashlib.sha256(raw).hexdigest(),
                             "suite_image": data["suite"]["image_digest"]})
        lines = [f"### {profile}", "", "| Test | Keycloak 26.7.2 | Shibboleth IdP 5.2.3 | SimpleSAMLphp 2.5.0 |",
                 "|---|---|---|---|"]
        for case_id in sorted(set().union(*(set(c) for c in columns))):
            cells = []
            for product, cases in zip(PRODUCTS, columns, strict=True):
                case = cases.get(case_id)
                if case is None:
                    cells.append("Not run")
                    continue
                qualification = QUALIFICATIONS.get((product, case_id))
                if qualification:
                    if qualification[1] in {"S1", "S2"} and case["verdict"] != "NOT_VERIFIED":
                        raise ValueError(f"Suite safeguard not reflected in result: {product} {case_id}")
                    cells.append(f"{qualification[0]} [{qualification[1]}]")
                    continue
                verdict = case["verdict"]
                if verdict == "FAIL" and case_id not in CONFIRMED_FAILURES:
                    raise ValueError(f"Unreviewed failure: {product} {case_id}")
                display = {"PASS": "Success", "FAIL": "**Failed (Product)**", "WARNING": "Warning",
                           "NOT_VERIFIED": "Not verified", "NOT_APPLICABLE": "N/A",
                           "NOT_OBSERVABLE": "Not observable", "INDETERMINATE": "Indeterminate",
                           "INCONSISTENT": "Inconsistent", "ERROR": "Error (Suite)"}.get(verdict, verdict)
                if product == 'simplesamlphp' and profile == 'browser_sso_idp' and case_id == 'IIP-IDP06-b-idp-01':
                    display += " (prior run; latest precision not verified)"
                cells.append(display + (" †" if (product == "shibboleth" and profile == "browser_sso_idp" and case_id in {'IIP-SSO01-fk-idp-01','IIP-SSO01-fu-idp-01','IIP-SSO01-gi-idp-01'}) or (product == "simplesamlphp" and profile == "browser_sso_idp" and case_id in {"IIP-IDP06-a-idp-01", "IIP-IDP06-b-idp-01"}) or (profile == "single_logout_idp" and (case_id in COMMON_RETESTS or case_id == "IIP-IDP17-a-idp-01" or case_id == "IIP-IDP18-a-idp-01" or case_id == "IIP-IDP19-a-idp-01" or case_id == "IIP-IDP19-c-idp-01" or (product == "shibboleth" and case_id == "IIP-IDP19-b-idp-01"))) or case_id in ADDITIONAL_RETESTS.get(profile, set()) or (product, profile, case_id) in alg_adopted or (product, profile, case_id) in peer_adopted or (product == "shibboleth" and ((profile == "metadata_idp" and case_id in POLLING_RETESTS) or (profile == "browser_sso_idp" and case_id == "IIP-IDP12-c-idp-01"))) else ""))
            lines.append(f"| `{case_id}` | " + " | ".join(cells) + " |")
        sections.append("\n".join(lines))
    template = Path(__file__).with_name("comparison-notes.md").read_text()
    rows = ["| Profile | Product | Run | Evidence directory |", "|---|---|---|---|"]
    for m in manifest:
        scope = " († listed supplemental cases only)" if "cases" in m else ""
        rows.append(f"| {m['profile']}{scope} | {m['product']} | `{m['run']}` | `{m['folder']}` |")
    reason_labels = {
        "case.pending-interaction": "設定・受信待ちに加え、判定処理未実装の経路を含む。全件台帳を参照",
        "attestation.interaction-disallowed": "自己申告を無効にした構成。確認せずに申告を代行しない",
        "browser_fixture_partial": "一部の試験だけ実行。残るvariantの証拠が不足",
        "request.signing.unavailable": "署名必須構成でSuiteが当該要求を署名できない",
        "force_authn_timestamp_precision_insufficient": "報告された時刻精度では新規認証を証明できない",
        "control_failed": "正常系対照が成立せず異常系を判定できない",
    }
    total = sum(sum(counter.values()) for counter in unresolved.values())
    reason_lines = ["## Not verifiedの内訳", "",
                   f"以下は表に採用したケース結果の延べ{total}件。†のケースは新Runの追加証拠を採用し、それ以外の既存証拠は保持しています。単一Runの集計や全試験の再完走を意味しません。比較表で設定不足として扱い直した旧FAILは、このNOT_VERIFIED集計には含めません。", "",
                   "| 理由 | Keycloak | Shibboleth IdP | SimpleSAMLphp | 解消に必要なこと |",
                   "|---|---:|---:|---:|---|"]
    reasons = set().union(*(counter.keys() for counter in unresolved.values()))
    for reason in sorted(reasons, key=lambda key: -sum(c[key] for c in unresolved.values())):
        counts = " | ".join(str(unresolved[p][reason]) for p in PRODUCTS)
        label = reason_labels.get(reason, "当該ケースの応答・対象設定・正常系対照を追加確認")
        reason_lines.append(f"| `{reason}` | {counts} | {label} |")
    reason_lines += ["", "Chromeと承認のブロックを解除するだけでは解消しません。自動判定やfixtureの未実装にはSuiteの実装が必要です。設定・自己申告の経路は証拠の裏付けが必要です。[全件台帳](26-unverified-case-inventory.md)にケースごとの原因と再試験を記録しています。"]
    text = template + "\n\n" + "\n".join(reason_lines) + "\n\n## テスト別比較\n\n" + "\n\n".join(sections) + "\n\n## 採用した実行証拠\n\n" + "\n".join(rows) + "\n"
    output.write_text(text)
    (root / "fix-verification/comparison-provenance.json").write_text(json.dumps(manifest, indent=2) + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("docs/23-reference-test-comparison.md"))
    args = parser.parse_args()
    render(args.evidence_root, args.output)
