"""Render a review-qualified comparison without changing signed definitions or raw results."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

# This generator selects evidence for public comparison.  Its integrity assertions
# must never be stripped by an optimized interpreter.
if not __debug__:
    raise RuntimeError('comparison generation must not run with Python optimization')

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
    "IIP-SSO05-a-idp-01", "IIP-SSO01-d-idp-01", "IIP-IDP10-b-idp-01", "IIP-IDP10-d-idp-01",
    "IIP-IDP05-a-idp-01", "IIP-IDP08-a-idp-01", "IIP-IDP17-t-idp-01",
    "IIP-IDP17-m-idp-01", "IIP-IDP15-a-idp-01",
}

def withdrawn_source_case(qualification):
    """Load the pinned withdrawn conclusion, not an older baseline placeholder."""
    path = Path(qualification['evidence_folder']) / qualification.get('result_file', 'result.json')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != qualification['result_sha256']:
        raise ValueError('Withdrawn comparison source digest differs')
    result = json.loads(raw)
    cases = [c for req in result['requirements'] for c in req['cases']
             if c['id'] == qualification['case']]
    if (result['run']['id'] != qualification['run'] or len(cases) != 1
            or cases[0]['verdict'] != qualification['audit_withdrawal']['original_verdict']
            or cases[0]['reason_code'] != qualification['audit_withdrawal']['original_reason']):
        raise ValueError('Withdrawn comparison Run or original conclusion differs')
    return cases[0]

def render(root, output):
    # One immutable campaign can qualify several comparison cells. Verify its
    # complete originals once per render; another invocation verifies them anew.
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

    verified_native_key_campaigns = {}
    from audit_algorithm_verification_evidence import withdrawals as algorithm_withdrawals
    from audit_force_authn_mechanism_evidence import withdrawals as force_authn_withdrawals
    from audit_async_feedback_failure_evidence import withdrawals as async_feedback_withdrawals
    from audit_metadata_full_ui_evidence import withdrawals as metadata_full_ui_withdrawals
    withdrawn={(r['product'],r['profile'],r['case']):r for r in algorithm_withdrawals(root) + force_authn_withdrawals(root) + async_feedback_withdrawals(root) + metadata_full_ui_withdrawals(root)}
    # The audited ledger owns the final per-case selection, including withdrawn conclusions.
    # Older feature-specific selections above must not resurrect a result rejected by that audit.
    ledger_selection = {}
    delta_path = root / "remaining-audit/retest-delta.json"
    if delta_path.exists():
        for row in json.loads(delta_path.read_text()):
            ledger_selection[(row["product"], row["profile"], row["case"])] = row
    for product in PRODUCTS:
        signer_key = (product, "single_logout_idp", "IIP-IDP17-ab-idp-01")
        signer_row = ledger_selection.get(signer_key)
        if signer_row is None or signer_row.get("verdict") == "NOT_VERIFIED":
            continue
        from verify_slo_registered_signer_acceptance import verify_adoption as verify_slo_signer
        signer_path, signer_cases = check_once(
            verify_slo_signer, root.parent / "reference-20261004", product, live=False)
        signer_raw = signer_path.read_bytes()
        signer_case = signer_cases[signer_key[2]]
        if (signer_row["run"] != json.loads(signer_raw)["run"]["id"]
                or signer_row["result_sha256"] != hashlib.sha256(signer_raw).hexdigest()
                or signer_row["verdict"] != signer_case["verdict"]
                or signer_row["reason_code"] != signer_case["reason_code"]
                or signer_row["evidence"] != signer_case["evidence"]):
            raise ValueError("Native SLO signer comparison selection differs from its verified Run")
    version_key = ("simplesamlphp", "browser_sso_idp", "IIP-SSO01-ep-idp-01")
    version_row = ledger_selection.get(version_key)
    if version_row is not None and version_row.get("verdict") != "NOT_VERIFIED":
        from verify_version_mismatch_acceptance import verify as verify_version_mismatch
        version_path, version_ids = check_once(
            verify_version_mismatch, root.parent / "reference-20261004", live=False)
        version_raw = version_path.read_bytes()
        version_result = json.loads(version_raw)
        version_cases = [case for requirement in version_result["requirements"]
                         for case in requirement["cases"] if case["id"] in version_ids]
        if version_ids != {version_key[2]} or len(version_cases) != 1:
            raise ValueError("Version mismatch comparison has an unexpected case scope")
        version_case = version_cases[0]
        if (version_row["run"] != version_result["run"]["id"]
                or version_row["result_sha256"] != hashlib.sha256(version_raw).hexdigest()
                or version_row["verdict"] != version_case["verdict"]
                or version_row["reason_code"] != version_case["reason_code"]
                or version_row["evidence"] != version_case["evidence"]):
            raise ValueError("Version mismatch comparison selection differs from its verified Run")
    full_ui_key = ("shibboleth", "metadata_idp", "IIP-MD05-f-idp-01")
    full_ui_row = ledger_selection.get(full_ui_key)
    if full_ui_row is not None and full_ui_row.get("verdict") == "PASS":
        from verify_shibboleth_full_ui_acceptance import verify_adoption as verify_shib_full_ui
        path, verified_cases = check_once(verify_shib_full_ui,
            root.parent / "reference-20261003", live=False)
        raw = path.read_bytes()
        verified_case = verified_cases[full_ui_key[2]]
        if (full_ui_row["run"] != json.loads(raw)["run"]["id"]
                or full_ui_row["result_sha256"] != hashlib.sha256(raw).hexdigest()
                or full_ui_row["reason_code"] != verified_case["reason_code"]
                or full_ui_row["evidence"] != verified_case["evidence"]):
            raise ValueError("Native full UI ledger selection differs from its independently verified Run")
        withdrawn.pop(full_ui_key, None)
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
                ('keycloak', 'ecp_idp'): {
                    'folder': '../reference-20260915/peer-intent/keycloak/ecp_alg',
                    'cases': {
                        'IIP-ALG04-a-idp-01': ('PASS', 'browser.encryption.aes128-gcm.decrypted'),
                        'IIP-ALG06-a-idp-01': ('PASS', 'browser.encryption.rsa-oaep-mgf1p.decrypted')}},
                ('simplesamlphp', 'browser_sso_idp'): {
                    'folder': '../reference-20260915/peer-intent/simplesamlphp/browser_alg_enc',
                    'cases': {
                        'IIP-ALG06-a-idp-01': ('PASS', 'browser.encryption.rsa-oaep-mgf1p.decrypted'),
                        'IIP-IDP09-a-idp-01': ('PASS', 'configuration.passive.assertion-encryption-capability')}},
                ('simplesamlphp', 'ecp_idp'): {
                    'folder': '../reference-20260915/peer-intent/simplesamlphp/ecp_alg_enc',
                    'cases': {
                        'IIP-ALG06-a-idp-01': ('PASS', 'browser.encryption.rsa-oaep-mgf1p.decrypted')}},
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
            for (selected_product, selected_profile, case_id), row in ledger_selection.items():
                if (selected_product, selected_profile) != (product, profile):
                    continue
                selected_folder = Path(row["evidence_folder"])
                result_path = selected_folder / row.get("result_file", "result.json")
                if not result_path.exists():
                    result_path = root / selected_folder / row.get("result_file", "result.json")
                selected_raw = result_path.read_bytes()
                assert hashlib.sha256(selected_raw).hexdigest() == row["result_sha256"]
                selected = json.loads(selected_raw)
                assert selected["run"]["id"] == row["run"]
                matches = [c for req in selected["requirements"] for c in req["cases"] if c["id"] == case_id]
                assert len(matches) == 1
                replacement = matches[0]
                assert (replacement["verdict"], replacement["reason_code"]) == (row["verdict"], row["reason_code"])
                if (product, profile, case_id) in {
                        ("shibboleth", "browser_sso_idp", "IIP-ALG08-a-idp-01"),
                        ("shibboleth", "browser_sso_idp", "IIP-ALG08-b-idp-01"),
                        ("shibboleth", "ecp_idp", "IIP-ALG08-a-idp-01"),
                        ("shibboleth", "ecp_idp", "IIP-ALG08-b-idp-01")}:
                    if profile == "ecp_idp":
                        from verify_algorithm_prevention_ecp_acceptance import \
                            verify_adoption as verify_algorithm_prevention
                    else:
                        from verify_algorithm_prevention_acceptance import \
                            verify_adoption as verify_algorithm_prevention
                    verified_path, verified_cases = check_once(verify_algorithm_prevention,
                        root.parent / "reference-20260930")
                    assert result_path.resolve() == verified_path.resolve()
                    assert replacement == verified_cases[case_id]
                cases[case_id] = replacement
                peer_adopted.add((product, profile, case_id))
                manifest.append({"profile": profile, "product": product, "folder": str(result_path.parent),
                                 "run": row["run"], "cases": [case_id],
                                 "result_sha256": row["result_sha256"],
                                 "suite_image": selected["suite"]["image_digest"], "selection": "audited-ledger"})
            # This observation was already conclusive in the baseline, so it is not
            # part of remaining-audit's unresolved set. Preserve its stronger native
            # signed-original verification without counting it as a new resolution.
            if product == 'shibboleth' and profile == 'browser_sso_idp':
                from verify_shibboleth_post_error_binding_acceptance import verify as verify_shibboleth_post_error
                verified_path, verified_cases = check_once(verify_shibboleth_post_error, root.parent / 'reference-20261001')
                case_id = 'IIP-SSO03-b-idp-01'
                assert cases[case_id]['verdict'] == verified_cases[case_id]['verdict'] == 'PASS'
                selected_raw = verified_path.read_bytes()
                selected = json.loads(selected_raw)
                cases[case_id] = verified_cases[case_id]
                peer_adopted.add((product, profile, case_id))
                manifest.append({'profile': profile, 'product': product,
                    'folder': str(verified_path.parent), 'run': selected['run']['id'], 'cases': [case_id],
                    'result_sha256': hashlib.sha256(selected_raw).hexdigest(),
                    'suite_image': selected['suite']['image_digest'], 'selection': 'native-original-strengthening'})
            for case_id in list(cases):
                qualification=withdrawn.get((product,profile,case_id))
                if qualification is None: continue
                original=cases[case_id]
                if original['reason_code']=='algorithm.native-verification-observed':
                    from verify_native_signed_acceptance import verify as verify_native_signed
                    _,verified=check_once(verify_native_signed, root.parent/'reference-20260918',profile,product)
                    assert product in {'shibboleth','simplesamlphp','keycloak'} and original==verified[case_id]
                    continue
                # Ledger selection skips withdrawn results. The baseline can therefore
                # still hold a much older NOT_VERIFIED instead of the audited legacy PASS.
                # Qualify the actual pinned source before rendering its withdrawn state.
                original=withdrawn_source_case(qualification)
                assert original['verdict']=='PASS'
                cases[case_id]=dict(original,outcome='NOT_VERIFIED',verdict='NOT_VERIFIED',
                    reason_code=qualification['reason_code'],reason=qualification['reason_code'])
                manifest.append(dict(profile=profile,product=product,folder=qualification['evidence_folder'],
                    run=qualification['run'],cases=[case_id],result_sha256=qualification['result_sha256'],
                    suite_image='review-qualification',audit_withdrawal=qualification['audit_withdrawal']))
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
                if verdict == "FAIL" and case_id not in CONFIRMED_FAILURES and (product, profile, case_id) not in ledger_selection:
                    raise ValueError(f"Unreviewed failure: {product} {case_id}")
                display = {"PASS": "Success", "FAIL": "**Failed (Product)**", "WARNING": "Warning",
                           "NOT_VERIFIED": "Not verified", "NOT_APPLICABLE": "N/A",
                           "NOT_OBSERVABLE": "Not observable", "INDETERMINATE": "Indeterminate",
                           "INCONSISTENT": "Inconsistent", "ERROR": "Error (Suite)"}.get(verdict, verdict)
                native_authn_failure = (product, profile, case_id) == ("shibboleth", "browser_sso_idp", "IIP-SSO01-gc-idp-01") and (product, profile, case_id) in ledger_selection
                native_certificate_failure = (product == "keycloak" and profile == "metadata_idp"
                    and case_id in {"IIP-MD12-b-idp-01", "IIP-MD12-d-idp-01", "IIP-MD06-a9-idp-01"}
                    and case["reason_code"] == "metadata.certificate.native-valid-request-rejected"
                    and (product, profile, case_id) in ledger_selection)
                if native_certificate_failure:
                    from verify_native_certificate_acceptance import verify as verify_native_certificates
                    _, verified = check_once(verify_native_certificates, root.parent / 'reference-20260918', runtime=case_id == "IIP-MD06-a9-idp-01")
                    assert case == verified[case_id]
                native_key_failure = ((product,profile,case_id)==("keycloak","metadata_idp","IIP-MD07-a-idp-01")
                    and case["reason_code"]=="metadata.keys.selection-violated" and (product,profile,case_id) in ledger_selection)
                if native_key_failure:
                    from verify_metadata_key_acceptance import verify as verify_metadata_keys
                    _,verified=check_once(verify_metadata_keys, root.parent/'reference-20260918')
                    assert case==verified[case_id]
                native_runtime_key_failure = (
                    profile == "metadata_idp" and product in {"keycloak", "simplesamlphp"}
                    and case_id in {"IIP-MD05-cd-idp-01", "IIP-MD06-a5-idp-01", "IIP-MD06-a7-idp-01"}
                    and case["reason_code"] == {
                        "keycloak": "metadata.keys.selection-violated",
                        "simplesamlphp": "metadata.keys.keyvalue-runtime-unavailable",
                    }[product]
                    and (product, profile, case_id) in ledger_selection)
                if native_runtime_key_failure:
                    if product not in verified_native_key_campaigns:
                        if product == "keycloak":
                            from verify_keycloak_native_key_policy_acceptance import verify_adoption as verify_runtime_keys
                            evidence_root = root.parent / 'reference-20260930'
                        else:
                            from verify_ssp_keyvalue_runtime_acceptance import verify as verify_runtime_keys
                            evidence_root = root.parent / 'reference-20261001'
                        _, verified_native_key_campaigns[product] = check_once(verify_runtime_keys, evidence_root, live=False)
                    assert case == verified_native_key_campaigns[product][case_id]
                    native_key_failure = True
                native_default_acs_failure = ((product, profile, case_id) in {
                    ("keycloak", "metadata_idp", "IIP-MD05-av-idp-01"),
                    ("shibboleth", "metadata_idp", "IIP-MD05-av-idp-01"),
                    ("simplesamlphp", "metadata_idp", "IIP-MD05-av-idp-01"),
                }
                    and case["reason_code"] == "metadata.fixture-probe.violated"
                    and (product, profile, case_id) in ledger_selection)
                if native_default_acs_failure:
                    if product == "keycloak":
                        from verify_keycloak_default_acs_acceptance import verify as verify_default_acs
                    elif product == "shibboleth":
                        from verify_shibboleth_default_acs_acceptance import verify as verify_default_acs
                    else:
                        from verify_ssp_default_acs_acceptance import verify as verify_default_acs
                    _, verified = check_once(verify_default_acs, root.parent / 'reference-20260930')
                    assert case == verified[case_id]
                native_attribute_name_failure = (
                    (product, profile, case_id) == ("keycloak", "browser_sso_idp", "IIP-IDP01-a-idp-01")
                    and case["reason_code"] == "capability_absent"
                    and (product, profile, case_id) in ledger_selection)
                if native_attribute_name_failure:
                    from verify_keycloak_attribute_name_absence import verify as verify_attribute_name_absence
                    _, verified = check_once(verify_attribute_name_absence, root.parent / 'reference-20260930')
                    assert case == verified[case_id]
                native_nameid_omission_failure = (
                    (product, profile, case_id) == ("keycloak", "browser_sso_idp", "IIP-IDP11-a-idp-01")
                    and case["reason_code"] == "capability_absent"
                    and (product, profile, case_id) in ledger_selection)
                if native_nameid_omission_failure:
                    from verify_keycloak_nameid_omission_absence import verify_adoption as verify_nameid_absence
                    _, verified = check_once(verify_nameid_absence, root.parent / 'reference-20260930')
                    assert case == verified[case_id]
                native_ssp_validity_failure = (
                    product == "simplesamlphp" and profile == "metadata_idp"
                    and case_id in {"IIP-MD04-a-idp-01", "IIP-MD04-c-idp-01"}
                    and case["reason_code"] == "metadata.fixture-probe.violated"
                    and (product, profile, case_id) in ledger_selection)
                if native_ssp_validity_failure:
                    from verify_ssp_validity_capability_absence import verify as verify_ssp_validity
                    _, verified = check_once(verify_ssp_validity, root.parent / 'reference-20260930')
                    assert case == verified[case_id]
                native_keycloak_validity_failure = (
                    product == "keycloak" and profile == "metadata_idp"
                    and case_id in {"IIP-MD04-a-idp-01", "IIP-MD04-b-idp-01",
                                    "IIP-MD04-c-idp-01", "IIP-MD05-as-idp-01"}
                    and case["reason_code"] in {
                        "metadata.fixture-probe.violated", "capability_absent"}
                    and (product, profile, case_id) in ledger_selection)
                if native_keycloak_validity_failure:
                    from verify_keycloak_validity_capability_absence import \
                        verify as verify_keycloak_validity
                    _, verified = check_once(verify_keycloak_validity,
                        root.parent / 'reference-20260930', case_id)
                    assert case == verified[case_id]
                native_metadata_source_failure = (
                    product == "keycloak" and profile == "metadata_idp"
                    and case_id in {"IIP-MD06-b-idp-01", "IIP-MD03-d-idp-01"}
                    and case["reason_code"] == "capability_absent"
                    and (product, profile, case_id) in ledger_selection)
                if native_metadata_source_failure:
                    from verify_keycloak_metadata_source_capability_absence import \
                        verify_adoption as verify_metadata_source_absence
                    _, verified = check_once(verify_metadata_source_absence, root.parent / 'reference-20260930')
                    assert case == verified[case_id]
                native_metadata_signature_failure = (
                    product == "keycloak" and profile == "metadata_idp"
                    and case_id in {"IIP-MD03-a-idp-01", "IIP-MD03-b-idp-01",
                                    "IIP-MD03-c-idp-01"}
                    and case["reason_code"] == "capability_absent"
                    and (product, profile, case_id) in ledger_selection)
                if native_metadata_signature_failure:
                    from verify_keycloak_metadata_signature_capability_absence import \
                        verify_adoption as verify_metadata_signature_absence
                    _, verified = check_once(verify_metadata_signature_absence,
                        root.parent / 'reference-20260930')
                    assert case == verified[case_id]
                native_metadata_application_failure = (
                    (product, profile, case_id) == ("keycloak", "metadata_idp", "IIP-MD06-a-idp-01")
                    and case["reason_code"] == "metadata.application.accepted-post-endpoint-rejected"
                    and (product, profile, case_id) in ledger_selection)
                if native_metadata_application_failure:
                    from verify_keycloak_metadata_supersession_acceptance import verify_adoption as verify_native_application
                    _, verified = check_once(verify_native_application, root.parent / 'reference-20261001', live=False)
                    assert case == verified[case_id]
                native_metadata_supersession_failure = (
                    (product, profile, case_id) == ("keycloak", "metadata_idp", "IIP-MD06-ab-idp-01")
                    and case["reason_code"] == "metadata.supersession.accepted-post-endpoint-rejected"
                    and (product, profile, case_id) in ledger_selection)
                if native_metadata_supersession_failure:
                    from verify_keycloak_supersession_counterexample_acceptance import verify_adoption as verify_native_supersession
                    _, verified = check_once(verify_native_supersession, root.parent / 'reference-20261001', live=False)
                    assert case == verified[case_id]
                native_encrypted_logout_failure = (
                    (product, profile, case_id) == ("simplesamlphp", "single_logout_idp", "IIP-IDP19-c-idp-01")
                    and case["reason_code"] == "slo.encrypted-id.multiple-keys.unknown-key-accepted"
                    and (product, profile, case_id) in ledger_selection)
                if native_encrypted_logout_failure:
                    from verify_ssp_encrypted_logout_acceptance import verify as verify_native_encrypted_logout
                    _, verified = check_once(verify_native_encrypted_logout, root.parent / 'reference-20261001', live=False)
                    assert case == verified[case_id]
                native_schema_admission_failure = (
                    (product, profile, case_id) == ("keycloak", "metadata_idp", "IIP-MD05-b-idp-01")
                    and case["reason_code"] == "metadata.schema.native-valid-endpoint-extension-rejected"
                    and (product, profile, case_id) in ledger_selection)
                if native_schema_admission_failure:
                    from verify_keycloak_native_schema_admission_acceptance import verify_adoption as verify_native_schema
                    _, verified = check_once(verify_native_schema, root.parent / 'reference-20261001', live=False)
                    assert case == verified[case_id]
                native_attribute_index_failure = (
                    (product, profile, case_id) == ("simplesamlphp", "browser_sso_idp", "IIP-IDP04-b-idp-01")
                    and case["reason_code"] == "browser.attribute-index.selection-ignored"
                    and (product, profile, case_id) in ledger_selection)
                if native_attribute_index_failure:
                    from verify_ssp_attribute_service_index_acceptance import verify as verify_native_attribute_index
                    _, verified = check_once(verify_native_attribute_index, root.parent / 'reference-20261001', live=False)
                    assert case == verified[case_id]
                if verdict == "FAIL" and case_id not in CONFIRMED_FAILURES and not native_authn_failure and not native_certificate_failure and not native_key_failure and not native_default_acs_failure and not native_attribute_name_failure and not native_nameid_omission_failure and not native_ssp_validity_failure and not native_keycloak_validity_failure and not native_metadata_source_failure and not native_metadata_signature_failure and not native_metadata_application_failure and not native_metadata_supersession_failure and not native_encrypted_logout_failure and not native_schema_admission_failure and not native_attribute_index_failure:
                    display = "**Failed (台帳採用・原因分類未確認)**"
                if product == 'simplesamlphp' and profile == 'browser_sso_idp' and case_id == 'IIP-IDP06-b-idp-01' and case['reason_code'] != 'audit.force-authn-mechanism-access-unproven':
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
        "audit.slo-async-session-failure-unproven": "IdP自身のセッション終了失敗を安全に誘導し、正常終了と失敗通知の両対照を観測する必要がある",
        "audit.metadata-full-ui-controls-unproven": "正しい配置のUIInfo・DiscoHintsを取り込み、全variantの値を製品のUIまたは実効読み戻しで確認する必要がある",
        "control_failed": "正常系対照が成立せず異常系を判定できない",
    }
    total = sum(sum(counter.values()) for counter in unresolved.values())
    reason_lines = ["## Not verifiedの内訳", "",
                   f"以下は表に採用したケース結果の延べ{total}件。†のケースは新Runの追加証拠を採用し、それ以外の既存証拠は保持しています。単一Runの集計や全試験の再完走を意味しません。比較表で設定不足として扱い直した旧FAILは、このNOT_VERIFIED集計には含めません。", "",
                   "| 理由 | Keycloak | Shibboleth IdP | SimpleSAMLphp | 解消に必要なこと |",
                   "|---|---:|---:|---:|---|"]
    reasons = set().union(*(counter.keys() for counter in unresolved.values()))
    for reason in sorted(reasons, key=lambda key: (-sum(c[key] for c in unresolved.values()), key)):
        counts = " | ".join(str(unresolved[p][reason]) for p in PRODUCTS)
        label = reason_labels.get(reason, "当該ケースの応答・対象設定・正常系対照を追加確認")
        reason_lines.append(f"| `{reason}` | {counts} | {label} |")
    reason_lines += ["", "Chromeと承認のブロックを解除するだけでは解消しません。自動判定やfixtureの未実装にはSuiteの実装が必要です。設定・自己申告の経路は証拠の裏付けが必要です。[全件台帳](26-unverified-case-inventory.md)にケースごとの原因と再試験を記録しています。"]
    template += "\n\n台帳で採用済みの追加結果は、Run・SHA-256・Verdictを照合して比較表へ反映しています。`Failed (台帳採用・原因分類未確認)`は保存済み判定の転記であり、この更新で製品への原因帰属を追加承認したものではありません。"
    text = template + "\n\n" + "\n".join(reason_lines) + "\n\n## テスト別比較\n\n" + "\n\n".join(sections) + "\n\n## 採用した実行証拠\n\n" + "\n".join(rows) + "\n"
    output.write_text(text)
    (root / "fix-verification/comparison-provenance.json").write_text(json.dumps(manifest, indent=2) + "\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("docs/23-reference-test-comparison.md"))
    args = parser.parse_args()
    from acceptance_dependency_discovery import dependency_discovery_scope
    with dependency_discovery_scope():
        render(args.evidence_root, args.output)
