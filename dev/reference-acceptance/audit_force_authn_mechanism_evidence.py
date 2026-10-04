"""Withdraw one legacy external-only ForceAuthn mechanism conclusion.

Qualification only: immutable Suite originals and the approved ATTESTED contract
are preserved. External reauthentication cannot prove internal reachability.
"""
import hashlib
import json
from pathlib import Path
import yaml

CASE = 'IIP-IDP06-b-idp-01'
REASON = 'audit.force-authn-mechanism-access-unproven'
SOURCE = 'queue-integrated-implementation/simplesamlphp/browser_sso_idp'
RESULT_SHA = 'b4da124a09c08d888dffe19adca365447a3bb3a27a125b523f3f8b9a76e08f44'
TRANSCRIPT_SHA = '649ac55b63b94e5f58f196ef10b42c0a444204cd83511a86fb23427a1e1a4e39'
VARIANT = 'IIP-IDP06.b#v-e6fa1fe5de'
REPO = Path(__file__).resolve().parents[2]


def withdrawals(root):
    source = Path(root) / SOURCE
    raw = (source / 'result.json').read_bytes()
    transcript_raw = (source / 'transcript.json').read_bytes()
    sha = lambda value: hashlib.sha256(value).hexdigest()
    assert sha(raw) == RESULT_SHA and sha(transcript_raw) == TRANSCRIPT_SHA
    catalog_raw = (REPO / 'tests/cases.yaml').read_bytes()
    definitions = yaml.safe_load(catalog_raw)['cases']
    definition = next(c for c in definitions if c['id'] == CASE)
    assert definition['case_digest'] == 'sha256:7642c77cfa0d640d1cc6baf96d91301709754a1a4597db479114c855e26bd671'
    assert definition['mode'] == 'ATTESTED' and definition['covers_variants'] == [VARIANT]
    assert definition['interpretation_constraints'] == ['Because external observation only sees reauthentication when true, reachability inside the mechanism is ATTESTED.']
    result = json.loads(raw)
    case = next(c for req in result['requirements'] for c in req['cases'] if c['id'] == CASE)
    assert (case['mode'], case['outcome'], case['verdict'], case['reason_code']) == ('ATTESTED', 'SATISFIED', 'PASS', 'force_authn_fresh_authentication_observed')
    entries = json.loads(transcript_raw)
    indexed = {entry['id']: entry for entry in entries}
    assert len(indexed) == len(entries) and all(entry['runId'] == result['run']['id'] for entry in entries)
    assert len(case['evidence']) == 4 and all(ref['kind'] == 'transcript' for ref in case['evidence'])
    for ref in case['evidence']:
        observed = indexed[ref['reference']]
        assert observed['direction'] == 'INBOUND' and observed['samlSummary']['type'] == 'Response'
    return [dict(product='simplesamlphp', profile='browser_sso_idp', case=CASE,
        run=result['run']['id'], reason_code=REASON, verdict='NOT_VERIFIED', interaction=None,
        evidence_folder=str(source), result_sha256=sha(raw), evidence=case['evidence'], mode='ATTESTED',
        audit_withdrawal=dict(original_verdict='PASS', original_reason=case['reason_code'],
            original_attested_flag=case['attested'], transcript_sha256=sha(transcript_raw),
            approved_case_digest=definition['case_digest'], approved_variant=VARIANT,
            approved_catalog_sha256=sha(catalog_raw),
            basis='External Response/AuthnInstant observations do not prove authentication-mechanism access to ForceAuthn; no internal trace or corroborated mechanism evidence is referenced.',
            scope='SimpleSAMLphp legacy Run only; original result unchanged; IDP06.a and Shibboleth native mechanism evidence are unaffected.'))]
