"""Withdraw legacy algorithm conclusions lacking recorded receiver-side signature controls.

This is a review qualification, never a mutation of the original Suite result.
The legacy scenario needs a normal response and three negative fixture observations.
One successful response proves neither rejection of those fixtures nor signature verification.
"""
import hashlib
import json
from pathlib import Path

CASES = {'IIP-ALG01-a-idp-01', 'IIP-ALG02-a-idp-01'}
REASON = 'audit.algorithm-verification-controls-unproven'
SOURCES = {
    ('keycloak', 'browser_sso_idp'): 'interaction-followup/after/keycloak/browser_sso_idp',
    ('simplesamlphp', 'browser_sso_idp'): 'interaction-followup/after/simplesamlphp/browser_sso_idp',
    ('shibboleth', 'browser_sso_idp'): 'interaction-followup/after/shibboleth/browser_sso_idp',
    ('shibboleth', 'metadata_idp'): 'interaction-followup/after/shibboleth/metadata_idp',
    ('shibboleth', 'ecp_idp'): 'shibboleth/ecp_idp/run4',
    ('shibboleth', 'single_logout_idp'): 'remaining-audit/shibboleth/fresh_common',
}


def withdrawals(root):
    rows = []
    for (product, profile), folder in SOURCES.items():
        source = Path(root) / folder
        raw = (source / 'result.json').read_bytes()
        result = json.loads(raw)
        transcript_raw = (source / 'transcript-index.json').read_bytes()
        transcript = {e['id']: e for e in json.loads(transcript_raw)}
        cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
        for case_id in sorted(CASES):
            case = cases[case_id]
            assert case['verdict'] == 'PASS' and case['reason_code'] == 'idp.signed-request.satisfied'
            assert case['attested'] is False and len(case['evidence']) == 1
            assert case['evidence'][0]['kind'] == 'transcript'
            observed = transcript[case['evidence'][0]['reference']]
            assert observed['runId'] == result['run']['id'] and observed['direction'] == 'INBOUND'
            assert observed['samlSummary']['type'] == 'Response'
            assert observed['samlSummary']['statusCode'] == 'urn:oasis:names:tc:SAML:2.0:status:Success'
            rows.append(dict(product=product, profile=profile, case=case_id, run=result['run']['id'],
                reason_code=REASON, verdict='NOT_VERIFIED', interaction=None,
                evidence_folder=str(source), result_sha256=hashlib.sha256(raw).hexdigest(),
                evidence=case['evidence'], mode=case['mode'],
                audit_withdrawal=dict(original_verdict=case['verdict'], original_reason=case['reason_code'],
                    transcript_sha256=hashlib.sha256(transcript_raw).hexdigest(),
                    basis='Only the successful control response is referenced; invalid-request rejection is unproven.',
                    scope='Review qualification; original result preserved; no new product verdict assigned.')))
    return rows


if __name__ == '__main__':
    import sys
    rows = withdrawals(sys.argv[1])
    path = Path(sys.argv[1]) / 'remaining-audit/algorithm-verification-withdrawals.json'
    path.write_text(json.dumps(rows, indent=2) + '\n')
    print('Algorithm observations requiring renewed verification:', len(rows))
