"""Withdraw two legacy async-SLO feedback conclusions with an unproved failure path.

This qualifies only the pinned legacy campaigns.  A malformed Destination is not
the approved IdP-own-session termination failure; raw results remain unchanged.
"""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml

CASE = 'IIP-IDP17-b2-idp-01'
REASON = 'audit.slo-async-session-failure-unproven'
PROFILE = 'single_logout_idp'
REPO = Path(__file__).resolve().parents[2]
AUDIT = 'reference-20261002/cross-cluster-audit/slo-async-feedback-adopted-boundary'
VARIANTS = ['IIP-IDP17.b2#v-2359a2c376', 'IIP-IDP17.b2#v-f39de0daee']
CASE_DIGEST = 'sha256:91e2b6359f319012aca9c8633f574ed217d4d009bac39bc1b1bd9935312bb09f'
CONSTRAINT = ('If the failure path cannot be safely induced, use '
              'not_verified(session_termination_failure_not_inducible) and do not mark '
              'the target as violating. Reuse the same induction mechanism as IIP-IDP17.o.')
AUDIT_SHA = 'f069d71b9dafd30118d02ae4a66e326b3a988d8d48db539d775b73d29eb3c97a'
FACTS_SHA = 'a60e63935e9505add7109d47637d91c3e30058f41532eb5a76ea08d820e841af'
PINS = {
    'keycloak': {
        'run': 'run_P9PEZYWNZW63V20ETYAP94H7KX',
        'result': 'aae94533164d1bc519e38db8d7660a4585d8bf487861b643909f4c4e17fe7528',
        'exchange': '9b91ca75c5ddd018cc5ce8ea635b6da531372e8a42c7ef24de7bbd39d7c52bcc',
        'transcript': '26b8cc5365b4222e93fd8a44c4af7e22a9475d7d8afd4dc7467ca9a61e54b1e4',
        'requests': {
            'tx_4F93C5E2HJ0EAXVZ6D7MTA65ZD': 'dabdd90c1312e086c3f7e6c2e302a1a41871f5647f89b188d2e85f2020dc2649',
            'tx_MQDMWC3T150S4KJFAHZQKSDCBW': '946c6d0324bffe4cdb259a307a97fb01b25dade6a7f1222921392bdcaaccdacf'},
        'failure': 'tx_DBDH33NZBVKTN7AJ3FTZJ9D7HA',
        'feedback': 'tx_SESEMHXYV0HS5HN5CZNAWQSMPT',
        'response': 'tx_F9PZQREGH8YVQNYF90P6PKT1JN',
        'evidence': ['tx_TPDTYZ7ZTDQ9NN6XBR21R7JJS7', 'tx_F9PZQREGH8YVQNYF90P6PKT1JN']},
    'shibboleth': {
        'run': 'run_9KV70EB8T30AXEBZKCAK1C1WWE',
        'result': '1643e841301989808f4553d1cffde0dad446ebbfea4a50526930df9170dd0ba0',
        'exchange': 'c6250b9e589a7cc30a2bf8fd00f258bedf60921914d8c29db1710fb0a536f89f',
        'transcript': '8b3576097b97ebc7f0f71c6644bcd8cc2ff5565c9139beb66219db1271f6d2e8',
        'requests': {
            'tx_S4R2MVTFG6KG74JGBN6NCN6NKQ': '16861f7433f0d4150cead649037aa10dc4ba31577d50b239aa2370fcdc2e052a',
            'tx_RT5DK8YNBH88YN7RQJSQ3V3HSD': '18490627bde4b04dbccec2d335399baa0e7fb83c36b87ec291d260c13a66444e'},
        'failure': 'tx_FCG0C42S30PK3QP9AM3QQP9E6J',
        'feedback': 'tx_318QXPZNJ7XZC4PXXPVSDXSYZG',
        'response': None,
        'evidence': ['tx_C88SY724Z00NET2GTA1D3KCV7Q']}}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned(path, expected):
    path = Path(path)
    require(path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]),
            'Original is missing or symlinked: ' + path.name)
    raw = path.read_bytes()
    require(sha(raw) == expected, 'Original SHA-256 differs: ' + path.name)
    return raw


def approved():
    raw = (REPO / 'tests/cases.yaml').read_bytes()
    loader = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)
    definitions = yaml.load(raw, Loader=loader)['cases']
    matches = [c for c in definitions if c['id'] == CASE]
    require(len(matches) == 1, 'Approved async feedback case is not unique')
    case = matches[0]
    require(case['case_digest'] == CASE_DIGEST and case['mode'] == 'BROWSER'
            and case['covers_variants'] == VARIANTS
            and CONSTRAINT in case['interpretation_constraints'],
            'Approved own-session failure contract differs')
    groups = case['variant_groups']
    require(len(groups) == 1 and groups[0]['kind'] == 'all_of'
            and groups[0]['members'] == VARIANTS, 'Approved feedback all-of differs')
    require(any(c.get('kind') == 'negative' and c.get('fixture') == 'mut-iip-idp17-b2-idp'
                for c in case['controls']), 'Approved feedback mutant missing')
    return case, sha(raw)


def withdrawals(root):
    """Return two qualified NOT_VERIFIED rows; no supplied verdict/evidence overrides."""
    root = Path(root).absolute()
    require(root.name == 'reference-20260914' and root.is_dir() and not root.is_symlink(),
            'Expected reference-20260914 evidence root')
    audit_folder = root.parent / AUDIT
    audit = json.loads(pinned(audit_folder / 'review.json', AUDIT_SHA))
    facts = json.loads(pinned(audit_folder / 'request-bound-facts.json', FACTS_SHA))
    require(audit['schema'] == 'samlscope-slo-async-approved-boundary-review-v1'
            and audit['case'] == CASE and audit['currentlyAdoptedObservationsReviewed'] == 2
            and audit['approvedFailureVariant'] == VARIANTS[1]
            and audit['factsSha256'] == FACTS_SHA
            and audit['operations']['canonicalMutations'] == 0,
            'Independent native audit is not the qualified two-case review')
    definition, catalog_sha = approved()
    rows = []
    for product, pin in PINS.items():
        source = root.parent / 'reference-20260915/slo-oracle' / product / 'slo_probe_browser'
        result_raw = pinned(source / 'result.json', pin['result'])
        exchange_raw = pinned(source / 'exchange-log.json', pin['exchange'])
        transcript_raw = pinned(audit_folder / (product + '-transcript.json'), pin['transcript'])
        result = json.loads(result_raw)
        cases = [c for req in result['requirements'] for c in req['cases'] if c['id'] == CASE]
        require(len(cases) == 1 and result['run']['id'] == pin['run'], 'Foreign legacy Run/case')
        case = cases[0]
        require((case['mode'], case['outcome'], case['verdict'], case['reason_code'], case['attested'])
                == ('BROWSER', 'SATISFIED', 'PASS',
                    'slo.async.feedback.distinguishes-success-and-failure', False),
                'Legacy conclusion is not the audited feedback PASS')
        require(case['evidence'] == [{'kind': 'transcript', 'reference': x} for x in pin['evidence']],
                'Legacy case evidence differs')
        entries = json.loads(transcript_raw)
        indexed = {e['id']: e for e in entries}
        require(len(indexed) == len(entries) and all(e['runId'] == pin['run'] for e in entries),
                'Foreign/duplicate transcript original')
        selected = [e for e in entries if e.get('samlSummary', {}).get('scenario_case_id') == CASE]
        require(len(selected) == 3 and all(e['direction'] == 'OUTBOUND' for e in selected)
                and {e['samlSummary']['fixture_id'] for e in selected}
                == {'slo-async-login', 'slo-async-destination-mismatch', 'slo-async-trusted'},
                'Legacy trace is not the exact malformed-Destination surrogate')
        exchanges = [e for e in json.loads(exchange_raw) if e.get('caseId') == CASE]
        require(len(exchanges) == 3 and {e['actionId'] for e in exchanges}
                == {e['correlationId'] for e in selected}, 'Legacy operation action binding differs')
        own_facts = [f for f in facts if f['product'] == product]
        require(len(own_facts) == 2 and {f['requestReference'] for f in own_facts} == set(pin['requests']),
                'Native request audit is incomplete')
        for fact in own_facts:
            reference = fact['requestReference']
            entry = indexed[reference]
            raw = pinned(audit_folder / (reference + '.xml'), pin['requests'][reference])
            request = ET.fromstring(raw)
            require(request.tag == '{urn:oasis:names:tc:SAML:2.0:protocol}LogoutRequest'
                    and request.get('ID') == '_' + entry['correlationId']
                    and entry['correlationId'] == fact['action'] and fact['runId'] == pin['run']
                    and fact['requestSha256'] == sha(raw)
                    and fact['fixture'] == entry['samlSummary']['fixture_id']
                    and request.find('{http://www.w3.org/2000/09/xmldsig#}Signature') is not None
                    and request.find('{urn:oasis:names:tc:SAML:2.0:protocol}Extensions/'
                                     '{urn:oasis:names:tc:SAML:2.0:protocol:ext:async-slo}Asynchronous') is not None,
                    'Async signed request/independent audit binding differs')
            destination = request.get('Destination')
            require(destination == fact['destination'] and (
                destination == 'https://samlscope.invalid/sp/slo'
                if fact['fixture'] == 'slo-async-destination-mismatch'
                else destination == entry['url']), 'Surrogate Destination proof differs')
        failure = indexed[pin['failure']]
        mismatch = next(e for e in selected if e['samlSummary']['fixture_id'] == 'slo-async-destination-mismatch')
        normal = next(e for e in selected if e['samlSummary']['fixture_id'] == 'slo-async-trusted')
        feedback = indexed[pin['feedback']]
        require(failure['method'] == 'BROWSER' and failure['status'] == 400
                and failure['correlationId'] == mismatch['correlationId']
                and feedback['method'] == 'BROWSER' and feedback['status'] == 200
                and feedback['correlationId'] == normal['correlationId'],
                'Native wrong-Destination/correct-request HTTP binding differs')
        if pin['response']:
            response = indexed[pin['response']]
            require(response['samlSummary']['type'] == 'LogoutResponse'
                    and response['samlSummary']['statusCode'] == 'urn:oasis:names:tc:SAML:2.0:status:Success'
                    and response['samlSummary']['inResponseTo'] == '_' + normal['correlationId']
                    and '/sp/slo' in feedback['url'] and ':18080/' in feedback['url'],
                    'Keycloak success response/Suite-landing qualification differs')
        qualified = [x for x in audit['findings'] if x['product'] == product]
        require(len(qualified) == 1 and qualified[0]['run'] == pin['run']
                and qualified[0]['approvedOwnSessionFailureProven'] is False
                and qualified[0]['surrogateFailureRequest'] == mismatch['id']
                and qualified[0]['surrogateFailureHTTP'] == failure['id']
                and qualified[0]['correctRequest'] == normal['id']
                and qualified[0]['correctFeedback'] == feedback['id'],
                'Own-session failure absence is not the qualified audit finding')
        rows.append(dict(product=product, profile=PROFILE, case=CASE, run=pin['run'],
            reason_code=REASON, verdict='NOT_VERIFIED', interaction=None, evidence_folder=str(source),
            result_sha256=pin['result'], evidence=case['evidence'], mode='BROWSER',
            audit_withdrawal=dict(original_verdict='PASS', original_reason=case['reason_code'],
                original_attested_flag=case['attested'], transcript_sha256=pin['transcript'],
                approved_case_digest=definition['case_digest'], approved_variants=VARIANTS,
                approved_catalog_sha256=catalog_sha, native_audit_sha256=AUDIT_SHA,
                request_bound_facts_sha256=FACTS_SHA,
                native_audit_folder=str(audit_folder), request_original_sha256=pin['requests'],
                basis='Malformed-Destination rejection does not demonstrate failure to terminate the IdP own session; the approved all-of failed-logout variant is not proved.',
                scope='Pinned legacy async feedback Run only; original result/transcript unchanged; no product violation inferred.')))
    return rows
