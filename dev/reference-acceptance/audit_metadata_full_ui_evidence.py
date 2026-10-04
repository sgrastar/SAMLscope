"""Withdraw only two pinned MD05.f adoptions whose full DiscoHints fixture was mis-scoped.

Historical results/transcripts remain unchanged. Metadata acceptance and SSO do
not prove the approved extension values are available on a native read-back/UI.
"""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import yaml

REPO = Path(__file__).resolve().parents[2]
CASE = 'IIP-MD05-f-idp-01'
PROFILE = 'metadata_idp'
REASON = 'audit.metadata-full-ui-controls-unproven'
CASE_DIGEST = 'sha256:e8ce095dabf52d95fbacb362f4d24f450fe5f0da3dded7febe0c49ff969cf28c'
AUDIT = 'reference-20261003/cross-cluster-audit/keycloak-ui-complete-qualification/legacy-md05f-variant-matrix.json'
AUDIT_SHA = 'eb9bb3729ca7ebf1737dccfd3910b16fad45f218ef69df1a0a914a304b156b5d'
VARIANTS = [CASE.replace('-f-idp-01', '.f#') + value for value in
            ['v-4ab799adba', 'v-5f83e32e5b', 'v-65581d50d7', 'v-70733bfdff']]
RUNS = {'shibboleth': 'run_2BY1BA5BX6205P5Q5YQ15YC1KF',
        'simplesamlphp': 'run_YHD2ZJ212CAQJHBN4QVZ129E1G'}
MD = '{urn:oasis:names:tc:SAML:2.0:metadata}'
UI = '{urn:oasis:names:tc:SAML:metadata:ui}'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned(path, expected):
    path = Path(path)
    require(path.is_file() and not any(p.is_symlink() for p in [path, *path.parents]),
            'Missing/symlinked legacy original: ' + path.name)
    raw = path.read_bytes()
    require(sha(raw) == expected, 'Legacy original SHA-256 differs: ' + path.name)
    return raw


def approved():
    raw = (REPO / 'tests/cases.yaml').read_bytes()
    loader = getattr(yaml, 'CSafeLoader', yaml.SafeLoader)
    matches = [c for c in yaml.load(raw, Loader=loader)['cases'] if c['id'] == CASE]
    require(len(matches) == 1, 'Approved full UI case is not unique')
    case = matches[0]
    require(case['case_digest'] == CASE_DIGEST and case['role'] == 'idp'
            and case['mode'] == 'CONFIG' and case['configuration_failure_semantics'] == 'test_precondition'
            and set(case['covers_variants']) == set(VARIANTS), 'Approved full UI contract differs')
    groups = case['variant_groups']
    require(len(groups) == 1 and groups[0]['kind'] == 'all_of'
            and set(groups[0]['members']) == set(VARIANTS), 'Approved full UI all-of differs')
    require(any(c['kind'] == 'negative' and c['fixture'] == 'mut-iip-md05-f-idp'
                for c in case['controls']), 'Approved full UI mutant missing')
    require(any('read-back surface' in text and 'ignoring the extension' in text
                for text in case['interpretation_constraints']), 'Approved non-ignoring control differs')
    return case, sha(raw)


def withdrawals(root):
    """Return exactly two qualified NOT_VERIFIED rows, never caller-supplied verdicts."""
    root = Path(root).absolute()
    require(root.name == 'reference-20260914' and root.is_dir() and not root.is_symlink(),
            'Expected original reference-20260914 root')
    audit_path = root.parent / AUDIT
    audit = json.loads(pinned(audit_path, AUDIT_SHA))
    require(audit['schema'] == 'samlscope-md05f-legacy-extension-scope-review-v1'
            and audit['approvedCase'] == CASE and len(audit['rows']) == 2
            and set(audit['approvedAllOf']) == {v.split('#')[1] for v in VARIANTS}
            and audit['operations']['originalEdits'] == audit['operations']['canonicalEdits'] == 0,
            'Qualified two-observation native audit differs')
    definition, catalog_sha = approved()
    require({r['product'] for r in audit['rows']} == set(RUNS), 'Audited products differ')
    rows = []
    for audit_row in audit['rows']:
        product = audit_row['product']
        source = root.parent / 'reference-20260918' / (product + '-md05f-v107')
        raw = {name: pinned(source / name, digest) for name, digest in audit_row['originalPins'].items()}
        result = json.loads(raw['result.json'])
        matches = [c for req in result['requirements'] for c in req['cases'] if c['id'] == CASE]
        require(len(matches) == 1 and result['run']['id'] == RUNS[product] == audit_row['run']
                and result['profile']['id'] == 'metadata-idp', 'Foreign legacy Run/profile/case')
        case = matches[0]
        require(case == audit_row['originalCase'] and
                (case['mode'], case['outcome'], case['verdict'], case['reason_code'], case['attested']) ==
                ('CONFIG', 'SATISFIED', 'PASS', 'metadata.fixture-probe.satisfied', False),
                'Legacy conclusion is not the audited full UI PASS')
        require(set(case['diagnostics']['used_variants']) == {'control', 'full-ui-info'},
                'Legacy selected fixture inventory differs')
        entries = json.loads(raw['transcript.json'])
        indexed = {e['id']: e for e in entries}
        require(len(indexed) == len(entries) and all(e['runId'] == RUNS[product] for e in entries)
                and all(e['kind'] == 'transcript' and e['reference'].removeprefix('transcript:') in indexed
                        for e in case['evidence']), 'Foreign/duplicate/unbound legacy evidence')
        fixture = ET.fromstring(raw['full-ui-info/fixture.xml'])
        parents = {c: p for p in fixture.iter() for c in p}
        info = fixture.findall('.//' + UI + 'UIInfo')
        hints = fixture.findall('.//' + UI + 'DiscoHints')
        require(len(info) == len(hints) == 1 and parents[hints[0]] is info[0]
                and parents[info[0]].tag == MD + 'Extensions'
                and not parents[info[0]].findall(UI + 'DiscoHints'),
                'Original is not the exact mis-scoped full DiscoHints fixture')
        imported = json.loads(raw['full-ui-info/import.json'])
        flow = json.loads(raw['full-ui-info/flow.json'])
        require(imported['configuration_read_back'] is True and imported['status'] == 'success'
                and imported['fixture_sha256'] == sha(raw['full-ui-info/fixture.xml'])
                and flow['run'] == RUNS[product] and flow['variant'] == 'full-ui-info'
                and flow['correlated_success'] is True
                and flow['negative_control']['correlated_success'] is False,
                'Native acceptance/control originals differ')
        if product == 'simplesamlphp':
            native_php = json.loads(raw['full-ui-info/parser-output.json'])['php']
            require(all(value in native_php for value in ['UIInfo', 'Description', 'Logo'])
                    and all(value not in native_php for value in
                            ['DiscoHints', 'IPHint', 'DomainHint', 'GeolocationHint']),
                    'Audited native read-back absence differs')
        require(audit_row['wholeCaseQualification'] is False and audit_row['noProductFailureInferred'] is True,
                'Native audit does not qualify this withdrawal')
        rows.append(dict(product=product, profile=PROFILE, case=CASE, run=RUNS[product],
            reason_code=REASON, verdict='NOT_VERIFIED', interaction=None, mode='CONFIG',
            evidence_folder=str(source), result_sha256=sha(raw['result.json']), evidence=case['evidence'],
            audit_withdrawal=dict(original_verdict='PASS', original_reason=case['reason_code'],
                approved_case_digest=definition['case_digest'], approved_variants=VARIANTS,
                approved_catalog_sha256=catalog_sha, native_audit_sha256=AUDIT_SHA,
                native_audit_file=str(audit_path), original_pins=audit_row['originalPins'],
                basis='DiscoHints was inside UIInfo instead of role/Extensions; the approved full DiscoHints variant and non-ignoring extension controls are not proved.',
                scope='Exactly the pinned v107 MD05.f Run; old results/transcripts retained; no product violation inferred.')))
    return rows


if __name__ == '__main__':
    import sys
    print(json.dumps(withdrawals(sys.argv[1]), indent=2))
