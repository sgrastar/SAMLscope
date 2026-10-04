"""Validate explicitly selected native-parser acceptance evidence before ledger adoption.

HTTP 500 from the signature control is recorded, never converted into a rejection verdict.
Only positive metadata-consumption cases with all required signed flows are adopted here.
MD03.c (metadata-signature trust) and KeyValue consumption are deliberately excluded.
"""
import hashlib
import json
from pathlib import Path
from verify_keycloak_import_batch import ADOPTED as COMMON

ADOPTED = dict(COMMON, **{
    'IIP-MD05-ad-idp-01': ['multiple-signing-keys-first','multiple-signing-keys','multiple-omitted-keys-first','multiple-omitted-keys-second'],
    'IIP-MD06-a9-idp-01': ['certificate-expired','certificate-not-yet-valid','certificate-empty-subject','certificate-unknown-ca',
        'certificate-critical-extension','certificate-noncritical-extension','certificate-no-digital-signature','certificate-unrelated-eku'],
    'IIP-MD07-a-idp-01': ['entity-root','multiple-signing-keys-first','multiple-signing-keys','three-signing-keys-first','three-signing-keys-second','three-signing-keys'],
    'IIP-MD12-b-idp-01': ['certificate-expired','certificate-not-yet-valid'],
    'IIP-MD12-d-idp-01': ['certificate-not-yet-valid','certificate-critical-extension','certificate-noncritical-extension',
        'certificate-no-digital-signature','certificate-unrelated-eku','certificate-empty-subject','certificate-unknown-ca','entity-root'],
})

def verify(root, *, folder="simplesamlphp-native-parser-3", adopted=None, require_signature_control=True):
    adopted = ADOPTED if adopted is None else adopted
    final=Path(root)/folder
    path=final/'result.json';result=json.loads(path.read_text());run=result['run']['id']
    restored=json.loads((final/'restoration.json').read_text())
    assert restored['restored'] and restored['original_sha256']==restored['final_sha256']
    entries={e['id']:e for e in json.loads((final/'transcript.json').read_text())}
    cases={c['id']:c for r in result['requirements'] for c in r['cases']}
    for case_id,variants in adopted.items():
        case=cases[case_id]
        assert (case['verdict'],case['reason_code'])==('PASS','metadata.fixture-probe.satisfied')
        assert set(variants).issubset(case['diagnostics']['used_variants'])
        for variant in ['control',*variants]:
            folder=final/variant;data=json.loads((folder/'import.json').read_text())
            assert data['status']=='success' and data['restored'] and data['configuration_read_back']
            assert data['import_path']=='native-parser-cli' and data['validate_authnrequest'] is True
            assert data['configuration_settle_seconds']==3
            assert hashlib.sha256((folder/'fixture.xml').read_bytes()).hexdigest()==data['fixture_sha256']
            assert hashlib.sha256((folder/'parser-output.json').read_bytes()).hexdigest()==data['parser_output_sha256']
            flow=json.loads((folder/'flow.json').read_text())
            assert flow['run']==run and flow['variant']==variant and flow['correlated_success']
            if require_signature_control:
                negative=flow['negative_control']
                assert negative['source']=='suite' and negative['correlated_success'] is False
                assert negative['receipt']=='no-response:HTTP-500'
            exchange=flow['positive_exchange'];assert exchange['success']
            refs=exchange['transcript_ids'];assert len(refs)>=2
            issued=entries[refs[0]]
            assert issued['direction']=='OUTBOUND' and issued['runId']==run
            assert issued['samlSummary']['variant']==variant
            assert issued['samlSummary']['metadataSignatureControl']=='valid'
            assert issued['samlSummary']['id']==exchange['request_id']
            for ref in refs[1:]:
                entry=entries[ref];summary=entry['samlSummary']
                assert entry['direction']=='INBOUND' and entry['runId']==run
                assert summary['inResponseTo']==exchange['request_id'] and summary['metadataProbeAccepted'] is True
                assert summary['statusCode']=='urn:oasis:names:tc:SAML:2.0:status:Success'
        for ref in case['evidence']:
            assert ref['kind']=='transcript'
            assert entries[ref['reference'].removeprefix('transcript:')]['runId']==run
    return path,cases

if __name__=='__main__':
    import sys
    verify(sys.argv[1]);print('Verified native parser evidence for',len(ADOPTED),'cases')
