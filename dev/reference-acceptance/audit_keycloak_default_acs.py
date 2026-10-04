"""Audit native import and observed ACS mismatches against native import and original protocol evidence."""
import hashlib
import json
import zipfile
from pathlib import Path
from verify_default_acs_batch import EXPECTED, selection_mismatches


def audit(root):
    folder = Path(root)/'keycloak-default-acs'
    path = folder/'result.json'
    result = json.loads(path.read_text())
    run = result['run']['id']
    assert run == json.loads((folder/'created.json').read_text())['run']['id']
    cases = {c['id']: c for req in result['requirements'] for c in req['cases']}
    case = cases['IIP-IDP12-c-idp-01']
    assert (case['verdict'], case['reason_code']) == ('FAIL','metadata.fixture-probe.violated')
    assert set(['control', *EXPECTED]).issubset(case['diagnostics']['fetched_variants'])
    entries = {e['id']:e for e in json.loads((folder/'transcript.json').read_text())}
    for variant in ['control', *EXPECTED]:
        source = folder/variant
        imported = json.loads((source/'import.json').read_text())
        assert imported['status'] == 'success' and imported['cleanup']['read_back_absent']
        assert imported['import']['ui_status'] == 'client-settings-page'
        readback = imported['import']['read_back']
        assert readback['client_id'] == imported['fixture']['entity_id']
        assert readback['saml_attributes']['saml.client.signature'] == 'true'
        assert hashlib.sha256((source/'fixture.xml').read_bytes()).hexdigest() == imported['fixture']['sha256']
        flow = json.loads((source/'flow.json').read_text())
        assert flow['run'] == run and flow['variant'] == variant and flow['correlated_success']
        exchange = flow['positive_exchange']
        assert exchange['success'] and len(exchange['transcript_ids']) >= 2
        request = entries[exchange['transcript_ids'][0]]
        assert request['direction'] == 'OUTBOUND' and request['runId'] == run
        assert request['samlSummary']['variant'] == variant
        assert request['samlSummary']['metadataSignatureControl'] == 'valid'
        assert request['samlSummary']['id'] == exchange['request_id']
        for ref in exchange['transcript_ids'][1:]:
            response = entries[ref]
            assert response['direction'] == 'INBOUND' and response['runId'] == run
            assert response['samlSummary']['inResponseTo'] == exchange['request_id']
            assert response['samlSummary']['metadataProbeAccepted'] is True
    for ref in case['evidence']:
        assert ref['kind'] == 'transcript'
        assert entries[ref['reference'].removeprefix('transcript:')]['runId'] == run
    mismatches = selection_mismatches(path, cases)
    assert {m['variant'] for m in mismatches} == {'default-acs-second', 'default-acs-first-omitted'}
    for mismatch in mismatches:
        imported = json.loads((folder/mismatch['variant']/'import.json').read_text())
        assert imported['import']['read_back']['saml_attributes']['saml_assertion_consumer_url_post'] == mismatch['observed_url']
    implementation=folder/'product-implementation'
    source=json.loads((implementation/'source.json').read_text())
    jar=implementation/source['jar']
    assert hashlib.sha256(jar.read_bytes()).hexdigest()==source['jar_sha256']
    with zipfile.ZipFile(jar) as archive:
        assert hashlib.sha256(archive.read(source['class'])).hexdigest()==source['class_sha256']
    bytecode=(implementation/source['bytecode']).read_text()
    method=bytecode.split('public static java.lang.String getServiceURL(',1)[1].split('private static java.lang.String getArtifactResolutionService(',1)[0]
    assert 'IndexedEndpointType.getBinding:' in method and 'IndexedEndpointType.getLocation:' in method
    assert 'isIsDefault' not in method and 'getIndex:' not in method
    return dict(run=run, result_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                native_import_mismatches=mismatches, product_verdict_supported=True,
                scope='Keycloak 26.7.2 native console metadata import',
                control_basis='Successful baseline; original fixture imported; changed endpoint query and signing key consumed; no request ACS selection attributes',
                implementation=source)

def verify(root):
    audit(root)
    path=Path(root)/'keycloak-default-acs/result.json'
    result=json.loads(path.read_text())
    cases={c['id']:c for req in result['requirements'] for c in req['cases']}
    return path,cases

if __name__ == '__main__':
    import sys
    report=audit(sys.argv[1])
    (Path(sys.argv[1])/'keycloak-default-acs/audit.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
