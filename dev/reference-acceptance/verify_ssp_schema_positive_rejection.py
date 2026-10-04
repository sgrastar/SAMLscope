"""Adopt the native rejection of a schema-valid MD05.b positive fixture."""
import hashlib
import json
from pathlib import Path
import subprocess

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
SCHEMAS = {
    'saml-schema-assertion-2.0.xsd': '08e0ca7c3eb68c2e8b8d36f038e8c1f4b9e88d6a3b8633e48475dd56762d1717',
    'saml-schema-metadata-2.0.xsd': '85a51fab6bc4dbf707edcf5e0bceb002b6e58c71be11bac97d07a4e59a0a5173',
    'xenc-schema.xsd': '43624bca041542df8ce4f4ac143c4828c9ab503bf116522f1812a33f964deda4',
    'xml.xsd': '61960fb3131e38022caad5360e2f33a3382578ab3c80cd58bd74320ede61b20c',
    'xmldsig-core-schema.xsd': '35cf8197da812c85e40d57891b35c94187569ed474a2dac813ce5090dafcd35c',
}
CASE = 'IIP-MD05-b-idp-01'


def verify(root):
    folder = Path(root) / 'ssp-native-mdq-schema-valid-v1'
    evaluation = folder / 'evaluation-native-positive'
    read = lambda name: json.loads((folder / name).read_text())
    eval_read = lambda name: json.loads((evaluation / name).read_text())
    for name, digest in SCHEMAS.items():
        assert SHA((folder / 'schema' / name).read_bytes()) == digest
    fixture = folder / 'schema-global-element-families/proxy-response.xml'
    subprocess.run(['xmllint', '--nonet', '--noout', '--schema',
                    str(folder / 'schema/saml-schema-metadata-2.0.xsd'), str(fixture)],
                   check=True, capture_output=True, timeout=30)
    receipt_raw = (folder / 'qualified-metadata-rejection-receipt.json').read_bytes()
    receipt = json.loads(receipt_raw)
    assert receipt == read('native-positive-rejection-receipt.json')
    assert receipt['evidenceAdapter'] == 'simplesamlphp-native-mdq-positive'
    assert receipt['runId'] == read('created.json')['run']['id']
    assert receipt['restored'] and not receipt['conditionIssues']
    assert len(receipt['rejections']) == 1
    rejection = receipt['rejections'][0]
    assert rejection['variant'] == 'schema-global-element-families'
    assert rejection['fixtureSha256'] == SHA(fixture.read_bytes())
    native = rejection['nativeRejection']
    log = (folder / 'schema-global-element-families/native-rejection.log').read_text().rstrip('\n')
    assert native['logRecord'] == log and native['detailSha256'] == SHA(log.encode())
    assert '[critical] Uncaught Exception: Must have at least one AuthzService in PDPDescriptor.' in log
    assert (folder / 'original-config.php').read_bytes() == (folder / 'final-config.php').read_bytes()
    restoration = read('restoration.json')
    assert restoration['restored'] and restoration['original_sha256'] == restoration['final_sha256']
    sources = json.loads((folder / 'effective-source.json').read_text())
    assert any(row.get('type') == 'mdq' and row.get('server') == 'http://127.0.0.1:8081'
               for row in sources)
    operations = read('operation-counts.json')
    assert operations['restored'] and operations['human_operations'] == 0 and operations['product_restarts'] == 0
    proof = read('replay-v2.json')
    assert proof['run'] == receipt['runId'] and proof['adapter'] == receipt['evidenceAdapter']
    assert proof['receipt_sha256'] == SHA(receipt_raw)
    assert proof['proven_variants'] == {'schema-global-element-families': receipt['evidenceAdapter']}
    assert len(proof['negative_controls']) >= 22 and set(proof['negative_controls'].values()) == {'NOT_VERIFIED'}
    installation = eval_read('receipt-installation.json')
    assert installation['run'] == receipt['runId'] and installation['read_back']
    assert installation['sha256'] == SHA(receipt_raw)
    before = {entry['id']: entry for entry in eval_read('transcript-before.json')}
    after = {entry['id']: entry for entry in eval_read('transcript.json')}
    assert before == after == {entry['id']: entry for entry in read('transcript.json')}
    assert receipt['targetMetadataSha256'] == SHA((folder / 'target-metadata.xml').read_bytes())
    manifest = read('decoded-manifest.json')
    assert len({row['id'] for row in manifest}) == len(manifest)
    for row in manifest:
        path = (folder / row['file']).resolve()
        assert path.parent == (folder / 'decoded').resolve() and SHA(path.read_bytes()) == row['sha256']
    result = eval_read('result.json')
    replayed = json.loads((folder / 'evaluation-native-positive-v125/result.json').read_text())
    assert {entry['id']: entry for entry in json.loads(
        (folder / 'evaluation-native-positive-v125/transcript.json').read_text())} == after
    assert result['run']['id'] == receipt['runId']
    assert result['target']['metadata_digest'] == 'sha256:' + receipt['targetMetadataSha256']
    assert {row['caseId']: row['outcome'] for row in eval_read('evaluation.json')['completed']}[CASE] == 'VIOLATED'
    cases = {row['id']: row for requirement in result['requirements'] for row in requirement['cases']}
    case = cases[CASE]
    assert (case['outcome'], case['verdict'], case['reason_code']) == \
           ('VIOLATED', 'FAIL', 'metadata.fixture-probe.violated')
    assert case['attested'] is False
    replayed_case = next(row for requirement in replayed['requirements'] for row in requirement['cases']
                         if row['id'] == CASE)
    assert (replayed_case['outcome'], replayed_case['verdict'], replayed_case['reason_code']) == \
           (case['outcome'], case['verdict'], case['reason_code'])
    return folder / 'evaluation-native-positive-v125/result.json', {CASE: replayed_case}
