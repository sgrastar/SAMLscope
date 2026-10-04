"""Adopt only the two expiry obligations proved through SimpleSAMLphp's native MDQ source."""
import hashlib
import json
from pathlib import Path

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
CASES = {'IIP-MD04-b-idp-01', 'IIP-MD05-as-idp-01'}


def verify(root, case):
    assert case in CASES
    folder = Path(root) / 'ssp-native-mdq-fixtures-v1'
    evaluation = folder / 'evaluation-native-rejection'
    read = lambda name: json.loads((folder / name).read_text())
    eval_read = lambda name: json.loads((evaluation / name).read_text())
    receipt_raw = (folder / 'qualified-metadata-rejection-receipt.json').read_bytes()
    receipt = json.loads(receipt_raw)
    assert receipt == read('native-rejection-receipt.json')
    assert receipt['evidenceAdapter'] == 'simplesamlphp-native-mdq'
    assert receipt['runId'] == read('created.json')['run']['id']
    assert receipt['restored'] and not receipt['conditionIssues']
    assert len(receipt['rejections']) == 1 and receipt['rejections'][0]['variant'] == 'expired'
    native = receipt['rejections'][0]['nativeRejection']
    log = (folder / 'expired/native-rejection.log').read_text().rstrip('\n')
    assert native['logRecord'] == log and native['detailSha256'] == SHA(log.encode())
    assert '[critical] Uncaught Exception: Metadata for the entity [' in log
    assert '] expired ' in log
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
    assert proof['proven_variants'] == {'expired': 'simplesamlphp-native-mdq'}
    assert len(proof['negative_controls']) >= 20 and set(proof['negative_controls'].values()) == {'NOT_VERIFIED'}
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
    assert result['run']['id'] == receipt['runId']
    assert result['target']['metadata_digest'] == 'sha256:' + receipt['targetMetadataSha256']
    completed = {row['caseId']: row['outcome'] for row in eval_read('evaluation.json')['completed']}
    assert all(completed.get(name) == 'SATISFIED' for name in CASES)
    cases = {row['id']: row for requirement in result['requirements'] for row in requirement['cases']}
    assert all((cases[name]['outcome'], cases[name]['verdict'], cases[name]['reason_code']) ==
               ('SATISFIED', 'PASS', 'metadata.fixture-probe.satisfied') for name in CASES)
    assert all(cases[name]['attested'] is False for name in CASES)
    return evaluation / 'result.json', {case: cases[case]}
