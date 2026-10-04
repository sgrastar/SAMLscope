"""Adopt SimpleSAMLphp's native MDQ result only after source, flow, and restore checks."""
import hashlib
import json
from datetime import datetime
from pathlib import Path

CASE = 'IIP-MD01-a-idp-01'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def read(folder, name):
    return json.loads((folder / name).read_text())


def case(result):
    return next(c for requirement in result['requirements'] for c in requirement['cases']
                if c['id'] == CASE)


def verify(root):
    folder = Path(root) / 'ssp-native-mdq-direct-v1'
    before = read(folder, 'result.json')
    after = read(folder, 'evaluation-result.json')
    run = read(folder, 'created.json')['run']['id']
    assert before['run']['id'] == after['run']['id'] == run
    assert case(before)['verdict'] == 'NOT_VERIFIED'
    accepted = case(after)
    assert (accepted['outcome'], accepted['verdict'], accepted['reason_code'], accepted['attested']) == (
        'SATISFIED', 'PASS', 'mdq.native-acquisition-observed', False)
    assert read(folder, 'transcript.json') == read(folder, 'adopted-transcript.json')
    original = (folder / 'original-config.php').read_bytes()
    final = (folder / 'final-config.php').read_bytes()
    restoration = read(folder, 'restoration.json')
    assert restoration['restored'] and original == final
    assert SHA(original) == restoration['original_sha256'] == restoration['final_sha256']
    operations = read(folder, 'operation-counts.json')
    assert operations['configuration_writes'] == 2 and operations['restoration_writes'] == 1
    assert operations['product_restarts'] == operations['human_operations'] == 0
    installed = read(folder, 'mdq-receipt-install.json')
    assert installed['runId'] == run and len(installed['readBackSha256']) == 9
    manifest = read(folder, 'mdq-receipt-manifest.json')
    assert manifest['runId'] == run and manifest['adapter'] == 'simplesamlphp-native-mdq-v1'
    entity = manifest['entityId']
    assert entity not in original.decode()
    source = read(folder, 'mdq-request.json')
    assert source['entity_id'] == entity
    raw = (folder / 'mdq-response.xml').read_bytes()
    assert SHA(raw) == source['response_sha256'] == manifest['mdqResponseSha256']
    transcript = read(folder, 'transcript.json')
    entries = {entry['id']: entry for entry in transcript}
    assert len(entries) == len(transcript)
    request = entries[manifest['requestTranscriptId']]
    response = entries[manifest['responseTranscriptId']]
    assert request['samlSummary']['type'] == 'AuthnRequest'
    assert response['samlSummary']['inResponseTo'] == request['samlSummary']['id']
    assert response['samlSummary']['statusCode'] == 'urn:oasis:names:tc:SAML:2.0:status:Success'
    fetches = [json.loads(line) for line in (folder / 'proxy-requests.jsonl').read_text().splitlines() if line]
    assert any(fetch['entityId'] == entity and fetch['responseSha256'] == SHA(raw)
               and request['timestamp'] < datetime.fromisoformat(fetch['observedAt'].replace('Z', '+00:00')).timestamp()
               < response['timestamp'] for fetch in fetches)
    assert 'SimpleSAML\\Metadata\\Sources\\MDQ: loading metadata entity [' + entity + ']' in (
        folder / 'mdq-product-observation.log').read_text()
    references = {e['reference'] for e in accepted['evidence']}
    assert {f'transcript:{manifest[key]}' for key in ('requestTranscriptId', 'responseTranscriptId')} <= references
    assert run + '.mdq/manifest.json' in references
    adopted_path = folder / 'evaluation/result.json'
    assert adopted_path.read_bytes() == (folder / 'evaluation-result.json').read_bytes()
    return adopted_path, {CASE: accepted}


if __name__ == '__main__':
    import sys
    path, cases = verify(sys.argv[1])
    print(path, {name: row['verdict'] for name, row in cases.items()})
