"""Adopt native MDQ acquisition only with restored product configuration and Run evidence."""
import hashlib
import json
from pathlib import Path

CASE = 'IIP-MD01-a-idp-01'


def read(folder, name):
    return json.loads((folder / name).read_text())


def case(result):
    return next(c for requirement in result['requirements'] for c in requirement['cases']
                if c['id'] == CASE)


def verify(root):
    folder = Path(root) / 'shibboleth-dynamic-mdq-v8'
    before = read(folder, 'result.json')
    corrupt = read(folder, 'corrupt-result.json')
    after = read(folder, 'adopted-result.json')
    run = before['run']['id']
    assert run == corrupt['run']['id'] == after['run']['id'] == read(folder, 'created.json')['run']['id']
    assert (case(before)['verdict'], case(corrupt)['verdict']) == ('NOT_VERIFIED', 'NOT_VERIFIED')
    accepted = case(after)
    assert (accepted['outcome'], accepted['verdict'], accepted['reason_code'], accepted['attested']) == (
        'SATISFIED', 'PASS', 'mdq.native-acquisition-observed', False)
    assert read(folder, 'transcript.json') == read(folder, 'adopted-transcript.json')
    restoration = read(folder, 'restoration.json')
    original = (folder / 'original-providers.xml').read_bytes()
    final = (folder / 'final-providers.xml').read_bytes()
    assert restoration['restored'] and original == final
    assert hashlib.sha256(original).hexdigest() == restoration['original_sha256'] == restoration['final_sha256']
    operations = read(folder, 'operation-counts.json')
    assert operations['human_operations'] == 0 and operations['configuration_write_attempts'] == 2
    assert operations['restoration_write_attempts'] == 1 and operations['reloads'] == 2
    installed = read(folder, 'mdq-receipt-install.json')
    assert installed['runId'] == run and len(installed['readBackSha256']) == 7
    manifest = read(folder, 'mdq-receipt-manifest.json')
    assert manifest['runId'] == run and manifest['entityId'] not in original.decode()
    assert 'Dynamic' + run in (folder / 'configured-providers.xml').read_text()
    assert 'Successfully loaded new EntityDescriptor with entityID' in (
        folder / 'mdq-product-observation.log').read_text()
    transcript = read(folder, 'transcript.json')
    entries = {entry['id']: entry for entry in transcript}
    assert len(entries) == len(transcript)
    assert entries[manifest['responseTranscriptId']]['samlSummary']['inResponseTo'] == (
        entries[manifest['requestTranscriptId']]['samlSummary']['id'])
    referenced = {e['reference'] for e in accepted['evidence']}
    assert {f'transcript:{manifest[key]}' for key in (
        'requestTranscriptId', 'responseTranscriptId')} <= referenced
    assert run + '.mdq/manifest.json' in referenced
    adopted_path = folder / 'evaluation/result.json'
    assert adopted_path.read_bytes() == (folder / 'adopted-result.json').read_bytes()
    return adopted_path, {CASE: accepted}


if __name__ == '__main__':
    import sys
    path, cases = verify(sys.argv[1])
    print(path, {name: row['verdict'] for name, row in cases.items()})
