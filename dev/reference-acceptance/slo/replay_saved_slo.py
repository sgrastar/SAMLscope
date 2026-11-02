#!/usr/bin/env python3
"""Replay diagnostic Java reads; export only derived public references and outcome gaps."""
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / 'build/acceptance/reference-20261031/slo'
JAVA = '/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home/bin/java'
SHA = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    pins = json.loads((OUT / 'java-dependency-pins.json').read_text())
    if not all(SHA(Path(p)) == h for p, h in pins.items()):
        raise ValueError('Changed local dependency generation')
    cp = os.pathsep.join([str(OUT / 'javac-classes'), *pins.keys()])
    records = []
    files = set()

    def inspect(result, sha, run, case, transcript=None, manifest=None):
        paths = [result] + ([transcript, manifest] if transcript else [])
        files.update(paths)
        command = [JAVA, '-cp', cp, 'com.samlscope.runner.cases.ReadSloStoredEvidence',
                   'offline', str(result), sha, run, case]
        if transcript:
            command.extend([str(transcript), str(manifest)])
            for item in json.loads(manifest.read_text()):
                file = (manifest.parent / item['file']).resolve()
                if not file.is_relative_to(manifest.parent.resolve()):
                    raise ValueError('Foreign decoded original')
                files.add(file)
        before = {str(p.relative_to(ROOT)): SHA(p) for p in files}
        p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=True)
        after = {str(p.relative_to(ROOT)): SHA(p) for p in files}
        if before != after:
            raise ValueError('Read mutated a public original')
        records.append({'sourceResult': str(result.relative_to(ROOT)), 'sourceTranscript':
                        str(transcript.relative_to(ROOT)) if transcript else None,
                        'inspection': json.loads(p.stdout), 'readOriginalsUnchanged': True})

    for row in json.loads((OUT / 'ledger-observations.json').read_text()):
        inv = row['inventory']
        inspect(ROOT / row['resultPath'], inv['result_sha256'], inv['run'], inv['case'])
    for folder in ('reference-20260930/keycloak-target-logout-absence-v158-r7',
                   'reference-20260930/shibboleth-slo-correlated-v164-r5',
                   'reference-20260930/ssp-slo-iframe-v131i',
                   'reference-20261001/shibboleth-native-slo-v178-r7/receipt/failure',
                   'reference-20261004/shibboleth-soap-slo-continuation-r5/evaluation-actual'):
        d = ROOT / 'build/acceptance' / folder
        result = d / 'result.json'
        run = json.loads(result.read_text())['run']['id']
        # SOAP originals/manifest are outside its evaluation export, in the SAME Run.
        original = d.parent if folder.endswith('/evaluation-actual') else d
        transcript = original / ('transcript-final.json' if folder.endswith('/evaluation-actual') else 'transcript.json')
        inspect(result, SHA(result), run, 'IIP-IDP18-d-idp-01', transcript, original / 'decoded-manifest.json')
    (OUT / 'reader-replay.json').write_text(json.dumps(records, indent=2) + '\n')
    (OUT / 'replayed-original-pins.json').write_text(json.dumps(
        {str(p.relative_to(ROOT)): SHA(p) for p in sorted(files)}, indent=2) + '\n')
    print(f'{len(records)} diagnostic reads; original bytes unchanged; no adoptions')


if __name__ == '__main__':
    main()
