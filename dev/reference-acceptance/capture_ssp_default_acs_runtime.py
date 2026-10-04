#!/usr/bin/env python3
"""Capture the Runner identity and an immutable re-evaluation for one default-ACS campaign."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request


BASE = 'http://localhost:18080'
CONTAINER = 'samlscope-reference-suite'
JAR = '/opt/samlscope/lib/runner-0.1.0.jar'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def api(path, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    headers = {} if body is None else {'Content-Type': 'application/json'}
    request = urllib.request.Request(BASE + path, data=body, headers=headers)
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    args = parser.parse_args()
    folder = args.folder.resolve()
    run = json.loads((folder / 'created.json').read_text())['run']['id']
    runtime = folder / 'suite-runtime.json'
    evaluation = folder / 'evaluation-v136'
    if runtime.exists() or evaluation.exists():
        raise RuntimeError('Refusing to overwrite captured runtime evidence')

    inspect = subprocess.check_output(['docker', 'inspect', CONTAINER])
    inspect_data = json.loads(inspect)[0]
    jar = folder / 'suite-runner-0.1.0.jar'
    subprocess.run(['docker', 'cp', f'{CONTAINER}:{JAR}', str(jar)], check=True)
    jar_raw = jar.read_bytes()
    runtime.write_text(json.dumps({
        'run': run,
        'container': {
            'name': inspect_data['Name'].removeprefix('/'),
            'id': inspect_data['Id'],
            'image': inspect_data['Image'],
            'started_at': inspect_data['State']['StartedAt'],
        },
        'runner_jar': {
            'path': JAR,
            'sha256': sha(jar_raw),
        },
        'docker_inspect_sha256': sha(inspect),
    }, ensure_ascii=False, indent=2) + '\n')
    (folder / 'suite-container-inspect.json').write_bytes(inspect)

    evaluation.mkdir()
    before = api(f'/api/runs/{run}/transcript')
    evaluation_result = api(f'/api/runs/{run}/protocol-evidence/evaluate', {})
    after = api(f'/api/runs/{run}/transcript')
    if {entry['id']: entry for entry in before} != {entry['id']: entry for entry in after}:
        raise RuntimeError('Formal re-evaluation changed the transcript')
    result = api(f'/api/runs/{run}/result.json')
    for name, value in {
            'transcript-before.json': before,
            'evaluation.json': evaluation_result,
            'transcript.json': after,
            'result.json': result,
    }.items():
        (evaluation / name).write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({'run': run, 'runner_jar_sha256': sha(jar_raw),
                      'transcript_entries': len(after)}, sort_keys=True))


if __name__ == '__main__':
    main()
