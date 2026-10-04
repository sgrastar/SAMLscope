#!/usr/bin/env python3
"""Export product-origin DTD parser refusal bound to a restored browser-chain Run."""

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
from pathlib import Path


CASE = 'IIP-G03-b-idp-01'
VARIANTS = ('dtd-authn-request', 'dtd-external-entity-authn-request')
ERROR = re.compile(r'^([0-9-]{10} [0-9:,]{12}) ERROR \[org\.keycloak\.saml\.common\].*ParsingException.*DOCTYPE is disallowed.*$')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(folder, name):
    return json.loads((folder / name).read_text())


def export(folder: Path):
    folder = folder.resolve()
    result = read(folder, 'result.json')
    run = result['run']['id']
    assert read(folder, 'created.json')['run']['id'] == run
    restoration = read(folder, 'restoration.json')
    assert restoration['restored'] and restoration['cleanup']['read_back_absent']
    assert read(folder, 'import.json')['status'] == 'success'
    transcript = read(folder, 'transcript.json')
    outbound = {e['samlSummary']['fixture_id']: e for e in transcript
                if e['direction'] == 'OUTBOUND'
                and (e.get('samlSummary') or {}).get('scenario_case_id') == CASE}
    assert set(outbound) == {'baseline-success', *VARIANTS}
    baseline_id = '_' + outbound['baseline-success']['samlSummary']['action_id']
    responses = [e for e in transcript if e['direction'] == 'INBOUND'
                 and e.get('correlationId') == baseline_id]
    assert len(responses) == 1 and responses[0]['samlSummary']['statusCode'].endswith(':Success')
    manifest = {e['id']: e for e in read(folder, 'decoded-manifest.json')}
    assert all(e['id'] in manifest for e in outbound.values())

    first = min(e['timestamp'] for e in outbound.values())
    last = max(e['timestamp'] for e in outbound.values())
    since = dt.datetime.fromtimestamp(first - 10, dt.timezone.utc).isoformat()
    until = dt.datetime.fromtimestamp(last + 10, dt.timezone.utc).isoformat()
    logs = subprocess.run(['docker', 'logs', '--since', since, '--until', until,
                           'samlscope-reference-keycloak'], capture_output=True, text=True, check=True)
    matched = []
    for line in (logs.stdout + logs.stderr).splitlines():
        m = ERROR.fullmatch(line)
        if m:
            moment = dt.datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S,%f').replace(tzinfo=dt.timezone.utc)
            matched.append((moment.timestamp(), line))

    rejections = []
    used = set()
    for variant in VARIANTS:
        request = outbound[variant]
        candidates = [(i, text) for i, (time, text) in enumerate(matched)
                      if request['timestamp'] <= time <= request['timestamp'] + 5]
        assert len(candidates) == 1, (variant, candidates)
        index, line = candidates[0]
        assert index not in used
        used.add(index)
        original = manifest[request['id']]
        raw = (folder / original['file']).read_bytes()
        assert sha(raw) == original['sha256']
        assert request['decodedSamlBytes'] == len(raw)
        assert not any(e['direction'] == 'INBOUND'
                       and e.get('correlationId') == '_' + request['samlSummary']['action_id']
                       for e in transcript)
        rejections.append(dict(variant=variant, requestReference=request['id'],
                               requestSha256=sha(raw), productLog=line, logSha256=sha(line.encode())))

    receipt = dict(schema='samlscope-native-dtd-rejection-v1', runId=run,
                   adapter='keycloak-native-parser', restored=True,
                   targetMetadataSha256=sha((folder / 'target-metadata.xml').read_bytes()),
                   baselineRequest=outbound['baseline-success']['id'],
                   baselineResponse=responses[0]['id'], rejections=rejections)
    path = folder / 'native-dtd-rejection.json'
    path.write_text(json.dumps(receipt, indent=2) + '\n')
    return path


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('folder', type=Path)
    args = p.parse_args()
    print(export(args.folder))
