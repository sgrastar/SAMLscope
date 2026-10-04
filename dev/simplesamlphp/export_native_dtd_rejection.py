#!/usr/bin/env python3
"""Export SimpleSAMLphp's parser-origin DTD refusals for one restored Run."""

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
from pathlib import Path


CASE = 'IIP-G03-b-idp-01'
VARIANTS = ('dtd-authn-request', 'dtd-external-entity-authn-request')
ERROR = re.compile(r'^\[([A-Za-z]{3} [A-Za-z]{3} [ 0-9]{2} [0-9:.]{15} [0-9]{4})\] '
                   r'\[php:notice\].*\[critical\] Uncaught Exception: '
                   r'Dangerous XML detected, DOCTYPE nodes are not allowed in the XML body$')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(folder, name):
    return json.loads((folder / name).read_text())


def export(folder):
    folder = folder.resolve()
    run = read(folder, 'result.json')['run']['id']
    assert read(folder, 'created.json')['run']['id'] == run
    restored = read(folder, 'restoration.json')
    assert restored['restored'] and not restored['failures']
    assert restored['original_sha256'] == restored['final_sha256']
    transcript = read(folder, 'transcript.json')
    outbound = {e['samlSummary']['fixture_id']: e for e in transcript
                if e['direction'] == 'OUTBOUND'
                and (e.get('samlSummary') or {}).get('scenario_case_id') == CASE}
    assert set(outbound) == {'baseline-success', *VARIANTS}
    baseline = outbound['baseline-success']
    baseline_id = '_' + baseline['samlSummary']['action_id']
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
                           'samlscope-reference-ssp'], capture_output=True, text=True, check=True)
    matched = []
    for line in (logs.stdout + logs.stderr).splitlines():
        match = ERROR.fullmatch(line)
        if match:
            when = dt.datetime.strptime(match.group(1), '%a %b %d %H:%M:%S.%f %Y')
            matched.append((when.replace(tzinfo=dt.timezone.utc).timestamp(), line))
    rejections = []
    used = set()
    for variant in VARIANTS:
        request = outbound[variant]
        later_requests = [outbound[other]['timestamp'] for other in VARIANTS
                          if outbound[other]['timestamp'] > request['timestamp']]
        end = min(request['timestamp'] + 5,
                  min(later_requests) if later_requests else float('inf'))
        candidates = [(i, line) for i, (when, line) in enumerate(matched)
                      if request['timestamp'] <= when < end]
        assert len(candidates) == 1, (variant, candidates)
        index, line = candidates[0]
        assert index not in used
        used.add(index)
        original = manifest[request['id']]
        data = (folder / original['file']).read_bytes()
        assert sha(data) == original['sha256'] and request['decodedSamlBytes'] == len(data)
        assert not any(e['direction'] == 'INBOUND'
                       and e.get('correlationId') == '_' + request['samlSummary']['action_id']
                       for e in transcript)
        rejections.append(dict(variant=variant, requestReference=request['id'],
                               requestSha256=sha(data), productLog=line,
                               logSha256=sha(line.encode())))
    receipt = dict(schema='samlscope-native-dtd-rejection-v1', runId=run,
                   adapter='simplesamlphp-native-parser', restored=True,
                   targetMetadataSha256=sha((folder / 'target-metadata.xml').read_bytes()),
                   baselineRequest=baseline['id'], baselineResponse=responses[0]['id'],
                   rejections=rejections)
    path = folder / 'native-dtd-rejection.json'
    path.write_text(json.dumps(receipt, indent=2) + '\n')
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    args = parser.parse_args()
    print(export(args.folder))
