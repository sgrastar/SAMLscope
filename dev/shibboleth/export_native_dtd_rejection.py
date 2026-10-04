#!/usr/bin/env python3
"""Export Shibboleth IdP's own DTD parser errors for one restored Run."""

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
from pathlib import Path


CASE = 'IIP-G03-b-idp-01'
VARIANTS = ('dtd-authn-request', 'dtd-external-entity-authn-request')
ERROR = re.compile(r'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d,\d{3}) - .* - '
                   r'ERROR \[net\.shibboleth\.shared\.xml\.impl\.BasicParserPool:72\] - XML Parsing Error$')
CAUSE = 'Caused by: org.xml.sax.SAXParseException;'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(folder, name):
    return json.loads((folder / name).read_text())


def export(folder):
    folder = folder.resolve()
    run = read(folder, 'result.json')['run']['id']
    assert read(folder, 'created.json')['run']['id'] == run
    restoration = read(folder, 'restoration.json')
    assert restoration['restored']
    assert restoration['original_sha256'] == restoration['final_sha256']
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

    raw_log = subprocess.run(['docker', 'exec', 'samlscope-reference-shibboleth',
                              'cat', '/opt/reference-idp/logs/idp-process.log'],
                             capture_output=True, text=True, check=True).stdout.splitlines()
    errors = []
    for index, line in enumerate(raw_log):
        match = ERROR.fullmatch(line)
        if not match:
            continue
        cause = next((item for item in raw_log[index + 1:index + 20]
                      if item.startswith(CAUSE) and 'DOCTYPE is disallowed' in item), None)
        if cause:
            when = dt.datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S,%f')
            errors.append((when.replace(tzinfo=dt.timezone.utc).timestamp(), line + '\n' + cause))
    rejections = []
    used = set()
    for variant in VARIANTS:
        request = outbound[variant]
        candidates = [(i, log) for i, (when, log) in enumerate(errors)
                      if request['timestamp'] <= when <= request['timestamp'] + 5]
        assert len(candidates) == 1, (variant, candidates)
        index, log = candidates[0]
        assert index not in used
        used.add(index)
        original = manifest[request['id']]
        data = (folder / original['file']).read_bytes()
        assert sha(data) == original['sha256'] and request['decodedSamlBytes'] == len(data)
        assert not any(e['direction'] == 'INBOUND'
                       and e.get('correlationId') == '_' + request['samlSummary']['action_id']
                       for e in transcript)
        rejections.append(dict(variant=variant, requestReference=request['id'],
                               requestSha256=sha(data), productLog=log,
                               logSha256=sha(log.encode())))
    receipt = dict(schema='samlscope-native-dtd-rejection-v1', runId=run,
                   adapter='shibboleth-native-parser', restored=True,
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
