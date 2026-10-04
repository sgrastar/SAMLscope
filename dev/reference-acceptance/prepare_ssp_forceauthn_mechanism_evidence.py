#!/usr/bin/env python3
"""Package genuine native-stage originals without assigning an outcome."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

CASE = 'IIP-IDP06-b-idp-01'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
READ = lambda path: json.loads(path.read_bytes())


def prepare(source, directory):
    source, directory = Path(source), Path(directory)
    browser = source / 'browser'
    run = READ(browser / 'created.json')['run']
    folder = directory / (run['id'] + '.simplesamlphp-forceauthn-mechanism')
    if folder.exists():
        raise ValueError('Refusing to replace originals')
    folder.mkdir(parents=True)
    root_files = ['collector.py', 'native-state-command.php', 'profile.json', 'scope-before.json',
                  'native-mechanism-observations.json', 'native-http-observations.json',
                  'mechanism-operation-counts.json']
    root_files += [p.name for p in source.glob('native-*.php') if p.name not in root_files]
    browser_files = ['target-metadata.xml', 'suite-sp-metadata.xml', 'created.json', 'native-configuration.json',
                     'restoration.json', 'restoration-resolution-readback.json', 'original-sp-config.php',
                     'final-sp-config.php', 'configured-sp-config.php', 'fixture.xml', 'operation-counts.json']
    browser_files += ['target-' + kind + '-' + phase + '.json'
                     for kind in ('container-inspect', 'runtime') for phase in ('start', 'end')]
    for names, parent in ((root_files, source), (browser_files, browser)):
        for name in names:
            shutil.copyfile(parent / name, folder / name)
    target = READ(browser / 'plan.json')['plan']['plan']['target']['entityId']
    requester = READ(browser / 'plan.json')['plan']['entityId']
    manifest = dict(schema='samlscope-simplesamlphp-forceauthn-mechanism-v1', runId=run['id'], planId=run['planId'],
                    caseId=CASE, campaignId='native-authentication-mechanism', targetEntityId=target,
                    requesterEntityId=requester, targetMetadataSha256=SHA((browser / 'target-metadata.xml').read_bytes()))
    entries = READ(browser / 'transcript.json')
    observations = READ(source / 'native-mechanism-observations.json')['observations']
    for label, observation in zip(('baseline', 'forced'), observations[1:], strict=True):
        request_id = observation['state']['requestId']
        out = [e for e in entries if e['direction'] == 'OUTBOUND'
               and e['samlSummary'].get('scenario_case_id') == 'IIP-IDP06-a-idp-01'
               and e['samlSummary'].get('request_id') == request_id]
        if not out:
            import xml.etree.ElementTree as ET
            out = [e for e in entries if e['direction'] == 'OUTBOUND'
                   and e['samlSummary'].get('scenario_case_id') == 'IIP-IDP06-a-idp-01'
                   and ET.fromstring((browser / 'decoded' / (e['id'] + '.xml')).read_bytes()).get('ID') == request_id]
        incoming = [e for e in entries if e['direction'] == 'INBOUND'
                    and e['samlSummary'].get('inResponseTo') == request_id]
        if not incoming:
            import xml.etree.ElementTree as ET
            incoming = [e for e in entries if e['direction'] == 'INBOUND' and (browser / 'decoded' / (e['id'] + '.xml')).exists()
                        and ET.fromstring((browser / 'decoded' / (e['id'] + '.xml')).read_bytes()).get('InResponseTo') == request_id]
        if len(out) != 1 or len(incoming) != 1:
            raise ValueError('Unique same-Run request and response required')
        manifest[label] = dict(requestReference=out[0]['id'], responseReference=incoming[0]['id'],
                               requestSha256=SHA((browser / 'decoded' / (out[0]['id'] + '.xml')).read_bytes()),
                               responseSha256=SHA((browser / 'decoded' / (incoming[0]['id'] + '.xml')).read_bytes()))
        for suffix in ('.request.xml', '.request.body', '.html'):
            shutil.copyfile(source / 'native-http-originals' / (request_id + suffix), folder / (label + suffix))
    manifest['files'] = {p.name: SHA(p.read_bytes()) for p in sorted(folder.iterdir())}
    (folder / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return folder


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    print(prepare(args.source, args.directory))
