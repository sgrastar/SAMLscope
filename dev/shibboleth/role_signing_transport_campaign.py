#!/usr/bin/env python3
"""Bracket a native refresh/signature campaign with complete HTTP-only source/listener read-backs."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

spec = importlib.util.spec_from_file_location('shib_http_scope_native', Path(__file__).with_name('import_metadata_batch.py'))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
docker = native.docker
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NOW = lambda: datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
XSI = '{http://www.w3.org/2001/XMLSchema-instance}'
NS = '{urn:mace:shibboleth:2.0:metadata}'


def snapshot(folder, phase):
    started = NOW()
    providers = docker('cat', native.CONFIG)
    server = docker('cat', '/usr/local/tomcat/conf/server.xml')
    record = dict(providersPath=native.CONFIG, providersFile='http-' + phase + '-providers.xml',
                  providersSha256=SHA(providers), serverPath='/usr/local/tomcat/conf/server.xml',
                  serverFile='http-' + phase + '-server.xml', serverSha256=SHA(server), files=[])
    (folder / record['providersFile']).write_bytes(providers)
    (folder / record['serverFile']).write_bytes(server)
    for index, provider in enumerate(ET.fromstring(providers)):
        if provider.tag != NS + 'MetadataProvider' or provider.get(XSI + 'type') != 'FilesystemMetadataProvider':
            raise ValueError('HTTP-unused proof requires complete native filesystem source inventory')
        path = provider.get('metadataFile', '').replace('%{idp.home}', '/opt/reference-idp')
        if not path.startswith('/opt/reference-idp/metadata/') or '..' in path:
            raise ValueError('Unsafe native source path')
        raw = docker('cat', path)
        file = 'http-' + phase + '-source-' + str(index) + '.xml'
        (folder / file).write_bytes(raw)
        record['files'].append(dict(nativePath=path, file=file, sha256=SHA(raw)))
    record['recordedAt'] = started if phase == 'before' else NOW()
    (folder / ('http-' + phase + '-snapshot.json')).write_text(json.dumps(record, indent=2) + '\n')
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    before = snapshot(out, 'before')
    child = out / 'refresh'
    process = subprocess.run([sys.executable, str(Path(__file__).with_name('metadata_refresh_campaign.py')),
        '--output', str(child)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    (out / 'campaign.log').write_bytes(process.stdout)
    after = snapshot(out, 'after')
    if process.returncode != 0:
        raise RuntimeError('Native refresh failed; scope and restored configuration retained')
    if before['serverSha256'] != after['serverSha256'] or before['providersSha256'] != after['providersSha256']:
        raise RuntimeError('Native listener/source configuration changed')
    first = {row['nativePath']: row['sha256'] for row in before['files']}
    second = {row['nativePath']: row['sha256'] for row in after['files']}
    if first != second:
        raise RuntimeError('Native metadata source originals changed')
    run = json.loads((child / 'created.json').read_text())['run']['id']
    target = (child / 'target-metadata.xml').read_bytes()
    entity = ET.fromstring(target).get('entityID')
    scope = dict(schema='samlscope-shibboleth-role-signing-transport-v1', runId=run,
                 targetEntityId=entity, targetMetadataSha256=SHA(target), before=before, after=after)
    (out / 'http-scope.json').write_text(json.dumps(scope, indent=2) + '\n')
    installer_spec = importlib.util.spec_from_file_location('shib_http_scope_receipt', Path(__file__).with_name('install_metadata_refresh_receipt.py'))
    installer = importlib.util.module_from_spec(installer_spec)
    installer_spec.loader.exec_module(installer)
    if installer.install(child) != run:
        raise RuntimeError('Refresh receipt Run mismatch')
    destination = '/data/metadata-rejection-evidence/' + run + '.refresh'
    installed = []
    for source in sorted(out.glob('http-*.xml')) + [out / 'http-scope.json']:
        subprocess.run(['docker', 'cp', str(source), 'samlscope-reference-suite:' + destination + '/' + source.name],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        raw = subprocess.check_output(['docker', 'exec', 'samlscope-reference-suite', 'cat', destination + '/' + source.name])
        if raw != source.read_bytes():
            raise RuntimeError('Native transport original placement read-back differs')
        installed.append(dict(file=source.name, sha256=SHA(raw)))
    (out / 'http-scope-receipt-install.json').write_text(json.dumps(dict(runId=run, destination=destination,
        files=installed, recordedAt=NOW(), native_scope_file_reads=4+len(before['files'])+len(after['files']),
        native_scope_configuration_writes=0, human_operations=0), indent=2) + '\n')
    print(run, 'native XML signature and HTTP-only scope originals installed', flush=True)


if __name__ == '__main__':
    main()
