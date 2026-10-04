#!/usr/bin/env python3
"""Install a restored SimpleSAMLphp MDQ campaign as Run-scoped originals."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

FILES = ('original-config.php', 'configured-config.php', 'final-config.php',
         'proxy-router.php', 'proxy-requests.jsonl', 'mdq-product-observation.log',
         'mdq-response.xml', 'mdq-request.json')
SHA = lambda raw: hashlib.sha256(raw).hexdigest()


def install(folder):
    folder = Path(folder).resolve()
    created = json.loads((folder / 'created.json').read_text())
    run = created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run):
        raise ValueError('Invalid Run')
    restoration = json.loads((folder / 'restoration.json').read_text())
    originals = {name: (folder / name).read_bytes() for name in FILES}
    if not restoration['restored'] or originals['original-config.php'] != originals['final-config.php']:
        raise ValueError('Product configuration was not restored')
    if SHA(originals['original-config.php']) != restoration['original_sha256']:
        raise ValueError('Restoration hash mismatch')
    transcript = json.loads((folder / 'transcript.json').read_text())
    if any(entry['runId'] != run for entry in transcript):
        raise ValueError('Mixed Run transcript')
    ids = {entry['id']: entry for entry in transcript}
    correlation = json.loads((folder / 'sso-correlation.json').read_text())
    request = ids[correlation['requestTranscriptId']]
    response = ids[correlation['responseTranscriptId']]
    if request['samlSummary'].get('type') != 'AuthnRequest' \
            or response['samlSummary'].get('inResponseTo') != request['samlSummary'].get('id') \
            or response['samlSummary'].get('statusCode') != 'urn:oasis:names:tc:SAML:2.0:status:Success':
        raise ValueError('SSO response does not correlate')
    mdq = json.loads(originals['mdq-request.json'])
    entity = mdq['entity_id']
    if SHA(originals['mdq-response.xml']) != mdq['response_sha256']:
        raise ValueError('MDQ response hash mismatch')
    fetches = [json.loads(line) for line in originals['proxy-requests.jsonl'].decode().splitlines() if line]
    if not any(item['entityId'] == entity and item['responseSha256'] == mdq['response_sha256']
               for item in fetches):
        raise ValueError('Product MDQ fetch is not bound to response original')
    manifest = dict(schema='samlscope-native-mdq-acquisition-v1', runId=run,
                    adapter='simplesamlphp-native-mdq-v1', entityId=entity,
                    originalSha256=SHA(originals['original-config.php']),
                    configuredSha256=SHA(originals['configured-config.php']),
                    finalSha256=SHA(originals['final-config.php']),
                    proxyRouterSha256=SHA(originals['proxy-router.php']),
                    proxyRequestsSha256=SHA(originals['proxy-requests.jsonl']),
                    productLogSha256=SHA(originals['mdq-product-observation.log']),
                    mdqResponseSha256=SHA(originals['mdq-response.xml']),
                    mdqRequestSha256=SHA(originals['mdq-request.json']),
                    requestTranscriptId=request['id'], responseTranscriptId=response['id'])
    manifest_file = folder / 'mdq-receipt-manifest.json'
    manifest_file.write_text(json.dumps(manifest, indent=2) + '\n')
    target = '/data/metadata-rejection-evidence/' + run + '.mdq'
    subprocess.run(['docker', 'exec', 'samlscope-reference-suite', 'mkdir', '-p', target], check=True)
    for name in FILES:
        subprocess.run(['docker', 'cp', str(folder / name), 'samlscope-reference-suite:' + target + '/' + name], check=True)
    subprocess.run(['docker', 'cp', str(manifest_file), 'samlscope-reference-suite:' + target + '/manifest.json'], check=True)
    names = [*FILES, 'manifest.json']
    check = subprocess.check_output(['docker', 'exec', 'samlscope-reference-suite', 'sha256sum',
                                     *[target + '/' + name for name in names]], text=True)
    actual = [line.split()[0] for line in check.splitlines()]
    expected = [*[SHA(originals[name]) for name in FILES], SHA(manifest_file.read_bytes())]
    if actual != expected:
        raise ValueError('Suite read-back mismatch')
    (folder / 'mdq-receipt-install.json').write_text(json.dumps(dict(runId=run, target=target,
        readBackSha256=actual, productConfigurationWrites=2, restorationWrites=1,
        productRestarts=0, humanOperations=0), indent=2) + '\n')
    return run


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder')
    print(install(parser.parse_args().folder))
