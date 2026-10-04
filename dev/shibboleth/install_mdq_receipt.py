#!/usr/bin/env python3
"""Install one restored native-MDQ campaign for Run-side evidence evaluation."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path


FILES = ('original-providers.xml', 'configured-providers.xml',
         'final-providers.xml', 'mdq-product-observation.log',
         'mdq-response.xml', 'mdq-request.json')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def one(entries, kind, feed=None):
    found = [entry for entry in entries if entry['samlSummary'].get('type') == kind
             and (feed is None or entry['samlSummary'].get('feed') == feed)]
    if len(found) != 1:
        raise ValueError(f'Expected one {kind}/{feed}; got {len(found)}')
    return found[0]


def install(folder):
    folder = Path(folder).resolve()
    created = json.loads((folder / 'created.json').read_text())
    run = created['run']['id']
    if not run.startswith('run_') or len(run) != 30:
        raise ValueError('Invalid Run identifier')
    if json.loads((folder / 'result.json').read_text())['run']['id'] != run:
        raise ValueError('Result belongs to another Run')
    restoration = json.loads((folder / 'restoration.json').read_text())
    originals = {name: (folder / name).read_bytes() for name in FILES}
    if not restoration['restored'] or originals['original-providers.xml'] != originals['final-providers.xml']:
        raise ValueError('Product configuration was not restored')
    if sha(originals['original-providers.xml']) != restoration['original_sha256']:
        raise ValueError('Restoration record is inconsistent')
    transcript = json.loads((folder / 'transcript.json').read_text())
    if any(entry['runId'] != run for entry in transcript):
        raise ValueError('Mixed Run transcript')
    request, response = one(transcript, 'AuthnRequest'), one(transcript, 'Response')
    mdq = json.loads(originals['mdq-request.json'])
    entity = mdq['entity_id']
    if mdq['response_sha256'] != sha(originals['mdq-response.xml']):
        raise ValueError('Suite MDQ response hash mismatch')
    if response['samlSummary'].get('normalFlowAccepted') is not True \
            or response['samlSummary'].get('inResponseTo') != request['samlSummary']['id']:
        raise ValueError('SSO success does not correlate with request')
    if 'Dynamic' + run not in originals['mdq-product-observation.log'].decode():
        raise ValueError('Product load event missing')
    manifest = dict(schema='samlscope-native-mdq-acquisition-v1', runId=run,
                    adapter='shibboleth-dynamic-http-mdq-v1', entityId=entity,
                    originalSha256=sha(originals['original-providers.xml']),
                    configuredSha256=sha(originals['configured-providers.xml']),
                    finalSha256=sha(originals['final-providers.xml']),
                    productLogSha256=sha(originals['mdq-product-observation.log']),
                    mdqResponseSha256=sha(originals['mdq-response.xml']),
                    mdqRequestSha256=sha(originals['mdq-request.json']),
                    requestTranscriptId=request['id'], responseTranscriptId=response['id'])
    target = '/data/metadata-rejection-evidence/' + run + '.mdq'
    subprocess.run(['docker', 'exec', 'samlscope-reference-suite', 'mkdir', '-p', target], check=True)
    for name in FILES:
        subprocess.run(['docker', 'cp', str(folder / name), 'samlscope-reference-suite:' + target + '/' + name], check=True)
    manifest_file = folder / 'mdq-receipt-manifest.json'
    manifest_file.write_text(json.dumps(manifest, indent=2) + '\n')
    subprocess.run(['docker', 'cp', str(manifest_file), 'samlscope-reference-suite:' + target + '/manifest.json'], check=True)
    checked = subprocess.check_output(['docker', 'exec', 'samlscope-reference-suite', 'sha256sum',
                                       *[target + '/' + name for name in FILES], target + '/manifest.json'], text=True)
    values = [line.split()[0] for line in checked.splitlines()]
    if values != [*[sha(originals[name]) for name in FILES], sha(manifest_file.read_bytes())]:
        raise ValueError('Suite read-back differs from campaign originals')
    (folder / 'mdq-receipt-install.json').write_text(json.dumps(dict(
        runId=run, target=target, readBackSha256=values, configurationWrites=2,
        configurationReloads=2, restorationWrites=1, humanOperations=0), indent=2) + '\n')
    return run


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder')
    print(install(parser.parse_args().folder))
