#!/usr/bin/env python3
"""Install hashed native originals for the fail-closed two-peer persistent NameID reader."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

SCHEMA = 'samlscope-shibboleth-persistent-pairwise-v1'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
READ = lambda path: json.loads(Path(path).read_text())
KINDS = {'generators': 'nameid-xml', 'properties': 'nameid-properties', 'audit': 'audit-xml',
         'providers': 'metadata-provider-xml', 'resolver': 'attribute-resolver-xml'}
P = '{urn:oasis:names:tc:SAML:2.0:protocol}'
A = '{urn:oasis:names:tc:SAML:2.0:assertion}'
PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent'
SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'


def instant(value):
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc).isoformat().replace('+00:00', 'Z')
    datetime.fromisoformat(value.replace('Z', '+00:00'))
    return value


def prepare(folder):
    folder = Path(folder).resolve()
    restoration = READ(folder / 'restoration.json')
    if restoration.get('restored') is not True:
        raise ValueError('Native restoration has not been verified')
    receipt = folder / 'receipt-v1'
    receipt.mkdir(exist_ok=True)
    manifest = {'schema': SCHEMA, 'peers': [], 'configurationFiles': []}

    def copy(source, name):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name) or Path(source).is_symlink():
            raise ValueError('Unsafe original name or symlink')
        raw = Path(source).read_bytes()
        target = receipt / name
        target.write_bytes(raw)
        if target.read_bytes() != raw:
            raise ValueError('Original copy read-back differs')
        return name, SHA(raw)

    for label in ('primary', 'secondary'):
        peer_folder = folder / label
        run = READ(peer_folder / 'created.json')['run']
        entries = READ(peer_folder / 'transcript.json')
        originals = {row['id']: peer_folder / row['file'] for row in READ(peer_folder / 'decoded-manifest.json')}
        by_id = {entry['id']: entry for entry in entries}
        if len(by_id) != len(entries) or any(entry['runId'] != run['id'] for entry in entries):
            raise ValueError('Cross-Run or duplicate transcript')
        request = [entry for entry in entries if entry.get('samlSummary', {}).get('scenario_case_id') == 'IIP-SSO05-a3-idp-01'
                   and entry['direction'] == 'OUTBOUND']
        if len(request) != 1:
            raise ValueError('Required a3 policy request is missing or ambiguous')
        req = request[0]
        xml = ET.fromstring(originals[req['id']].read_bytes())
        policies = xml.findall(P + 'NameIDPolicy')
        if xml.tag != P + 'AuthnRequest' or len(policies) != 1 or policies[0].get('Format') != PERSISTENT or xml.find(A + 'Subject') is not None:
            raise ValueError('Required request is not a pure persistent NameIDPolicy')
        responses = []
        for entry in entries:
            if entry['direction'] != 'INBOUND' or entry['id'] not in originals:
                continue
            root = ET.fromstring(originals[entry['id']].read_bytes())
            if root.tag != P + 'Response' or root.get('InResponseTo') != xml.get('ID'):
                continue
            status = root.find(P + 'Status/' + P + 'StatusCode')
            if status is not None and status.get('Value') == SUCCESS:
                responses.append(entry)
        if len(responses) != 1:
            raise ValueError('Required a3 response is missing or ambiguous')
        meta_file, meta_sha = copy(peer_folder / 'native-effective-peer-metadata.xml', label + '-native-metadata.xml')
        audit_file, audit_sha = copy(folder / 'native-principal-audit.log', label + '-audit.log')
        read_file, read_sha = copy(peer_folder / 'native-mdquery-operation.json', label + '-native-metadata-read.json')
        copy(peer_folder / 'transcript.json', label + '-transcript.json')
        copy(peer_folder / 'decoded-manifest.json', label + '-decoded-manifest.json')
        target = (peer_folder / 'target-metadata.xml').read_bytes()
        if label == 'primary':
            manifest['runId'] = run['id']
            manifest['targetMetadataSha256'] = SHA(target)
        elif SHA(target) != manifest['targetMetadataSha256']:
            raise ValueError('Peer target metadata differs')
        manifest['peers'].append(dict(runId=run['id'], entityId='http://localhost:18080/p/' + run['planId'],
            nativeMetadataFile=meta_file, nativeMetadataSha256=meta_sha, auditFile=audit_file, auditSha256=audit_sha,
            nativeMetadataReadFile=read_file, nativeMetadataReadSha256=read_sha,
            exchanges=[dict(requestReference=req['id'], responseReference=responses[0]['id'])]))

    for name, kind in KINDS.items():
        suffix = '.properties' if name == 'properties' else '.xml'
        original_source = folder / ('original-' + name + suffix)
        if name == 'properties':
            original_source = folder / 'original-properties.properties'
        configured_source = folder / ('configured-' + name + suffix)
        final_source = folder / ('final-' + name + suffix)
        original = original_source.read_bytes()
        configured = configured_source.read_bytes()
        final = final_source.read_bytes()
        if original != final:
            raise ValueError('Native original/final differs: ' + name)
        row = dict(kind=kind)
        for prefix, source in (('original', original_source), ('configured', configured_source), ('final', final_source)):
            row[prefix + 'File'], row[prefix + 'Sha256'] = copy(source, prefix + '-' + kind + suffix)
        row['readBacks'] = []
        for phase in ('primary-before', 'primary-after', 'secondary-before', 'secondary-after'):
            source = folder / (phase + '-' + name + suffix)
            if name == 'resolver' and phase == 'primary-before':
                source = folder / 'primary-resolver-readback.xml'
                recorded = READ(folder / 'resolver-readback.json')['recordedAt']
            elif name == 'resolver':
                recorded = READ(folder / (phase + '-resolver.json'))['recordedAt']
            else:
                recorded = READ(folder / (phase + '-configuration.json'))['recordedAt']
            if source.read_bytes() != configured:
                raise ValueError('Native settings changed between peers: ' + phase + '/' + name)
            file, digest = copy(source, phase + '-' + kind + suffix)
            row['readBacks'].append(dict(phase=phase, file=file, sha256=digest, recordedAt=instant(recorded)))
        manifest['configurationFiles'].append(row)
    copy(folder / 'operations.json', 'operations.json')
    copy(folder / 'operation-counts.json', 'operation-counts.json')
    copy(folder / 'restoration.json', 'restoration.json')
    (receipt / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return receipt, manifest


def install(folder):
    receipt, manifest = prepare(folder)
    run = manifest['runId']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run):
        raise ValueError('Invalid primary Run')
    destination = '/data/persistent-nameid-evidence/' + run
    subprocess.run(['docker', 'exec', 'samlscope-reference-suite', 'mkdir', '-p', destination], check=True)
    readbacks = []
    for source in sorted(receipt.iterdir()):
        if not source.is_file() or source.is_symlink():
            raise ValueError('Unsafe receipt source')
        subprocess.run(['docker', 'cp', str(source), 'samlscope-reference-suite:' + destination + '/' + source.name],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        actual = subprocess.check_output(['docker', 'exec', 'samlscope-reference-suite', 'cat', destination + '/' + source.name])
        if actual != source.read_bytes():
            raise ValueError('Installed original read-back differs')
        readbacks.append(dict(file=source.name, sha256=SHA(actual)))
    (Path(folder) / 'receipt-placement-readback.json').write_text(json.dumps(dict(destination=destination,
        recordedAt=instant(datetime.now(timezone.utc).isoformat()), files=readbacks), indent=2) + '\n')
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    parser.add_argument('--prepare-only', action='store_true')
    args = parser.parse_args()
    if args.prepare_only:
        print(prepare(args.folder)[0])
    else:
        print(install(args.folder))
