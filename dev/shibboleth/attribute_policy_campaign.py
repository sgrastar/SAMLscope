#!/usr/bin/env python3
"""Record fixed-policy attribute-release comparisons; never assign a product verdict."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET

from attribute_name_capability import docker, XSI
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, save, flow, BASE

FORMAT = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri'
UID = 'urn:oid:0.9.2342.19200300.100.1.1'
SURNAME = 'urn:oid:2.5.4.4'
CONDITIONS = [
    ('baseline', 'control', None),
    ('entity-present', 'attribute-policy-entity-present', None),
    ('entity-absent', 'attribute-policy-entity-absent', None),
    ('requested-required', 'attribute-policy-requested-required', None),
    ('requested-optional', 'attribute-policy-requested-optional', None),
    ('requested-absent', 'attribute-policy-requested-absent', None),
    ('index-zero', 'attribute-policy-indexed', 0),
    ('index-one', 'attribute-policy-indexed', 1),
    ('index-zero-repeat', 'attribute-policy-indexed', 0),
]
SERVICES = {'metadata-providers': 'shibboleth.MetadataResolverService',
            'attribute-resolver': 'shibboleth.AttributeResolverService',
            'attribute-filter': 'shibboleth.AttributeFilterService'}
MARKERS = ['anchor', 'entity', 'required', 'optional', 'surname']


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def policies(originals, entity, run, temporary):
    """Add isolated attributes and a requester-scoped policy; retain existing policies."""
    ET.register_namespace('xsi', XSI)
    md = 'urn:mace:shibboleth:2.0:metadata'
    ET.register_namespace('', md)
    providers = ET.fromstring(originals['metadata-providers'])
    providers.insert(0, ET.Element('{' + md + '}MetadataProvider', {
        'id': 'AttributePolicy' + run, '{' + XSI + '}type': 'FilesystemMetadataProvider',
        'metadataFile': temporary}))
    provider_xml = ET.tostring(providers)
    ns = 'urn:mace:shibboleth:2.0:resolver'
    ET.register_namespace('', ns)
    resolver = ET.fromstring(originals['attribute-resolver'])
    for marker in MARKERS:
        id_ = 'samlscopePolicy_' + marker
        if any(e.get('id') == id_ for e in resolver):
            raise ValueError('Reserved policy attribute already exists')
        definition = ET.SubElement(resolver, '{' + ns + '}AttributeDefinition',
                                   {'id': id_, '{' + XSI + '}type': 'Simple'})
        ET.SubElement(definition, '{' + ns + '}InputAttributeDefinition', {'ref': 'uid'})
        ET.SubElement(definition, '{' + ns + '}AttributeEncoder', {
            '{' + XSI + '}type': 'SAML2String', 'name': 'urn:samlscope:test:policy:' + marker,
            'nameFormat': FORMAT, 'encodeType': 'false'})
    resolver_xml = ET.tostring(resolver)
    ns = 'urn:mace:shibboleth:2.0:afp'
    ET.register_namespace('', ns)
    filters = ET.fromstring(originals['attribute-filter'])
    policy = ET.SubElement(filters, '{' + ns + '}AttributeFilterPolicy', {'id': 'AttributePolicy' + run})
    ET.SubElement(policy, '{' + ns + '}PolicyRequirementRule', {'{' + XSI + '}type': 'Requester', 'value': entity})
    for marker in MARKERS:
        rule = ET.SubElement(policy, '{' + ns + '}AttributeRule', {'attributeID': 'samlscopePolicy_' + marker})
        if marker == 'anchor':
            rule.set('permitAny', 'true')
        elif marker == 'entity':
            ET.SubElement(rule, '{' + ns + '}PermitValueRule', {'{' + XSI + '}type': 'EntityAttributeExactMatch',
                'attributeName': 'urn:samlscope:test:release-policy', 'attributeNameFormat': FORMAT,
                'attributeValue': 'release'})
        else:
            ET.SubElement(rule, '{' + ns + '}PermitValueRule', {'{' + XSI + '}type': 'AttributeInMetadata',
                'attributeName': SURNAME if marker == 'surname' else UID, 'attributeNameFormat': FORMAT,
                'onlyIfRequired': 'false' if marker == 'optional' else 'true', 'matchIfMetadataSilent': 'false'})
    return {'metadata-providers': provider_xml, 'attribute-resolver': resolver_xml,
            'attribute-filter': ET.tostring(filters)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    paths = {n: '/opt/reference-idp/conf/' + n + '.xml' for n in SERVICES}
    originals = {n: docker('cat', p) for n, p in paths.items()}
    expected = dict(originals)
    operations, observations, reloads, changed = [], [], [], []
    temporary_written = False
    plan_result = api('/api/plans', dict(name='Shibboleth fixed attribute release policy',
        profile='browser_sso_idp', targetKind='IDP', targetEntityId='http://localhost:18280/idp/shibboleth',
        metadataSourceKind='URL', metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={},
        parameters=dict(clockSkewToleranceSeconds=180, metadataRefreshWaitSeconds=300,
                        testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', plan_result)
    plan = plan_result['plan']['plan']['id']
    created = api('/api/plans/' + plan + '/runs', {})
    save(out / 'created.json', created)
    run = created['run']['id']
    if not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}', plan) or not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run):
        raise ValueError('Invalid generated identifiers')
    temporary = '/opt/reference-idp/metadata/attribute-policy-' + run + '.xml'
    if docker('sh', '-c', 'if test -e ' + temporary + '; then echo exists; fi').strip():
        raise ValueError('Temporary metadata already exists')
    configured = policies(originals, BASE + '/p/' + plan, run, temporary)
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))

    def write(path, data, label):
        record = dict(operation='write', label=label, attempted=True, read_back=False, sha256=sha(data))
        operations.append(record)
        docker('sh', '-c', 'cat > ' + path, data=data)
        if docker('cat', path) != data:
            raise RuntimeError('Configuration read-back mismatch')
        record['read_back'] = True

    def reload(service, label):
        record = dict(service=service, label=label, attempted=True, completed=False)
        reloads.append(record)
        log = docker('/opt/reference-idp/bin/reload-service.sh', '-id', service, '-u', 'http://localhost:8080/idp')
        (out / (label + '-reload.log')).write_bytes(log)
        record['completed'] = True

    def fixed_readback():
        actual = {n: sha(docker('cat', p)) for n, p in paths.items()}
        if actual != {n: sha(configured[n]) for n in paths}:
            raise RuntimeError('Fixed policy changed during comparisons')
        return actual

    indexed_hash = None
    try:
        for label, variant, selector in CONDITIONS:
            folder = out / label
            folder.mkdir()
            state = api('/api/runs/' + run + '/metadata-lab/automatic-polling',
                        dict(variants=[variant], pollingDelaySeconds=0))
            save(folder / 'campaign.json', state)
            with urllib.request.urlopen(state['automaticStartUrl'], timeout=30) as response:
                if response.status != 202:
                    raise RuntimeError('Fixture was dispatched before native metadata preparation')
                response.read()
            with urllib.request.urlopen(state['metadataUrl'], timeout=30) as response:
                fixture = response.read()
            (folder / 'fixture.xml').write_bytes(fixture)
            digest = sha(fixture)
            if selector is not None and indexed_hash is not None and digest != indexed_hash:
                raise RuntimeError('Indexed metadata changed; comparisons cannot be adopted')
            same_indexed_metadata = selector is not None and indexed_hash is not None
            if not same_indexed_metadata:
                temporary_written = True
                write(temporary, fixture, label + '-metadata')
            elif sha(docker('cat', temporary)) != indexed_hash:
                raise RuntimeError('Imported indexed metadata changed')
            if not changed:
                for name in paths:
                    changed.append(name)
                    expected[name] = configured[name]
                    write(paths[name], configured[name], name)
                    reload(SERVICES[name], name)
                    if name == 'attribute-resolver':
                        reload('shibboleth.AttributeRegistryService', 'attribute-registry')
            elif not same_indexed_metadata:
                reload(SERVICES['metadata-providers'], label + '-metadata')
            if selector is not None:
                indexed_hash = digest
            before = fixed_readback()
            record = dict(label=label, run=run, variant=variant, selector=selector, fixture_sha256=digest,
                          metadata_write_skipped=same_indexed_metadata, configuration_before=before, status='incomplete')
            observations.append(record)
            try:
                flow(run, folder / 'flow.json', attribute_service_index=selector)
                record['status'] = 'protocol-recorded'
                if label == 'baseline':
                    save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
            finally:
                record['configuration_after'] = fixed_readback()
                save(folder / 'observation.json', record)
                save(out / 'observations.json', observations)
    finally:
        failures = []
        for name in reversed(changed):
            try:
                if docker('cat', paths[name]) != expected[name]:
                    raise RuntimeError('Concurrent configuration change; refusing to overwrite')
                write(paths[name], originals[name], 'restore-' + name)
                reload(SERVICES[name], 'restore-' + name)
                if name == 'attribute-resolver':
                    reload('shibboleth.AttributeRegistryService', 'restore-attribute-registry')
            except Exception as error:
                failures.append(name + ':' + type(error).__name__)
        # Do not remove a provider file if its configuration restoration failed.
        if temporary_written and not failures:
            operations.append(dict(operation='delete', label='temporary-metadata', attempted=True))
            docker('rm', '--', temporary)
        final = {n: sha(docker('cat', p)) for n, p in paths.items()}
        removed = not docker('sh', '-c', 'if test -e ' + temporary + '; then echo exists; fi').strip()
        restored = not failures and removed and final == {n: sha(raw) for n, raw in originals.items()}
        save(out / 'restoration.json', dict(restored=restored, temporary_file_removed=removed,
            original_sha256={n: sha(raw) for n, raw in originals.items()}, final_sha256=final, failures=failures))
        save(out / 'operations.json', dict(run=run, operations=operations, reloads=reloads, restored=restored,
                                         driver_sha256=sha(Path(__file__).read_bytes()),
                                         completed_conditions=sum(r['status'] == 'protocol-recorded' for r in observations)))
        for endpoint in ['result.json', 'transcript', 'protocol-evidence']:
            save(out / (endpoint if '.' in endpoint else endpoint + '.json'), api('/api/runs/' + run + '/' + endpoint))
        manifest = []
        for entry in json.loads((out / 'transcript.json').read_text()):
            if not entry.get('decodedSamlRef'):
                continue
            if not re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}', entry['id']):
                raise ValueError('Invalid transcript identifier')
            path = out / 'decoded' / (entry['id'] + '.xml')
            path.parent.mkdir(exist_ok=True)
            subprocess.run(['docker', 'cp', 'samlscope-reference-suite:/data/' + entry['decodedSamlRef'], str(path)],
                           check=True, stdout=subprocess.DEVNULL)
            manifest.append(dict(id=entry['id'], file=str(path.relative_to(out)), sha256=sha(path.read_bytes())))
        save(out / 'decoded-manifest.json', manifest)
        subprocess.run(['docker', 'cp', 'samlscope-reference-suite:/data/target-metadata/' + run + '.xml',
                        str(out / 'target-metadata.xml')], check=True, stdout=subprocess.DEVNULL)
        if not restored:
            raise RuntimeError('Restoration incomplete; evidence adoption blocked')
    print('Recorded', len(observations), 'conditions for', run, '; no verdict assigned')


if __name__ == '__main__':
    main()
