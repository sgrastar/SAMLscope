#!/usr/bin/env python3
"""Import once, hold native requester policies fixed, collect A/B/A; never assign a verdict."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import urllib.request as http
import urllib.parse as urls
import xml.etree.ElementTree as ET
from attribute_name_capability import docker
from attribute_policy_campaign import SERVICES
from relying_party_attribute_preparation import prepare, verify_readback
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'keycloak'))
from import_metadata_batch import api, save, BASE
from reference_flow import Client

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
VARIANTS = {'first': 'attribute-policy-entity-absent', 'second': 'attribute-policy-requested-absent'}


class AcsSubmitted(Exception):
    def __init__(self, status):
        self.status = status


class StopAtAcs(http.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urls.urlsplit(req.full_url)
        if parsed.netloc == 'localhost:18080' and re.fullmatch(r'/p/plan_[0-9A-HJKMNP-TV-Z]{26}/sp/acs/0', parsed.path):
            # This is transport completion, not proof of SAML acceptance or signature validity.
            raise AcsSubmitted(code)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    out = parser.parse_args().output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    credentials = (os.environ.get('REFERENCE_USERNAME', 'samlscope-m0-user'),
                   os.environ.get('REFERENCE_PASSWORD', 'samlscope-m0-password'))
    login_binding = secrets.token_hex(32)
    plan_result = api('/api/plans', dict(name='Shibboleth relying-party attribute comparison',
        profile='browser_sso_idp', targetKind='IDP', targetEntityId='http://localhost:18280/idp/shibboleth',
        metadataSourceKind='URL', metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={}, parameters=dict(clockSkewToleranceSeconds=180,
        metadataRefreshWaitSeconds=300, testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', plan_result)
    plan = plan_result['plan']['plan']['id']
    created = api('/api/plans/' + plan + '/runs', {})
    save(out / 'created.json', created)
    run = created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}', run) or not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}', plan):
        raise ValueError('Invalid generated identifiers')
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
    campaign = api('/api/runs/' + run + '/metadata-lab/preloaded', {})
    save(out / 'campaign.json', campaign)
    with http.urlopen(campaign['preloadedMetadataUrl'], timeout=60) as response:
        raw = response.read()
    (out / 'fixture.xml').write_bytes(raw)
    entities = {side: BASE + '/p/' + plan + '/metadata-peer/' + variant for side, variant in VARIANTS.items()}
    aggregate = ET.fromstring(raw)
    for entity in entities.values():
        if len([node for node in aggregate if node.get('entityID') == entity]) != 1:
            raise ValueError('Preloaded peer missing or ambiguous')
    temporary = '/opt/reference-idp/metadata/relying-party-' + run + '.xml'
    if docker('sh', '-c', 'test ! -e ' + temporary + ' && echo absent').strip() != b'absent':
        raise ValueError('Temporary metadata already exists')
    paths = {name: '/opt/reference-idp/conf/' + name + '.xml' for name in SERVICES}
    originals = {name: docker('cat', path) for name, path in paths.items()}
    files = {side: temporary for side in entities}
    configured = prepare(originals, run, entities, files)
    operations, observations, changed = [], [], []
    written = False

    def write(path, data, label):
        record = dict(operation='write', label=label, sha256=SHA(data), read_back=False)
        operations.append(record)
        docker('sh', '-c', 'cat > ' + path, data=data)
        if docker('cat', path) != data: raise RuntimeError('Native write read-back mismatch')
        record['read_back'] = True

    def reload(name, label):
        operation = dict(operation='reload', label=label, completed=False)
        operations.append(operation)
        log = docker('/opt/reference-idp/bin/reload-service.sh', '-id', name, '-u', 'http://localhost:8080/idp')
        (out / (label + '-reload.log')).write_bytes(log)
        operation['completed'] = True

    def readback():
        if docker('cat', temporary) != raw: raise RuntimeError('Imported aggregate changed')
        return verify_readback(configured, {name: docker('cat', path) for name, path in paths.items()}, run, entities, files)

    try:
        written = True
        write(temporary, raw, 'metadata')
        for name, path in paths.items():
            changed.append(name)
            write(path, configured[name], name)
            reload(SERVICES[name], name)
            if name == 'attribute-resolver': reload('shibboleth.AttributeRegistryService', 'attribute-registry')
        save(out / 'preparation.json', dict(native=readback(), login_input_binding=login_binding,
            login_provenance='fixed-in-memory-driver-input', authenticated_principal_verified=False))
        start = urls.urlsplit(campaign['preloadedStartUrl'])
        for condition, side in [('first', 'first'), ('second', 'second'), ('first-repeat', 'first')]:
            variant = VARIANTS[side]
            index = campaign['preloadedVariants'].index(variant)
            url = urls.urlunsplit(start._replace(path='/p/' + plan + '/start/metadata-preloaded/' + str(index)))
            before_ids = {entry['id'] for entry in api('/api/runs/' + run + '/transcript')}
            record = dict(condition=condition, entity_id=entities[side], variant=variant, before=readback(),
                login_input_binding=login_binding, status='incomplete')
            observations.append(record)
            client = Client()
            client.op = http.build_opener(http.HTTPCookieProcessor(client.jar), StopAtAcs())
            try:
                record['flow_status'] = client.flow(url, None, *credentials)
            except AcsSubmitted as submitted:
                record['flow_status'] = 'acs-submitted'
                record['http_status'] = submitted.status
            finally:
                record['after'] = readback()
                record['new_transcript_ids'] = [entry['id'] for entry in api('/api/runs/' + run + '/transcript') if entry['id'] not in before_ids]
                record['status'] = 'observed'
                save(out / 'observations.json', observations)
    finally:
        failures = []
        for name in reversed(changed):
            try:
                if docker('cat', paths[name]) != configured[name]: raise RuntimeError('Concurrent native configuration change')
                write(paths[name], originals[name], 'restore-' + name)
                reload(SERVICES[name], 'restore-' + name)
                if name == 'attribute-resolver': reload('shibboleth.AttributeRegistryService', 'restore-attribute-registry')
            except Exception as error: failures.append(name + ':' + type(error).__name__)
        if written and not failures:
            docker('rm', '--', temporary)
            operations.append(dict(operation='delete', label='metadata'))
        final = {name: SHA(docker('cat', path)) for name, path in paths.items()}
        removed = docker('sh', '-c', 'test ! -e ' + temporary + ' && echo absent').strip() == b'absent'
        restored = not failures and removed and final == {name: SHA(raw) for name, raw in originals.items()}
        save(out / 'restoration.json', dict(restored=restored, failures=failures, temporary_removed=removed,
            original_sha256={name: SHA(raw) for name, raw in originals.items()}, final_sha256=final))
        save(out / 'operations.json', dict(run=run, operations=operations, restored=restored, verdict_adopted=False))
        entries = api('/api/runs/' + run + '/transcript')
        save(out / 'transcript.json', entries)
        manifest = []
        for entry in entries:
            reference = entry.get('decodedSamlRef')
            if not reference: continue
            if not re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}', entry['id']) or '..' in Path(reference).parts or Path(reference).is_absolute():
                raise ValueError('Invalid transcript reference')
            path = out / 'decoded' / (entry['id'] + '.xml')
            path.parent.mkdir(exist_ok=True)
            subprocess.run(['docker', 'cp', 'samlscope-reference-suite:/data/' + reference, str(path)], check=True, stdout=subprocess.DEVNULL)
            manifest.append(dict(id=entry['id'], file=str(path.relative_to(out)), sha256=SHA(path.read_bytes())))
        save(out / 'decoded-manifest.json', manifest)
        subprocess.run(['docker', 'cp', 'samlscope-reference-suite:/data/target-metadata/' + run + '.xml',
                        str(out / 'target-metadata.xml')], check=True, stdout=subprocess.DEVNULL)
        if not restored: raise RuntimeError('Restoration incomplete')
    print('Recorded', len(observations), 'conditions;', run, '; no verdict assigned')


if __name__ == '__main__':
    main()
