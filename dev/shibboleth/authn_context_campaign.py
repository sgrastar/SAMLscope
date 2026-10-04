#!/usr/bin/env python3
"""Execute native authentication comparisons with original SAML evidence and exact restoration; no verdict."""
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
from authn_context_preparation import configure, inputs
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'keycloak'))
from import_metadata_batch import api, save, BASE
from reference_flow import Client

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
VARIANT = 'nameid-omission'
SERVICES = {'metadata-providers': 'shibboleth.MetadataResolverService',
            'authn/authn-comparison': None, 'authn/authn-properties': None}


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
    plan_result = api('/api/plans', dict(name='Shibboleth native authentication context comparison',
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
    campaign = api('/api/runs/' + run + '/metadata-lab/preloaded', dict(variants=[VARIANT]))
    save(out / 'campaign.json', campaign)
    with http.urlopen(campaign['preloadedMetadataUrl'], timeout=60) as response:
        raw = response.read()
    (out / 'fixture.xml').write_bytes(raw)
    entities = {'target': BASE + '/p/' + plan + '/metadata-peer/' + VARIANT}
    aggregate = ET.fromstring(raw)
    for entity in entities.values():
        if len([node for node in aggregate if node.get('entityID') == entity]) != 1:
            raise ValueError('Preloaded peer missing or ambiguous')
    temporary = '/opt/reference-idp/metadata/authn-context-' + run + '.xml'
    if docker('sh', '-c', 'test ! -e ' + temporary + ' && echo absent').strip() != b'absent':
        raise ValueError('Temporary metadata already exists')
    paths = {name: '/opt/reference-idp/conf/' + name + '.xml' for name in SERVICES}
    paths['authn/authn-properties'] = '/opt/reference-idp/conf/authn/authn.properties'
    originals = {name: docker('cat', path) for name, path in paths.items()}
    namespace = 'urn:mace:shibboleth:2.0:metadata'
    ET.register_namespace('', namespace)
    ET.register_namespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance')
    providers = ET.fromstring(originals['metadata-providers'])
    providers.insert(0, ET.Element('{' + namespace + '}MetadataProvider', {
        'id': 'AuthnContext' + run, '{http://www.w3.org/2001/XMLSchema-instance}type': 'FilesystemMetadataProvider',
        'metadataFile': temporary}))
    configured = dict(originals)
    configured['metadata-providers'] = ET.tostring(providers)
    native_versions = {}
    for mode in ['normal', 'maximum']:
        comparison, properties = configure(originals['authn/authn-comparison'], originals['authn/authn-properties'], mode == 'maximum')
        native_versions[mode] = {'authn/authn-comparison': comparison, 'authn/authn-properties': properties}
        for name, value in native_versions[mode].items():
            (out / (mode + '-' + name.replace('/', '-') + '.xml')).write_bytes(value)
    for name, value in originals.items():
        (out / ('original-' + name.replace('/', '-'))).write_bytes(value)
    target_path = out / 'target-metadata.xml'
    subprocess.run(['docker', 'cp', 'samlscope-reference-suite:/data/target-metadata/' + run + '.xml', str(target_path)], check=True, stdout=subprocess.DEVNULL)
    input_record = dict(schema='samlscope-authn-context-inputs-v1', runId=run,
                        targetMetadataSha256=SHA(target_path.read_bytes()), inputs=inputs())
    save(out / 'inputs.json', input_record)
    input_dir = '/data/authn-context-inputs'
    subprocess.run(['docker', 'exec', 'samlscope-reference-suite', 'mkdir', '-p', input_dir], check=True)
    subprocess.run(['docker', 'cp', str(out / 'inputs.json'), 'samlscope-reference-suite:' + input_dir + '/' + run + '.json'], check=True)
    operations, observations, changed = [dict(operation='suite-input-write', label='authn-context-inputs', sha256=SHA((out / 'inputs.json').read_bytes()))], [], []
    written = False

    def save_operations():
        save(out / 'operations-in-progress.json', dict(run=run, operations=operations))

    def write(path, data, label):
        record = dict(operation='write', label=label, sha256=SHA(data), read_back=False)
        operations.append(record)
        save_operations()
        docker('sh', '-c', 'cat > ' + path, data=data)
        if docker('cat', path) != data: raise RuntimeError('Native write read-back mismatch')
        record['read_back'] = True
        save_operations()

    def reload(name, label):
        operation = dict(operation='reload', label=label, completed=False)
        operations.append(operation)
        save_operations()
        log = docker('/opt/reference-idp/bin/reload-service.sh', '-id', name, '-u', 'http://localhost:8080/idp')
        (out / (label + '-reload.log')).write_bytes(log)
        operation['completed'] = True

    def readback():
        properties = docker('cat', '/opt/reference-idp/conf/idp.properties').decode()
        flows = re.findall(r'^\s*idp.authn.flows\s*[=:]\s*(.*?)\s*$', properties, re.M)
        if flows != ['Password']: raise RuntimeError('Native active authentication flows unproven')
        if docker('cat', temporary) != raw: raise RuntimeError('Imported aggregate changed')
        actual = {name: docker('cat', path) for name, path in paths.items()}
        if actual != configured: raise RuntimeError('Native configuration changed')
        return {name: SHA(raw) for name, raw in actual.items()}

    def restart(label):
        operation = dict(operation='restart', label=label, completed=False)
        operations.append(operation)
        save_operations()
        subprocess.run(['docker', 'restart', 'samlscope-reference-shibboleth'], check=True, stdout=subprocess.DEVNULL, timeout=60)
        docker('/usr/local/tomcat/bin/startup.sh')
        operations.append(dict(operation='tomcat-start', label=label, completed=True))
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                with http.urlopen('http://localhost:18280/idp/shibboleth', timeout=3) as response:
                    if response.status == 200:
                        operation['completed'] = True
                        save_operations()
                        return
            except Exception:
                time.sleep(1)
        raise RuntimeError('Native IdP failed to become ready')

    try:
        written = True
        write(temporary, raw, 'metadata')
        for name in paths:
            changed.append(name)
        configured.update(native_versions['normal'])
        for name in paths:
            write(paths[name], configured[name], name)
        restart('normal-comparison')
        save(out / 'preparation.json', dict(run=run, entity_id=entities['target'], native=readback(), login_input_binding=login_binding,
            login_provenance='fixed-in-memory-driver-input', authenticated_principal_verified=False, active_authentication_flows='Password'))
        start = urls.urlsplit(campaign['preloadedStartUrl'])
        # Group all inputs by native configuration to minimize restarts.
        for mode in ['normal', 'maximum']:
            if mode == 'maximum':
                configured.update(native_versions[mode])
                for name in native_versions[mode]:
                    write(paths[name], configured[name], mode + '-' + name)
                restart(mode + '-comparison')
            for item in input_record['inputs']:
                if (item['id'].startswith('gc-') or item['id'].startswith('control-')) != (mode == 'maximum'):
                    continue
                condition = item['id']
                index = campaign['preloadedVariants'].index(VARIANT)
                query = urls.parse_qsl(start.query) + [('authn', condition)]
                url = urls.urlunsplit(start._replace(path='/p/' + plan + '/start/metadata-preloaded/' + str(index), query=urls.urlencode(query)))
                before_ids = {entry['id'] for entry in api('/api/runs/' + run + '/transcript')}
                record = dict(condition=condition, entity_id=entities['target'], variant=VARIANT, before=readback(),
                    login_input_binding=login_binding, native_mode=mode, status='incomplete')
                observations.append(record)
                client = Client()
                client.op = http.build_opener(http.HTTPCookieProcessor(client.jar), StopAtAcs())
                try:
                    record['flow_status'] = client.flow(url, None, *credentials)
                except AcsSubmitted as submitted:
                    record['flow_status'] = 'acs-submitted'
                    record['http_status'] = submitted.status
                except Exception as error:
                    record['flow_status'] = 'unobserved'
                    record['error_type'] = type(error).__name__
                finally:
                    record['after'] = readback()
                    record['new_transcript_ids'] = [entry['id'] for entry in api('/api/runs/' + run + '/transcript') if entry['id'] not in before_ids]
                    record['status'] = 'observed'
                    save(out / 'observations.json', observations)
    finally:
        failures = []
        for name in reversed(changed):
            try:
                if docker('cat', paths[name]) not in (configured[name], originals[name]): raise RuntimeError('Concurrent native configuration change')
                write(paths[name], originals[name], 'restore-' + name)
                configured[name] = originals[name]
            except Exception as error: failures.append(name + ':' + type(error).__name__)
        if changed and not failures:
            try:
                restart('restore-authentication')
            except Exception as error:
                failures.append('restore-startup:' + type(error).__name__)
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
