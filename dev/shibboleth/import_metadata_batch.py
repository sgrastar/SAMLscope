#!/usr/bin/env python3
"""Exercise original fixtures through a temporary native Shibboleth filesystem provider."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, save, flow

CONTAINER = 'samlscope-reference-shibboleth'
CONFIG = '/opt/reference-idp/conf/metadata-providers.xml'
SUITE = 'samlscope-reference-suite'
SIGNING_CERT = '/opt/reference-idp/credentials/suite-metadata-signing.pem'


def docker(*args, data=None):
    return subprocess.run(['docker', 'exec', '-i', CONTAINER, *args], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=90).stdout


def suite_cat(path):
    return subprocess.run(['docker', 'exec', SUITE, 'cat', path],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=90).stdout


def pem(der):
    body = base64.b64encode(der).decode('ascii')
    lines = '\n'.join(body[i:i + 64] for i in range(0, len(body), 64))
    return ('-----BEGIN CERTIFICATE-----\n' + lines + '\n-----END CERTIFICATE-----\n').encode('ascii')


def write(path, data):
    # Paths are generated below, never derived from metadata input.
    docker('sh', '-c', 'cat > ' + path, data=data)
    assert docker('cat', path) == data


def reload(folder, name):
    result = docker('/opt/reference-idp/bin/reload-service.sh', '-id',
                    'shibboleth.MetadataResolverService', '-u', 'http://localhost:8080/idp')
    (folder / (name + '-reload.log')).write_bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--variants', required=True)
    parser.add_argument('--profile', choices=['metadata_idp', 'browser_sso_idp', 'ecp_idp', 'single_logout_idp'], default='metadata_idp')
    parser.add_argument('--continue-inconclusive', action='store_true', help='Continue after a non-baseline protocol attempt; never infer a verdict')
    parser.add_argument('--metadata-signature-filter', action='store_true',
                        help='After the control load, trust the polling key and require a valid document signature')
    parser.add_argument('--trust-alias',
                        help='Trust this Suite key alias for the target variant instead of the control polling key')
    parser.add_argument('--trust-variant-poll', action='store_true',
                        help='Trust each variant polling key so its signature transform and KeyInfo are verified')
    args = parser.parse_args()
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    variants = args.variants.split(',')
    if not variants or variants[0] != 'control':
        raise ValueError('Start with control')
    original = docker('cat', CONFIG)
    (out / 'original-providers.xml').write_bytes(original)
    created = api('/api/plans', dict(name='Shibboleth native filesystem metadata batch',
        profile=args.profile, targetKind='IDP', targetEntityId='http://localhost:18280/idp/shibboleth',
        metadataSourceKind='URL', metadataSourceLocation='http://samlscope-reference-shibboleth:8080/idp/shibboleth',
        suiteMetadataDelivery='HTTP_URL', declaredFeatures={},
        parameters=dict(clockSkewToleranceSeconds=180, metadataRefreshWaitSeconds=300,
                        testUserHint='samlscope-m0-user', requestSigningMode='REQUIRED'),
        interaction=dict(allowBrowserSteps=True, allowAttestation=False, preset='quick'), authorizedTarget=True))
    save(out / 'plan.json', created)
    plan = created['plan']['plan']['id']
    created = api('/api/plans/' + plan + '/runs', {})
    save(out / 'created.json', created)
    run = created['run']['id']
    path = '/opt/reference-idp/metadata/algorithm-' + run + '.xml'
    if docker('sh', '-c', 'if test -e ' + path + '; then echo exists; fi').strip():
        raise ValueError('Refusing to overwrite existing provider file')
    save(out / 'preflight.json', api('/api/runs/' + run + '/preflight', {}))
    save(out / 'campaign.json', api('/api/runs/' + run + '/metadata-lab/automatic-polling',
                                  dict(variants=variants, pollingDelaySeconds=0)))
    ns = 'urn:mace:shibboleth:2.0:metadata'
    xsi = 'http://www.w3.org/2001/XMLSchema-instance'
    ET.register_namespace('', ns)
    ET.register_namespace('xsi', xsi)
    providers = ET.fromstring(original)
    provider_attributes = {'id': 'Algorithm' + run, '{' + xsi + '}type': 'FilesystemMetadataProvider',
                           'metadataFile': path}
    if args.metadata_signature_filter or args.trust_variant_poll:
        # A rejected document must not tear down the resolver service; keep the previous load.
        provider_attributes['failFastInitialization'] = 'false'
    provider = ET.Element('{' + ns + '}MetadataProvider', provider_attributes)
    providers.insert(0, provider)
    configured = ET.tostring(providers)
    (out / 'configured-providers.xml').write_bytes(configured)
    operations = []
    config_changed = False
    signature_filter_written = False

    def install_signature_filter(folder, alias, reload_service=True):
        # Trust one Suite key out of band, then require a signed root. Added after a successful
        # load so the trusted document initialises before any reject fixture appears.
        certificate = pem(suite_cat('/data/keys/' + plan + '/' + alias + '/signing-certificate.der'))
        for child in list(provider):
            if child.tag == '{' + ns + '}MetadataFilter':
                provider.remove(child)
        signer = ET.SubElement(provider, '{' + ns + '}MetadataFilter',
            {'{' + xsi + '}type': 'SignatureValidation', 'requireSignedRoot': 'true',
             'certificateFile': SIGNING_CERT})
        write(SIGNING_CERT, certificate)
        (out / 'signing-certificate.pem').write_bytes(certificate)
        (out / 'signing-filter.xml').write_bytes(ET.tostring(signer))
        (out / 'configured-providers.xml').write_bytes(ET.tostring(providers))
        write(CONFIG, ET.tostring(providers))
        if reload_service:
            reload(folder, 'import-filter')
        return True

    try:
        for variant in variants:
            state = api('/api/runs/' + run + '/metadata-lab')
            if state['selectedVariant'] != variant:
                raise RuntimeError('Campaign variant mismatch')
            folder = out / variant
            folder.mkdir()
            record = dict(product='shibboleth', import_path='native-filesystem-provider', variant=variant,
                          run=run, status='incomplete', entity_id='http://localhost:18080/p/' + plan)
            operations.append(record)
            try:
                with urllib.request.urlopen(state['automaticStartUrl'], timeout=30) as response:
                    assert response.status == 202
                with urllib.request.urlopen(state['metadataUrl'], timeout=30) as response:
                    fixture = response.read()
                (folder / 'fixture.xml').write_bytes(fixture)
                record['fixture_sha256'] = hashlib.sha256(fixture).hexdigest()
                write(path, fixture)
                record['configuration_read_back'] = True
                if not config_changed:
                    config_changed = True
                    write(CONFIG, configured)
                if args.trust_variant_poll and variant != 'control':
                    alias = 'poll-' + hashlib.sha256(variant.encode()).hexdigest()[:16]
                    signature_filter_written = install_signature_filter(folder, alias, reload_service=False)
                    record['signature_trust_alias'] = alias
                    config_changed = True
                reload(folder, 'import')
                record['provider_reloaded'] = True
                if args.trust_alias and variant != 'control' and not signature_filter_written:
                    signature_filter_written = install_signature_filter(folder, args.trust_alias)
                    record['signature_trust_alias'] = args.trust_alias
                try:
                    flow(run, folder / 'flow.json',
                         suite_signature_control=variant != 'ecdsa-sha256-invalid-signature')
                    record['status'] = 'success'
                    print(variant, 'verified', flush=True)
                except RuntimeError as error:
                    record['protocol_attempt_error'] = str(error)
                    if variant == 'control' or not args.continue_inconclusive:
                        raise
                    pending = api('/api/runs/' + run + '/metadata-lab')
                    if pending['campaignIndex'] == state['campaignIndex']:
                        request = urllib.request.Request(pending['automaticContinueUrl'], data=b'')
                        with urllib.request.urlopen(request, timeout=30) as response:
                            response.read()
                        record['continued_without_verdict'] = True
                    print(variant, 'inconclusive', flush=True)
                if variant == 'control':
                    save(out / 'tests-start.json', api('/api/runs/' + run + '/tests/start', {}))
                    if args.metadata_signature_filter and not args.trust_alias:
                        alias = 'poll-' + hashlib.sha256(b'control').hexdigest()[:16]
                        signature_filter_written = install_signature_filter(folder, alias)
            finally:
                save(folder / 'import.json', record)
                save(out / 'operations.json', operations)
    finally:
        if config_changed:
            write(CONFIG, original)
            reload(out, 'restore')
        docker('rm', '-f', path)
        if signature_filter_written:
            docker('rm', '-f', SIGNING_CERT)
        restored = docker('cat', CONFIG) == original
        removed = not docker('sh', '-c', 'if test -e ' + path + '; then echo exists; fi').strip()
        certificate_removed = not docker(
            'sh', '-c', 'if test -e ' + SIGNING_CERT + '; then echo exists; fi').strip()
        assert restored and removed and certificate_removed
        save(out / 'restoration.json', dict(restored=restored, temporary_file_removed=removed,
            signature_certificate_removed=certificate_removed,
            original_sha256=hashlib.sha256(original).hexdigest(), final_sha256=hashlib.sha256(docker('cat', CONFIG)).hexdigest()))
        for record in operations:
            record['restored'] = restored and removed
            save(out / record['variant'] / 'import.json', record)
        save(out / 'operations.json', operations)
        for name in ['result.json', 'transcript', 'protocol-evidence']:
            try:
                save(out / (name if '.' in name else name + '.json'), api('/api/runs/' + run + '/' + name))
            except Exception as error:
                save(out / (name.replace('.', '-') + '-unavailable.json'), dict(reason=str(error)))
        print('Run', run, 'restored', restored and removed, flush=True)


if __name__ == '__main__':
    main()
