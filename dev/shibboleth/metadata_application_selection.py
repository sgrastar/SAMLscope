#!/usr/bin/env python3
"""Replay public saved requests in the fixed native selector; no protocol or setting operations."""
import argparse
import base64
import datetime
import hashlib
import json
import pathlib
import secrets
import subprocess
import xml.etree.ElementTree as ET

SOURCE = pathlib.Path(__file__).with_name('ShibbolethMetadataSelectionProducer.java')
CONTAINER = 'samlscope-reference-shibboleth'
NS = {'md': 'urn:oasis:names:tc:SAML:2.0:metadata', 'p': 'urn:oasis:names:tc:SAML:2.0:protocol'}
BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:'
SHA = lambda raw: hashlib.sha256(raw).hexdigest()
NOW = lambda: datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00', 'Z')

def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=60)

def docker(*args):
    return run('docker', 'exec', CONTAINER, *args)

def inspect():
    fmt = '{"id":{{json .Id}},"image":{{json .Image}},"startedAt":{{json .State.StartedAt}},"running":{{json .State.Running}},"mounts":{{json .Mounts}}}'
    return json.loads(run('docker', 'inspect', '--format', fmt, CONTAINER).stdout)

def capture(folder, output):
    folder, output = folder.absolute(), output.absolute()
    assert not output.exists() and not any(p.is_symlink() for p in [folder, output, *folder.parents, *output.parents])
    receipt = folder / 'receipt'
    manifest = json.loads((receipt / 'manifest.json').read_bytes())
    assert manifest['adapter'] == 'shibboleth-native-accepted-metadata-application-v1'
    assert json.loads((receipt / 'restoration.json').read_bytes())['restored'] is True
    decoded = {row['id']: row for row in json.loads((folder / 'decoded-manifest.json').read_bytes())}
    probes = {row['fixture']: row for row in manifest['probes']}
    before = json.loads((receipt / 'native-originals/no-valid-until-before.json').read_bytes())
    metadata = (receipt / 'native' / before['cacheFile']).read_bytes()
    assert SHA(metadata) == before['cacheSha256']
    entity = ET.fromstring(metadata)
    records = []
    def record(label, fixture, profile, incoming, outgoing, purpose='actual-recorded-request'):
        probe = probes[fixture]
        ref = probe['requestReference']
        original = decoded[ref]
        raw = (folder / original['file']).read_bytes()
        assert SHA(raw) == original['sha256']
        return dict(label=label, requestReference=ref, requestSha256=SHA(raw), requestBase64=base64.b64encode(raw).decode(),
                    metadataSha256=SHA(metadata), metadataBase64=base64.b64encode(metadata).decode(), profileId=profile,
                    inboundBinding=BINDING + incoming, outgoingList=outgoing, observationPurpose=purpose)
    browser = 'http://shibboleth.net/ns/profiles/saml2/sso/browser'
    ecp = 'http://shibboleth.net/ns/profiles/saml2/sso/ecp'
    slo = 'http://shibboleth.net/ns/profiles/saml2/logout'
    browser_list = 'shibboleth.OutgoingSAML2SSOBindings'
    for label, fixture in [('post-default', 'new-key-default-acs'), ('post-second', 'new-key-second-acs'), ('old-acs', 'new-key-old-acs')]:
        records.append(record(label, fixture, browser, 'HTTP-POST', browser_list))
    records.append(record('paos', 'fixture-ecp-metadata-b-paos', ecp, 'SOAP', 'shibboleth.OutgoingECPBindings'))
    records.append(record('slo-front', 'new-key-slo-route', slo, 'HTTP-POST', 'shibboleth.OutgoingSAML2SLOFrontBindings'))
    redirect = record('unsupported-browser-redirect', 'new-key-second-acs', browser, 'HTTP-POST', browser_list,
                      'isolated-binding-applicability-control')
    request = ET.fromstring(base64.b64decode(redirect['requestBase64']))
    advertised = entity.find("md:SPSSODescriptor/md:AssertionConsumerService[@index='3']", NS)
    assert advertised is not None and advertised.get('Binding') == BINDING + 'HTTP-Redirect'
    request.set('AssertionConsumerServiceURL', advertised.get('Location'))
    request.set('ProtocolBinding', advertised.get('Binding'))
    raw = ET.tostring(request, encoding='utf-8')
    redirect.update(requestSha256=SHA(raw), requestBase64=base64.b64encode(raw).decode(),
                    originalRequestSha256=decoded[redirect['requestReference']]['sha256'])
    records.append(redirect)
    records.append(record('slo-back-channel', 'new-key-slo-route', slo, 'SOAP', 'shibboleth.OutgoingSOAPBindings',
                          'isolated-synchronous-binding-applicability-control'))
    payload = dict(schema='samlscope-native-metadata-selection-input-v1', purpose='stock-native-consumer',
                   runId=manifest['runId'], entityId=manifest['entityId'], originalManifestSha256=SHA((receipt/'manifest.json').read_bytes()),
                   targetMetadataSha256=manifest['targetMetadataSha256'], records=records)
    output.mkdir()
    save(output / 'native-selection-input.json', payload)
    (output / 'native-selection-source.java').write_bytes(SOURCE.read_bytes())
    (output / 'logback.xml').write_bytes(b'<configuration><root level="OFF"/></configuration>\n')
    temp = '/tmp/shib-application-selection-' + secrets.token_hex(6)
    native_paths = ['/usr/local/tomcat/webapps/idp/WEB-INF/lib/' + name + '-5.2.3.jar'
                    for name in ('idp-conf-impl', 'idp-saml-impl', 'opensaml-saml-impl', 'opensaml-saml-api')]
    commands, compiler, java_calls, removed = [], 0, 0, False
    native_before = inspect()
    try:
        before_raw = docker('sha256sum', *native_paths).stdout
        (output / 'native-jars-before.sha256').write_bytes(before_raw)
        docker('mkdir', temp)
        for local, remote in [('native-selection-source.java', SOURCE.name), ('native-selection-input.json', 'input.json'), ('logback.xml', 'logback.xml')]:
            run('docker', 'cp', str(output / local), CONTAINER + ':' + temp + '/' + remote)
        compiler += 1
        command = ['docker', 'exec', CONTAINER, 'javac', '-cp', '/usr/local/tomcat/webapps/idp/WEB-INF/lib/*', '-d', temp, temp + '/' + SOURCE.name]
        start = NOW(); result = run(*command)
        (output / 'compile.stdout').write_bytes(result.stdout); (output / 'compile.stderr').write_bytes(result.stderr)
        commands.append(dict(operation='native-public-compile', command=command, startedAt=start, completedAt=NOW(), exitCode=result.returncode))
        java_calls += 1
        command = ['docker', 'exec', CONTAINER, 'java', '-Dlogback.configurationFile=' + temp + '/logback.xml', '-cp', temp + ':/usr/local/tomcat/webapps/idp/WEB-INF/lib/*', 'ShibbolethMetadataSelectionProducer', temp + '/input.json', temp + '/' + SOURCE.name]
        start = NOW(); result = run(*command)
        (output / 'native-selection-output.json').write_bytes(result.stdout)
        (output / 'native-selection-output.stderr').write_bytes(result.stderr)
        invocation = dict(schema='samlscope-native-metadata-selection-invocation-v1', purpose='public-native-selection-replay',
                          command=command, startedAt=start, completedAt=NOW(), exitCode=result.returncode,
                          sourceSha256=SHA(SOURCE.read_bytes()), inputSha256=SHA((output/'native-selection-input.json').read_bytes()),
                          outputSha256=SHA(result.stdout), stderrSha256=SHA(result.stderr))
        save(output / 'native-selection-invocation.json', invocation)
        commands.append(dict(operation='native-public-java', **invocation))
        after_raw = docker('sha256sum', *native_paths).stdout
        (output / 'native-jars-after.sha256').write_bytes(after_raw)
        assert before_raw == after_raw and inspect() == native_before
    except subprocess.CalledProcessError as failure:
        (output/'failed-command.stdout').write_bytes(failure.stdout or b''); (output/'failed-command.stderr').write_bytes(failure.stderr or b'')
        save(output/'failed-command.json', dict(command=list(failure.cmd), exitCode=failure.returncode))
        raise
    finally:
        docker('rm', '-rf', temp); removed = True
        save(output/'operations.json', dict(commands=commands, nativeContainerBefore=native_before, nativeContainerAfter=inspect(),
                nativeCompilerCalls=compiler, nativePublicJavaCalls=java_calls, temporarySourceRemoved=removed,
                productSettings=0, protocolOperations=0, credentialPosts=0, productRestarts=0, personOperations=0))
    return output

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=pathlib.Path); parser.add_argument('output', type=pathlib.Path)
    args = parser.parse_args(); print(capture(args.folder, args.output))
