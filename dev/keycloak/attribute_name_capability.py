#!/usr/bin/env python3
"""Native attribute-name/format capability experiment; explicit client settings, exact deletion."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import hashlib
import urllib.request as http
import urllib.parse as urls
import xml.etree.ElementTree as ET
import zipfile
from relying_party_attribute_campaign import client_recipe, projection, ADMIN, api, save, BASE, Client

SERVICES_JAR = '/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar'
ATTRIBUTE_HELPER = 'org/keycloak/protocol/saml/mappers/AttributeStatementHelper.class'
ATTRIBUTE_HELPER_CLASS = 'org.keycloak.protocol.saml.mappers.AttributeStatementHelper'
RUNTIME_DEPENDENCIES = {
    'keycloak-server-spi-runtime.jar': '/opt/keycloak/lib/lib/main/org.keycloak.keycloak-server-spi-26.7.2.jar',
    'keycloak-saml-core-public-runtime.jar': '/opt/keycloak/lib/lib/main/org.keycloak.keycloak-saml-core-public-26.7.2.jar',
}
ATTRIBUTE_FORMAT_PROVIDERS = {
    'saml-user-session-note-mapper', 'saml-group-membership-mapper',
    'saml-user-property-mapper', 'saml-role-list-mapper',
    'saml-hardcode-attribute-mapper', 'saml-user-attribute-mapper',
}
ATTRIBUTE_FORMAT_OPTIONS = ['Basic', 'URI Reference', 'Unspecified']
ATTRIBUTE_FORMAT_IMPLEMENTATIONS = {
    'saml-group-membership-mapper': 'org.keycloak.protocol.saml.mappers.GroupMembershipMapper',
    'saml-hardcode-attribute-mapper': 'org.keycloak.protocol.saml.mappers.HardcodedAttributeMapper',
    'saml-role-list-mapper': 'org.keycloak.protocol.saml.mappers.RoleListMapper',
    'saml-user-attribute-mapper': 'org.keycloak.protocol.saml.mappers.UserAttributeStatementMapper',
    'saml-user-property-mapper': 'org.keycloak.protocol.saml.mappers.UserPropertyAttributeStatementMapper',
    'saml-user-session-note-mapper': 'org.keycloak.protocol.saml.mappers.UserSessionNoteStatementMapper',
}


def capture_runtime_capability(out, token):
    """Retain the installed provider inventory and bytecode which implements NameFormat coercion."""
    inspect_raw = subprocess.check_output(['docker', 'inspect', 'samlscope-reference-keycloak'])
    inspect = json.loads(inspect_raw)[0]
    if inspect.get('State', {}).get('Running') is not True:
        raise RuntimeError('Keycloak is not running')
    for mount in inspect.get('Mounts', []):
        destination = mount.get('Destination', '').rstrip('/')
        if SERVICES_JAR == destination or SERVICES_JAR.startswith(destination + '/'):
            raise RuntimeError('Keycloak runtime JAR is covered by a mount')
    (out / 'target-container-inspect.json').write_bytes(inspect_raw)
    request = http.Request('http://localhost:18180/admin/serverinfo',
        headers={'Authorization': 'Bearer ' + token})
    with http.urlopen(request, timeout=30) as response:
        server_info = json.load(response)
    providers = server_info.get('protocolMapperTypes', {}).get('saml')
    if not isinstance(providers, list):
        raise RuntimeError('SAML protocol mapper inventory unavailable')
    relevant = []
    for provider in providers:
        properties = {p.get('name'): p for p in provider.get('properties', [])}
        if 'attribute.nameformat' not in properties:
            continue
        prop = properties['attribute.nameformat']
        if prop.get('type') != 'List' or prop.get('options') != ATTRIBUTE_FORMAT_OPTIONS:
            raise RuntimeError('Unexpected NameFormat provider schema')
        relevant.append(provider)
    if {p.get('id') for p in relevant} != ATTRIBUTE_FORMAT_PROVIDERS:
        raise RuntimeError('Installed NameFormat provider inventory changed')
    server_raw = (json.dumps(providers, indent=2, sort_keys=True) + '\n').encode()
    (out / 'saml-protocol-mapper-schemas.json').write_bytes(server_raw)
    jar = out / 'keycloak-services-runtime.jar'
    subprocess.run(['docker', 'cp', 'samlscope-reference-keycloak:' + SERVICES_JAR, str(jar)],
                   check=True, stdout=subprocess.DEVNULL)
    with zipfile.ZipFile(jar) as archive:
        helper = archive.read(ATTRIBUTE_HELPER)
    (out / 'AttributeStatementHelper.class').write_bytes(helper)
    javap = subprocess.check_output(['javap', '-classpath', str(jar), '-c', '-p', ATTRIBUTE_HELPER_CLASS])
    method = javap.decode()
    required = [
        'createAttributeType(org.keycloak.models.ProtocolMapperModel)',
        '// String attribute.nameformat', '// String URI Reference', '// String Unspecified',
        'ATTRIBUTE_FORMAT_BASIC', 'ATTRIBUTE_FORMAT_URI', 'ATTRIBUTE_FORMAT_UNSPECIFIED',
        'AttributeType.setNameFormat',
    ]
    if any(token not in method for token in required):
        raise RuntimeError('Installed NameFormat implementation is not recognizable')
    (out / 'AttributeStatementHelper.javap.txt').write_bytes(javap)
    producer_implementations = {}
    with zipfile.ZipFile(jar) as archive:
        for provider_id, class_name in sorted(ATTRIBUTE_FORMAT_IMPLEMENTATIONS.items()):
            entry = class_name.replace('.', '/') + '.class'
            class_bytes = archive.read(entry)
            stem = class_name.rsplit('.', 1)[-1]
            class_file = out / (stem + '.class')
            class_file.write_bytes(class_bytes)
            disassembly = subprocess.check_output(
                ['javap', '-classpath', str(jar), '-c', '-p', class_name])
            if b'org/keycloak/protocol/saml/mappers/AttributeStatementHelper.' not in disassembly:
                raise RuntimeError('Attribute producer does not use the constrained NameFormat helper')
            javap_file = out / (stem + '.javap.txt')
            javap_file.write_bytes(disassembly)
            producer_implementations[provider_id] = {
                'class_name': class_name,
                'class_entry': entry,
                'class_file': class_file.name,
                'class_sha256': hashlib.sha256(class_bytes).hexdigest(),
                'javap_file': javap_file.name,
                'javap_sha256': hashlib.sha256(disassembly).hexdigest(),
            }
    dependencies = {}
    for name, source in RUNTIME_DEPENDENCIES.items():
        destination = out / name
        subprocess.run(['docker', 'cp', 'samlscope-reference-keycloak:' + source, str(destination)],
                       check=True, stdout=subprocess.DEVNULL)
        dependencies[name] = {'runtime_path': source,
                              'sha256': hashlib.sha256(destination.read_bytes()).hexdigest()}
    harness_source = b'''import java.util.Map;\nimport org.keycloak.models.ProtocolMapperModel;\nimport org.keycloak.protocol.saml.mappers.AttributeStatementHelper;\npublic final class VerifyKCNameFormat {\n public static void main(String[] args) {\n  for (String value : new String[]{"Basic","URI Reference","Unspecified","urn:samlscope:test:attribute-name-format"}) {\n   var model=new ProtocolMapperModel();\n   model.setConfig(Map.of("attribute.name","urn:samlscope:test:attribute-name","attribute.nameformat",value));\n   var attribute=AttributeStatementHelper.createAttributeType(model);\n   System.out.println(value+"\\t"+attribute.getNameFormat());\n  }\n }\n}\n'''
    source_file = out / 'VerifyKCNameFormat.java'
    source_file.write_bytes(harness_source)
    classpath = ':'.join([str(jar), *[str(out / name) for name in RUNTIME_DEPENDENCIES]])
    subprocess.run(['javac', '-cp', classpath, str(source_file)], check=True, capture_output=True)
    harness_class = out / 'VerifyKCNameFormat.class'
    execution = subprocess.check_output(['java', '-cp', str(out) + ':' + classpath, 'VerifyKCNameFormat'])
    expected_execution = (b'Basic\turn:oasis:names:tc:SAML:2.0:attrname-format:basic\n'
        b'URI Reference\turn:oasis:names:tc:SAML:2.0:attrname-format:uri\n'
        b'Unspecified\turn:oasis:names:tc:SAML:2.0:attrname-format:unspecified\n'
        b'urn:samlscope:test:attribute-name-format\turn:oasis:names:tc:SAML:2.0:attrname-format:basic\n')
    if execution != expected_execution:
        raise RuntimeError('Installed NameFormat execution did not prove the expected coercion')
    (out / 'nameformat-execution.txt').write_bytes(execution)
    manifest = {
        'schema': 'samlscope-keycloak-attribute-nameformat-capability-v1',
        'container_id': inspect['Id'], 'image_id': inspect['Image'],
        'container_started_at': inspect['State']['StartedAt'], 'runtime_jar_path': SERVICES_JAR,
        'runtime_jar_sha256': hashlib.sha256(jar.read_bytes()).hexdigest(),
        'helper_class_entry': ATTRIBUTE_HELPER,
        'helper_class_sha256': hashlib.sha256(helper).hexdigest(),
        'provider_schemas_sha256': hashlib.sha256(server_raw).hexdigest(),
        'javap_sha256': hashlib.sha256(javap).hexdigest(),
        'producer_implementations': producer_implementations,
        'runtime_dependencies': dependencies,
        'harness_source_sha256': hashlib.sha256(harness_source).hexdigest(),
        'harness_class_sha256': hashlib.sha256(harness_class.read_bytes()).hexdigest(),
        'execution_sha256': hashlib.sha256(execution).hexdigest(),
        'nameformat_provider_ids': sorted(ATTRIBUTE_FORMAT_PROVIDERS),
        'accepted_configuration_tokens': ATTRIBUTE_FORMAT_OPTIONS,
        'unknown_value_falls_back_to_basic': True,
        'product_configuration_writes': 0, 'product_restarts': 0, 'human_operations': 0,
    }
    save(out / 'runtime-capability.json', manifest)
    return manifest


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--conclude-capability-absent',action='store_true',
        help='Conclude the normative capability branch after retaining runtime bytecode evidence')
    args=parser.parse_args()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    created=api('/api/plans',dict(name='Keycloak native attribute names and formats',profile='browser_sso_idp',targetKind='IDP',
        targetEntityId='http://localhost:18180/realms/samlscope',metadataSourceKind='URL',
        metadataSourceLocation='http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor',
        suiteMetadataDelivery='HTTP_URL',declaredFeatures={},parameters=dict(clockSkewToleranceSeconds=180,metadataRefreshWaitSeconds=300,
        testUserHint='samlscope-m0-user',requestSigningMode='REQUIRED'),interaction=dict(allowBrowserSteps=True,allowAttestation=False,preset='quick'),authorizedTarget=True))
    save(out/'plan.json',created);plan=created['plan']['plan']['id']
    run_created=api('/api/plans/'+plan+'/runs',{});save(out/'created.json',run_created);args.run=run_created['run']['id']
    if not re.fullmatch(r'run_[0-9A-HJKMNP-TV-Z]{26}',args.run) or not re.fullmatch(r'plan_[0-9A-HJKMNP-TV-Z]{26}',plan):raise ValueError('Invalid Run or Plan')
    save(out/'preflight.json',api('/api/runs/'+args.run+'/preflight',{}))
    entity=BASE+'/p/'+plan
    with http.urlopen(entity+'/metadata',timeout=30) as response:fixture=response.read()
    (out/'fixture.xml').write_bytes(fixture)
    recipe=client_recipe(ET.fromstring(fixture),'first')
    recipe['protocolMappers']=[]
    if recipe['clientId']!=entity:raise ValueError('Unexpected baseline identity')
    request=http.Request('http://localhost:18180/realms/master/protocol/openid-connect/token',data=urls.urlencode(dict(
        client_id='admin-cli',username=os.environ.get('KEYCLOAK_ADMIN_USERNAME','admin'),
        password=os.environ.get('KEYCLOAK_ADMIN_PASSWORD','admin'),grant_type='password')).encode())
    with http.urlopen(request,timeout=30) as response:token=json.load(response)['access_token']
    runtime = capture_runtime_capability(out, token) if args.conclude_capability_absent else None
    operations=[]
    def admin(path,body=None,method='GET'):
        request=http.Request(ADMIN+path,data=None if body is None else json.dumps(body).encode(),method=method,
            headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'})
        row=dict(method=method,path=path.split('?')[0],status='attempted');operations.append(row)
        with http.urlopen(request,timeout=30) as response:
            row['status']=response.status;raw=response.read()
            return json.loads(raw) if raw else None
    lookup='/clients?clientId='+urls.quote(entity,safe='')
    if admin(lookup):raise ValueError('Refusing existing client overwrite')
    identifier=None;restored=False;failures=[]
    try:
        admin('/clients',recipe,'POST')
        clients=admin(lookup)
        if len(clients)!=1:raise ValueError('Created client ambiguous')
        identifier=clients[0]['id']
        if not re.fullmatch(r'[a-f0-9-]{36}',identifier):raise ValueError('Invalid client ID')
        records=[]
        for condition in ['baseline','custom']:
            if condition=='custom':
                recipe['protocolMappers']=[dict(name='samlscope-capability-'+str(index),protocol='saml',protocolMapper='saml-user-property-mapper',
                    consentRequired=False,config={'user.attribute':'firstName','attribute.name':name,
                        'attribute.nameformat':'urn:samlscope:test:attribute-name-format'})
                    for index,name in enumerate(['urn:samlscope:test:attribute-name','SAMLscope arbitrary attribute'])]
                admin('/clients/'+identifier,recipe,'PUT')
            record=dict(condition=condition,before=projection(admin('/clients/'+identifier),recipe))
            records.append(record)
            before={row['id'] for row in api('/api/runs/'+args.run+'/transcript')}
            flow=Client().flow(entity+'/start/m0-roundtrip?run='+args.run,None,
                os.environ.get('REFERENCE_USERNAME','samlscope-m0-user'),os.environ.get('REFERENCE_PASSWORD','samlscope-m0-password'))
            record.update(flow=flow,after=projection(admin('/clients/'+identifier),recipe),
                new_transcript_ids=[row['id'] for row in api('/api/runs/'+args.run+'/transcript') if row['id'] not in before])
            save(out/'observations.json',records)
            if flow!='recorded':raise RuntimeError('Normal login not recorded')
            if condition=='baseline':
                save(out/'tests-start.json',api('/api/runs/'+args.run+'/tests/start',{}))
                save(out/'control-protocol-evidence.json',api('/api/runs/'+args.run+'/protocol-evidence'))
        save(out/'protocol-evidence-before-conclusion.json',api('/api/runs/'+args.run+'/protocol-evidence'))
        if args.conclude_capability_absent:
            note = ('Machine-verified Keycloak runtime evidence: AttributeStatementHelper coerces every '
                    'unrecognized attribute.nameformat value to Basic; installed provider schemas expose only '
                    'Basic, URI Reference, and Unspecified. Evidence manifest sha256=' +
                    hashlib.sha256((out/'runtime-capability.json').read_bytes()).hexdigest())
            save(out/'configure.json',api('/api/runs/'+args.run+'/cases/IIP-IDP01-a-idp-01/configure',
                dict(value='capability_absent',note=note)))
        else:
            save(out/'configure.json',api('/api/runs/'+args.run+'/cases/IIP-IDP01-a-idp-01/configure',dict(value='CONFIRMED')))
    finally:
        try:
            clients=admin(lookup)
            if len(clients)>1:raise ValueError('Cleanup identity ambiguous')
            if clients:
                current=clients[0]
                if current['clientId']!=entity or (identifier is not None and current['id']!=identifier):
                    raise ValueError('Cleanup identity changed')
                identifier=current['id']
                if not re.fullmatch(r'[a-f0-9-]{36}',identifier):raise ValueError('Invalid cleanup ID')
                admin('/clients/'+identifier,method='DELETE')
            restored=not admin(lookup)
        except Exception as error:failures.append(type(error).__name__)
        save(out/'operations.json',dict(run=args.run,admin_operations=operations,restored=restored,
            failures=failures,created_client_id=identifier,existing_clients_overwritten=False,human_operations=0))
        save(out/'run-after.json',api('/api/runs/'+args.run))
        if not restored or failures:raise RuntimeError('Native baseline cleanup incomplete')
    save(out/'result.json',api('/api/runs/'+args.run+'/result.json'))
    entries=api('/api/runs/'+args.run+'/transcript');save(out/'transcript.json',entries);manifest=[]
    for entry in entries:
        ref=entry.get('decodedSamlRef')
        if not ref:continue
        if not re.fullmatch(r'tx_[0-9A-HJKMNP-TV-Z]{26}',entry['id']) or Path(ref).is_absolute() or '..' in Path(ref).parts:raise ValueError('Invalid original reference')
        path=out/'decoded'/(entry['id']+'.xml');path.parent.mkdir(exist_ok=True)
        subprocess.run(['docker','cp','samlscope-reference-suite:/data/'+ref,str(path)],check=True,stdout=subprocess.DEVNULL)
        manifest.append(dict(id=entry['id'],file=str(path.relative_to(out)),sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    save(out/'decoded-manifest.json',manifest)
    subprocess.run(['docker','cp','samlscope-reference-suite:/data/target-metadata/'+args.run+'.xml',str(out/'target-metadata.xml')],check=True,stdout=subprocess.DEVNULL)
    print('Recorded native capability attempt;',args.run,'; temporary client deleted')


if __name__=='__main__':main()
