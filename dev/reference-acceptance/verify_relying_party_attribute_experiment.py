#!/usr/bin/env python3
"""Audit local native preparation and exact protocol references; no conformance verdict."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'shibboleth'))
from relying_party_attribute_preparation import recipe
from attribute_policy_preparation import canonical


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_keycloak_preparation(folder, prepared, run, restoration):
    if prepared['run'] != run or prepared.get('metadata_interpretation_claimed') is not False \
            or prepared.get('source_attribute') != 'firstName':
        raise ValueError('Invalid native Keycloak preparation scope')
    entities = prepared['entity_ids']
    if set(entities) != {'first', 'second'} or len(set(entities.values())) != 2:
        raise ValueError('Distinct native clients required')
    if restoration['failures'] or restoration['existing_clients_overwritten'] is not False:
        raise ValueError('Native client restoration incomplete')
    recipes = json.loads((folder / 'client-recipes.json').read_text())
    if set(recipes) != set(entities) or set(prepared['native']) != set(entities):
        raise ValueError('Native client scope differs')
    md = '{urn:oasis:names:tc:SAML:2.0:metadata}'
    ds = '{http://www.w3.org/2000/09/xmldsig#}'
    original = ET.fromstring((folder / 'fixture.xml').read_bytes())
    policies = {}
    for side, entity_id in entities.items():
        matches = [entity for entity in original.findall(md+'EntityDescriptor') if entity.get('entityID') == entity_id]
        if len(matches) != 1: raise ValueError('Original client identity ambiguous')
        roles = matches[0].findall(md+'SPSSODescriptor')
        if len(roles) != 1: raise ValueError('Original SP role ambiguous')
        certificates = {''.join(node.itertext()).strip() for node in roles[0].findall('.//'+ds+'X509Certificate')}
        if len(certificates) != 1: raise ValueError('Original SP key ambiguous')
        certificate = certificates.pop()
        acs = [node.get('Location') for node in roles[0].findall(md+'AssertionConsumerService')
               if node.get('Binding') == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']
        if not acs: raise ValueError('Original POST endpoint missing')
        mappers = [dict(name='samlscope-rp-'+marker, protocol='saml', protocolMapper='saml-user-property-mapper',
                       consentRequired=False, config={'user.attribute':'firstName',
                       'attribute.name':'urn:samlscope:test:relying-party:'+marker,
                       'attribute.nameformat':'URI Reference'}) for marker in ['anchor', side]]
        expected = dict(clientId=entity_id, protocol='saml', enabled=True, redirectUris=acs,
            fullScopeAllowed=False, defaultClientScopes=[], optionalClientScopes=[], protocolMappers=mappers,
            attributes={'saml.client.signature':'true', 'saml.signing.certificate':certificate,
                'saml.server.signature':'true', 'saml.assertion.signature':'true', 'saml.encrypt':'true',
                'saml.encryption.certificate':certificate, 'saml.force.post.binding':'true',
                'saml_assertion_consumer_url_post':acs[0]})
        actual = dict(prepared['native'][side])
        identifier = actual.pop('id')
        if not re.fullmatch(r'[a-f0-9-]{36}', identifier) or restoration['deleted_client_ids'].get(side) != identifier:
            raise ValueError('Native client deletion identity differs')
        for candidate in [expected, actual, recipes[side]]:
            candidate['protocolMappers'] = sorted(candidate['protocolMappers'], key=lambda mapper:mapper['name'])
        if actual != expected or recipes[side] != expected:
            raise ValueError('Native Keycloak mapper semantics differ')
        policies[side] = mappers
    encode = lambda value: json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    return dict(run=run, entity_ids=entities, policy_sha256=digest(encode(policies)),
        configuration_sha256={'clients':digest(encode(prepared['native']))}, source_attribute='firstName')


def verify_ssp_preparation(folder, prepared, run):
    if prepared['run'] != run or set(prepared['entity_ids']) != {'first', 'second'}:
        raise ValueError('Invalid native SSP preparation scope')
    if len(set(prepared['entity_ids'].values())) != 2:
        raise ValueError('Distinct native SSP requesters required')
    expected = {side: dict(authproc={'50': {'class': 'core:AttributeCopy', 'uid': [
        'urn:samlscope:test:relying-party:anchor', 'urn:samlscope:test:relying-party:' + side]}},
        name_format='urn:oasis:names:tc:SAML:2.0:attrname-format:uri', encryption=True,
        validate_authnrequest=True) for side in ['first', 'second']}
    if prepared['native']['policies'] != expected:
        raise ValueError('Native SSP attribute recipe differs')
    parser_raw = (folder / 'parser-output.json').read_bytes()
    parser = json.loads(parser_raw)
    if set(parser) != {'first', 'second'} or prepared['parser_sha256'] != digest(parser_raw):
        raise ValueError('Native parser output changed')
    for side in expected:
        if parser[side]['policy'] != expected[side] or parser[side]['entity_id'] != prepared['entity_ids'][side]:
            raise ValueError('Native parser requester association differs')
    overlay = '\n'.join(parser[side]['php'] for side in ['first', 'second']).encode()
    if overlay != (folder / 'overlay.php').read_bytes() or prepared['overlay_sha256'] != digest(overlay):
        raise ValueError('Native overlay changed')
    if prepared['fixture_sha256'] != digest((folder / 'fixture.xml').read_bytes()):
        raise ValueError('Native imported original changed')
    configuration = prepared['native']['configuration_sha256']
    if not isinstance(configuration, str) or not re.fullmatch(r'[0-9a-f]{64}', configuration):
        raise ValueError('Native read-back fingerprint unavailable')
    return dict(run=run, entity_ids=prepared['entity_ids'],
        policy_sha256=digest(json.dumps(expected,sort_keys=True,separators=(',',':')).encode()),
        configuration_sha256={'saml20-sp-remote': configuration})


def verify(folder):
    def read(name): return json.loads((folder / name).read_text())
    run = read('created.json')['run']['id']
    restoration = read('restoration.json')
    prepared = read('preparation.json')
    keycloak = prepared.get('source') == 'native-admin-client-user-property-mapper'
    if not restoration['restored'] or (not keycloak and restoration['original_sha256'] != restoration['final_sha256']):
        raise ValueError('Native restoration unproven')
    if prepared['login_provenance'] != 'fixed-in-memory-driver-input':
        raise ValueError('Login preparation scope unproven')
    if keycloak:
        native = verify_keycloak_preparation(folder, prepared, run, restoration)
    elif prepared.get('source') == 'native-parser-cli-and-core-AttributeCopy':
        native = verify_ssp_preparation(folder, prepared, run)
    else:
        if restoration['failures'] or not restoration['temporary_removed']:
            raise ValueError('Native restoration incomplete')
        native = prepared['native']
        if native['run'] != run:
            raise ValueError('Preparation scope unproven')
        files = {side: native['nodes']['metadata-providers'][0]['attributes']['metadataFile'] for side in ['first', 'second']}
        expected = {name: [canonical(node) for node in nodes] for name, nodes in recipe(run, native['entity_ids'], files).items()}
        if native['nodes'] != expected or native['policy_sha256'] != digest(json.dumps(expected,
                sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()):
            raise ValueError('Native policy meaning differs from recipe')
    protocol = read('production-observation.json')
    if protocol['run'] != run or protocol['issues'] or not protocol['same_attribute_input']:
        raise ValueError('Verified attribute exchanges unavailable')
    if protocol['transcript_sha256'] != digest((folder / 'transcript.json').read_bytes()) \
            or protocol['target_metadata_sha256'] != digest((folder / 'target-metadata.xml').read_bytes()):
        raise ValueError('Production observation originals changed')
    entries = read('transcript.json')
    by_id = {entry['id']: entry for entry in entries}
    if len(by_id) != len(entries) or any(entry['runId'] != run for entry in entries):
        raise ValueError('Transcript scope ambiguous')
    originals = {}
    for row in read('decoded-manifest.json'):
        path = (folder / row['file']).resolve()
        if path.parent != (folder / 'decoded').resolve() or row['id'] in originals:
            raise ValueError('Invalid original evidence path')
        raw = path.read_bytes()
        if digest(raw) != row['sha256'] or len(raw) != by_id[row['id']]['decodedSamlBytes']:
            raise ValueError('Original evidence changed')
        originals[row['id']] = raw
    observations = read('observations.json')
    if [row['condition'] for row in observations] != ['first', 'second', 'first-repeat'] or len(protocol['observations']) != 3:
        raise ValueError('Incomplete ordered comparison')
    used = set()
    bindings = []
    for observation, verified in zip(observations, protocol['observations']):
        if observation['before'] != prepared['native'] or observation['after'] != prepared['native'] \
                or observation['login_input_binding'] != prepared['login_input_binding']:
            raise ValueError('Native preparation or driver input changed')
        if verified['variant'] != observation['variant'] or verified['entity_id'] != observation['entity_id']:
            raise ValueError('Relying party association differs')
        refs = [ref['reference'] for ref in verified['evidence']]
        if len(refs) != 4 or set(refs[2:]) != set(observation['new_transcript_ids']) or used.intersection(refs[2:]):
            raise ValueError('Exchange provenance differs or reused')
        used.update(refs[2:])
        if originals[refs[1]] != (folder / 'fixture.xml').read_bytes():
            raise ValueError('Native imported aggregate differs from Recorder')
        request = ET.fromstring(originals[refs[2]])
        if request.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text != observation['entity_id']:
            raise ValueError('Original requester differs')
        side = 'second' if observation['condition'] == 'second' else 'first'
        if verified['markers'] != ['anchor', side] or observation['entity_id'] != native['entity_ids'][side]:
            raise ValueError('Entity-specific attribute difference unobserved')
        bindings.append(dict(condition=observation['condition'], entity_id=observation['entity_id'],
            request_reference=refs[2], response_reference=refs[3], markers=verified['markers']))
    return dict(run=run, native_preparation_bound=True, exchanges=bindings,
                native_binding={**{key: native[key] for key in ['policy_sha256', 'configuration_sha256']},
                                'source_attribute': native.get('source_attribute', 'uid')},
                same_attribute_input=True, verdict_adopted=False,
                reason='formal-case-registration-and-receipt-verification-pending')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    folder = parser.parse_args().evidence.resolve()
    report = verify(folder)
    with (folder / 'native-protocol-binding.json').open('x') as output:
        json.dump(report, output, indent=2)
        output.write('\n')
    print('Native preparation and protocol references bound; no verdict assigned')
