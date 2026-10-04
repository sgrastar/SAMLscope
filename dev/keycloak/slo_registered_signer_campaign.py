#!/usr/bin/env python3
"""Register two native peers, authenticate once, run three exact Suite SLO signer controls, restore."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / 'dev/slo'), str(REPO / 'dev/keycloak')]
from registered_signer_common import collect, docker, runtime, SHA, NOW, require, public_json, save, MD, mounted_hashes
from attribute_policy_capability_absence import product_token, redact_client_credentials

CONTAINER = 'samlscope-reference-keycloak'
ADMIN = 'http://localhost:18180/admin/realms/samlscope'
SERVICES = '/opt/keycloak/lib/lib/main/org.keycloak.keycloak-services-26.7.2.jar'
MOUNTS = {'/opt/keycloak/data/import/realm-samlscope.json':dict(source=REPO/'dev/keycloak/realm-samlscope.json',rw=False)}
SERVICES_SHA = '213c45bb357e0881ead8284f12308e3c9fd8e09e7f0b6ec816f95f8b0921bea9'


class KeycloakProduct:
    name = 'Keycloak'
    adapter = 'keycloak-native-slo-issuer-key-v1'
    origin = 'http://localhost:18180'
    target = origin + '/realms/samlscope'
    metadata_url = target + '/protocol/saml/descriptor'
    metadata_source = 'http://samlscope-reference-keycloak:8080/realms/samlscope/protocol/saml/descriptor'

    def bind(self, out, receipt):
        self.out, self.receipt = out, receipt
        self.token = None
        self.operations, self.clients, self.created_entities = [], {}, {}
        self.original_policy = None

    def native(self, path, method='GET', data=None, xml=False, allow_token_refresh=True):
        if self.token is None:
            self.token = product_token()
        raw = data if isinstance(data, bytes) else None if data is None else json.dumps(data, separators=(',', ':')).encode()
        row = dict(method=method, url=ADMIN + path, startedAt=NOW(),
                   productSettingWrite=method in ('PUT', 'DELETE') or method == 'POST' and path != '/client-description-converter')
        self.operations.append(row); save(self.out / 'native-operations.json', self.operations)
        request = urllib.request.Request(ADMIN + path, data=raw, method=method,
            headers={'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/xml' if xml else 'application/json'})
        try:
            response = urllib.request.urlopen(request, timeout=40)
        except urllib.error.HTTPError as failure:
            response = failure
        try:
            reply, status, location = response.read(1024 * 1024 + 1), response.status, response.headers.get('Location')
        finally:
            response.close()
        require(len(reply) <= 1024 * 1024, 'Oversize native public response')
        row.update(finishedAt=NOW(), status=status); save(self.out / 'native-operations.json', self.operations)
        if status == 401 and allow_token_refresh:
            # Explicit native authentication rejection, with every attempted operation retained separately.
            self.token = product_token()
            return self.native(path, method, data, xml, allow_token_refresh=False)
        value = json.loads(reply) if reply else None
        cleaned, redactions = redact_client_credentials(value)
        def remove_generation_timestamp(value, path=''):
            # Native brief client lookup is a list, while direct client readback is an object.
            # Remove only this unnecessary credential-generation metadata at either shape.
            if isinstance(value, dict):
                for key in list(value):
                    child_path = path + '/' + key.replace('~', '~0').replace('/', '~1')
                    if key == 'client.secret.creation.time':
                        del value[key]
                        redactions.append(child_path)
                    else:
                        remove_generation_timestamp(value[key], child_path)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    remove_generation_timestamp(child, path + '/' + str(index))
        remove_generation_timestamp(cleaned)
        public_json(cleaned)
        record = dict(row, responsePublic=cleaned, publicProjection='native-client-public-readback-v1', removedFieldNames=redactions)
        if raw is not None:
            record['requestSha256'] = SHA(raw)
        return cleaned, record, location

    def policy(self):
        value = {label: self.native('/client-policies/' + label)[0] for label in ('policies', 'profiles')}
        require(value == {'policies': {'policies': []}, 'profiles': {'profiles': []}}, 'Unqualified extra native policies; no login attempted')
        return value

    def preflight(self):
        require(runtime(CONTAINER,MOUNTS)['image'] == 'sha256:9d1f1b2b7261ff53c66cb1092dfcdc34a5fb77e81f9e6a6e75b8b6a795de8067', 'Unexpected native product image')
        actual = docker('exec', CONTAINER, 'sha256sum', SERVICES).decode().split()[0]
        require(actual == SERVICES_SHA, 'Native SLO implementation source changed')
        source = REPO / 'build/acceptance/reference-20261002/keycloak-metadata-entity-identity-r1/native-runtime/org.keycloak.keycloak-services-26.7.2.jar'
        require(source.is_file() and not source.is_symlink() and SHA(source.read_bytes()) == actual, 'Pinned immutable native source unavailable')
        directory = self.receipt / 'native-source'; directory.mkdir()
        os.link(source, directory / 'keycloak-services.jar')
        self.original_policy = self.policy()

    def lookup(self, peer):
        path = '/clients?clientId=' + urllib.parse.quote(peer['entity'], safe='') + '&briefRepresentation=true'
        value, record, _ = self.native(path)
        require(isinstance(value, list) and len(value) <= 1 and all(p.get('clientId') == peer['entity'] for p in value),
                'Native Issuer lookup is ambiguous or resolves a foreign client')
        return value, record

    def state(self, label, peers):
        hosted_file = 'native-readbacks/' + label + '-hosted-metadata.xml'
        (self.receipt / 'native-readbacks').mkdir(exist_ok=True)
        with urllib.request.urlopen(self.metadata_url, timeout=40) as response:
            require(response.status == 200, 'Hosted native metadata readback failed')
            raw = response.read(1024 * 1024 + 1)
        hosted = ET.fromstring(raw)
        require(hosted.tag == '{' + MD + '}EntityDescriptor' and hosted.get('entityID') == self.target,
                'Actual native hosted metadata belongs to a different product')
        (self.receipt / hosted_file).write_bytes(raw)
        rows, readbacks = [], []
        for peer in peers:
            inventory, lookup = self.lookup(peer)
            row = dict(entity=peer['entity'], present=bool(inventory))
            readbacks.append(dict(entity=peer['entity'], lookup=lookup))
            if inventory:
                current, get, _ = self.native('/clients/' + inventory[0]['id'])
                require(current.get('protocol') == 'saml' and current.get('clientId') == peer['entity'], 'Native peer representation differs')
                name = 'native-readbacks/registered-' + peer['label'] + '-client.json'
                canonical = (json.dumps(current, sort_keys=True, separators=(',', ':')) + '\n').encode()
                saved = self.receipt / name
                if saved.exists():
                    require(saved.read_bytes() == canonical, 'Registered native representation changed during the operation epoch')
                else:
                    saved.write_bytes(canonical)
                der = base64.b64decode(''.join(current['attributes']['saml.signing.certificate'].split()), validate=True)
                row.update(signingCertificates=[base64.b64encode(der).decode()], nativeMetadataFile=name)
                readbacks[-1]['readback'] = get
            rows.append(row)
        policies = self.policy()
        encoded = (json.dumps(policies, sort_keys=True, separators=(',', ':')) + '\n').encode()
        directory = self.receipt / ('original-configuration' if label == 'initial' else 'final-configuration' if label == 'restoration' else 'configuration-' + label)
        directory.mkdir(exist_ok=True); (directory / 'policies.json').write_bytes(encoded)
        observed_runtime=runtime(CONTAINER,MOUNTS)
        return dict(runtime=observed_runtime, mountedFileHashes=mounted_hashes(CONTAINER,observed_runtime), hostedEntityId=hosted.get('entityID'), hostedMetadataFile=hosted_file,
            hostedMetadataReadback=dict(method='GET', url=self.metadata_url, status=200, rawBodySha256=SHA(raw)),
            peers=rows, nativePeerApiReadbacks=readbacks, configurationFiles={'policies.json': SHA(encoded)}, policies=policies,
            sourceHashes={'keycloak-services.jar': docker('exec', CONTAINER, 'sha256sum', SERVICES).decode().split()[0]},
            operativeConsumer={'class': 'org.keycloak.protocol.saml.SamlService$PostBindingProtocol',
                              'method': 'executeRequest', 'messageClass': 'LogoutRequestType'})

    def prepare(self, peers):
        for peer in peers:
            require(self.lookup(peer)[0] == [], 'Refusing to replace an existing native peer')
            raw = (self.receipt / peer['label'] / 'fixture.xml').read_bytes()
            converted, record, _ = self.native('/client-description-converter', 'POST', raw, True)
            require(record['status'] == 200 and converted.get('clientId') == peer['entity'] and converted.get('protocol') == 'saml'
                    and not converted.get('id'), 'Native XML converter prerequisite failed')
            # The unchanged native converter result is used. SAML signature attributes are not synthesized by Suite.
            require(converted.get('attributes', {}).get('saml.client.signature') == 'true', 'Native signature enforcement was not enabled by the metadata')
            save(self.out / (peer['label'] + '-conversion.json'), record)
            _, created, location = self.native('/clients', 'POST', converted)
            require(created['status'] == 201 and location, 'Fresh native peer creation failed')
            identity = location.rsplit('/', 1)[-1]; require(re.fullmatch(r'[0-9a-f-]{36}', identity), 'Unexpected native client identity')
            # Record ownership immediately so a later readback failure still deletes only this client.
            self.clients[peer['entity']] = identity
            save(self.out / 'created-native-clients.json', self.clients)
        require(len(self.clients) == 2, 'Both registered peers were not prepared')

    def before_http(self):
        return None

    def after_http(self, before):
        return {}

    def restore(self, peers):
        failures = []
        for entity, identity in reversed(list(self.clients.items())):
            _, response, _ = self.native('/clients/' + identity, 'DELETE')
            if response['status'] != 204:
                failures.append('delete')
        absent = all(self.lookup(peer)[0] == [] for peer in peers)
        policy_same = self.policy() == self.original_policy
        restored = not failures and absent and policy_same
        save(self.out / 'native-restoration.json', dict(restored=restored, newPeerEntitiesAbsent=absent,
             originalPoliciesUnchanged=policy_same, ownedClientCount=len(self.clients)))
        return restored

    def counts(self):
        return dict(nativeConfigurationWrites=sum(o['productSettingWrite'] for o in self.operations),
            restorationWrites=sum(o['method'] == 'DELETE' for o in self.operations), productRestarts=0,
            nativeHttpAttempts=len(self.operations), nativeConverterAttempts=sum(o['url'].endswith('/client-description-converter') for o in self.operations))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--min-free-mib', type=int, default=96)
    args = parser.parse_args()
    collect(KeycloakProduct(), args.output, min_free_mib=args.min_free_mib)
