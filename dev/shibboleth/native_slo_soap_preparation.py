#!/usr/bin/env python3
"""Historical host-only SOAP preparation prototype; never an installable native fixture.

The operative collector copies the exact signed MetadataPrepared transcript produced by
SloPropagationFixtures. Its error is a signed Responder over HTTP 200. The older manual
three-route fixture here remains a diagnostic of namespace/provider/flow parsing only;
it must not be substituted for the Run-scoped factory originals or adopted as evidence.
"""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import urllib.parse
import xml.etree.ElementTree as ET

MD = 'urn:oasis:names:tc:SAML:2.0:metadata'
SAML = 'urn:oasis:names:tc:SAML:2.0:protocol'
SOAP = 'http://schemas.xmlsoap.org/soap/envelope/'
SOAP_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP'
PROVIDER = 'urn:mace:shibboleth:2.0:metadata'
XSI = 'http://www.w3.org/2001/XMLSchema-instance'
FLOW = 'http://www.springframework.org/schema/webflow'
CASE = 'IIP-IDP17-r-idp-01'
MAX_BYTES = 1024 * 1024
IDENTITY = r'[0-9A-HJKMNP-TV-Z]{26}'


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse(raw):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BYTES, 'Invalid public XML size')
    require(b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(), 'External XML declarations forbidden')
    return ET.fromstring(raw)


def identity(plan, run):
    require(re.fullmatch('plan_' + IDENTITY, plan) and re.fullmatch('run_' + IDENTITY, run), 'Invalid Plan/Run identity')


def public_url(value):
    url = urllib.parse.urlsplit(value)
    require(url.scheme in ('http', 'https') and url.netloc and not url.username and not url.password
            and not url.fragment, 'Non-public or invalid endpoint')
    keys = [key.lower() for key, _ in urllib.parse.parse_qsl(url.query, keep_blank_values=True)]
    require(not set(keys) & {'authstate', 'execution', 'csrf', 'token', 'sessionkey', 'password', 'secret', 'auth_session_id'},
            'Capability query refused before public export')
    return url


def run_endpoint(value, run):
    url = public_url(value)
    fields = urllib.parse.parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
    existing = [v for k, v in fields if k == 'run']
    require(not existing or existing == [run], 'Foreign or duplicate Run endpoint')
    if not existing:
        fields.append(('run', run))
    return urllib.parse.urlunsplit(url._replace(query=urllib.parse.urlencode(fields)))


def soap_metadata(primary_bytes, plan, run, trial):
    """Keep keys/ACS/other roles, replace only SLO advertisements with real SOAP routes."""
    identity(plan, run)
    require(trial in ('failure', 'all-success'), 'Unknown propagation trial')
    primary = parse(primary_bytes)
    entity = primary.get('entityID', '')
    url = public_url(entity)
    require(primary.tag == '{' + MD + '}EntityDescriptor' and url.path == '/p/' + plan and not url.query,
            'Primary Suite metadata is not this Plan')
    roles = primary.findall('{' + MD + '}SPSSODescriptor')
    require(len(roles) == 1, 'Exactly one operative Suite SP role required')
    sp = roles[0]
    keys = sp.findall('{' + MD + '}KeyDescriptor')
    acs = sp.findall('{' + MD + '}AssertionConsumerService')
    require(keys and acs, 'Suite keys and ACS must be supplied by original metadata')
    require(len({a.get('index') for a in acs}) == len(acs), 'Duplicate Suite ACS index')
    for node in primary.iter():
        for field in ('Location', 'ResponseLocation'):
            if node.get(field):
                public_url(node.get(field))
    advertised = [x for x in sp.findall('{' + MD + '}SingleLogoutService') if x.get('Binding') == SOAP_BINDING]
    require(len(advertised) == 1, 'Original primary SOAP SLO advertisement required')
    primary_soap = advertised[0]
    require(public_url(primary_soap.get('Location', '')).path == '/p/' + plan + '/sp/slo/soap',
            'Primary SOAP location is not the actual Suite SP route')
    for endpoint in list(sp.findall('{' + MD + '}SingleLogoutService')):
        sp.remove(endpoint)
    primary_soap.set('Location', run_endpoint(primary_soap.get('Location'), run))
    if primary_soap.get('ResponseLocation'):
        primary_soap.set('ResponseLocation', run_endpoint(primary_soap.get('ResponseLocation'), run))
    sp.append(primary_soap)
    root = ET.Element('{' + MD + '}EntitiesDescriptor', {'Name': 'native-soap-propagation-' + run})
    root.append(primary)
    peers = []
    # Session registration order is evidence, never a promise about native iteration order.
    for label in ('fail', 'remain', 'remain2'):
        peer = entity + '/sp-' + label
        path = '/p/' + plan + ('/idp/slo/soap' if label == 'remain2' else
                              '/sp/slo-fail' if trial == 'failure' and label == 'fail' else '/sp/slo/soap')
        endpoint = urllib.parse.urlunsplit(url._replace(path=path, query='run=' + run))
        descriptor = ET.SubElement(root, '{' + MD + '}EntityDescriptor', {'entityID': peer, 'ID': '_' + run + '-' + label})
        role = ET.SubElement(descriptor, '{' + MD + '}SPSSODescriptor', {
            'protocolSupportEnumeration': SAML, 'AuthnRequestsSigned': 'false', 'WantAssertionsSigned': 'true'})
        for key in keys:
            role.append(copy.deepcopy(key))
        ET.SubElement(role, '{' + MD + '}SingleLogoutService', {'Binding': SOAP_BINDING, 'Location': endpoint})
        for a in acs:
            role.append(copy.deepcopy(a))
        peers.append({'label': label, 'entity': peer, 'soapEndpoint': endpoint})
    return ET.tostring(root, encoding='utf-8'), peers


def provider_configuration(original, run):
    require(re.fullmatch('run_' + IDENTITY, run), 'Invalid Run')
    root = parse(original)
    require(root.tag == '{' + PROVIDER + '}MetadataProvider', 'Unexpected native provider root')
    provider_id = 'NativeSoapPropagation-' + run
    path = '/opt/reference-idp/metadata/native-soap-propagation-' + run + '.xml'
    require(not any(n.get('id') == provider_id or n.get('metadataFile') == path for n in root.iter()),
            'Provider/source is already owned by another attempt')
    root.insert(0, ET.Element('{' + PROVIDER + '}MetadataProvider', {
        'id': provider_id, '{' + XSI + '}type': 'FilesystemMetadataProvider', 'metadataFile': path}))
    return ET.tostring(root, encoding='utf-8'), path


def sequential_flow_contract(raw):
    """Read stock structural transitions, not comments or constant-pool names."""
    root = parse(raw)
    require(root.tag == '{' + FLOW + '}flow', 'Wrong native Webflow resource')
    states = {n.get('id'): n for n in root if n.get('id')}
    call = states.get('CallPropagationFlow')
    require(call is not None and call.tag == '{' + FLOW + '}subflow-state'
            and call.get('subflow') == '#{currentEvent.id}', 'Native propagation call missing')
    require(any(n.get('to') == 'PopulateNextLogoutPropagationContext' and n.get('on') is None
                for n in call.findall('{' + FLOW + '}transition')), 'Failure must return to native next-participant state')
    require('RestoreProfileRequestContextTree' in states and 'BuildResponse' in states
            and 'CheckForPartialLogout' in states, 'Original context/final response closure missing')
    return {'resourceSha256': sha(raw), 'originBinding': SOAP_BINDING,
            'targetEndpointSuffix': '/idp/profile/SAML2/SOAP/SLO',
            'sequentialSubflowTransition': True, 'affectsVerdict': False}


def soap_message(raw, name):
    root = parse(raw)
    require(root.tag == '{' + SOAP + '}Envelope', 'Actual SOAP 1.1 Envelope required')
    body = root.findall('{' + SOAP + '}Body')
    require(len(body) == 1 and len(body[0]) == 1 and body[0][0].tag == '{' + SAML + '}' + name,
            'SOAP Body must contain exactly the selected SAML message')
    return body[0][0]


def write_preparation(output, primary, providers, native_flow, plan, run, trial):
    fixture, peers = soap_metadata(primary, plan, run, trial)
    configured, source_path = provider_configuration(providers, run)
    flow = sequential_flow_contract(native_flow)
    output.mkdir(parents=True, exist_ok=False)
    files = {'suite-primary-original.xml': primary, 'original-providers.xml': providers,
             'configured-soap-metadata.xml': fixture, 'configured-providers.xml': configured,
             'native-slo-back-flow.xml': native_flow, 'source-native_slo_soap_preparation.py': Path(__file__).read_bytes()}
    for name, raw in files.items():
        (output / name).write_bytes(raw)
    manifest = {'schema': 'samlscope-shibboleth-soap-propagation-preparation-v1', 'runId': run, 'planId': plan,
                'trial': trial, 'caseId': CASE, 'status': 'prepared-not-applied', 'affectsVerdict': False,
                'nativeSourcePath': source_path, 'peers': peers, 'nativeFlow': flow,
                'requiredOrigin': 'Same-Run deterministic Suite outbox signed LogoutRequest, SOAP envelope, native SOAP SLO endpoint',
                'requiredFailureProof': 'Actual raw SOAP request and emitted HTTP500 SOAP Fault originals, same Run/request/peer/session/native scope/time; no flags-only proof',
                'requiredContinuation': 'Native new distinct participant request issued after actual500, correlated Suite SOAP response, inside exactly one initiator/final-response window',
                'requiredReadback': 'Applied metadata source/provider byte readback plus native mdquery for all four SP entities; then exact restoration/readiness/runtime',
                'files': {name: {'sha256': sha(raw), 'bytes': len(raw)} for name, raw in files.items()},
                'estimatedBudgetOnly': {'credentialUpperBoundPerTrial': 1, 'authenticatedParticipants': 4,
                                        'nativePropagationRequests': 3, 'originSoapRequests': 1,
                                        'configurationWritesIncludingRestore': 3, 'metadataReloadsIncludingRestore': 2},
                'actualOperations': {'productSettings': 0, 'protocolSends': 0, 'credentials': 0, 'nativeCommands': 0},
                'preparedAt': datetime.now(timezone.utc).isoformat()}
    (output / 'preparation.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('suite-metadata', 'original-providers', 'native-slo-back-flow', 'output'):
        parser.add_argument('--' + flag, type=Path, required=True)
    parser.add_argument('--plan-id', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--trial', choices=('failure', 'all-success'), default='failure')
    args = parser.parse_args()
    write_preparation(args.output, args.suite_metadata.read_bytes(), args.original_providers.read_bytes(),
                      args.native_slo_back_flow.read_bytes(), args.plan_id, args.run_id, args.trial)
    print('SOAP preparation saved; native operations 0; origin/failure Recorder qualification required')


if __name__ == '__main__':
    main()
