#!/usr/bin/env python3
"""Capture ForceAuthn at the actual stock password-mechanism state boundary.

The existing browser chain supplies signed omission/false/true inputs. This
collector reads the native UserPassBase login-stage state before credentials
are submitted, retaining neither cookies nor the AuthState handle. It assigns
no outcome and restores the temporary peer through the existing batch driver.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import subject_confirmation_campaign as subject
from native_ui_privacy import sanitized, contains_state_secret

_chain_spec = importlib.util.spec_from_file_location('ssp_mechanism_browser_chain',
    Path(__file__).with_name('browser_chain_campaign.py'))
chain = importlib.util.module_from_spec(_chain_spec)
_chain_spec.loader.exec_module(chain)

REPO = Path(__file__).resolve().parents[2]
CASE = 'IIP-IDP06-b-idp-01'
DRIVER_CASE = 'IIP-IDP06-a-idp-01'
SOURCES = {
    'idp-saml2': 'modules/saml/src/IdP/SAML2.php',
    'idp': 'src/SimpleSAML/IdP.php',
    'auth-source': 'src/SimpleSAML/Auth/Source.php',
    'userpass': 'modules/exampleauth/src/Auth/Source/UserPass.php',
    'userpass-base': 'modules/core/src/Auth/UserPassBase.php',
    'login-controller': 'modules/core/src/Controller/Login.php',
    'auth-state': 'src/SimpleSAML/Auth/State.php',
}
STATE = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$i=json_decode(stream_get_contents(STDIN),true,512,JSON_THROW_ON_ERROR);$_COOKIE=$i['cookies'];
$stage=\SimpleSAML\Module\core\Auth\UserPassBase::STAGEID;
$s=\SimpleSAML\Auth\State::loadState($i['authState'],$stage);
$id=$s[\SimpleSAML\Module\core\Auth\UserPassBase::AUTHID];
$source=\SimpleSAML\Auth\Source::getById($id);
if($source===null)throw new RuntimeException('Native selected source unavailable');
$method=new ReflectionMethod($source,'authenticate');
echo json_encode(['requestId'=>$s['saml:RequestId'],'consumerURL'=>$s['saml:ConsumerURL'],
 'binding'=>$s['saml:Binding'],'responder'=>$s['Responder'],'forceAuthn'=>$s['ForceAuthn'],
 'isPassive'=>$s['isPassive'],'mechanismId'=>$id,'mechanismClass'=>get_class($source),
 'stateStage'=>$stage,'declaringClass'=>$method->getDeclaringClass()->getName(),
 'mechanismSourceSha256'=>hash_file('sha256',$method->getFileName()),
 'stateHandlePersisted'=>false,'credentialsPersisted'=>false],JSON_THROW_ON_ERROR);
'''


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    folder = args.output.resolve()
    if not folder.is_relative_to(REPO / 'build/acceptance') or folder.exists():
        raise ValueError('Fresh acceptance output required')
    folder.mkdir(parents=True)
    live = subprocess.check_output(['docker', 'exec', 'samlscope-reference-suite',
        'sha256sum', '/opt/samlscope/lib/api-0.1.0.jar']).decode().split()[0]
    archive = REPO / 'build/acceptance/reference-20261004/deployment-v229/runtime-built/api-0.1.0.jar'
    if sha(archive.read_bytes()) != live:
        raise ValueError('Pinned current profile artifact unavailable')
    with zipfile.ZipFile(archive) as jar:
        raw = jar.read('profiles/browser_sso_idp.json')
    profile = json.loads(raw)
    cases = {row['id']: row['digest'] for row in profile['cases']}
    if not {CASE, DRIVER_CASE} <= set(cases):
        raise ValueError('Approved source and destination cases are not planned')
    (folder / 'profile.json').write_bytes(raw)
    save(folder / 'scope-before.json', dict(case=CASE, driverCase=DRIVER_CASE,
        profile='browser_sso_idp', profileSha256=sha(raw), deployedApiSha256=live,
        caseDigests={case: cases[case] for case in (CASE, DRIVER_CASE)},
        outcomeAssigned=False))
    records, response_originals, request_originals, observations = [], {}, {}, []
    clients = []

    class MechanismClient(subject.NativeClient):
        def __init__(self):
            super().__init__(records, response_originals, request_originals, observations)
            clients.append(self)

    original_client, original_state, original_argv = chain.Client, subject.STATE, sys.argv
    try:
        for name, path in SOURCES.items():
            (folder / ('native-' + name + '.php')).write_bytes(subprocess.check_output([
                'docker', 'exec', chain.CONTAINER, 'cat', '/var/simplesamlphp/' + path]))
        (folder / 'native-state-command.php').write_text(STATE)
        (folder / 'collector.py').write_bytes(Path(__file__).read_bytes())
        chain.Client, subject.STATE = MechanismClient, STATE
        sys.argv = [str(Path(chain.__file__)), '--output', str(folder / 'browser'),
            '--only-cases', DRIVER_CASE, '--stop-after-case', DRIVER_CASE,
            '--reuse-session', '--no-idp-initiated-sso']
        chain.main()
    finally:
        chain.Client, subject.STATE, sys.argv = original_client, original_state, original_argv
        save(folder / 'native-mechanism-observations.json', dict(observations=observations))
        save(folder / 'native-http-observations.json', dict(records=records))
        originals = folder / 'native-http-originals'
        originals.mkdir(exist_ok=True)
        for row in records:
            request_id = row['request_id']
            page = sanitized(response_originals[request_id].decode(), None)
            if contains_state_secret(page):
                raise ValueError('Native state secret retained')
            (originals / (request_id + '.html')).write_text(page)
            xml, body = request_originals[request_id]
            (originals / (request_id + '.request.xml')).write_bytes(xml)
            (originals / (request_id + '.request.body')).write_bytes(body)
            row['persisted_body_sha256'] = sha(page.encode())
        save(folder / 'native-http-observations.json', dict(records=records))
        for name, path in SOURCES.items():
            if not (folder / ('native-' + name + '.php')).exists():
                continue
            after = subprocess.check_output(['docker', 'exec', chain.CONTAINER,
                'cat', '/var/simplesamlphp/' + path])
            (folder / ('native-' + name + '-after.php')).write_bytes(after)
            if after != (folder / ('native-' + name + '.php')).read_bytes():
                raise ValueError('Native mechanism code changed')
        save(folder / 'mechanism-operation-counts.json', dict(
            nativeStateReadbacks=len(observations), credentialPosts=sum(c.credentialPosts for c in clients),
            protocolOperations=len(records), humanOperations=0, nativeCodeWrites=0,
            outcomeAssigned=False))


if __name__ == '__main__':
    main()
