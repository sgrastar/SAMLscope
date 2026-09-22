"""Register the Suite SP and two propagation participants in the reference SimpleSAMLphp metadata.

SimpleSAMLphp consumes SP metadata as a PHP array, so the participant entries are generated from
the Suite's own SP metadata and appended to saml20-sp-remote.php. The failing participant points at
the Suite's /sp/slo-fail fixture (HTTP 500) and the remaining participant at the recorded
front-channel /sp/slo?run= route, so the target's continuation is captured by the Suite.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / 'dev/keycloak'))
from import_metadata_batch import api, BASE

CONTAINER = 'samlscope-reference-ssp'
TARGET = '/var/simplesamlphp/metadata/saml20-sp-remote.php'
MD = 'urn:oasis:names:tc:SAML:2.0:metadata'


def call(*args, data=None):
    return subprocess.run(['docker', 'exec', '-i', CONTAINER, *args], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120, check=True).stdout


def read_file():
    return call('cat', TARGET)


def write_file(payload):
    subprocess.run(['docker', 'exec', '-i', CONTAINER, 'sh', '-c', 'cat > ' + TARGET],
                   input=payload, check=True, timeout=120)


def entity_entry(entity_id, slo_location, acs_location, cert_b64):
    return (
        "$metadata[%s] = array (\n"
        "  'entityid' => %s,\n"
        "  'AssertionConsumerService' => array (\n"
        "    array ('index' => 0, 'isDefault' => true, 'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 'Location' => %s),\n"
        "  ),\n"
        "  'SingleLogoutService' => array (\n"
        "    array ('Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'Location' => %s),\n"
        "    array ('Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', 'Location' => %s),\n"
        "    array ('Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:SOAP', 'Location' => %s),\n"
        "  ),\n"
        "  'keys' => array (\n"
        "    array ('encryption' => false, 'signing' => true, 'type' => 'X509Certificate', 'X509Certificate' => %s),\n"
        "  ),\n"
        "  'validate.authnrequest' => false,\n"
        "  'saml20.sign.response' => true,\n"
        "  'saml20.sign.assertion' => true,\n"
        ");\n"
    ) % (php(entity_id), php(entity_id), php(acs_location), php(slo_location),
         php(slo_location), php(slo_location), php(cert_b64))


def php(value):
    return "'" + value.replace('\\', '\\\\').replace("'", "\\'") + "'"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(BASE + '/p/' + args.plan + '/metadata', timeout=60) as response:
        suite_metadata = response.read()
    role = ET.fromstring(suite_metadata).find('{%s}SPSSODescriptor' % MD)
    acs = role.find('{%s}AssertionConsumerService' % MD).get('Location')
    cert = role.find('{%s}KeyDescriptor' % MD).find(
        '{http://www.w3.org/2000/09/xmldsig#}KeyInfo').find(
        '{http://www.w3.org/2000/09/xmldsig#}X509Data').find(
        '{http://www.w3.org/2000/09/xmldsig#}X509Certificate').text.strip()

    before = read_file()
    (args.output / 'sp-remote.before.php').write_bytes(before)
    entity = BASE + '/p/' + args.plan
    if entity.encode() not in before:
        raise RuntimeError('Suite entity is not present in saml20-sp-remote.php')
    base = 'http://localhost:18080/p/' + args.plan
    additions = ''
    additions += entity_entry(base + '/sp-fail',
                              base + '/sp/slo-fail?run=' + args.run, acs, cert)
    additions += entity_entry(base + '/sp-remain',
                              base + '/sp/slo?run=' + args.run, acs, cert)
    write_file(before + additions.encode())
    after = read_file()
    (args.output / 'sp-remote.after.php').write_bytes(after)
    record = dict(plan=args.plan, run=args.run, container=CONTAINER, file=TARGET, writes=1,
                  before_sha256=hashlib.sha256(before).hexdigest(),
                  after_sha256=hashlib.sha256(after).hexdigest(),
                  appended=after.startswith(before))
    (args.output / 'setup.json').write_text(json.dumps(record, indent=2))
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
