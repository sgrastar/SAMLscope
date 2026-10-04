"""Publish the Suite SP metadata for a plan into the reference Shibboleth filesystem provider.

The reference IdP resolves its Suite SP metadata from %{idp.home}/metadata/suite.xml through a
FilesystemMetadataProvider, so nothing populates that file automatically. This restores the
missing prerequisite of the SLO propagation harness without hand-editing the container.

The previous content is saved next to the output directory so it can be restored verbatim.
"""
import argparse
import hashlib
import json
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

CONTAINER = 'samlscope-reference-shibboleth'
SUITE_FILE = '/opt/reference-idp/metadata/suite.xml'
METADATA_NS = 'urn:oasis:names:tc:SAML:2.0:metadata'


def as_entities_descriptor(published):
    """Wrap the Suite's single EntityDescriptor so participant siblings stay schema-valid.

    The reference provider file root is an EntitiesDescriptor; appending EntityDescriptor
    siblings directly under an EntityDescriptor is not valid metadata and the IdP refuses
    to load it.
    """
    descriptor = ET.fromstring(published)
    if descriptor.tag == '{%s}EntitiesDescriptor' % METADATA_NS:
        return published
    if descriptor.tag != '{%s}EntityDescriptor' % METADATA_NS:
        raise RuntimeError('unexpected Suite metadata root ' + descriptor.tag)
    root = ET.Element('{%s}EntitiesDescriptor' % METADATA_NS)
    root.append(descriptor)
    return ET.tostring(root, xml_declaration=True, encoding='UTF-8')


def call(*args):
    return subprocess.check_output(['docker', *args], stderr=subprocess.STDOUT)


def read_suite():
    return call('exec', CONTAINER, 'cat', SUITE_FILE)


def write_suite(payload):
    subprocess.run(['docker', 'exec', '-i', CONTAINER, 'sh', '-c', 'cat > ' + SUITE_FILE],
                   input=payload, check=True)


def reload_resolver():
    subprocess.run(['docker', 'exec', CONTAINER, '/opt/reference-idp/bin/reload-service.sh',
                    '-id', 'shibboleth.MetadataResolverService', '-u', 'http://localhost:8080/idp'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--plan', required=True)
    parser.add_argument('--suite', default='http://localhost:18080')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(args.suite + '/p/' + args.plan + '/metadata', timeout=60) as response:
        fetched = response.read()
    if b'EntityDescriptor' not in fetched:
        raise RuntimeError('Suite SP metadata is not an EntityDescriptor')
    published = as_entities_descriptor(fetched)

    before = read_suite()
    (args.output / 'suite.xml.before').write_bytes(before)
    write_suite(published)
    reload_resolver()
    after = read_suite()
    (args.output / 'suite.xml.after').write_bytes(after)
    record = {
        'plan': args.plan,
        'container': CONTAINER,
        'file': SUITE_FILE,
        'writes': 1,
        'reload': 'MetadataResolverService',
        'before_sha256': hashlib.sha256(before).hexdigest(),
        'published_sha256': hashlib.sha256(published).hexdigest(),
        'after_sha256': hashlib.sha256(after).hexdigest(),
        'written_back': after == published,
    }
    (args.output / 'publish.json').write_text(json.dumps(record, indent=2))
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
