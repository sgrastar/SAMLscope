#!/usr/bin/env python3
"""Probe the installed native parser/filter without changing configuration or assigning verdicts."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

CONDITIONS = ('baseline', 'entity-present', 'entity-absent', 'requested-required',
              'requested-optional', 'requested-absent', 'index-zero', 'index-one', 'index-zero-repeat')
PHP = r'''
require '/var/simplesamlphp/lib/_autoload.php';
$xml = stream_get_contents(STDIN);
(new \SimpleSAML\Utils\XML())->checkSAMLMessage($xml, 'saml-meta');
$entities = \SimpleSAML\Metadata\SAMLParser::parseDescriptorsString($xml);
$metadata = $entities[$argv[1]]->getMetadata20SP();
if ($metadata === null) { throw new \RuntimeException('Missing SP descriptor'); }
$state = ['Attributes' => [
    'urn:oid:0.9.2342.19200300.100.1.1' => ['synthetic-input'],
    'urn:oid:2.5.4.4' => ['synthetic-input'],
    'urn:samlscope:test:unrequested' => ['synthetic-input']],
    'Destination' => $metadata, 'Source' => []];
$config = [];
$filter = new \SimpleSAML\Module\core\Auth\Process\AttributeLimit($config, null);
$filter->process($state);
$sources = [];
foreach ([\SimpleSAML\Metadata\SAMLParser::class,
          \SimpleSAML\Module\core\Auth\Process\AttributeLimit::class] as $class) {
    $file = (new \ReflectionClass($class))->getFileName();
    $sources[$class] = ['file' => $file, 'sha256' => hash_file('sha256', $file)];
}
$selected = [];
foreach (['attributes', 'attributes.required', 'attributes.NameFormat', 'EntityAttributes'] as $key) {
    $selected[$key] = $metadata[$key] ?? null;
}
echo json_encode(['parsed' => $selected, 'filtered_names' => array_keys($state['Attributes']),
    'product_sources' => $sources], JSON_THROW_ON_ERROR);
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixtures', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('Refusing to overwrite evidence')
    # Validate all inputs before invoking the product. Inputs are unmodified original fixtures.
    fixtures = []
    for condition in CONDITIONS:
        path = args.fixtures / condition / 'fixture.xml'
        raw = path.read_bytes()
        root = ET.fromstring(raw)
        if root.tag != '{urn:oasis:names:tc:SAML:2.0:metadata}EntityDescriptor' or not root.get('entityID'):
            raise ValueError('Expected a single EntityDescriptor')
        fixtures.append((condition, path, raw, root.attrib['entityID']))
    args.output.mkdir(parents=True)
    records = []
    try:
        for condition, path, raw, entity in fixtures:
            result = subprocess.run(['docker', 'exec', '-i', 'samlscope-reference-ssp',
                'php', '-r', PHP, entity], input=raw, capture_output=True, timeout=40)
            record = dict(condition=condition, fixture=str(path.resolve()),
                fixture_sha256=hashlib.sha256(raw).hexdigest(), exit_code=result.returncode)
            records.append(record)
            (args.output / (condition + '.stderr')).write_bytes(result.stderr)
            if result.returncode:
                raise RuntimeError('Native probe failed: ' + condition)
            record['observation'] = json.loads(result.stdout)
            print(condition, json.dumps(record['observation'], sort_keys=True), flush=True)
    finally:
        report = dict(schema='samlscope-native-attribute-policy-probe-v1',
            scope='native-parser-and-filter-only', protocol_observed=False, verdict_adopted=False,
            operations=dict(native_probe_attempts=len(records), product_configuration_writes=0,
                            service_reloads=0, protocol_roundtrips=0, human_operations=0),
            records=records)
        (args.output / 'observations.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
