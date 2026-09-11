#!/usr/bin/env python3
"""Inventory actual third-party runtime JAR notices and embedded schemas."""
import argparse
import hashlib
import io
import json
import re
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OWN = {'api', 'core', 'saml', 'store', 'runner', 'peer'}


def inventory(archive=None, jar_paths=None):
    if jar_paths is not None:
        payloads = [(Path(p).name, Path(p).read_bytes()) for p in sorted(jar_paths)]
    else:
        with zipfile.ZipFile(archive) as distribution:
            payloads = [(Path(name).name, distribution.read(name)) for name in sorted(distribution.namelist())
                        if '/lib/' in name and name.endswith('.jar')]
    return inventory_payloads(payloads)


def inventory_payloads(payloads):
    packages = []
    for filename, data in sorted(payloads):
        if any(filename.startswith(module + '-') for module in OWN):
            continue
        with zipfile.ZipFile(io.BytesIO(data)) as jar:
            notices = []
            schemas = []
            coordinates = []
            declarations = []
            for resource in sorted(jar.namelist()):
                if resource.endswith('/'):
                    continue
                if re.search(r'(^|/)(license|licence|notice|copying|copyright)(?:[.\-_][^/]*)?$', resource, re.I):
                    content = jar.read(resource)
                    try: text = content.decode('utf-8')
                    except UnicodeDecodeError: text = content.decode('latin-1')
                    notices.append({'file': resource, 'text': text, 'sha256': hashlib.sha256(content).hexdigest()})
                if resource == 'META-INF/MANIFEST.MF':
                    content = jar.read(resource)
                    unfolded = content.decode('utf-8', errors='replace').replace('\r\n', '\n').replace('\n ', '')
                    fields = dict(re.findall(r'^(SPDX-License-Identifier|Bundle-License|Bundle-Copyright|Implementation-Vendor): (.*)$', unfolded, re.M))
                    if fields:
                        declarations.append({'file': resource, 'sha256': hashlib.sha256(content).hexdigest(), 'fields': fields})
                if resource.startswith('META-INF/maven/') and resource.endswith('/pom.xml'):
                    content = jar.read(resource)
                    pom = ET.fromstring(content)
                    licenses = [{child.tag.split('}')[-1]: child.text for child in item}
                                for item in pom.findall('./{*}licenses/{*}license')]
                    if licenses:
                        declarations.append({'file': resource, 'sha256': hashlib.sha256(content).hexdigest(), 'licenses': licenses})
                if resource.endswith('.xsd'):
                    schemas.append({'file': resource, 'sha256': hashlib.sha256(jar.read(resource)).hexdigest(),
                                    'review_status': 'RESOURCE_PERMISSION_REVIEW_PENDING'})
                if resource.startswith('META-INF/maven/') and resource.endswith('/pom.properties'):
                    values = dict(re.findall(r'^(groupId|artifactId|version)=(.*)$',jar.read(resource).decode(),re.M))
                    coordinates.append(values)
            packages.append({'file': filename, 'sha256': hashlib.sha256(data).hexdigest(),
                             'coordinates': coordinates, 'notices': notices, 'declarations': declarations,
                             'notice_status': 'RETAINED_PACKAGE_NOTICES' if notices else ('PACKAGE_DECLARATIONS_RETAINED_REVIEW_PENDING' if declarations else 'NOTICE_REVIEW_PENDING'),
                             'embedded_schemas': schemas})
    if not packages:
        raise ValueError('No third-party runtime packages found')
    permission_path = ROOT / 'LICENSES/java-permissions.json'
    permissions = json.loads(permission_path.read_text())['packages'] if permission_path.exists() else {}
    for package in packages:
        permission = permissions.get(package['file'])
        if permission is None:
            continue
        if permission['jar_sha256'] != package['sha256']:
            raise ValueError('Stale reviewed permission evidence: ' + package['file'])
        package['permission'] = permission
        package['notice_status'] = 'UPSTREAM_PERMISSION_AND_NOTICES_RETAINED'
        for schema in package['embedded_schemas']:
            review = permission.get('resource_reviews', {}).get(schema['file'])
            if review is None:
                continue
            if review['sha256'] != schema['sha256']:
                raise ValueError('Stale resource review: ' + package['file'] + '!' + schema['file'])
            schema['review_status'] = 'REVIEWED_UPSTREAM_DISTRIBUTION_CONTEXT'
            schema['review'] = review
    return {'scope': 'Third-party Java runtime packages in the SAMLscope application distribution. Package notices do not relicense embedded third-party schemas. Permission records apply to unchanged upstream package distribution only.',
            'generator': 'dev/licensing/java_dependencies.py', 'packages': packages}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('archive', type=Path, nargs='?')
    parser.add_argument('--inputs-json', type=Path, help='Resolved external JAR paths for regeneration without an existing distribution')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if bool(args.archive) == bool(args.inputs_json):
        parser.error('Supply one archive or --inputs-json')
    result = inventory(args.archive, json.loads(args.inputs_json.read_text()) if args.inputs_json else None)
    output = ROOT / 'web/public/licenses/java-dependencies.json'
    text = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
    if args.check:
        if not output.exists() or output.read_text() != text:
            raise SystemExit('Java dependency inventory differs; regenerate before distribution')
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text)
    print('Runtime packages:',len(result['packages']))
    print('Packages without embedded notice or declaration evidence:',[p['file'] for p in result['packages'] if not p['notices'] and not p['declarations'] and not p.get('permission')])
    print('Embedded schemas:',sum(len(p['embedded_schemas']) for p in result['packages']))


if __name__ == '__main__':
    main()
