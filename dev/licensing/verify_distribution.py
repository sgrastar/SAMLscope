#!/usr/bin/env python3
"""Check retained notices in actual archives and optional website output."""
import argparse
import io
import json
import tarfile
import zipfile
from pathlib import Path

from java_dependencies import inventory

ROOT = Path(__file__).resolve().parents[2]


def verify(files):
    prefix = next(p[:-len('LICENSING.md')] for p in files if p.count('/') == 1 and p.endswith('/LICENSING.md'))
    checked = []
    for name in ['LICENSE', 'LICENSING.md', *['LICENSES/' + p.name for p in (ROOT / 'LICENSES').iterdir() if p.is_file()]]:
        assert files[prefix + name] == (ROOT / name).read_bytes(), name
        checked.append(name)
    api = next(p for p in files if '/lib/api-' in p and p.endswith('.jar'))
    runner = next(p for p in files if '/lib/runner-' in p and p.endswith('.jar'))
    with zipfile.ZipFile(io.BytesIO(files[api])) as jar:
        for name in ['LICENSE', 'LICENSING.md', 'LICENSES/source-notices.json', 'LICENSES/material-index.json']:
            assert jar.read('META-INF/samlscope/' + name) == (ROOT / name).read_bytes(), name
        assert jar.read('public/licenses/java-dependencies.json') == (ROOT / 'web/public/licenses/java-dependencies.json').read_bytes()
        assert jar.read('public/licenses/source-membership.json') == (ROOT / 'web/public/licenses/source-membership.json').read_bytes()
        dependencies = json.loads(jar.read('public/licenses/browser-dependencies.json'))
        assert dependencies['packages'] and all(p['notices'] for p in dependencies['packages'])
        assert jar.read('public/licenses/source-notices.json') == (ROOT / 'LICENSES/source-notices.json').read_bytes()
    with zipfile.ZipFile(io.BytesIO(files[runner])) as jar:
        assert jar.read('META-INF/samlscope/LICENSES/CC-BY-SA-4.0.txt') == (ROOT / 'LICENSES/CC-BY-SA-4.0.txt').read_bytes()
    return {'retained_files': checked, 'browser_packages': [p['name'] for p in dependencies['packages']]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--website', type=Path)
    args = parser.parse_args()
    results = {}
    own_jars = []
    for module in ['api', 'core', 'saml', 'store', 'runner', 'peer']:
        paths = list((ROOT / module / 'build/libs').glob('*.jar'))
        assert paths and any(p.name.endswith('-sources.jar') for p in paths), module
        for path in paths:
            with zipfile.ZipFile(path) as jar:
                for name in ['LICENSE', 'LICENSING.md', 'LICENSES/CC-BY-SA-4.0.txt']:
                    assert jar.read('META-INF/samlscope/' + name) == (ROOT / name).read_bytes(), str(path) + ':' + name
            own_jars.append(str(path.relative_to(ROOT)))
    results['standalone_jars'] = own_jars
    for suffix in ['zip', 'tar']:
        path = ROOT / f'api/build/distributions/samlscope-0.1.0.{suffix}'
        if suffix == 'zip':
            assert inventory(path) == json.loads((ROOT / 'web/public/licenses/java-dependencies.json').read_text()), 'Runtime JAR inventory is stale'
            with zipfile.ZipFile(path) as archive:
                files = {p: archive.read(p) for p in archive.namelist() if not p.endswith('/')}
        else:
            with tarfile.open(path) as archive:
                files = {p.name: archive.extractfile(p).read() for p in archive.getmembers() if p.isfile()}
        results[suffix] = verify(files)
    if args.website:
        dist = args.website / 'dist'
        catalog = json.loads((dist / 'data/traceability.json').read_text())
        index = json.loads((ROOT / 'LICENSES/material-index.json').read_text())
        assert all(row['sourceIds'] == index['obligation_sources'][row['obligation']] for row in catalog['rows']), 'Website source membership differs'
        assert catalog['attribution']['originalContentLicenseText'] == (ROOT / 'LICENSES/CC-BY-SA-4.0.txt').read_text()
        assert (dist / 'licenses/cc-by-sa-4.0.txt').read_bytes() == (ROOT / 'LICENSES/CC-BY-SA-4.0.txt').read_bytes()
        assert 'Licenses and sources' in (dist / 'licenses/index.html').read_text()
        results['website'] = 'License page, catalog and standalone content-license download verified'
    output = ROOT / 'build/license-distribution-report.json'
    output.write_text(json.dumps(results, indent=2) + '\n')
    print('ZIP/TAR, nested application and runner JAR notices match' + ('; website downloads match' if args.website else ''))


if __name__ == '__main__':
    main()
