#!/usr/bin/env python3
"""Verify the reviewed runtime and the retained corresponding-source download.

This does not infer permission from a dependency name or an SPDX scanner result.
The manifest describes a reviewed, unchanged linux/amd64 runtime. Regenerate and
review the evidence when changing that runtime; never copy an old approval to it.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]


def assemble_asset(asset, cache, output):
    """Rebuild a reviewed source asset without extracting or modifying upstream archives."""
    cache.mkdir(parents=True, exist_ok=True)
    output.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output / asset['name'], 'w', format=tarfile.PAX_FORMAT) as archive:
        index = json.dumps({'description': asset['description'], 'files': asset['files']},
                           sort_keys=True, indent=2).encode() + b'\n'
        info = tarfile.TarInfo('SOURCE-INDEX.json')
        info.size = len(index)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(index))
        for source in sorted(asset['files'], key=lambda x: x['name']):
            if Path(source['name']).name != source['name']:
                raise ValueError('Unsafe source filename')
            path = cache / source['name']
            if not path.exists():
                with urllib.request.urlopen(source['url'], timeout=120) as response, path.open('wb') as target:
                    while chunk := response.read(1024 * 1024):
                        target.write(chunk)
            with path.open('rb') as stream:
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                if digest != source['sha256'] or path.stat().st_size != source['size']:
                    raise ValueError('Source input changed: ' + source['name'])
                stream.seek(0)
                info = tarfile.TarInfo(source['name'])
                info.size = source['size']
                info.mode = 0o644
                archive.addfile(info, stream)


def check_download(asset):
    digest = hashlib.sha256()
    size = 0
    with urllib.request.urlopen(asset['url'], timeout=120) as response:
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    if digest.hexdigest() != asset['sha256'] or size != asset['size']:
        raise ValueError('Corresponding-source asset changed: ' + asset['url'])


def check_runtime(manifest, image):
    architecture = subprocess.check_output(
        ['docker', 'image', 'inspect', '--format', '{{.Architecture}}', image], text=True).strip()
    if architecture != 'amd64':
        raise ValueError('Only the reviewed linux/amd64 runtime is cleared by this manifest')
    expected = manifest['runtime_file_sha256']
    actual = subprocess.check_output(
        ['docker', 'run', '--rm', '--network=none', '--entrypoint', '/usr/bin/sha256sum',
         image, *sorted(expected)], text=True)
    observed = dict((line.split(None, 1)[1].strip(), line.split(None, 1)[0])
                    for line in actual.splitlines())
    if observed != expected:
        raise ValueError('Runtime package inventory, JRE release or retained legal text changed')
    # Copyright files in Ubuntu refer to these complete license texts.
    subprocess.run(['docker', 'run', '--rm', '--network=none', '--entrypoint', '/bin/sh',
                    image, '-ec', 'for f in GPL-2 GPL-3 LGPL-2 LGPL-2.1 LGPL-3; do '
                    'test -s /usr/share/common-licenses/$f; done'], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', help='Locally built runtime image; required in publication CI')
    parser.add_argument('--assemble', type=Path, help='Rebuild source assets into this directory')
    parser.add_argument('--cache', type=Path, default=ROOT / 'build/container-source-cache')
    args = parser.parse_args()
    manifest = json.loads((ROOT / 'LICENSES/container-source-manifest.json').read_text())
    final_from = [line for line in (ROOT / 'Dockerfile').read_text().splitlines()
                  if line.startswith('FROM ')][-1]
    if final_from != 'FROM ' + manifest['base_image']:
        raise ValueError('Final base image is not the reviewed source-availability boundary')
    if args.image:
        check_runtime(manifest, args.image)
    for asset in manifest['assets']:
        if args.assemble:
            assemble_asset(asset, args.cache, args.assemble)
            path = args.assemble / asset['name']
            with path.open('rb') as stream:
                if (hashlib.file_digest(stream, 'sha256').hexdigest() != asset['sha256']
                        or path.stat().st_size != asset['size']):
                    raise ValueError('Rebuilt source asset differs from reviewed bytes')
        else:
            check_download(asset)
    print(('Source bundles reproduced and hash-verified' if args.assemble
           else 'Reviewed container sources are publicly downloadable and hash-verified')
          + ('; actual runtime inventory and notices match' if args.image else ''))


if __name__ == '__main__':
    main()
