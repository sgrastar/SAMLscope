"""Capture target container identity and runtime version around an IDP12.b campaign."""

import hashlib
import json
import subprocess
from pathlib import Path

TARGETS = {
    'keycloak': {
        'container': 'samlscope-reference-keycloak',
        'port': '18180',
        'version_command': ['/opt/keycloak/bin/kc.sh', '--version'],
        'version_source': None,
    },
    'shibboleth': {
        'container': 'samlscope-reference-shibboleth',
        'port': '18280',
        'version_command': ['/opt/reference-idp/bin/version.sh'],
        'version_source': '/opt/reference-idp/dist/idp.installed.version',
    },
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def capture(output, product, phase):
    if product not in TARGETS or phase not in {'start', 'end'}:
        raise ValueError('Unsupported target runtime capture')
    output = Path(output)
    target = TARGETS[product]
    prefix = output / ('target-runtime-' + phase)
    paths = [prefix.with_suffix('.json'), output / ('target-container-inspect-' + phase + '.json'),
             output / ('target-version-runtime-' + phase + '.txt')]
    if target['version_source']:
        paths.append(output / ('target-version-source-' + phase + '.txt'))
    if any(path.exists() for path in paths):
        raise RuntimeError('Refusing to overwrite target runtime originals')
    inspect_raw = subprocess.check_output(['docker', 'inspect', target['container']], timeout=60)
    inspected = json.loads(inspect_raw)
    if not isinstance(inspected, list) or len(inspected) != 1:
        raise RuntimeError('Target inspect did not return exactly one container')
    item = inspected[0]
    version_raw = subprocess.check_output(
        ['docker', 'exec', target['container'], *target['version_command']], timeout=60)
    source_raw = None
    if target['version_source']:
        source_raw = subprocess.check_output(
            ['docker', 'exec', target['container'], 'cat', target['version_source']], timeout=60)
    image_raw = subprocess.check_output(['docker', 'image', 'inspect', item['Image']], timeout=60)
    image = json.loads(image_raw)
    if not isinstance(image, list) or len(image) != 1:
        raise RuntimeError('Target image inspect did not return exactly one image')
    ports = item.get('NetworkSettings', {}).get('Ports', {}).get('8080/tcp') or []
    binding = {
        'container_name': item['Name'].removeprefix('/'),
        'container_id': item['Id'],
        'configured_image': item['Config']['Image'],
        'image_id': item['Image'],
        'repo_digests': sorted(image[0].get('RepoDigests') or []),
        'container_started_at': item['State']['StartedAt'],
        'running_at_capture': item['State']['Running'],
        'host_port': int(target['port']),
        'host_port_bound': any(row.get('HostIp') == '127.0.0.1'
                               and row.get('HostPort') == target['port'] for row in ports),
    }
    (output / ('target-container-inspect-' + phase + '.json')).write_bytes(inspect_raw)
    (output / ('target-version-runtime-' + phase + '.txt')).write_bytes(version_raw)
    summary = {
        'product': product,
        'binding': binding,
        'docker_inspect_sha256': sha(inspect_raw),
        'runtime_version': {
            'command': target['version_command'],
            'sha256': sha(version_raw),
            'value': version_raw.decode().strip(),
        },
    }
    if source_raw is not None:
        (output / ('target-version-source-' + phase + '.txt')).write_bytes(source_raw)
        summary['version_source'] = {
            'path': target['version_source'], 'sha256': sha(source_raw),
            'value': source_raw.decode().strip(),
        }
    prefix.with_suffix('.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n')
    return summary
