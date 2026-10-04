#!/usr/bin/env python3
"""Run one native Shibboleth target-initiated SLO probe with byte-exact metadata restoration."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


REPO = Path(__file__).resolve().parents[2]
CONTAINER = 'samlscope-reference-shibboleth'
METADATA = '/opt/reference-idp/metadata/suite.xml'
DRIVERS = {
    'target': REPO / 'dev/shibboleth/slo_target_initiated_probe.mjs',
    'webflow': REPO / 'dev/shibboleth/playwright_chain.mjs',
    'correlated': REPO / 'dev/shibboleth/slo_correlated_propagation.mjs',
}
PLAN = 'plan_3C0PZPNZD8P9C1MXK9V9QJ43DD'


def docker(*args, input_bytes=None):
    return subprocess.run(['docker', *args], input=input_bytes,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=True, timeout=90).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--driver', choices=DRIVERS, default='target')
    args = parser.parse_args()
    driver = DRIVERS[args.driver]
    out = args.output.resolve()
    if out.exists() and any(out.iterdir()):
        raise ValueError('Evidence directory must be empty')
    out.mkdir(parents=True, exist_ok=True)
    original = docker('exec', CONTAINER, 'cat', METADATA)
    (out / 'suite.xml.before').write_bytes(original)
    if PLAN.encode() not in original:
        raise ValueError('The pinned reference plan is not configured in native metadata')
    stage = out / 'driver'
    stage.mkdir()
    shutil.copyfile(driver, stage / driver.name)
    modules = Path(os.environ.get('SAML_SCOPE_PLAYWRIGHT_MODULES',
                                   '/private/tmp/samlscope-playwright/node_modules'))
    (stage / 'node_modules').symlink_to(modules, target_is_directory=True)
    env = os.environ.copy()
    env['SAML_SCOPE_ROOT'] = str(REPO)
    result_code = None
    restored = False
    try:
        executed = subprocess.run(['node', str(stage / driver.name), PLAN, str(out)],
                                  cwd=REPO, env=env, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
        result_code = executed.returncode
        (out / 'probe.log').write_text(executed.stdout)
        (out / 'suite.xml.after-probe').write_bytes(docker('exec', CONTAINER, 'cat', METADATA))
    finally:
        docker('exec', '-i', CONTAINER, 'sh', '-c', 'cat > ' + METADATA,
               input_bytes=original)
        docker('exec', CONTAINER, '/opt/reference-idp/bin/reload-service.sh',
               '-id', 'shibboleth.MetadataResolverService', '-u', 'http://localhost:8080/idp')
        final = docker('exec', CONTAINER, 'cat', METADATA)
        restored = final == original
        (out / 'suite.xml.restored').write_bytes(final)
        (out / 'operation-counts.json').write_text(json.dumps({
            'product_configuration_changes': 1,
            'product_configuration_restorations': 1,
            'service_reloads': 2,
            'human_operations': 0,
            'original_sha256': hashlib.sha256(original).hexdigest(),
            'final_sha256': hashlib.sha256(final).hexdigest(),
            'restored': restored,
            'browser_exit_code': result_code,
        }, indent=2) + '\n')
    if not restored or result_code != 0:
        raise RuntimeError(f'Probe failed or metadata not restored: exit={result_code}, restored={restored}')
    sys.path.insert(0, str(REPO / 'dev/reference-acceptance'))
    from capture_run_originals import capture
    record_name = 'probe-record.json' if args.driver == 'target' else 'webflow-record.json'
    record = json.loads((out / record_name).read_text())
    if (out / 'transcript.json').exists():
        transcript = json.loads((out / 'transcript.json').read_text())
    else:
        import urllib.request
        with urllib.request.urlopen('http://localhost:18080/api/runs/' + record['run'] + '/transcript',
                                    timeout=30) as response:
            transcript = json.loads(response.read())
        (out / 'transcript.json').write_text(json.dumps(transcript, indent=2) + '\n')
    capture(out, record['run'], transcript)
    print('Run', record['run'])


if __name__ == '__main__':
    main()
